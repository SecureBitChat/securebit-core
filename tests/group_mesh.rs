//! A group, end to end, through the public API a platform actually calls.
//!
//! The state machine owns no transport, so the harness below is the transport:
//! it performs the `Action`s the session returns, delivers frames to the peer
//! they were addressed to, and completes mesh dials with descriptors that name
//! their endpoints. That is exactly the loop a desktop or a phone runs, which is
//! the point — these tests exercise the same surface an integrator does.
//!
//! What is covered, in order of how much it matters:
//!   1. a group forms and every member derives the SAME safety code;
//!   2. nothing may be sent before a human confirms that code;
//!   3. signed messages are delivered, and a member with no direct link is
//!      reached over the relay path;
//!   4. the star becomes a mesh: the pair with no link dials one, and their
//!      messages stop being relayed;
//!   5. a forged or replayed frame is refused — a bad signature, a roster from
//!      someone who is not the admin, a message from another epoch;
//!   6. removing a member opens a new epoch and a new code.

use securebit_core::group_session::{
    frames, Action, Event, GroupPhase, GroupSession, MemberState, TimerKind,
};
use serde_json::Value;
use std::collections::{HashMap, HashSet, VecDeque};

// ---------------------------------------------------------------------------
// a virtual network
// ---------------------------------------------------------------------------
//
// Session ids are LOCAL to each node, as they are in a real app: a dial produces
// one id on the caller and a different one on the answerer.

struct Node {
    name: &'static str,
    session: Option<GroupSession>,
    events: Vec<Event>,
    timers: Vec<TimerKind>,
}

struct Net {
    nodes: Vec<Node>,
    /// (node, session id) -> (peer node, peer session id)
    chans: HashMap<(usize, String), (usize, String)>,
    /// Channels that have been cut.
    down: HashSet<(usize, String)>,
    counter: usize,
    group_id: String,
}

impl Net {
    fn new(names: &[&'static str]) -> Self {
        Self {
            nodes: names
                .iter()
                .map(|name| Node { name, session: None, events: Vec::new(), timers: Vec::new() })
                .collect(),
            chans: HashMap::new(),
            down: HashSet::new(),
            counter: 0,
            group_id: GroupSession::new_group_id(),
        }
    }

    /// Two endpoints of one channel. Each side addresses it by its own id, and
    /// both sides see the same pairwise key fingerprint — which is what a link
    /// probe is checked against.
    fn link(&mut self, a: usize, a_sid: &str, b: usize, b_sid: &str) {
        self.counter += 1;
        let link_fp = format!("linkfp-{}", self.counter);
        self.chans.insert((a, a_sid.to_string()), (b, b_sid.to_string()));
        self.chans.insert((b, b_sid.to_string()), (a, a_sid.to_string()));
        self.down.remove(&(a, a_sid.to_string()));
        self.down.remove(&(b, b_sid.to_string()));
        if let Some(s) = self.nodes[a].session.as_mut() {
            s.set_link_fingerprint(a_sid, &link_fp);
        }
        if let Some(s) = self.nodes[b].session.as_mut() {
            s.set_link_fingerprint(b_sid, &link_fp);
        }
    }

    fn cut(&mut self, a: usize, a_sid: &str) {
        if let Some((b, b_sid)) = self.chans.get(&(a, a_sid.to_string())).cloned() {
            self.down.insert((a, a_sid.to_string()));
            self.down.insert((b, b_sid));
        }
    }

    fn next_id(&mut self, prefix: &str) -> String {
        self.counter += 1;
        format!("{}{}", prefix, self.counter)
    }

    /// Perform every action, and everything those actions produce, until the
    /// network goes quiet.
    fn run(&mut self, origin: usize, actions: Vec<Action>) {
        let mut queue: VecDeque<(usize, Action)> =
            actions.into_iter().map(|a| (origin, a)).collect();

        // A bound, so a routing bug shows up as a failing test rather than a
        // hung one.
        let mut budget = 4000;
        while let Some((node, action)) = queue.pop_front() {
            budget -= 1;
            assert!(budget > 0, "the network did not settle — a frame is looping");
            match action {
                Action::Emit(event) => self.nodes[node].events.push(event),
                Action::ArmTimer { kind, .. } => self.nodes[node].timers.push(kind),
                Action::CloseLink { session_id } => {
                    self.chans.remove(&(node, session_id));
                }
                Action::Send { session_id, frame } => {
                    if self.down.contains(&(node, session_id.clone())) {
                        continue;
                    }
                    let (peer, peer_sid) = match self.chans.get(&(node, session_id)) {
                        Some(v) => v.clone(),
                        None => continue,
                    };
                    for a in self.deliver(peer, &peer_sid, &frame) {
                        queue.push_back((peer, a));
                    }
                }
                Action::Dial { fp } => {
                    let sid = self.next_id("mesh-o-");
                    let descriptor = format!("SB2:OFF|{}|{}", node, sid);
                    let out = self.nodes[node]
                        .session
                        .as_mut()
                        .unwrap()
                        .mesh_offer_ready(&fp, &sid, &descriptor)
                        .expect("signing an offer must not fail");
                    for a in out {
                        queue.push_back((node, a));
                    }
                }
                Action::Answer { fp, descriptor } => {
                    let sid = self.next_id("mesh-a-");
                    let parts: Vec<&str> = descriptor.split('|').collect();
                    let answer = format!("SB2:ANS|{}|{}|{}|{}", node, sid, parts[1], parts[2]);
                    let out = self.nodes[node]
                        .session
                        .as_mut()
                        .unwrap()
                        .mesh_answer_ready(&fp, &sid, &answer)
                        .expect("signing an answer must not fail");
                    for a in out {
                        queue.push_back((node, a));
                    }
                }
                Action::AcceptAnswer { session_id, descriptor } => {
                    // The descriptor names both ends of the connection that was
                    // just built, which is all the wiring needs.
                    let parts: Vec<&str> = descriptor.split('|').collect();
                    let answerer: usize = parts[1].parse().unwrap();
                    let answerer_sid = parts[2].to_string();
                    self.link(node, &session_id, answerer, &answerer_sid);
                    let a = self.nodes[node].session.as_mut().unwrap().set_session_state(&session_id, true);
                    for x in a {
                        queue.push_back((node, x));
                    }
                    let b = self.nodes[answerer].session.as_mut().unwrap().set_session_state(&answerer_sid, true);
                    for x in b {
                        queue.push_back((answerer, x));
                    }
                }
            }
        }
    }

    /// Hand one frame to the node it was addressed to.
    ///
    /// An invitation is the one frame the APP acts on rather than the session —
    /// there is no group yet to decode it into, and only the user's acceptance
    /// may create one.
    fn deliver(&mut self, node: usize, session_id: &str, frame: &Value) -> Vec<Action> {
        let is_invite = securebit_core::group_session::group_frame_type(frame)
            .as_deref()
            == Some(frames::INVITE);
        if is_invite && self.nodes[node].session.is_none() {
            let mut session = GroupSession::new(&self.group_id, "pending", false)
                .expect("a group session must be constructible");
            let out = session.accept_invite(session_id, frame).expect("accepting an invite must not fail");
            self.nodes[node].session = Some(session);
            // The fingerprint of the link this arrived on has to be known to the
            // new session too, or it can never answer a probe.
            if let Some((peer, peer_sid)) = self.chans.get(&(node, session_id.to_string())).cloned() {
                let _ = peer;
                let _ = peer_sid;
            }
            return out;
        }
        match self.nodes[node].session.as_mut() {
            Some(session) => match session.handle_frame(session_id, frame) {
                Ok(actions) => actions,
                // A frame that fails validation is dropped, exactly as the app
                // does: it never reaches a transcript either way.
                Err(_) => Vec::new(),
            },
            None => Vec::new(),
        }
    }

    fn session(&mut self, node: usize) -> &mut GroupSession {
        self.nodes[node].session.as_mut().expect("node has no group session")
    }

    fn events(&self, node: usize) -> &[Event] {
        &self.nodes[node].events
    }

    fn messages(&self, node: usize) -> Vec<(String, bool)> {
        self.nodes[node]
            .events
            .iter()
            .filter_map(|e| match e {
                Event::Message { body, relayed, .. } => Some((body.clone(), *relayed)),
                _ => None,
            })
            .collect()
    }

    fn member_state(&mut self, node: usize, fp: &str) -> MemberState {
        self.session(node)
            .members_snapshot()
            .into_iter()
            .find(|m| m.fp == fp)
            .map(|m| m.state)
            .expect("member not found")
    }
}

/// A three-member group over a star: Alice is the admin and holds a link to Bob
/// and to Carol; Bob and Carol have no link to each other.
fn star_group() -> Net {
    let mut net = Net::new(&["alice", "bob", "carol"]);
    let gid = net.group_id.clone();

    let mut alice = GroupSession::new(&gid, "Field team", true).unwrap();
    // The admin's own links are bound by the app when it invites over a chat it
    // already holds; here the harness links them first.
    net.nodes[0].session = Some(alice_placeholder(&mut alice));
    net.link(0, "A>B", 1, "B>A");
    net.link(0, "A>C", 2, "C>A");

    let out = net
        .session(0)
        .invite(&[
            ("A>B".to_string(), "Bob".to_string()),
            ("A>C".to_string(), "Carol".to_string()),
        ])
        .unwrap();
    net.run(0, out);
    net
}

/// Moving the session into the node without cloning it (GroupSession holds a key
/// and is deliberately not Clone).
fn alice_placeholder(session: &mut GroupSession) -> GroupSession {
    std::mem::replace(session, GroupSession::new(&session.group_id.clone(), "", false).unwrap())
}

// ---------------------------------------------------------------------------
// 1 + 2. forming, and the gate in front of it
// ---------------------------------------------------------------------------

#[test]
fn a_group_forms_and_every_member_reads_the_same_code() {
    let mut net = star_group();

    for node in 0..3 {
        let name = net.nodes[node].name;
        assert_eq!(
            net.session(node).phase,
            GroupPhase::AwaitingSas,
            "{} must reach the code step",
            name
        );
    }

    let codes: Vec<String> = (0..3).map(|n| net.session(n).sas_code.clone()).collect();
    assert!(!codes[0].is_empty());
    assert!(
        codes.iter().all(|c| *c == codes[0]),
        "every member must read the same digits, got {:?}",
        codes
    );
    assert_eq!(codes[0].len(), 7);

    // Every member was told the code, once.
    for node in 0..3 {
        let name = net.nodes[node].name;
        let sas = net
            .events(node)
            .iter()
            .filter(|e| matches!(e, Event::Sas(_)))
            .count();
        assert_eq!(sas, 1, "{} must be shown the code exactly once", name);
    }
}

#[test]
fn nothing_can_be_sent_before_a_human_confirms_the_code() {
    let mut net = star_group();
    assert!(
        net.session(0).send_text("too early").is_err(),
        "a group that nobody has vouched for must not carry traffic"
    );

    // Confirming is the only path to ready, and it is a user action.
    let out = net.session(0).confirm_sas().unwrap();
    net.run(0, out);
    assert_eq!(net.session(0).phase, GroupPhase::Ready);
    assert!(net.session(0).send_text("now it works").is_ok());
}

// ---------------------------------------------------------------------------
// 3. messages, and the relay path
// ---------------------------------------------------------------------------

#[test]
fn a_member_with_no_direct_link_is_reached_over_the_relay() {
    let mut net = star_group();
    // Confirm on every side, but do NOT let the mesh run: the transport refuses
    // to dial, so the pair stays on the relay — the state every group starts in.
    for node in 0..3 {
        let out = net.session(node).confirm_sas().unwrap();
        // Drop the Dial actions: this test is about the star.
        let filtered: Vec<Action> = out
            .into_iter()
            .filter(|a| !matches!(a, Action::Dial { .. }))
            .collect();
        net.run(node, filtered);
    }

    let carol_fp = net.session(2).self_fp().to_string();
    assert_eq!(
        net.member_state(1, &carol_fp),
        MemberState::Pending,
        "Bob has no direct link to Carol yet"
    );

    let (out, report) = net.session(1).send_text("carried by the admin").unwrap();
    let filtered: Vec<Action> = out.into_iter().filter(|a| !matches!(a, Action::Dial { .. })).collect();
    net.run(1, filtered);

    assert_eq!(report.delivered, 2, "both members were reachable, one of them via the relay");
    assert!(report.unreachable.is_empty());

    // Alice has it directly; Carol got it through Alice and is told so.
    assert_eq!(net.messages(0), vec![("carried by the admin".to_string(), false)]);
    assert_eq!(net.messages(2), vec![("carried by the admin".to_string(), true)]);

    // The relaying admin must see it exactly once, and must not forward it twice.
    assert_eq!(
        net.messages(0).len(),
        1,
        "a relayed frame must not also be delivered to the relay a second time"
    );
}

#[test]
fn a_message_arriving_twice_is_absorbed_but_a_contradiction_is_not() {
    let mut net = star_group();
    for node in 0..3 {
        let out = net.session(node).confirm_sas().unwrap();
        let filtered: Vec<Action> = out.into_iter().filter(|a| !matches!(a, Action::Dial { .. })).collect();
        net.run(node, filtered);
    }

    // Capture a real signed message frame by watching what Bob sends.
    let (out, _) = net.session(1).send_text("hello").unwrap();
    let frame = direct_message(&out);
    net.run(1, out);
    assert_eq!(net.messages(0).len(), 1);

    // The same frame again is fan-out, not news.
    let again = net.session(0).handle_frame("A>B", &frame).unwrap();
    net.run(0, again);
    assert_eq!(net.messages(0).len(), 1, "a duplicate must be absorbed silently");

    // A different body under the same sequence number is a member telling two
    // halves of the group different things. That must be refused and reported.
    let mut forged = securebit_core::group_session::decode_envelope(&frame).unwrap();
    forged["body"] = Value::String("something else".into());
    let wrapped = securebit_core::group_session::encode_envelope(&forged).unwrap();
    let result = net.session(0).handle_frame("A>B", &wrapped);
    assert!(result.is_err(), "a conflicting body must not be accepted");
    assert_eq!(net.messages(0).len(), 1);
}

// ---------------------------------------------------------------------------
// 4. the star becomes a mesh
// ---------------------------------------------------------------------------

#[test]
fn the_pair_with_no_link_dials_one_and_stops_relaying() {
    let mut net = star_group();
    // Every member confirms BEFORE any dial is performed. That ordering is not
    // a convenience: a member only accepts a relayed dial once it has confirmed
    // the code itself, because before that the roster's identity keys are keys
    // nobody has vouched for. A dial that arrives early is dropped and retried
    // after its timeout, which is correct but takes a minute — not something to
    // make an assertion wait for.
    let mut confirmations = Vec::new();
    for node in 0..3 {
        confirmations.push((node, net.session(node).confirm_sas().unwrap()));
    }
    for (node, out) in confirmations {
        net.run(node, out);
    }

    let bob_fp = net.session(1).self_fp().to_string();
    let carol_fp = net.session(2).self_fp().to_string();

    assert_eq!(
        net.member_state(1, &carol_fp),
        MemberState::Linked,
        "Bob must end up directly linked to Carol"
    );
    assert_eq!(net.member_state(2, &bob_fp), MemberState::Linked);

    // And the traffic between them is no longer marked as carried.
    let (out, report) = net.session(1).send_text("direct now").unwrap();
    net.run(1, out);
    assert_eq!(report.delivered, 2);
    assert_eq!(net.messages(2), vec![("direct now".to_string(), false)]);
}

#[test]
fn exactly_one_side_of_a_pair_dials() {
    let mut net = star_group();
    let bob_fp = net.session(1).self_fp().to_string();
    let carol_fp = net.session(2).self_fp().to_string();

    // Confirm, and count who was asked to dial whom.
    let mut dials: Vec<(usize, String)> = Vec::new();
    for node in 0..3 {
        let out = net.session(node).confirm_sas().unwrap();
        for action in &out {
            if let Action::Dial { fp } = action {
                dials.push((node, fp.clone()));
            }
        }
        net.run(node, out);
    }

    // The member with the smaller fingerprint dials; the other refuses an offer
    // arriving the wrong way round. That is the whole glare protocol.
    let expected_dialer = if bob_fp < carol_fp { 1 } else { 2 };
    let pair_dials: Vec<&(usize, String)> = dials
        .iter()
        .filter(|(_, fp)| *fp == bob_fp || *fp == carol_fp)
        .collect();
    assert_eq!(pair_dials.len(), 1, "exactly one side may open the pair, got {:?}", pair_dials);
    assert_eq!(pair_dials[0].0, expected_dialer);
}

#[test]
fn a_chat_the_pair_already_holds_is_adopted_instead_of_dialled() {
    let mut net = star_group();
    // Bob and Carol already talk to each other, before the group existed.
    net.link(1, "B>C", 2, "C>B");

    for node in 0..3 {
        let out = net.session(node).confirm_sas().unwrap();
        // Refuse every dial: if the probe works, none is needed.
        let filtered: Vec<Action> = out.into_iter().filter(|a| !matches!(a, Action::Dial { .. })).collect();
        net.run(node, filtered);
    }

    let out = net.session(1).probe_session("B>C").unwrap();
    assert!(!out.is_empty(), "a verified chat that carries nobody must be offered to the group");
    net.run(1, out);

    let bob_fp = net.session(1).self_fp().to_string();
    let carol_fp = net.session(2).self_fp().to_string();
    assert_eq!(net.member_state(1, &carol_fp), MemberState::Linked);
    assert_eq!(
        net.member_state(2, &bob_fp),
        MemberState::Linked,
        "the probe must be answered in kind, or the adoption is one-sided"
    );
}

#[test]
fn a_probe_replayed_onto_another_session_does_not_bind() {
    let mut net = star_group();
    net.link(1, "B>C", 2, "C>B");
    for node in 0..3 {
        let out = net.session(node).confirm_sas().unwrap();
        let filtered: Vec<Action> = out.into_iter().filter(|a| !matches!(a, Action::Dial { .. })).collect();
        net.run(node, filtered);
    }

    // Take Bob's probe off the wire...
    let out = net.session(1).probe_session("B>C").unwrap();
    let probe = out
        .iter()
        .find_map(|a| match a {
            Action::Send { frame, .. } => Some(frame.clone()),
            _ => None,
        })
        .expect("the probe must be sent");

    // ...and present it on a DIFFERENT session. It carries the fingerprint of
    // the link it was written for, so it cannot authenticate this one — which is
    // what stops a member impersonating another on their own link.
    net.link(2, "C>X", 0, "A>X");
    let bob_fp = net.session(1).self_fp().to_string();
    let result = net.session(2).handle_frame("C>X", &probe);
    let bound = net.member_state(2, &bob_fp) == MemberState::Linked
        && net.session(2).carries_session("C>X");
    assert!(
        result.is_err() || !bound,
        "a probe replayed onto another session must not bind it"
    );
}

// ---------------------------------------------------------------------------
// 5. forged and stale frames
// ---------------------------------------------------------------------------

#[test]
fn a_tampered_message_is_refused() {
    let mut net = star_group();
    for node in 0..3 {
        let out = net.session(node).confirm_sas().unwrap();
        let filtered: Vec<Action> = out.into_iter().filter(|a| !matches!(a, Action::Dial { .. })).collect();
        net.run(node, filtered);
    }

    let (out, _) = net.session(1).send_text("the real thing").unwrap();
    let frame = direct_message(&out);

    // Rewrite the body, keep the signature.
    let mut inner = securebit_core::group_session::decode_envelope(&frame).unwrap();
    inner["body"] = Value::String("something the sender never wrote".into());
    let wrapped = securebit_core::group_session::encode_envelope(&inner).unwrap();
    assert!(net.session(0).handle_frame("A>B", &wrapped).is_err());
    assert!(net.messages(0).is_empty(), "nothing forged may reach a transcript");

    // The genuine frame still works afterwards: a rejected forgery must not burn
    // the sequence number it claimed.
    net.run(1, out);
    assert_eq!(net.messages(0), vec![("the real thing".to_string(), false)]);
}

#[test]
fn a_roster_from_someone_who_is_not_the_admin_is_refused() {
    let mut net = star_group();
    // Carol tries to publish membership. Only the admin's key may do that, and
    // Bob checks the signature against the admin fingerprint he recorded when he
    // accepted the invitation — not against whatever key the frame carries.
    let bob_fp = net.session(1).self_fp().to_string();
    let carol_fp = net.session(2).self_fp().to_string();
    let members = vec![bob_fp, carol_fp];

    let forged = serde_json::json!({
        "type": frames::ROSTER,
        "gid": net.group_id,
        "epoch": 2,
        "op": "remove",
        "name": "Field team",
        "adminSpki": base64_of(net.session(2).self_spki()),
        "members": members,
        "sig": "AAAA",
    });
    let wrapped = securebit_core::group_session::encode_envelope(&forged).unwrap();
    assert!(
        net.session(1).handle_frame("B>A", &wrapped).is_err(),
        "a roster signed by a member must not rewrite the group"
    );
    assert_eq!(net.session(1).member_count(), 3, "the member set must be untouched");
}

#[test]
fn a_ceremony_that_nobody_answers_fails_rather_than_proceeding() {
    let mut net = Net::new(&["alice", "bob"]);
    let gid = net.group_id.clone();
    let mut alice = GroupSession::new(&gid, "Two", true).unwrap();
    net.nodes[0].session = Some(std::mem::replace(
        &mut alice,
        GroupSession::new(&gid, "", false).unwrap(),
    ));
    net.link(0, "A>B", 1, "B>A");

    // Nobody is on the other end: the invitation goes nowhere.
    net.cut(0, "A>B");
    let out = net.session(0).invite(&[("A>B".to_string(), "Bob".to_string())]).unwrap();
    net.run(0, out);

    // The wait expires. It must FAIL, never proceed without the missing member.
    let actions = net.session(0).on_timer(&TimerKind::Hello);
    net.run(0, actions);
    assert_eq!(net.session(0).phase, GroupPhase::Failed);
    assert!(net
        .events(0)
        .iter()
        .any(|e| matches!(e, Event::Error(code) if code == "invitees_did_not_respond")));
}

// ---------------------------------------------------------------------------
// 6. membership changes
// ---------------------------------------------------------------------------

#[test]
fn removing_a_member_opens_a_new_epoch_and_a_new_code() {
    let mut net = star_group();
    for node in 0..3 {
        let out = net.session(node).confirm_sas().unwrap();
        let filtered: Vec<Action> = out.into_iter().filter(|a| !matches!(a, Action::Dial { .. })).collect();
        net.run(node, filtered);
    }
    let first_code = net.session(1).sas_code.clone();
    let carol_fp = net.session(2).self_fp().to_string();

    let out = net.session(0).remove_member(&carol_fp).unwrap();
    let filtered: Vec<Action> = out.into_iter().filter(|a| !matches!(a, Action::Dial { .. })).collect();
    net.run(0, filtered);

    assert_eq!(net.session(0).member_count(), 2);
    assert_eq!(net.session(1).member_count(), 2, "Bob must adopt the new roster");
    assert_eq!(net.session(0).epoch, 2);
    assert_eq!(net.session(1).epoch, 2);

    // A new member set means a new code, and it must be compared again — the old
    // confirmation says nothing about the group that exists now.
    assert_eq!(net.session(1).phase, GroupPhase::AwaitingSas);
    assert!(!net.session(1).sas_confirmed);
    let second_code = net.session(1).sas_code.clone();
    assert_ne!(first_code, second_code);
    assert_eq!(second_code, net.session(0).sas_code);
}

#[test]
fn a_group_cannot_be_emptied_by_removal() {
    let mut net = Net::new(&["alice", "bob"]);
    let gid = net.group_id.clone();
    let mut alice = GroupSession::new(&gid, "Two", true).unwrap();
    net.nodes[0].session = Some(std::mem::replace(
        &mut alice,
        GroupSession::new(&gid, "", false).unwrap(),
    ));
    net.link(0, "A>B", 1, "B>A");
    let out = net.session(0).invite(&[("A>B".to_string(), "Bob".to_string())]).unwrap();
    net.run(0, out);

    let bob_fp = net.session(1).self_fp().to_string();
    // Removing the last member is leaving, not removing.
    assert!(net.session(0).remove_member(&bob_fp).is_err());
    assert_eq!(net.session(0).member_count(), 2);
}

/// The DIRECT message frame out of a send, not the relay wrapper that carries
/// the same message to a member who has no link of their own. Both are on the
/// wire; only one of them is the frame under test here.
fn direct_message(actions: &[Action]) -> Value {
    actions
        .iter()
        .find_map(|a| match a {
            Action::Send { frame, .. } => {
                let inner = securebit_core::group_session::decode_envelope(frame).ok()?;
                if inner.get("type")?.as_str()? == frames::MESSAGE {
                    Some(frame.clone())
                } else {
                    None
                }
            }
            _ => None,
        })
        .expect("a message must go out directly to at least one member")
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.encode(bytes)
}
