//! The group state machine — what turns N pairwise sessions into a group.
//!
//! A port of `src/group/GroupSession.js` in the web client, restructured as a
//! sans-IO state machine so it can run anywhere: this crate owns no transport,
//! no timers and no runtime. Every method takes what happened and returns a list
//! of [`Action`]s the platform is expected to perform — put this frame on that
//! session, dial that member, arm that timer. A desktop drives it from a
//! webview, a phone from native WebRTC, a test from a Vec.
//!
//! WHAT THIS IS AND IS NOT
//! -----------------------
//! It owns no transport. Every byte it sends leaves through an existing pairwise
//! session that is already SAS-verified and already ratcheted, and arrives
//! having been authenticated by that session. This adds the group layer on top:
//! who is a member, what epoch it is, what code the humans compare, and which of
//! the N-1 links a given frame should take.
//!
//! DELIVERY: DIRECT WHERE POSSIBLE, RELAYED WHERE NOT
//! --------------------------------------------------
//! A full mesh needs N(N-1)/2 pairwise links, and when a group is created only
//! the admin holds a link to everyone. Rather than block the group until every
//! pair is introduced, a frame for a member we cannot reach directly is handed
//! to a member who can reach both of us.
//!
//! That is safe because it is not a trust decision. Group messages and
//! membership operations are signed with the sender's group identity key, and
//! every member holds every other member's verifying key from the signed roster.
//! A relaying member can drop a frame or read a frame — they are a member, so
//! reading it is what membership already entitles them to — but they cannot
//! forge one, alter one, or attribute one to somebody else. What relaying costs
//! is metadata and availability, which is why a direct link is always preferred.
//!
//! Relaying is single-hop by construction. A frame carries `to`; a member that
//! is not the addressee forwards it once, marked, and a marked frame is never
//! forwarded again. There is no routing table to poison and no loop to form.
//!
//! ORDER OF OPERATIONS
//! -------------------
//!   1. invite    admin sends the group's name and its own identity key
//!   2. hello     each invitee replies with its identity key
//!   3. roster    admin signs the full member set for this epoch and broadcasts
//!   4. commit    every member commits to a secret nonce
//!   5. reveal    ONLY once every commitment has arrived, nonces are published
//!   6. code      every member computes the same digits and the humans compare
//!   7. ready     group traffic flows
//!   8. mesh      every pair without a link dials one, over the relay path
//!
//! Step 8 is the only one that can fail without the group noticing, and that is
//! deliberate: a pair that cannot connect directly keeps working exactly as it
//! did in step 7.

use crate::error::CoreError;
use crate::group_crypto::{self as gc, GroupIdentity, GroupSasCeremony, MemberOp, MeshKind};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use p384::ecdsa::VerifyingKey;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};

fn bad(m: impl Into<String>) -> CoreError {
    CoreError::invalid_input(m.into())
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

// ---------------------------------------------------------------------------
// wire vocabulary
// ---------------------------------------------------------------------------

/// Wire frame types. All group traffic rides the ordinary chat message path.
pub mod frames {
    pub const INVITE: &str = "g_invite";
    pub const HELLO: &str = "g_hello";
    pub const MEMBER: &str = "g_member";
    pub const ROSTER: &str = "g_roster";
    pub const COMMIT: &str = "g_commit";
    pub const REVEAL: &str = "g_reveal";
    pub const MESSAGE: &str = "g_msg";
    pub const RELAY: &str = "g_relay";
    pub const LEAVE: &str = "g_leave";
    pub const MESH_OFFER: &str = "g_moffer";
    pub const MESH_ANSWER: &str = "g_manswer";
    pub const MESH_ABORT: &str = "g_mabort";
    pub const PROBE: &str = "g_probe";
    /// The outer wrapper every group frame travels inside.
    pub const ENVELOPE: &str = "g_env";

    pub const ALL: [&str; 13] = [
        INVITE, HELLO, MEMBER, ROSTER, COMMIT, REVEAL, MESSAGE, RELAY, LEAVE,
        MESH_OFFER, MESH_ANSWER, MESH_ABORT, PROBE,
    ];
}

/// Is this something the group layer should be given at all?
pub fn is_group_frame(value: &Value) -> bool {
    match value.get("type").and_then(|t| t.as_str()) {
        Some(t) => t == frames::ENVELOPE || frames::ALL.contains(&t),
        None => false,
    }
}

/// The inner type of a frame, without decoding it.
///
/// Callers outside this module need it for exactly one decision — whether an
/// arriving frame is an invitation to a group they do not have yet — and that
/// decision has to be made before any group state exists to decode with. It is a
/// routing hint only; `decode_envelope` re-checks it against the frame it wraps.
pub fn group_frame_type(value: &Value) -> Option<String> {
    let t = value.get("type").and_then(|t| t.as_str())?;
    if t == frames::ENVELOPE {
        return value.get("t").and_then(|t| t.as_str()).map(String::from);
    }
    if frames::ALL.contains(&t) {
        return Some(t.to_string());
    }
    None
}

/// Wrap a frame so the pairwise chat path cannot alter it.
///
/// Group frames ride the chat send path, which sanitises its payload before
/// encrypting: `<`, `>` and `&` are escaped, control characters are stripped,
/// and the result is truncated. Every one of those is correct for chat text and
/// fatal for a signed frame — a body that came back HTML-escaped no longer
/// matches the hash its signature covers.
///
/// Base64 sidesteps all of it: its alphabet contains nothing a sanitiser
/// rewrites and it has no whitespace to trim. The group id and the inner type
/// stay outside the encoding so a frame can be routed — and an invitation
/// recognised — without decoding anything first. Neither reveals more than the
/// peer on that link already knows.
pub fn encode_envelope(frame: &Value) -> Result<Value, CoreError> {
    let json = serde_json::to_string(frame)
        .map_err(|e| CoreError::internal_error(format!("group frame is not serializable: {}", e)))?;
    let encoded = B64.encode(json.as_bytes());
    if encoded.len() > gc::FRAME_BUDGET_CHARS {
        return Err(bad("group frame exceeds the transport budget"));
    }
    Ok(json!({
        "type": frames::ENVELOPE,
        "gid": frame.get("gid").cloned().unwrap_or(Value::Null),
        "t": frame.get("type").cloned().unwrap_or(Value::Null),
        "d": encoded,
    }))
}

pub fn decode_envelope(envelope: &Value) -> Result<Value, CoreError> {
    if envelope.get("type").and_then(|t| t.as_str()) != Some(frames::ENVELOPE) {
        return Ok(envelope.clone());
    }
    let raw = envelope.get("d").and_then(|d| d.as_str()).unwrap_or("");
    if raw.len() > gc::FRAME_BUDGET_CHARS {
        return Err(bad("group frame exceeds the transport budget"));
    }
    let bytes = B64.decode(raw).map_err(|_| bad("envelope payload is not valid base64"))?;
    let frame: Value = serde_json::from_slice(&bytes)
        .map_err(|_| bad("envelope carried no recognisable frame"))?;
    let inner_type = frame.get("type").and_then(|t| t.as_str()).unwrap_or("");
    if !frames::ALL.contains(&inner_type) {
        return Err(bad("envelope carried no recognisable frame"));
    }
    // The routing hints outside the encoding are conveniences, not authority: if
    // they disagree with the frame they wrap, the frame was tampered with.
    if let Some(gid) = envelope.get("gid").and_then(|g| g.as_str()) {
        if frame.get("gid").and_then(|g| g.as_str()) != Some(gid) {
            return Err(bad("envelope group id does not match its frame"));
        }
    }
    if let Some(t) = envelope.get("t").and_then(|t| t.as_str()) {
        if inner_type != t {
            return Err(bad("envelope type does not match its frame"));
        }
    }
    Ok(frame)
}

// ---------------------------------------------------------------------------
// state vocabulary
// ---------------------------------------------------------------------------

/// A group's lifecycle. The order matters: nothing may be sent or displayed as
/// group traffic until `Ready`, and `Ready` is reachable only through
/// `AwaitingSas`, where a human confirmed the code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupPhase {
    Forming,
    Committing,
    Revealing,
    AwaitingSas,
    Ready,
    Failed,
}

impl GroupPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            GroupPhase::Forming => "forming",
            GroupPhase::Committing => "committing",
            GroupPhase::Revealing => "revealing",
            GroupPhase::AwaitingSas => "awaiting_sas",
            GroupPhase::Ready => "ready",
            GroupPhase::Failed => "failed",
        }
    }
}

/// Per-member link state. `SelfMember` is us; the rest describe the pairwise
/// session that carries them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberState {
    SelfMember,
    /// Pairwise session up and verified.
    Linked,
    /// A session exists but is not usable yet, or none does.
    Pending,
    /// Was linked; the connection dropped.
    Lost,
}

impl MemberState {
    pub fn as_str(self) -> &'static str {
        match self {
            MemberState::SelfMember => "self",
            MemberState::Linked => "linked",
            MemberState::Pending => "pending",
            MemberState::Lost => "lost",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberSnapshot {
    pub fp: String,
    pub name: String,
    pub session_id: Option<String>,
    pub state: MemberState,
}

/// What the platform is asked to do. Nothing here happens inside the core.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Put an already-wrapped frame on a pairwise session.
    Send { session_id: String, frame: Value },
    /// Build a connection to this member and report back with `mesh_offer_ready`.
    Dial { fp: String },
    /// Answer this member's relayed offer and report back with `mesh_answer_ready`.
    Answer { fp: String, descriptor: String },
    /// Apply an answer to a dial that is already open.
    AcceptAnswer { session_id: String, descriptor: String },
    /// Tear down a connection this group asked for.
    CloseLink { session_id: String },
    /// Call `on_timer` with this kind after `ms` milliseconds.
    ArmTimer { kind: TimerKind, ms: u64 },
    /// Something the user interface should hear about.
    Emit(Event),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TimerKind {
    /// The commit/reveal round for one epoch must finish or fail.
    Ceremony(u64),
    /// The admin's wait for invitees to publish their identity keys.
    Hello,
    /// One dial may only stay in flight so long.
    MeshDial(String),
    /// A pair whose backoff has expired may be dialled again.
    MeshMaintain,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Phase(GroupPhase),
    Members { members: Vec<MemberSnapshot>, epoch: u64 },
    Roster { name: String, epoch: u64, admin_fp: String },
    Sas(String),
    Confirmed,
    Message {
        fp: String,
        name: String,
        body: String,
        seq: u64,
        ts: i64,
        /// Whether this copy came straight from its author or was carried by
        /// another member. Worth showing: a relayed message is one a third
        /// member knew the timing of.
        relayed: bool,
    },
    Left { fp: String, name: String },
    /// The group is over — the admin left, or we are the last one in it.
    Ended(String),
    AddFailed(String),
    /// A member sent two different bodies under one sequence number. Both
    /// signatures are valid, so this is provable rather than suspected.
    Inconsistency { fp: String, name: String, seq: u64 },
    Error(String),
}

/// Who a broadcast could not reach, and how many it did.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DeliveryReport {
    pub delivered: usize,
    pub total: usize,
    pub unreachable: Vec<(String, String)>,
}

// ---------------------------------------------------------------------------
// timings
// ---------------------------------------------------------------------------

/// A member that has not committed by now is treated as absent and the ceremony
/// FAILS. It must fail rather than proceed: proceeding without a commitment is
/// exactly the grinding freedom the commit round removes.
pub const CEREMONY_MS: u64 = 60_000;
/// How long the admin waits for invitees to publish their identity keys.
pub const HELLO_MS: u64 = 45_000;
/// How long one mesh dial may stay in flight. Generous, because failing early
/// costs a direct link and gains nothing: the pair keeps working over the relay
/// the entire time the dial is running.
pub const MESH_DIAL_MS: u64 = 45_000;
/// Gap before a failed pair is dialled again, doubling per failure.
pub const MESH_RETRY_MS: u64 = 20_000;
/// How many mesh dials one member will have in flight at once.
pub const MESH_MAX_CONCURRENT_DIALS: usize = 2;
/// After this many consecutive failures a pair is left on the relay for good.
pub const MESH_MAX_ATTEMPTS: u32 = 3;
/// Bounded per sender: the pairwise ratchet already refuses genuinely old
/// frames, so this window only has to outlast fan-out and one relay hop.
const TRANSCRIPT_WINDOW: usize = 512;

struct Member {
    fp: String,
    name: String,
    spki: Vec<u8>,
    /// Our own key verifies nothing inbound, so it is not kept here.
    key: Option<VerifyingKey>,
    session_id: Option<String>,
    state: MemberState,
}

struct Dial {
    role: MeshKind,
    session_id: Option<String>,
    nonce: Vec<u8>,
    epoch: u64,
}

struct Failure {
    attempts: u32,
    next_at: i64,
}

struct PendingAdd {
    op: MemberOp,
    epoch: u64,
    before: HashSet<String>,
}

// ---------------------------------------------------------------------------
// the session
// ---------------------------------------------------------------------------

pub struct GroupSession {
    pub group_id: String,
    pub name: String,
    pub is_admin: bool,
    pub epoch: u64,
    pub admin_fp: String,
    pub phase: GroupPhase,
    pub sas_code: String,
    pub sas_confirmed: bool,

    identity: GroupIdentity,
    members: BTreeMap<String, Member>,
    /// sessionId -> fp, so an inbound frame can be attributed to a member.
    session_to_fp: HashMap<String, String>,
    /// sessionId -> that pairwise session's key fingerprint, for link probes.
    link_fingerprints: HashMap<String, String>,

    ceremony: Option<GroupSasCeremony>,
    seq: u64,
    /// Sender fingerprint -> (seq -> body hash). Does double duty: it absorbs
    /// the duplicates that fan-out and relay inevitably produce, and it is what
    /// catches a member sending two different bodies under one sequence number.
    transcript: HashMap<String, BTreeMap<u64, Vec<u8>>>,

    /// Invitees the admin is still waiting on, by sessionId.
    awaiting_hello: HashMap<String, String>,
    /// Commit and reveal frames that arrived before our own ceremony existed.
    ///
    /// Members start their ceremony when the roster reaches them, and the roster
    /// does not reach everyone at the same instant. Dropping those frames
    /// deadlocks the round for everyone. Bounded, because the sender of these
    /// frames chooses how many to send.
    pending_ceremony: Vec<Value>,
    /// Member identity keys that arrived ahead of the roster that names them.
    /// Nothing is applied from here until the admin's signed roster says which
    /// fingerprints are actually members.
    pending_keys: HashMap<String, (Vec<u8>, VerifyingKey, String)>,
    pending_add: Option<PendingAdd>,

    /// One entry per PAIR, never per direction.
    dials: HashMap<String, Dial>,
    failures: HashMap<String, Failure>,
    /// Sessions this group built itself, so teardown can close them.
    mesh_sessions: HashSet<String>,
    /// Sessions a probe has already been sent on, so it is sent once.
    probed: HashSet<String>,
    destroyed: bool,
}

impl GroupSession {
    pub fn new(group_id: &str, name: &str, is_admin: bool) -> Result<Self, CoreError> {
        gc::assert_group_id(group_id)?;
        gc::assert_name(name)?;
        let identity = GroupIdentity::generate()?;
        let mut session = Self {
            group_id: group_id.to_string(),
            name: name.to_string(),
            is_admin,
            epoch: 1,
            admin_fp: String::new(),
            phase: GroupPhase::Forming,
            sas_code: String::new(),
            sas_confirmed: false,
            identity,
            members: BTreeMap::new(),
            session_to_fp: HashMap::new(),
            link_fingerprints: HashMap::new(),
            ceremony: None,
            seq: 0,
            transcript: HashMap::new(),
            awaiting_hello: HashMap::new(),
            pending_ceremony: Vec::new(),
            pending_keys: HashMap::new(),
            pending_add: None,
            dials: HashMap::new(),
            failures: HashMap::new(),
            mesh_sessions: HashSet::new(),
            probed: HashSet::new(),
            destroyed: false,
        };
        let fp = session.identity.fingerprint.clone();
        let spki = session.identity.spki.clone();
        session.members.insert(
            fp.clone(),
            Member { fp: fp.clone(), name: "You".into(), spki, key: None, session_id: None, state: MemberState::SelfMember },
        );
        if is_admin {
            session.admin_fp = fp;
        }
        Ok(session)
    }

    pub fn new_group_id() -> String {
        gc::new_group_id()
    }

    pub fn self_fp(&self) -> &str {
        &self.identity.fingerprint
    }

    pub fn self_spki(&self) -> &[u8] {
        &self.identity.spki
    }

    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    pub fn carries_session(&self, session_id: &str) -> bool {
        self.session_to_fp.contains_key(session_id)
    }

    /// The pairwise key fingerprint of a session, as the platform measured it.
    ///
    /// Taken from the platform rather than from any frame: a probe is checked
    /// against the fingerprint WE hold for the session it arrived on, which is
    /// the whole reason a captured probe cannot be replayed onto another link.
    pub fn set_link_fingerprint(&mut self, session_id: &str, fingerprint: &str) {
        if fingerprint.is_empty() {
            self.link_fingerprints.remove(session_id);
        } else {
            self.link_fingerprints.insert(session_id.to_string(), fingerprint.to_string());
        }
    }

    pub fn members_snapshot(&self) -> Vec<MemberSnapshot> {
        self.members
            .values()
            .map(|m| MemberSnapshot {
                fp: m.fp.clone(),
                name: m.name.clone(),
                session_id: m.session_id.clone(),
                state: m.state,
            })
            .collect()
    }

    fn members_event(&self) -> Action {
        Action::Emit(Event::Members { members: self.members_snapshot(), epoch: self.epoch })
    }

    fn set_phase(&mut self, phase: GroupPhase, out: &mut Vec<Action>) {
        if self.phase == phase {
            return;
        }
        self.phase = phase;
        // Any phase other than Ready means nothing is currently confirmed.
        if phase != GroupPhase::Ready {
            self.sas_confirmed = false;
        }
        // The code survives from the moment it is computed (AwaitingSas) until
        // the group leaves Ready. Clearing it on the way INTO AwaitingSas would
        // erase the digits that were just derived.
        if phase != GroupPhase::Ready && phase != GroupPhase::AwaitingSas {
            self.sas_code.clear();
        }
        out.push(Action::Emit(Event::Phase(phase)));
    }

    fn fail(&mut self, code: &str, out: &mut Vec<Action>) {
        if self.destroyed {
            return;
        }
        self.phase = GroupPhase::Failed;
        self.ceremony = None;
        out.push(Action::Emit(Event::Phase(GroupPhase::Failed)));
        out.push(Action::Emit(Event::Error(code.to_string())));
    }

    // -----------------------------------------------------------------------
    // routing
    // -----------------------------------------------------------------------

    fn direct_peers(&self) -> Vec<&Member> {
        self.members
            .values()
            .filter(|m| m.state == MemberState::Linked && m.session_id.is_some())
            .collect()
    }

    /// Whoever can carry a frame to a member we cannot reach ourselves.
    ///
    /// The admin is preferred because by construction it holds a link to every
    /// member; any other directly-linked member is a fallback for when the admin
    /// is the one that has gone away.
    fn relay_for(&self, to_fp: &str) -> Option<String> {
        if let Some(admin) = self.members.get(&self.admin_fp) {
            if admin.state == MemberState::Linked && admin.session_id.is_some() && admin.fp != to_fp {
                return admin.session_id.clone();
            }
        }
        self.direct_peers()
            .into_iter()
            .find(|m| m.fp != to_fp)
            .and_then(|m| m.session_id.clone())
    }

    /// Send one frame to one member, directly if we can and relayed if we cannot.
    ///
    /// Returns whether this counts as delivered. A relay hop is unacknowledged:
    /// for a member we have never held a link to that is simply the normal path,
    /// but for one whose link we LOST it is a guess, and reporting it as
    /// delivered would tell the sender their message arrived when there is no
    /// reason to believe it did. The frame still goes — the target may be
    /// reachable from elsewhere in the mesh — it just does not count.
    fn send_to(&self, to_fp: &str, frame: &Value, out: &mut Vec<Action>) -> Result<bool, CoreError> {
        let member = match self.members.get(to_fp) {
            Some(m) if m.fp != self.self_fp() => m,
            _ => return Ok(false),
        };
        if member.state == MemberState::Linked {
            if let Some(session_id) = &member.session_id {
                out.push(Action::Send { session_id: session_id.clone(), frame: encode_envelope(frame)? });
                return Ok(true);
            }
        }
        let relay = match self.relay_for(to_fp) {
            Some(r) => r,
            None => return Ok(false),
        };
        let wrapped = json!({
            "type": frames::RELAY,
            "gid": self.group_id,
            "to": to_fp,
            "hopped": false,
            "inner": frame,
        });
        out.push(Action::Send { session_id: relay, frame: encode_envelope(&wrapped)? });
        Ok(member.state != MemberState::Lost)
    }

    /// Fan a frame out to every other member.
    ///
    /// Returns WHO could not be reached as well as how many could, because a
    /// count on its own cannot tell "Alice is offline" from "Bob is offline" —
    /// and the sender is the only person in a position to know the difference.
    fn broadcast(&self, frame: &Value, out: &mut Vec<Action>) -> Result<DeliveryReport, CoreError> {
        let targets: Vec<String> = self
            .members
            .keys()
            .filter(|fp| *fp != self.self_fp())
            .cloned()
            .collect();
        let mut report = DeliveryReport { delivered: 0, total: targets.len(), unreachable: Vec::new() };
        for fp in targets {
            match self.send_to(&fp, frame, out) {
                Ok(true) => report.delivered += 1,
                _ => {
                    let name = self.members.get(&fp).map(|m| m.name.clone()).unwrap_or_else(|| "A member".into());
                    report.unreachable.push((fp, name));
                }
            }
        }
        Ok(report)
    }

    // -----------------------------------------------------------------------
    // link bookkeeping
    // -----------------------------------------------------------------------

    /// Bind a pairwise session to a member.
    ///
    /// A member never holds two links at once. Rebinding to a new session — a
    /// mesh dial that succeeded where an old link had dropped, or a chat the
    /// user rebuilt by hand — drops the stale mapping, or a frame arriving on
    /// the dead session id would still be attributed to them.
    pub fn bind_session(&mut self, fp: &str, session_id: &str, state: MemberState) -> Vec<Action> {
        let mut out = Vec::new();
        let previous = match self.members.get(fp) {
            Some(m) => m.session_id.clone(),
            None => return out,
        };
        if let Some(old) = previous {
            if old != session_id {
                self.session_to_fp.remove(&old);
                self.close_mesh_session(&old, &mut out);
            }
        }
        if let Some(member) = self.members.get_mut(fp) {
            member.session_id = Some(session_id.to_string());
            member.state = state;
        }
        self.session_to_fp.insert(session_id.to_string(), fp.to_string());
        out.push(self.members_event());
        out
    }

    /// Detach a member from whatever link it was on, back to the relay path.
    ///
    /// Deliberately does NOT change the member's state to Lost — they are not
    /// offline, we just have no direct route to them.
    pub fn unbind_session(&mut self, fp: &str) -> Vec<Action> {
        let mut out = Vec::new();
        let session_id = match self.members.get(fp).and_then(|m| m.session_id.clone()) {
            Some(s) => s,
            None => return out,
        };
        self.session_to_fp.remove(&session_id);
        if let Some(member) = self.members.get_mut(fp) {
            member.session_id = None;
            if member.state == MemberState::Linked || member.state == MemberState::Lost {
                member.state = MemberState::Pending;
            }
        }
        self.close_mesh_session(&session_id, &mut out);
        out.push(self.members_event());
        // The member has no route of their own now, so the mesh should look at
        // building one. This is what makes a link dying recoverable rather than
        // permanent.
        self.mesh_maintain(&mut out);
        out
    }

    /// A pairwise session changed state; reflect it on whichever member owns it.
    pub fn set_session_state(&mut self, session_id: &str, connected: bool) -> Vec<Action> {
        let mut out = Vec::new();
        let fp = match self.session_to_fp.get(session_id) {
            Some(fp) => fp.clone(),
            None => return out,
        };
        let next = if connected { MemberState::Linked } else { MemberState::Lost };
        match self.members.get_mut(&fp) {
            Some(m) if m.state != MemberState::SelfMember && m.state != next => m.state = next,
            _ => return out,
        }
        out.push(self.members_event());

        // A dial that reached Linked is finished. A link that DROPPED is also
        // settled — the dial is over either way — but the failure counter is
        // left alone, because a link that worked and then died says nothing
        // about whether the pair can connect.
        if connected {
            self.settle_dial(&fp);
        }
        self.mesh_maintain(&mut out);
        out
    }

    // -----------------------------------------------------------------------
    // the mesh
    // -----------------------------------------------------------------------
    //
    // WHO DIALS: the member with the smaller fingerprint. That is the entire
    // glare protocol — both sides compute it from the roster they already agree
    // on, so exactly one side opens each pair and there is no simultaneous-offer
    // case to resolve. A member that receives an offer from someone it should
    // have been dialling ITSELF refuses it.
    //
    // WHEN: only once the group is Ready and the code is confirmed. Before that,
    // the roster's identity keys are keys nobody has vouched for yet, and a link
    // authenticated by an unconfirmed key is a link authenticated by nothing.

    fn close_mesh_session(&mut self, session_id: &str, out: &mut Vec<Action>) {
        if self.mesh_sessions.remove(session_id) {
            out.push(Action::CloseLink { session_id: session_id.to_string() });
        }
    }

    /// A dial is over, one way or another.
    fn settle_dial(&mut self, fp: &str) {
        self.dials.remove(fp);
        self.failures.remove(fp);
    }

    /// Give up on one pair, for now.
    ///
    /// The half-built connection is closed and the member goes back to being
    /// reached through somebody else — which is where they were before the dial
    /// started, so nothing the user can see gets worse. The backoff doubles per
    /// attempt because a pair that cannot connect is usually a network that will
    /// not allow it, and hammering at that produces load rather than links.
    fn mesh_fail(&mut self, fp: &str, tell_peer: bool, out: &mut Vec<Action>) {
        if let Some(dial) = self.dials.remove(fp) {
            let member_session = self.members.get(fp).and_then(|m| m.session_id.clone());
            match (&dial.session_id, member_session) {
                (Some(dialed), Some(current)) if *dialed == current => {
                    out.extend(self.unbind_session(fp));
                }
                (Some(dialed), _) => {
                    let dialed = dialed.clone();
                    self.close_mesh_session(&dialed, out);
                }
                _ => {}
            }
        }

        let failure = self.failures.entry(fp.to_string()).or_insert(Failure { attempts: 0, next_at: 0 });
        failure.attempts += 1;
        let backoff = MESH_RETRY_MS.saturating_mul(1u64 << (failure.attempts - 1).min(16));
        failure.next_at = now_ms() + backoff as i64;

        // Tell the peer so their half of the dial does not sit until it times
        // out. Best effort by definition — if we could reach them reliably we
        // would not be failing.
        if tell_peer && self.members.contains_key(fp) {
            let frame = json!({
                "type": frames::MESH_ABORT, "gid": self.group_id, "epoch": self.epoch,
                "from": self.self_fp(), "to": fp,
            });
            let _ = self.send_to(fp, &frame, out);
        }
        self.mesh_maintain(out);
    }

    /// Cancel every dial in flight and forget every backoff.
    ///
    /// Called when the epoch moves: a dial signed against the old epoch will not
    /// verify against the new one, and a pair that could not connect under the
    /// old membership deserves a fresh chance under the new one. Links that are
    /// already up are untouched.
    fn mesh_reset(&mut self, out: &mut Vec<Action>) {
        for fp in self.dials.keys().cloned().collect::<Vec<_>>() {
            let dial = self.dials.remove(&fp);
            if let Some(dial) = dial {
                let member_session = self.members.get(&fp).and_then(|m| m.session_id.clone());
                match (&dial.session_id, member_session) {
                    (Some(dialed), Some(current)) if *dialed == current => {
                        out.extend(self.unbind_session(&fp));
                    }
                    (Some(dialed), _) => {
                        let dialed = dialed.clone();
                        self.close_mesh_session(&dialed, out);
                    }
                    _ => {}
                }
            }
        }
        self.failures.clear();
        self.probed.clear();
    }

    /// Open dials for whoever still has no link, within the concurrency limit.
    fn mesh_maintain(&mut self, out: &mut Vec<Action>) {
        if self.destroyed || self.phase != GroupPhase::Ready || !self.sas_confirmed {
            return;
        }
        let now = now_ms();
        let mut in_flight = self.dials.len();
        let mut soonest = i64::MAX;

        // Fingerprint order, so every member walks the same list and the load of
        // being dialled is spread the same way everywhere.
        let ordered: Vec<String> = self.members.keys().cloned().collect();
        for fp in ordered {
            if in_flight >= MESH_MAX_CONCURRENT_DIALS {
                break;
            }
            let (state, has_session) = match self.members.get(&fp) {
                Some(m) => (m.state, m.session_id.is_some()),
                None => continue,
            };
            if state == MemberState::SelfMember || has_session || self.dials.contains_key(&fp) {
                continue;
            }
            // Their turn to dial, not ours.
            if self.self_fp() >= fp.as_str() {
                continue;
            }
            if let Some(failure) = self.failures.get(&fp) {
                if failure.attempts >= MESH_MAX_ATTEMPTS {
                    continue;
                }
                if now < failure.next_at {
                    soonest = soonest.min(failure.next_at);
                    continue;
                }
            }
            // Nothing can carry the offer, so there is no dial to make. When a
            // relay appears, that link coming up schedules another pass.
            if self.relay_for(&fp).is_none() {
                continue;
            }
            in_flight += 1;
            out.push(Action::Dial { fp });
        }

        if soonest != i64::MAX {
            let wait = (soonest - now).max(0) as u64 + 50;
            out.push(Action::ArmTimer { kind: TimerKind::MeshMaintain, ms: wait });
        }
    }

    /// The platform built an offer for `fp`: sign it and put it on the relay path.
    pub fn mesh_offer_ready(&mut self, fp: &str, session_id: &str, descriptor: &str) -> Result<Vec<Action>, CoreError> {
        let mut out = Vec::new();
        if self.destroyed || self.members.get(fp).map(|m| m.session_id.is_some()).unwrap_or(true) {
            // The world moved while the transport was gathering candidates.
            out.push(Action::CloseLink { session_id: session_id.to_string() });
            return Ok(out);
        }
        if self.dials.contains_key(fp) {
            out.push(Action::CloseLink { session_id: session_id.to_string() });
            return Ok(out);
        }
        let epoch = self.epoch;
        let nonce = random_nonce(gc::MESH_NONCE_BYTES);
        let sig = gc::sign_mesh_descriptor(
            &self.identity, &self.group_id, epoch, MeshKind::Offer, self.self_fp(), fp, descriptor, &nonce,
        )?;
        self.dials.insert(fp.to_string(), Dial { role: MeshKind::Offer, session_id: Some(session_id.to_string()), nonce: nonce.clone(), epoch });
        self.mesh_sessions.insert(session_id.to_string());
        // Bound now, as Pending: it makes this member's link state addressable
        // the moment the transport reports in, and Pending keeps every frame on
        // the relay path until it actually comes up.
        out.extend(self.bind_session(fp, session_id, MemberState::Pending));

        let frame = json!({
            "type": frames::MESH_OFFER, "gid": self.group_id, "epoch": epoch,
            "from": self.self_fp(), "to": fp, "d": descriptor,
            "n": B64.encode(&nonce), "sig": B64.encode(&sig),
        });
        if !self.send_to(fp, &frame, &mut out)? {
            self.mesh_fail(fp, false, &mut out);
            return Ok(out);
        }
        out.push(Action::ArmTimer { kind: TimerKind::MeshDial(fp.to_string()), ms: MESH_DIAL_MS });
        Ok(out)
    }

    /// The platform answered `fp`'s relayed offer: sign the answer and send it.
    pub fn mesh_answer_ready(&mut self, fp: &str, session_id: &str, descriptor: &str) -> Result<Vec<Action>, CoreError> {
        let mut out = Vec::new();
        let nonce = match self.dials.get(fp) {
            Some(d) if d.role == MeshKind::Answer && d.epoch == self.epoch => d.nonce.clone(),
            _ => {
                out.push(Action::CloseLink { session_id: session_id.to_string() });
                return Ok(out);
            }
        };
        let epoch = self.epoch;
        let sig = gc::sign_mesh_descriptor(
            &self.identity, &self.group_id, epoch, MeshKind::Answer, self.self_fp(), fp, descriptor, &nonce,
        )?;
        if let Some(dial) = self.dials.get_mut(fp) {
            dial.session_id = Some(session_id.to_string());
        }
        self.mesh_sessions.insert(session_id.to_string());
        out.extend(self.bind_session(fp, session_id, MemberState::Pending));

        let frame = json!({
            "type": frames::MESH_ANSWER, "gid": self.group_id, "epoch": epoch,
            "from": self.self_fp(), "to": fp, "d": descriptor,
            "n": B64.encode(&nonce), "sig": B64.encode(&sig),
        });
        if !self.send_to(fp, &frame, &mut out)? {
            self.mesh_fail(fp, false, &mut out);
            return Ok(out);
        }
        out.push(Action::ArmTimer { kind: TimerKind::MeshDial(fp.to_string()), ms: MESH_DIAL_MS });
        Ok(out)
    }

    fn on_mesh_offer(&mut self, frame: &Value, out: &mut Vec<Action>) -> Result<(), CoreError> {
        let from = field_fingerprint(frame, "from")?;
        if field_fingerprint(frame, "to")? != self.self_fp() {
            return Ok(());
        }
        if field_epoch(frame, "epoch")? != self.epoch {
            return Ok(());
        }
        if self.phase != GroupPhase::Ready || !self.sas_confirmed {
            return Ok(());
        }
        let key = match self.members.get(&from).and_then(|m| m.key) {
            Some(k) => k,
            None => return Err(bad("mesh dial from a non-member")),
        };
        if self.members.get(&from).map(|m| m.session_id.is_some()).unwrap_or(false) {
            return Ok(()); // already reachable directly
        }
        if self.dials.contains_key(&from) {
            return Ok(()); // one dial per pair
        }
        // We are the smaller fingerprint, so dialling this pair is OUR job. An
        // offer arriving the wrong way round is refused rather than answered.
        if self.self_fp() < from.as_str() {
            return Ok(());
        }
        let descriptor = frame.get("d").and_then(|d| d.as_str()).unwrap_or("");
        if descriptor.is_empty() || descriptor.len() > gc::MAX_DESCRIPTOR_CHARS {
            return Err(bad("mesh descriptor is missing or oversized"));
        }
        let nonce = decode_b64(frame, "n", gc::MESH_NONCE_BYTES)?;
        let sig = decode_b64(frame, "sig", gc::MAX_SIG_BYTES)?;
        if !gc::verify_mesh_descriptor(
            &key, &self.group_id, self.epoch, MeshKind::Offer, &from, self.self_fp(), descriptor, &nonce, &sig,
        ) {
            return Err(bad("mesh dial signature did not verify"));
        }

        self.dials.insert(from.clone(), Dial { role: MeshKind::Answer, session_id: None, nonce, epoch: self.epoch });
        out.push(Action::Answer { fp: from, descriptor: descriptor.to_string() });
        Ok(())
    }

    fn on_mesh_answer(&mut self, frame: &Value, out: &mut Vec<Action>) -> Result<(), CoreError> {
        let from = field_fingerprint(frame, "from")?;
        if field_fingerprint(frame, "to")? != self.self_fp() {
            return Ok(());
        }
        if field_epoch(frame, "epoch")? != self.epoch {
            return Ok(());
        }
        let (dial_session, dial_nonce) = match self.dials.get(&from) {
            Some(d) if d.role == MeshKind::Offer && d.epoch == self.epoch && d.session_id.is_some() => {
                (d.session_id.clone().unwrap(), d.nonce.clone())
            }
            _ => return Ok(()),
        };
        let key = match self.members.get(&from).and_then(|m| m.key) {
            Some(k) => k,
            None => return Err(bad("mesh answer from a non-member")),
        };
        let descriptor = frame.get("d").and_then(|d| d.as_str()).unwrap_or("");
        if descriptor.is_empty() || descriptor.len() > gc::MAX_DESCRIPTOR_CHARS {
            return Err(bad("mesh descriptor is missing or oversized"));
        }
        // The nonce we generated for THIS dial, or the answer belongs to another
        // attempt and is being replayed into this one.
        let nonce = decode_b64(frame, "n", gc::MESH_NONCE_BYTES)?;
        if nonce != dial_nonce {
            return Err(bad("mesh answer does not match the dial it claims"));
        }
        let sig = decode_b64(frame, "sig", gc::MAX_SIG_BYTES)?;
        if !gc::verify_mesh_descriptor(
            &key, &self.group_id, self.epoch, MeshKind::Answer, &from, self.self_fp(), descriptor, &nonce, &sig,
        ) {
            return Err(bad("mesh answer signature did not verify"));
        }
        out.push(Action::AcceptAnswer { session_id: dial_session, descriptor: descriptor.to_string() });
        Ok(())
    }

    fn on_mesh_abort(&mut self, frame: &Value, out: &mut Vec<Action>) -> Result<(), CoreError> {
        let from = field_fingerprint(frame, "from")?;
        if field_fingerprint(frame, "to")? != self.self_fp() {
            return Ok(());
        }
        if !self.dials.contains_key(&from) {
            return Ok(());
        }
        // No abort back — that is how two peers keep telling each other to stop.
        self.mesh_fail(&from, false, out);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // link probes
    // -----------------------------------------------------------------------

    /// Claim a pairwise chat we already hold as this group's link to a member.
    ///
    /// Two people who were already talking do not need a second connection built
    /// between them. The platform offers every verified chat that is not already
    /// carrying a member; whoever is on the other end and is in this group binds
    /// it, and the pair is meshed without dialling anything.
    pub fn probe_session(&mut self, session_id: &str) -> Result<Vec<Action>, CoreError> {
        let mut out = Vec::new();
        if self.destroyed || self.phase != GroupPhase::Ready || !self.sas_confirmed {
            return Ok(out);
        }
        if self.session_to_fp.contains_key(session_id) {
            return Ok(out);
        }
        self.send_probe(session_id, &mut out)?;
        Ok(out)
    }

    /// Sign and send one probe. Once per session per epoch, whatever asked.
    fn send_probe(&mut self, session_id: &str, out: &mut Vec<Action>) -> Result<bool, CoreError> {
        if self.destroyed || self.probed.contains(session_id) {
            return Ok(false);
        }
        let link_fp = match self.link_fingerprints.get(session_id) {
            Some(fp) if !fp.is_empty() => fp.clone(),
            _ => return Ok(false),
        };
        self.probed.insert(session_id.to_string());
        let sig = gc::sign_link_probe(&self.identity, &self.group_id, self.epoch, self.self_fp(), &link_fp)?;
        let frame = json!({
            "type": frames::PROBE, "gid": self.group_id, "epoch": self.epoch,
            "fp": self.self_fp(), "sig": B64.encode(&sig),
        });
        out.push(Action::Send { session_id: session_id.to_string(), frame: encode_envelope(&frame)? });
        Ok(true)
    }

    fn on_probe(&mut self, session_id: &str, frame: &Value, out: &mut Vec<Action>) -> Result<(), CoreError> {
        if self.destroyed || self.phase != GroupPhase::Ready || !self.sas_confirmed {
            return Ok(());
        }
        if field_epoch(frame, "epoch")? != self.epoch {
            return Ok(());
        }
        let fp = field_fingerprint(frame, "fp")?;
        if fp == self.self_fp() {
            return Ok(());
        }
        let key = match self.members.get(&fp).and_then(|m| m.key) {
            Some(k) => k,
            None => return Ok(()),
        };
        if self.session_to_fp.contains_key(session_id) {
            return Ok(()); // this session carries someone else
        }
        if let Some(member) = self.members.get(&fp) {
            if member.session_id.is_some() {
                // A link that is already carrying traffic is not replaced. But a
                // dial still being built loses to a chat that already works.
                if member.state == MemberState::Linked {
                    return Ok(());
                }
                if !self.dials.contains_key(&fp) {
                    return Ok(());
                }
            }
        }
        // The fingerprint of the session the probe ARRIVED on, read locally.
        // Taking it from the frame would defeat the whole point.
        let link_fp = match self.link_fingerprints.get(session_id) {
            Some(v) if !v.is_empty() => v.clone(),
            _ => return Ok(()),
        };
        let sig = decode_b64(frame, "sig", gc::MAX_SIG_BYTES)?;
        if !gc::verify_link_probe(&key, &self.group_id, self.epoch, &fp, &link_fp, &sig) {
            return Err(bad("link probe signature did not verify"));
        }

        // A probe only ever arrives on a link that is already up and verified —
        // it travelled over it — so this one is Linked, not Pending.
        self.settle_dial(&fp);
        out.extend(self.bind_session(&fp, session_id, MemberState::Linked));
        // Answer in kind, or the adoption is one-sided: the peer now routes to
        // us over this link, but without a probe back they never learn who is on
        // their end and would go on relaying to us forever.
        let _ = self.send_probe(session_id, out);
        self.mesh_maintain(out);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // step 1-2: invite / hello
    // -----------------------------------------------------------------------

    /// Admin: invite peers we already hold verified 1:1 sessions with.
    pub fn invite(&mut self, peers: &[(String, String)]) -> Result<Vec<Action>, CoreError> {
        if !self.is_admin {
            return Err(bad("only the admin invites"));
        }
        if peers.len() + 1 > gc::MAX_MEMBERS {
            return Err(bad(format!("a group is limited to {} members", gc::MAX_MEMBERS)));
        }
        let mut out = Vec::new();
        self.set_phase(GroupPhase::Forming, &mut out);
        for (session_id, name) in peers {
            self.awaiting_hello.insert(session_id.clone(), name.clone());
        }
        let frame = json!({
            "type": frames::INVITE, "gid": self.group_id, "epoch": self.epoch,
            "name": self.name, "adminSpki": B64.encode(self.self_spki()),
        });
        let envelope = encode_envelope(&frame)?;
        for (session_id, _) in peers {
            out.push(Action::Send { session_id: session_id.clone(), frame: envelope.clone() });
        }
        out.push(Action::ArmTimer { kind: TimerKind::Hello, ms: HELLO_MS });
        Ok(out)
    }

    /// Invitee: adopt an invitation and publish our own identity key back.
    pub fn accept_invite(&mut self, session_id: &str, envelope: &Value) -> Result<Vec<Action>, CoreError> {
        let frame = decode_envelope(envelope)?;
        let mut out = Vec::new();
        let admin_spki = decode_b64(&frame, "adminSpki", gc::MAX_SPKI_BYTES)?;
        let (key, fingerprint) = gc::import_member_identity(&admin_spki)?;
        self.admin_fp = fingerprint.clone();
        self.epoch = field_epoch(&frame, "epoch")?;
        let name = frame.get("name").and_then(|n| n.as_str()).unwrap_or("");
        gc::assert_name(name)?;
        self.name = name.to_string();

        self.members.insert(
            fingerprint.clone(),
            Member {
                fp: fingerprint.clone(),
                name: "Admin".into(),
                spki: admin_spki,
                key: Some(key),
                session_id: Some(session_id.to_string()),
                state: MemberState::Linked,
            },
        );
        self.session_to_fp.insert(session_id.to_string(), fingerprint);
        self.set_phase(GroupPhase::Forming, &mut out);
        out.push(self.members_event());

        let hello = json!({
            "type": frames::HELLO, "gid": self.group_id, "epoch": self.epoch,
            "spki": B64.encode(self.self_spki()),
        });
        out.push(Action::Send { session_id: session_id.to_string(), frame: encode_envelope(&hello)? });
        out.push(Action::ArmTimer { kind: TimerKind::Hello, ms: HELLO_MS });
        Ok(out)
    }

    fn on_hello(&mut self, session_id: &str, frame: &Value, out: &mut Vec<Action>) -> Result<(), CoreError> {
        if !self.is_admin {
            return Ok(()); // only the admin collects identity keys
        }
        // A hello is only ever an ANSWER to an invitation this admin sent, on the
        // very session it was sent over. Without that check the frame is an open
        // door: anyone holding a verified chat with the admin who has learnt the
        // group id could publish an identity key the admin never invited, and the
        // branch at the end of this method would sign and broadcast a roster
        // containing it. "Only the admin invites" has to be enforced here,
        // because this is the only place a member is created from something that
        // arrived on the wire.
        //
        // It also confines the frame to a DIRECT link: a hello wrapped in a relay
        // arrives with the RELAY's session id, which is never a session an
        // invitation went out on.
        let name = match self.awaiting_hello.get(session_id) {
            Some(n) => n.clone(),
            None => return Ok(()),
        };
        let spki = decode_b64(frame, "spki", gc::MAX_SPKI_BYTES)?;
        let (key, fingerprint) = gc::import_member_identity(&spki)?;
        if self.members.contains_key(&fingerprint) && fingerprint != self.self_fp() {
            return Ok(());
        }
        if self.members.len() >= gc::MAX_MEMBERS {
            return Err(bad("group is full"));
        }
        self.members.insert(
            fingerprint.clone(),
            Member {
                fp: fingerprint.clone(),
                name,
                spki,
                key: Some(key),
                session_id: Some(session_id.to_string()),
                state: MemberState::Linked,
            },
        );
        self.session_to_fp.insert(session_id.to_string(), fingerprint);
        self.awaiting_hello.remove(session_id);
        out.push(self.members_event());

        if self.awaiting_hello.is_empty() {
            if self.pending_add.is_some() {
                self.finish_add(out)?;
            } else {
                self.publish_roster(MemberOp::Create, out)?;
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // step 3: the signed roster
    // -----------------------------------------------------------------------

    /// Admin: sign the current member set for this epoch and broadcast it.
    fn publish_roster(&mut self, op: MemberOp, out: &mut Vec<Action>) -> Result<(), CoreError> {
        if !self.is_admin {
            return Err(bad("only the admin publishes the roster"));
        }
        let member_fps: Vec<String> = self.members.keys().cloned().collect();
        let ordered = gc::canonical_fingerprints(&member_fps)?;
        let sig = gc::sign_member_op(&self.identity, &self.group_id, self.epoch, op, &ordered, &self.name)?;

        // Member keys go out one frame each, BEFORE the roster that names them.
        //
        // They cannot ride inside the roster: eight members' SPKI would put the
        // frame past the ceiling the chat path truncates at, and a truncated
        // roster fails in the most confusing way possible. Splitting them costs
        // nothing in security, because the signed roster commits to the
        // FINGERPRINTS — a key that arrives separately is checked against the
        // fingerprint it claims, so a substituted key is refused whichever frame
        // carried it.
        for fp in &ordered {
            let (name, spki) = match self.members.get(fp) {
                Some(m) => (if m.name == "You" { "Admin".to_string() } else { m.name.clone() }, m.spki.clone()),
                None => continue,
            };
            let frame = json!({
                "type": frames::MEMBER, "gid": self.group_id, "epoch": self.epoch,
                "fp": fp, "name": name, "spki": B64.encode(&spki),
            });
            self.broadcast(&frame, out)?;
        }

        let roster = json!({
            "type": frames::ROSTER, "gid": self.group_id, "epoch": self.epoch,
            "op": op.as_str(), "name": self.name,
            "adminSpki": B64.encode(self.self_spki()),
            "members": ordered, "sig": B64.encode(&sig),
        });
        self.broadcast(&roster, out)?;
        self.start_ceremony(out)
    }

    /// A member's identity key, published ahead of the roster that names them.
    ///
    /// Held in a staging area rather than applied: until the admin's signed
    /// roster arrives, a key frame is an unverified claim about who is in the
    /// group. The fingerprint is derived from the bytes, never taken from the
    /// frame, so a member cannot register a key under someone else's name.
    fn on_member_key(&mut self, frame: &Value) -> Result<(), CoreError> {
        let epoch = field_epoch(frame, "epoch")?;
        if epoch < self.epoch {
            return Ok(());
        }
        if self.pending_keys.len() > gc::MAX_MEMBERS * 2 {
            return Ok(());
        }
        let spki = decode_b64(frame, "spki", gc::MAX_SPKI_BYTES)?;
        let (key, fingerprint) = gc::import_member_identity(&spki)?;
        if field_fingerprint(frame, "fp")? != fingerprint {
            return Err(bad("member key does not match its fingerprint"));
        }
        let name = frame.get("name").and_then(|n| n.as_str()).unwrap_or("Member");
        gc::assert_name(name)?;
        self.pending_keys.insert(fingerprint, (spki, key, name.to_string()));
        Ok(())
    }

    /// Member: adopt a roster.
    ///
    /// The admin's signature is checked against the key whose fingerprint IS the
    /// admin fingerprint we recorded at invite time — not against whatever key
    /// the frame happens to carry — so a member cannot promote itself by
    /// attaching its own key to a roster. The epoch must move forward, which
    /// refuses both a replay and a rollback to a membership that used to be
    /// valid.
    fn on_roster(&mut self, frame: &Value, out: &mut Vec<Action>) -> Result<(), CoreError> {
        let epoch = field_epoch(frame, "epoch")?;
        if self.is_admin {
            return Ok(()); // we authored it
        }
        if epoch < self.epoch {
            return Err(bad("roster epoch went backwards"));
        }
        let admin_spki = decode_b64(frame, "adminSpki", gc::MAX_SPKI_BYTES)?;
        let (admin_key, admin_fp) = gc::import_member_identity(&admin_spki)?;
        if !self.admin_fp.is_empty() && admin_fp != self.admin_fp {
            return Err(bad("roster was signed by someone other than the admin"));
        }
        let listed = frame.get("members").and_then(|m| m.as_array())
            .ok_or_else(|| bad("roster carries no member list"))?;
        if listed.len() > gc::MAX_MEMBERS {
            return Err(bad("roster exceeds the member limit"));
        }
        let claimed: Vec<String> = listed
            .iter()
            .map(|v| v.as_str().unwrap_or("").to_string())
            .collect();
        let member_fps = gc::canonical_fingerprints(&claimed)?;
        if !member_fps.iter().any(|fp| fp == self.self_fp()) {
            return Err(bad("roster does not include us"));
        }
        if !member_fps.contains(&admin_fp) {
            return Err(bad("roster does not include its author"));
        }

        // Match each named member to the key frame that arrived ahead of the
        // roster. A member the admin names but whose key never arrived is a
        // member we could not verify a single message from, so the roster is
        // refused outright rather than adopted with a hole in it.
        let mut imported: Vec<(String, String, Vec<u8>, Option<VerifyingKey>)> = Vec::new();
        for fp in &member_fps {
            if fp == self.self_fp() {
                imported.push((fp.clone(), "You".into(), self.identity.spki.clone(), None));
                continue;
            }
            if let Some((spki, key, name)) = self.pending_keys.get(fp) {
                imported.push((fp.clone(), name.clone(), spki.clone(), Some(*key)));
            } else if *fp == admin_fp {
                imported.push((fp.clone(), "Admin".into(), admin_spki.clone(), Some(admin_key)));
            } else {
                return Err(bad("roster names a member whose key never arrived"));
            }
        }

        let op = MemberOp::parse(frame.get("op").and_then(|o| o.as_str()).unwrap_or(""))?;
        let name = frame.get("name").and_then(|n| n.as_str()).unwrap_or("");
        gc::assert_name(name)?;
        let sig = decode_b64(frame, "sig", gc::MAX_SIG_BYTES)?;
        if !gc::verify_member_op(&admin_key, &self.group_id, epoch, op, &member_fps, name, &sig) {
            return Err(bad("roster signature did not verify"));
        }

        // Adopt. Existing links are preserved: the session we already hold with
        // the admin (and with anyone else) stays bound to the same fingerprint.
        self.epoch = epoch;
        self.name = name.to_string();
        self.admin_fp = admin_fp.clone();

        let previous: HashMap<String, (Option<String>, MemberState)> = self
            .members
            .iter()
            .map(|(fp, m)| (fp.clone(), (m.session_id.clone(), m.state)))
            .collect();
        self.members.clear();
        for (fp, name, spki, key) in imported {
            let old = previous.get(&fp);
            let is_self = fp == self.self_fp();
            self.members.insert(
                fp.clone(),
                Member {
                    fp: fp.clone(),
                    name: if is_self { "You".into() } else { name },
                    spki,
                    key: if is_self { None } else { key },
                    session_id: old.and_then(|(s, _)| s.clone()),
                    state: if is_self {
                        MemberState::SelfMember
                    } else if matches!(old, Some((_, MemberState::Linked))) {
                        MemberState::Linked
                    } else {
                        MemberState::Pending
                    },
                },
            );
        }
        // Drop session bindings for members who left.
        let live: HashSet<String> = self.members.keys().cloned().collect();
        self.session_to_fp.retain(|_, fp| live.contains(fp));

        out.push(Action::Emit(Event::Roster { name: self.name.clone(), epoch: self.epoch, admin_fp }));
        out.push(self.members_event());
        self.start_ceremony(out)
    }

    // -----------------------------------------------------------------------
    // steps 4-6: the safety code ceremony
    // -----------------------------------------------------------------------

    fn start_ceremony(&mut self, out: &mut Vec<Action>) -> Result<(), CoreError> {
        // A new round means a new epoch, and every dial in flight was signed
        // against the old one. Abandon them rather than let them arrive as
        // signatures that cannot verify; links already up are kept.
        self.mesh_reset(out);
        let member_fps: Vec<String> = self.members.keys().cloned().collect();
        let mut ceremony = GroupSasCeremony::new(&self.group_id, self.epoch, self.self_fp(), &member_fps)?;
        let commitment = ceremony.own_commitment()?;
        self.ceremony = Some(ceremony);
        self.set_phase(GroupPhase::Committing, out);

        // Our commitment goes out BEFORE anything held is replayed, and the
        // order is load-bearing. Draining first can complete the commit round on
        // the spot — every peer commitment may already be waiting — which
        // reveals our nonce and puts a reveal on the wire ahead of our own
        // commitment. A peer would then hold a reveal it cannot check until our
        // commitment turns up, making correctness depend on a peer's buffer
        // instead of on the protocol.
        let frame = json!({
            "type": frames::COMMIT, "gid": self.group_id, "epoch": self.epoch,
            "fp": self.self_fp(), "commit": B64.encode(commitment),
        });
        self.broadcast(&frame, out)?;
        out.push(Action::ArmTimer { kind: TimerKind::Ceremony(self.epoch), ms: CEREMONY_MS });

        // Only now replay what arrived before this ceremony existed.
        self.drain_pending_ceremony(out)?;
        self.maybe_reveal(out)
    }

    fn hold_ceremony_frame(&mut self, frame: &Value) {
        // Two frames per member per epoch is all that can legitimately be
        // outstanding; the cap keeps a chatty member from growing this without
        // bound while we wait for a roster.
        if self.pending_ceremony.len() >= gc::MAX_MEMBERS * 2 {
            return;
        }
        self.pending_ceremony.push(frame.clone());
    }

    fn drain_pending_ceremony(&mut self, out: &mut Vec<Action>) -> Result<(), CoreError> {
        let held = std::mem::take(&mut self.pending_ceremony);
        for frame in held {
            let kind = frame.get("type").and_then(|t| t.as_str()).unwrap_or("");
            // A held frame that no longer makes sense (wrong epoch, a member
            // dropped from the roster) is discarded, not fatal.
            let _ = if kind == frames::COMMIT {
                self.on_commit(&frame, out)
            } else if kind == frames::REVEAL {
                self.on_reveal(&frame, out)
            } else {
                Ok(())
            };
        }
        Ok(())
    }

    fn on_commit(&mut self, frame: &Value, out: &mut Vec<Action>) -> Result<(), CoreError> {
        if self.ceremony.is_none() {
            self.hold_ceremony_frame(frame);
            return Ok(());
        }
        if field_epoch(frame, "epoch")? != self.epoch {
            return Ok(());
        }
        let fp = field_fingerprint(frame, "fp")?;
        let commit = decode_b64(frame, "commit", gc::COMMIT_BYTES)?;
        if let Some(ceremony) = self.ceremony.as_mut() {
            ceremony.accept_commitment(&fp, &commit)?;
        }
        // A reveal we had to hold may now have the commitment it needs.
        self.drain_pending_ceremony(out)?;
        self.maybe_reveal(out)
    }

    /// Publish our nonce, but only once every commitment is in.
    ///
    /// The check lives in `GroupSasCeremony::reveal`, which fails otherwise.
    /// This method only asks whether the round is complete — it must never be
    /// changed to reveal on a timer or on a partial round.
    fn maybe_reveal(&mut self, out: &mut Vec<Action>) -> Result<(), CoreError> {
        let ready = match self.ceremony.as_ref() {
            Some(c) => !c.revealed && c.commitments_complete(),
            None => false,
        };
        if !ready {
            return Ok(());
        }
        self.set_phase(GroupPhase::Revealing, out);
        let nonce = self.ceremony.as_mut().unwrap().reveal()?;
        let frame = json!({
            "type": frames::REVEAL, "gid": self.group_id, "epoch": self.epoch,
            "fp": self.self_fp(), "nonce": B64.encode(&nonce),
        });
        self.broadcast(&frame, out)?;
        self.maybe_finish(out)
    }

    fn on_reveal(&mut self, frame: &Value, out: &mut Vec<Action>) -> Result<(), CoreError> {
        if self.ceremony.is_none() {
            self.hold_ceremony_frame(frame);
            return Ok(());
        }
        if field_epoch(frame, "epoch")? != self.epoch {
            return Ok(());
        }
        let fp = field_fingerprint(frame, "fp")?;
        // A reveal can outrun the commitment it opens, on a link where the two
        // frames took different paths. Hold it rather than failing the ceremony
        // for an ordering the network chose.
        if !self.ceremony.as_ref().map(|c| c.has_commitment(&fp)).unwrap_or(false) {
            self.hold_ceremony_frame(frame);
            return Ok(());
        }
        let nonce = decode_b64(frame, "nonce", gc::NONCE_BYTES)?;
        self.ceremony.as_mut().unwrap().accept_reveal(&fp, &nonce)?;
        self.maybe_finish(out)
    }

    fn maybe_finish(&mut self, out: &mut Vec<Action>) -> Result<(), CoreError> {
        let complete = self.ceremony.as_ref().map(|c| c.reveals_complete()).unwrap_or(false);
        if !complete {
            return Ok(());
        }
        // Reached from both on_reveal and maybe_reveal, so it must be
        // idempotent: the round produces one code and computing it twice is not
        // an error.
        if !self.sas_code.is_empty() {
            return Ok(());
        }
        let code = self.ceremony.as_mut().unwrap().finish()?;
        self.set_phase(GroupPhase::AwaitingSas, out);
        self.sas_code = code.clone();
        out.push(Action::Emit(Event::Sas(code)));
        Ok(())
    }

    /// The humans compared the digits and they matched.
    ///
    /// This is the only path to Ready, and it is driven by a user action — never
    /// by a frame arriving. It mirrors the 1:1 rule: completing a handshake
    /// proves somebody completed it, and only the out-of-band comparison proves
    /// who.
    pub fn confirm_sas(&mut self) -> Result<Vec<Action>, CoreError> {
        if self.phase != GroupPhase::AwaitingSas || self.sas_code.is_empty() {
            return Err(bad("there is no group code to confirm"));
        }
        let mut out = Vec::new();
        self.sas_confirmed = true;
        self.phase = GroupPhase::Ready;
        self.ceremony = None;
        out.push(Action::Emit(Event::Phase(GroupPhase::Ready)));
        out.push(Action::Emit(Event::Confirmed));
        // The moment the human vouches for the code, the roster's identity keys
        // become keys worth authenticating a transport with. This is the gate
        // the whole mesh waits behind.
        self.mesh_maintain(&mut out);
        Ok(out)
    }

    // -----------------------------------------------------------------------
    // step 7: messages
    // -----------------------------------------------------------------------

    pub fn send_text(&mut self, text: &str) -> Result<(Vec<Action>, DeliveryReport), CoreError> {
        if self.phase != GroupPhase::Ready || !self.sas_confirmed {
            return Err(bad("the group code has not been confirmed"));
        }
        if text.trim().is_empty() {
            return Err(bad("empty message"));
        }
        let body_hash = gc::hash_body(text.as_bytes())?;
        self.seq += 1;
        let seq = self.seq;
        let sig = gc::sign_group_message(&self.identity, &self.group_id, self.epoch, seq, self.self_fp(), &body_hash)?;
        let frame = json!({
            "type": frames::MESSAGE, "gid": self.group_id, "epoch": self.epoch,
            "seq": seq, "fp": self.self_fp(), "ts": now_ms(),
            "body": text, "sig": B64.encode(&sig),
        });
        let mut out = Vec::new();
        let report = self.broadcast(&frame, &mut out)?;
        Ok((out, report))
    }

    fn on_message(&mut self, frame: &Value, relayed: bool, out: &mut Vec<Action>) -> Result<(), CoreError> {
        let epoch = field_epoch(frame, "epoch")?;
        let seq = field_epoch(frame, "seq")?;
        let sender_fp = field_fingerprint(frame, "fp")?;
        if sender_fp == self.self_fp() {
            return Ok(()); // our own frame came back around
        }
        let (key, name) = match self.members.get(&sender_fp) {
            Some(m) => match m.key {
                Some(k) => (k, m.name.clone()),
                None => return Err(bad("message from a non-member")),
            },
            None => return Err(bad("message from a non-member")),
        };
        // A message from an epoch we have left is not applied: its signature is
        // valid but it belongs to a membership that no longer holds.
        if epoch != self.epoch {
            return Err(bad("message from another epoch"));
        }
        let body = frame.get("body").and_then(|b| b.as_str()).unwrap_or("");
        let body_hash = gc::hash_body(body.as_bytes())?;
        let sig = decode_b64(frame, "sig", gc::MAX_SIG_BYTES)?;
        if !gc::verify_group_message(&key, &self.group_id, epoch, seq, &sender_fp, &body_hash, &sig) {
            return Err(bad("message signature did not verify"));
        }

        // Transcript consistency AND duplicate suppression, in that order —
        // which is the whole point. Fan-out plus relay means the same frame
        // legitimately arrives twice, so a repeat has to be absorbed silently.
        // But "same sender, same sequence number" is NOT enough to call
        // something a duplicate: a member telling two halves of the group
        // different things does exactly that, and deduplicating on the key alone
        // would hide the split this record exists to catch. The body hash is
        // what separates the two cases.
        let by_member = self.transcript.entry(sender_fp.clone()).or_default();
        if let Some(previous) = by_member.get(&seq) {
            if previous.as_slice() == body_hash.as_slice() {
                return Ok(()); // the same message, arriving again
            }
            out.push(Action::Emit(Event::Inconsistency { fp: sender_fp.clone(), name, seq }));
            return Err(bad("member sent conflicting messages under one sequence number"));
        }
        by_member.insert(seq, body_hash.to_vec());
        if by_member.len() > TRANSCRIPT_WINDOW {
            if let Some(oldest) = by_member.keys().next().cloned() {
                by_member.remove(&oldest);
            }
        }

        let ts = frame.get("ts").and_then(|t| t.as_i64()).unwrap_or_else(now_ms);
        out.push(Action::Emit(Event::Message {
            fp: sender_fp,
            name,
            body: body.to_string(),
            seq,
            ts,
            relayed,
        }));
        Ok(())
    }

    // -----------------------------------------------------------------------
    // inbound dispatch
    // -----------------------------------------------------------------------

    /// Handle one frame that arrived on a pairwise session.
    ///
    /// Everything here is attacker-supplied in the sense that matters: it comes
    /// from a verified peer, but a group member is only as trustworthy as the
    /// group makes them. Types are matched against an explicit list and anything
    /// unrecognised is dropped rather than passed on.
    pub fn handle_frame(&mut self, session_id: &str, envelope: &Value) -> Result<Vec<Action>, CoreError> {
        self.handle_frame_inner(session_id, envelope, false)
    }

    fn handle_frame_inner(&mut self, session_id: &str, envelope: &Value, relayed: bool) -> Result<Vec<Action>, CoreError> {
        let mut out = Vec::new();
        if self.destroyed || !is_group_frame(envelope) {
            return Ok(out);
        }
        let frame = decode_envelope(envelope)?;
        let kind = frame.get("type").and_then(|t| t.as_str()).unwrap_or("").to_string();
        if !frames::ALL.contains(&kind.as_str()) {
            return Ok(out);
        }
        let gid = frame.get("gid").and_then(|g| g.as_str()).unwrap_or("");
        gc::assert_group_id(gid)?;
        if gid != self.group_id {
            return Ok(out);
        }

        match kind.as_str() {
            frames::RELAY => self.on_relay(session_id, &frame, &mut out)?,
            frames::HELLO => self.on_hello(session_id, &frame, &mut out)?,
            frames::MEMBER => self.on_member_key(&frame)?,
            frames::ROSTER => self.on_roster(&frame, &mut out)?,
            frames::COMMIT => self.on_commit(&frame, &mut out)?,
            frames::REVEAL => self.on_reveal(&frame, &mut out)?,
            frames::MESSAGE => self.on_message(&frame, relayed, &mut out)?,
            frames::LEAVE => self.on_leave(&frame, &mut out)?,
            frames::MESH_OFFER => self.on_mesh_offer(&frame, &mut out)?,
            frames::MESH_ANSWER => self.on_mesh_answer(&frame, &mut out)?,
            frames::MESH_ABORT => self.on_mesh_abort(&frame, &mut out)?,
            // A probe is a claim about the link it arrived on, so it is only
            // meaningful on a direct one. Relayed, it says nothing.
            frames::PROBE => {
                if !relayed {
                    self.on_probe(session_id, &frame, &mut out)?;
                }
            }
            // An invitation is handled by the app, which decides whether to join
            // at all — there is no group here yet to decode it into.
            frames::INVITE => {}
            _ => {}
        }
        Ok(out)
    }

    /// Single-hop relay.
    ///
    /// A frame addressed to us is unwrapped and handled. A frame addressed to
    /// someone else is forwarded exactly once — `hopped` makes a second forward
    /// impossible, so there is no loop to form and no path to lengthen.
    fn on_relay(&mut self, session_id: &str, frame: &Value, out: &mut Vec<Action>) -> Result<(), CoreError> {
        let to = field_fingerprint(frame, "to")?;
        let inner = match frame.get("inner") {
            Some(i) if is_group_frame(i) => i.clone(),
            _ => return Ok(()),
        };
        if inner.get("type").and_then(|t| t.as_str()) == Some(frames::RELAY) {
            return Ok(()); // never nest
        }
        if to == self.self_fp() {
            let actions = self.handle_frame_inner(session_id, &inner, true)?;
            out.extend(actions);
            return Ok(());
        }
        if frame.get("hopped").and_then(|h| h.as_bool()) == Some(true) {
            return Ok(()); // already relayed once; do not forward again
        }
        let next = match self.members.get(&to) {
            Some(m) if m.state == MemberState::Linked => match &m.session_id {
                Some(s) => s.clone(),
                None => return Ok(()),
            },
            _ => return Ok(()),
        };
        let mut forwarded = frame.clone();
        forwarded["hopped"] = Value::Bool(true);
        out.push(Action::Send { session_id: next, frame: encode_envelope(&forwarded)? });
        Ok(())
    }

    fn on_leave(&mut self, frame: &Value, out: &mut Vec<Action>) -> Result<(), CoreError> {
        let fp = field_fingerprint(frame, "fp")?;
        let name = match self.members.get(&fp) {
            Some(m) if fp != self.self_fp() => m.name.clone(),
            _ => return Ok(()),
        };
        out.push(Action::Emit(Event::Left { fp: fp.clone(), name }));

        // The admin leaving ends the group for everyone else. Nobody else can
        // sign a roster, so there is no next epoch and no safety code to compare
        // again — carrying on would leave a group that looks alive but can never
        // change membership.
        if !self.is_admin && fp == self.admin_fp {
            self.members.remove(&fp);
            self.session_to_fp.retain(|_, f| *f != fp);
            out.push(Action::Emit(Event::Ended("admin_left".into())));
            return Ok(());
        }
        // Only the admin rewrites membership; everyone else waits for the roster
        // the admin will publish for the new epoch.
        if !self.is_admin {
            return Ok(());
        }
        self.members.remove(&fp);
        self.session_to_fp.retain(|_, f| *f != fp);
        out.push(self.members_event());

        // A group of one is not a group. Publishing a roster for it would fail
        // inside canonical_fingerprints and abort mid-teardown.
        if self.members.len() < gc::MIN_MEMBERS {
            out.push(Action::Emit(Event::Ended("last_member_left".into())));
            return Ok(());
        }
        self.epoch += 1;
        self.publish_roster(MemberOp::Remove, out)
    }

    /// Tell the group we are leaving, best effort.
    pub fn leave(&mut self) -> Result<Vec<Action>, CoreError> {
        let mut out = Vec::new();
        let frame = json!({ "type": frames::LEAVE, "gid": self.group_id, "fp": self.self_fp() });
        let _ = self.broadcast(&frame, &mut out);
        Ok(out)
    }

    /// Admin: invite more people into a group that is already running.
    ///
    /// The group stays usable throughout. Nothing about the membership changes
    /// until the new members have published their identity keys and a roster for
    /// the next epoch actually goes out — at which point every member, old and
    /// new, runs a fresh commit/reveal round and compares a new code. That is
    /// not ceremony for its own sake: the safety code covers the member set, so
    /// a set that has changed has a different code.
    pub fn add_members(&mut self, peers: &[(String, String)]) -> Result<Vec<Action>, CoreError> {
        if !self.is_admin {
            return Err(bad("only the admin invites"));
        }
        if peers.is_empty() {
            return Ok(Vec::new());
        }
        if self.pending_add.is_some() {
            return Err(bad("an invitation round is already running"));
        }
        if self.members.len() + peers.len() > gc::MAX_MEMBERS {
            return Err(bad(format!("a group is limited to {} members", gc::MAX_MEMBERS)));
        }
        // Refuse a session that is already carrying a member: inviting someone
        // twice would have them answer with a second identity key and occupy two
        // slots in the safety code.
        for (session_id, _) in peers {
            if self.session_to_fp.contains_key(session_id) {
                return Err(bad("that chat is already a member of this group"));
            }
        }

        self.pending_add = Some(PendingAdd {
            op: MemberOp::Add,
            epoch: self.epoch + 1,
            before: self.members.keys().cloned().collect(),
        });
        for (session_id, name) in peers {
            self.awaiting_hello.insert(session_id.clone(), name.clone());
        }
        // The invitation already names the epoch the new roster will open, so an
        // invitee adopts it before anything is signed against it.
        let frame = json!({
            "type": frames::INVITE, "gid": self.group_id,
            "epoch": self.epoch + 1, "name": self.name,
            "adminSpki": B64.encode(self.self_spki()),
        });
        let envelope = encode_envelope(&frame)?;
        let mut out = Vec::new();
        for (session_id, _) in peers {
            out.push(Action::Send { session_id: session_id.clone(), frame: envelope.clone() });
        }
        out.push(Action::ArmTimer { kind: TimerKind::Hello, ms: HELLO_MS });
        Ok(out)
    }

    /// Close an add round: publish the new roster, or abandon it.
    ///
    /// A partial answer is still worth publishing — the people who did join are
    /// in — but if nobody joined, the group is left untouched rather than pushed
    /// through a re-keying that would achieve nothing except making everyone
    /// compare a new code.
    fn finish_add(&mut self, out: &mut Vec<Action>) -> Result<(), CoreError> {
        let round = match self.pending_add.take() {
            Some(r) => r,
            None => return Ok(()),
        };
        self.awaiting_hello.clear();
        let joined = self.members.keys().any(|fp| !round.before.contains(fp));
        if !joined {
            out.push(Action::Emit(Event::AddFailed("nobody_joined".into())));
            return Ok(());
        }
        self.epoch = round.epoch;
        out.push(self.members_event());
        self.publish_roster(round.op, out)
    }

    /// Admin: remove a member and re-key the group.
    ///
    /// The new epoch is what makes the removal effective — a new safety code
    /// every remaining member must compare again, and a member set the removed
    /// member is not in. There is no shared group key to rotate because there
    /// never was one: every message travels over pairwise ratchets, so a removed
    /// member simply stops being sent anything.
    pub fn remove_member(&mut self, fp: &str) -> Result<Vec<Action>, CoreError> {
        if !self.is_admin {
            return Err(bad("only the admin removes members"));
        }
        if fp == self.self_fp() {
            return Err(bad("the admin cannot remove themselves"));
        }
        if !self.members.contains_key(fp) {
            return Ok(Vec::new());
        }
        if self.members.len() - 1 < gc::MIN_MEMBERS {
            return Err(bad("a group cannot drop below two members — leave it instead"));
        }
        let mut out = Vec::new();
        self.members.remove(fp);
        self.session_to_fp.retain(|_, f| f != fp);
        self.epoch += 1;
        out.push(self.members_event());
        self.publish_roster(MemberOp::Remove, &mut out)?;
        Ok(out)
    }

    // -----------------------------------------------------------------------
    // timers
    // -----------------------------------------------------------------------

    /// A deadline the platform armed has expired.
    pub fn on_timer(&mut self, kind: &TimerKind) -> Vec<Action> {
        let mut out = Vec::new();
        if self.destroyed {
            return out;
        }
        match kind {
            TimerKind::Ceremony(epoch) => {
                if *epoch == self.epoch
                    && matches!(self.phase, GroupPhase::Committing | GroupPhase::Revealing)
                {
                    self.fail("ceremony_timed_out", &mut out);
                }
            }
            TimerKind::Hello => {
                if self.pending_add.is_some() {
                    let _ = self.finish_add(&mut out);
                } else if self.phase == GroupPhase::Forming {
                    let code = if self.is_admin { "invitees_did_not_respond" } else { "roster_never_arrived" };
                    self.fail(code, &mut out);
                }
            }
            TimerKind::MeshDial(fp) => {
                if self.dials.contains_key(fp) {
                    self.mesh_fail(fp, true, &mut out);
                }
            }
            TimerKind::MeshMaintain => self.mesh_maintain(&mut out),
        }
        out
    }

    /// Tear the group down. Connections this group opened are its to close.
    pub fn destroy(&mut self) -> Vec<Action> {
        self.destroyed = true;
        let mut out = Vec::new();
        for session_id in std::mem::take(&mut self.mesh_sessions) {
            out.push(Action::CloseLink { session_id });
        }
        self.ceremony = None;
        self.members.clear();
        self.session_to_fp.clear();
        self.transcript.clear();
        self.pending_ceremony.clear();
        self.pending_keys.clear();
        self.pending_add = None;
        self.dials.clear();
        self.failures.clear();
        self.probed.clear();
        out
    }
}

// ---------------------------------------------------------------------------
// field helpers — every one of these reads attacker-supplied JSON
// ---------------------------------------------------------------------------

fn field_fingerprint(frame: &Value, key: &str) -> Result<String, CoreError> {
    let value = frame.get(key).and_then(|v| v.as_str()).unwrap_or("");
    gc::assert_fingerprint(value)?;
    Ok(value.to_string())
}

fn field_epoch(frame: &Value, key: &str) -> Result<u64, CoreError> {
    let value = frame.get(key).and_then(|v| v.as_u64()).ok_or_else(|| bad("missing or malformed epoch"))?;
    gc::assert_epoch(value)
}

fn decode_b64(frame: &Value, key: &str, max: usize) -> Result<Vec<u8>, CoreError> {
    let raw = frame.get(key).and_then(|v| v.as_str()).unwrap_or("");
    // Bound BEFORE decoding: base64 expands 3:4, so this caps the allocation.
    if raw.len() > (max * 4) / 3 + 4 {
        return Err(bad("base64 payload exceeds its limit"));
    }
    B64.decode(raw).map_err(|_| bad("malformed base64"))
}

fn random_nonce(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut out = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}

// ---------------------------------------------------------------------------
// JSON surface for platform layers
// ---------------------------------------------------------------------------
//
// A platform drives this state machine over some boundary — Tauri IPC, a JNI
// call, a channel — and JSON is what every one of them already speaks. These
// conversions are the contract: the shapes below are what a desktop or a phone
// matches on, so they are part of the API and not an implementation detail.

impl TimerKind {
    pub fn to_json(&self) -> Value {
        match self {
            TimerKind::Ceremony(epoch) => json!({ "kind": "ceremony", "epoch": epoch }),
            TimerKind::Hello => json!({ "kind": "hello" }),
            TimerKind::MeshDial(fp) => json!({ "kind": "mesh_dial", "fp": fp }),
            TimerKind::MeshMaintain => json!({ "kind": "mesh_maintain" }),
        }
    }

    pub fn from_json(value: &Value) -> Result<Self, CoreError> {
        match value.get("kind").and_then(|k| k.as_str()).unwrap_or("") {
            "ceremony" => Ok(TimerKind::Ceremony(
                value.get("epoch").and_then(|e| e.as_u64()).unwrap_or(0),
            )),
            "hello" => Ok(TimerKind::Hello),
            "mesh_dial" => Ok(TimerKind::MeshDial(
                value.get("fp").and_then(|f| f.as_str()).unwrap_or("").to_string(),
            )),
            "mesh_maintain" => Ok(TimerKind::MeshMaintain),
            _ => Err(bad("unknown timer kind")),
        }
    }
}

impl MemberSnapshot {
    pub fn to_json(&self) -> Value {
        json!({
            "fp": self.fp,
            "name": self.name,
            "sessionId": self.session_id,
            "state": self.state.as_str(),
        })
    }
}

impl Event {
    pub fn to_json(&self) -> Value {
        match self {
            Event::Phase(phase) => json!({ "event": "phase", "phase": phase.as_str() }),
            Event::Members { members, epoch } => json!({
                "event": "members",
                "members": members.iter().map(|m| m.to_json()).collect::<Vec<_>>(),
                "epoch": epoch,
            }),
            Event::Roster { name, epoch, admin_fp } => json!({
                "event": "roster", "name": name, "epoch": epoch, "adminFp": admin_fp,
            }),
            Event::Sas(code) => json!({ "event": "sas", "code": code }),
            Event::Confirmed => json!({ "event": "confirmed" }),
            Event::Message { fp, name, body, seq, ts, relayed } => json!({
                "event": "message", "fp": fp, "name": name, "body": body,
                "seq": seq, "ts": ts, "relayed": relayed,
            }),
            Event::Left { fp, name } => json!({ "event": "left", "fp": fp, "name": name }),
            Event::Ended(reason) => json!({ "event": "ended", "reason": reason }),
            Event::AddFailed(reason) => json!({ "event": "addFailed", "reason": reason }),
            Event::Inconsistency { fp, name, seq } => json!({
                "event": "inconsistency", "fp": fp, "name": name, "seq": seq,
            }),
            Event::Error(code) => json!({ "event": "error", "code": code }),
        }
    }
}

impl Action {
    pub fn to_json(&self) -> Value {
        match self {
            Action::Send { session_id, frame } => json!({
                "action": "send", "sessionId": session_id, "frame": frame,
            }),
            Action::Dial { fp } => json!({ "action": "dial", "fp": fp }),
            Action::Answer { fp, descriptor } => json!({
                "action": "answer", "fp": fp, "descriptor": descriptor,
            }),
            Action::AcceptAnswer { session_id, descriptor } => json!({
                "action": "acceptAnswer", "sessionId": session_id, "descriptor": descriptor,
            }),
            Action::CloseLink { session_id } => json!({ "action": "closeLink", "sessionId": session_id }),
            Action::ArmTimer { kind, ms } => json!({
                "action": "armTimer", "timer": kind.to_json(), "ms": ms,
            }),
            Action::Emit(event) => json!({ "action": "emit", "event": event.to_json() }),
        }
    }
}

pub fn actions_to_json(actions: &[Action]) -> Value {
    Value::Array(actions.iter().map(|a| a.to_json()).collect())
}

impl DeliveryReport {
    pub fn to_json(&self) -> Value {
        json!({
            "delivered": self.delivered,
            "total": self.total,
            "unreachable": self.unreachable.iter()
                .map(|(fp, name)| json!({ "fp": fp, "name": name }))
                .collect::<Vec<_>>(),
        })
    }
}

impl GroupSession {
    /// Everything a user interface renders, in one call.
    pub fn snapshot(&self) -> Value {
        json!({
            "gid": self.group_id,
            "name": self.name,
            "isAdmin": self.is_admin,
            "epoch": self.epoch,
            "phase": self.phase.as_str(),
            "sasCode": self.sas_code,
            "sasConfirmed": self.sas_confirmed,
            "selfFp": self.self_fp(),
            "adminFp": self.admin_fp,
            "members": self.members_snapshot().iter().map(|m| m.to_json()).collect::<Vec<_>>(),
        })
    }
}

/// Read the group id and name out of an invitation, without joining anything.
///
/// The one frame a platform must understand before a group exists to decode it
/// with: an invitation is surfaced to the user, and only their acceptance may
/// create group state. Nothing arriving on the wire creates it on its own.
pub fn peek_invite(envelope: &Value) -> Result<Option<Value>, CoreError> {
    if group_frame_type(envelope).as_deref() != Some(frames::INVITE) {
        return Ok(None);
    }
    let frame = decode_envelope(envelope)?;
    let gid = frame.get("gid").and_then(|g| g.as_str()).unwrap_or("");
    gc::assert_group_id(gid)?;
    let name = frame.get("name").and_then(|n| n.as_str()).unwrap_or("");
    gc::assert_name(name)?;
    gc::assert_epoch(field_epoch(&frame, "epoch")?)?;
    Ok(Some(json!({ "gid": gid, "name": name, "frame": envelope })))
}
