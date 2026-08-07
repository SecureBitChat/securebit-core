//! SBQ2 — the compact connection descriptor.
//!
//! This is a byte-for-byte port of `src/network/descriptor/sbq2.js` in the web
//! client. The two implementations MUST agree exactly: a descriptor produced
//! here is scanned by a browser and vice versa, and both feed the same bytes
//! into the SAS transcript, so a single byte of disagreement is not a
//! compatibility bug that degrades — it is two peers reading different safety
//! codes and refusing to connect.
//!
//! What the descriptor carries and what it deliberately does not: only the
//! material needed to bring up DTLS (ICE credentials, the certificate
//! fingerprint, candidates), an expiry, and a 16-byte commitment to the key
//! material. Keys travel in band, over the channel the fingerprint authenticates
//! — see `keyexchange`.
//!
//! Everything here is a parser of hostile input. Lengths, ranges and alphabets
//! are checked before a value is used, and the SDP is rebuilt by a strict
//! serializer from validated primitives, never by pasting strings from the wire.

use crate::error::CoreError;
use sha2::{Digest, Sha256};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

pub const SBQ2_VERSION: u8 = 0x02;
pub const TEXT_PREFIX: &str = "SB2:";

pub const MAX_PAYLOAD_BYTES: usize = 512;
pub const MAX_CANDIDATES: usize = 8;
pub const MIN_UFRAG: usize = 4;
pub const MAX_UFRAG: usize = 64;
pub const MIN_PWD: usize = 22;
pub const MAX_PWD: usize = 64;
pub const FINGERPRINT_BYTES: usize = 32;
pub const COMMITMENT_BYTES: usize = 16;
pub const BINDING_BYTES: usize = 8;
pub const MAX_LIFETIME_MINUTES: u64 = 60;
pub const MAX_EXT_BYTES: usize = 255;
/// Byte budget for candidates admitted beyond the coverage set. Derived from the
/// acceptance target, not picked: the largest answer head measured is Firefox's
/// at 104 bytes, and QR version 8 at level M holds 152 in byte mode.
pub const SURPLUS_CANDIDATE_BYTES: usize = 48;
/// Clock-skew allowance on the expiry check, in milliseconds. Two minutes covers
/// ordinary drift without swallowing a grossly wrong clock — see the web client's
/// LIMITS.CLOCK_SKEW_MS for the full reasoning.
pub const CLOCK_SKEW_MS: i64 = 120_000;

/// Milliseconds from the Unix epoch to 2024-01-01T00:00:00Z.
const EPOCH_MS: i64 = 1_704_067_200_000;
const MAX_EXPIRY_UNITS: u32 = 0x00ff_ffff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorType { Offer = 0, Answer = 1 }

/// max-message-size packed into two flag bits. Index 3 means "explicit value in
/// extension 0x01"; RFC 8841 makes 64 KiB the default when the attribute is
/// absent, which is why absent and 65536 share an encoding.
const MMS_ENUM: [Option<u32>; 4] = [Some(262_144), Some(1_073_741_823), Some(65_536), None];
const MMS_EXPLICIT: u8 = 3;
pub const EXT_MAX_MESSAGE_SIZE: u8 = 0x01;

/// Candidate kinds. Wire constants — never renumber, only append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    HostV4 = 0, HostMdns = 1, SrflxV4 = 2, RelayV4 = 3,
    HostV6 = 4, SrflxV6 = 5, RelayV6 = 6,
}

impl Kind {
    fn from_u8(v: u8) -> Option<Kind> {
        Some(match v {
            0 => Kind::HostV4, 1 => Kind::HostMdns, 2 => Kind::SrflxV4, 3 => Kind::RelayV4,
            4 => Kind::HostV6, 5 => Kind::SrflxV6, 6 => Kind::RelayV6,
            _ => return None,
        })
    }
    fn addr_len(self) -> usize {
        match self {
            Kind::HostV4 | Kind::SrflxV4 | Kind::RelayV4 => 4,
            _ => 16,
        }
    }
    fn ctype(self) -> &'static str {
        match self {
            Kind::HostV4 | Kind::HostMdns | Kind::HostV6 => "host",
            Kind::SrflxV4 | Kind::SrflxV6 => "srflx",
            Kind::RelayV4 | Kind::RelayV6 => "relay",
        }
    }
    /// Address family for the coverage rule. mDNS is its own family: it resolves
    /// only on the sender's link, covering a case neither v4 nor v6 does.
    fn family(self) -> &'static str {
        match self {
            Kind::HostMdns => "mdns",
            Kind::HostV4 | Kind::SrflxV4 | Kind::RelayV4 => "v4",
            _ => "v6",
        }
    }
}

const TCPTYPE: [&str; 4] = ["", "passive", "active", "so"];
const SETUP: [&str; 3] = ["actpass", "active", "passive"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub kind: Kind,
    pub tcptype: u8,
    pub addr: Vec<u8>,
    pub port: u16,
    /// The sender's own priority. Used only for ranking during pruning; never
    /// encoded, because ICE priority merely orders connectivity checks and both
    /// peers compute their own.
    pub priority: u32,
}

impl Candidate {
    pub fn wire_size(&self) -> usize { 1 + self.kind.addr_len() + 2 }
    fn group_key(&self) -> String {
        format!("{}/{}/{}", self.kind.family(), self.kind.ctype(),
                if self.tcptype == 0 { "udp" } else { "tcp" })
    }
    /// An ICE-TCP `active`/`so` candidate is an outbound-only socket on the
    /// discard port: it pairs only with a remote `passive` and gives the peer no
    /// address to dial. Firefox advertises one on every connection, so it must
    /// not claim a coverage slot it cannot use.
    fn connectable(&self) -> bool { self.tcptype != 2 && self.tcptype != 3 }
}

#[derive(Debug, Clone)]
pub struct SdpFields {
    pub ufrag: String,
    pub pwd: String,
    pub fingerprint: [u8; FINGERPRINT_BYTES],
    pub setup: u8,
    pub max_message_size: u32,
    pub candidates: Vec<Candidate>,
}

#[derive(Debug, Clone)]
pub struct Descriptor {
    pub version: u8,
    pub dtype: DescriptorType,
    pub setup: u8,
    pub max_message_size: u32,
    pub expires_at_ms: i64,
    pub binding_tag: Option<[u8; BINDING_BYTES]>,
    pub fingerprint: [u8; FINGERPRINT_BYTES],
    pub ufrag: String,
    pub pwd: String,
    pub candidates: Vec<Candidate>,
    pub commitment: Option<[u8; COMMITMENT_BYTES]>,
}

fn bad(msg: impl Into<String>) -> CoreError { CoreError::invalid_input(msg.into()) }

fn is_ice_char(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

// ---------------------------------------------------------------------------
// SDP -> fields
// ---------------------------------------------------------------------------

fn parse_ipv4(s: &str) -> Option<Vec<u8>> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 { return None; }
    let mut out = Vec::with_capacity(4);
    for p in parts {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) { return None; }
        out.push(p.parse::<u8>().ok()?);
    }
    Some(out)
}

fn parse_ipv6(s: &str) -> Option<Vec<u8>> {
    if s.len() > 45 || !s.bytes().all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.') {
        return None;
    }
    // Dotted-quad tail, as used by IPv4-mapped and NAT64 addresses.
    let mut text = s.to_string();
    let mut tail4: Option<Vec<u8>> = None;
    if text.contains('.') {
        let idx = text.rfind(':')?;
        tail4 = Some(parse_ipv4(&text[idx + 1..])?);
        text = format!("{}0:0", &text[..idx + 1]);
    }
    let halves: Vec<&str> = text.split("::").collect();
    if halves.len() > 2 { return None; }
    let to_words = |part: &str| -> Option<Vec<u16>> {
        if part.is_empty() { return Some(vec![]); }
        part.split(':').map(|h| {
            if h.is_empty() || h.len() > 4 { None } else { u16::from_str_radix(h, 16).ok() }
        }).collect()
    };
    let head = to_words(halves[0])?;
    let tail = if halves.len() == 2 { to_words(halves[1])? } else { vec![] };
    let words: Vec<u16> = if halves.len() == 2 {
        if head.len() + tail.len() >= 8 { return None; }
        let gap = 8 - head.len() - tail.len();
        head.iter().copied().chain(std::iter::repeat(0).take(gap)).chain(tail.iter().copied()).collect()
    } else { head };
    if words.len() != 8 { return None; }
    let mut out = Vec::with_capacity(16);
    for w in &words { out.push((w >> 8) as u8); out.push((w & 0xff) as u8); }
    if let Some(t) = tail4 { out[12..16].copy_from_slice(&t); }
    Some(out)
}

fn parse_mdns(s: &str) -> Option<Vec<u8>> {
    let base = s.strip_suffix(".local").or_else(|| s.strip_suffix(".LOCAL"))?;
    let parts: Vec<&str> = base.split('-').collect();
    if parts.len() != 5 { return None; }
    if [8, 4, 4, 4, 12] != [parts[0].len(), parts[1].len(), parts[2].len(), parts[3].len(), parts[4].len()] {
        return None;
    }
    let hex: String = parts.concat().to_lowercase();
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) { return None; }
    (0..16).map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()).collect()
}

fn attr<'a>(lines: &[&'a str], name: &str) -> Option<&'a str> {
    let prefix = format!("a={}:", name);
    lines.iter().find(|l| l.starts_with(&prefix)).map(|l| l[prefix.len()..].trim())
}

/// Extract the fields SBQ2 carries from a browser-generated SDP.
pub fn parse_sdp(sdp: &str) -> Result<SdpFields, CoreError> {
    if sdp.len() > 64 * 1024 { return Err(bad("SDP is too large")); }
    let lines: Vec<&str> = sdp.split(|c| c == '\n' || c == '\r').filter(|l| !l.is_empty()).collect();

    let ufrag = attr(&lines, "ice-ufrag").ok_or_else(|| bad("SDP is missing ICE credentials"))?.to_string();
    let pwd = attr(&lines, "ice-pwd").ok_or_else(|| bad("SDP is missing ICE credentials"))?.to_string();

    let fp_line = attr(&lines, "fingerprint").ok_or_else(|| bad("SDP is missing a DTLS fingerprint"))?;
    let mut it = fp_line.split_whitespace();
    let alg = it.next().unwrap_or("");
    if !alg.eq_ignore_ascii_case("sha-256") {
        return Err(bad(format!("unsupported DTLS fingerprint algorithm: {}", &alg[..alg.len().min(16)])));
    }
    let hex_part = it.next().unwrap_or("");
    let octets: Vec<&str> = hex_part.split(':').collect();
    if octets.len() != FINGERPRINT_BYTES { return Err(bad("DTLS fingerprint has the wrong length")); }
    let mut fingerprint = [0u8; FINGERPRINT_BYTES];
    for (i, o) in octets.iter().enumerate() {
        if o.len() != 2 || !o.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(bad("DTLS fingerprint is not hex"));
        }
        fingerprint[i] = u8::from_str_radix(o, 16).map_err(|_| bad("DTLS fingerprint is not hex"))?;
    }

    let setup_str = attr(&lines, "setup").unwrap_or("actpass");
    let setup = SETUP.iter().position(|s| *s == setup_str)
        .ok_or_else(|| bad(format!("unsupported DTLS setup role: {}", &setup_str[..setup_str.len().min(16)])))? as u8;

    // RFC 8841: an absent a=max-message-size means 64 KiB.
    let max_message_size = match attr(&lines, "max-message-size") {
        None => 65_536,
        Some(v) => v.parse::<u32>().map_err(|_| bad("invalid a=max-message-size"))?,
    };

    let mut candidates = Vec::new();
    for line in &lines {
        let Some(rest) = line.strip_prefix("a=candidate:") else { continue };
        let p: Vec<&str> = rest.split_whitespace().collect();
        if p.len() < 8 || p[6] != "typ" { continue; }
        if p[1] != "1" { continue; }                       // component 1 only
        let transport = p[2].to_ascii_lowercase();
        let priority = p[3].parse::<u32>().unwrap_or(0);
        let addr = p[4];
        let Ok(port) = p[5].parse::<u16>() else { continue };
        if port == 0 { continue; }
        let ctype = p[7];

        let mut tcptype = 0u8;
        if transport == "tcp" {
            let Some(i) = p.iter().position(|x| *x == "tcptype") else { continue };
            let Some(t) = p.get(i + 1).and_then(|v| TCPTYPE.iter().position(|x| x == v)) else { continue };
            if t == 0 { continue; }
            tcptype = t as u8;
        } else if transport != "udp" {
            continue;
        }

        let (kind, bytes) = if let (Some(m), "host") = (parse_mdns(addr), ctype) {
            (Kind::HostMdns, m)
        } else if let Some(v4) = parse_ipv4(addr) {
            match ctype {
                "host" => (Kind::HostV4, v4),
                "srflx" | "prflx" => (Kind::SrflxV4, v4),
                "relay" => (Kind::RelayV4, v4),
                _ => continue,
            }
        } else if let Some(v6) = parse_ipv6(addr) {
            match ctype {
                "host" => (Kind::HostV6, v6),
                "srflx" | "prflx" => (Kind::SrflxV6, v6),
                "relay" => (Kind::RelayV6, v6),
                _ => continue,
            }
        } else { continue };

        candidates.push(Candidate { kind, tcptype, addr: bytes, port, priority });
    }

    Ok(SdpFields { ufrag, pwd, fingerprint, setup, max_message_size, candidates })
}

/// Coverage before count: one representative per (family, type, transport)
/// survives before any surplus is admitted, so an IPv6-only or UDP-blocked path
/// cannot be pruned away by a v4-first sort. Coverage is never cut to fit the
/// byte budget — a QR one version larger beats a connection that cannot be made.
pub fn prune_candidates(input: &[Candidate]) -> Vec<Candidate> {
    prune_candidates_with(input, MAX_CANDIDATES, SURPLUS_CANDIDATE_BYTES, true, 2)
}

pub fn prune_candidates_with(
    input: &[Candidate], max_candidates: usize, max_bytes: usize, keep_mdns: bool, max_relays: usize,
) -> Vec<Candidate> {
    let mut uniq: Vec<Candidate> = Vec::new();
    for c in input {
        if !keep_mdns && c.kind == Kind::HostMdns { continue; }
        if uniq.iter().any(|u| u.kind == c.kind && u.tcptype == c.tcptype && u.addr == c.addr && u.port == c.port) {
            continue;
        }
        uniq.push(c.clone());
    }
    // Stable sort by descending priority, matching the JS Array.sort contract.
    let mut ranked = uniq.clone();
    ranked.sort_by(|a, b| b.priority.cmp(&a.priority));

    let mut chosen: Vec<Candidate> = Vec::new();
    let mut groups: Vec<String> = Vec::new();
    let mut bytes = 0usize;
    let mut relays = 0usize;

    // Pass 1 — coverage.
    for c in &ranked {
        if !c.connectable() { continue; }
        let g = c.group_key();
        if groups.contains(&g) { continue; }
        groups.push(g);
        bytes += c.wire_size();
        if c.kind.ctype() == "relay" { relays += 1; }
        chosen.push(c.clone());
    }
    // Pass 2 — surplus, by the sender's own priority, inside both budgets.
    for c in &ranked {
        if chosen.iter().any(|x| x == c) { continue; }
        if chosen.len() >= max_candidates { break; }
        if bytes + c.wire_size() > max_bytes { continue; }
        if c.kind.ctype() == "relay" && relays >= max_relays { continue; }
        bytes += c.wire_size();
        if c.kind.ctype() == "relay" { relays += 1; }
        chosen.push(c.clone());
    }
    chosen.sort_by(|a, b| b.priority.cmp(&a.priority));
    chosen
}

// ---------------------------------------------------------------------------
// encode
// ---------------------------------------------------------------------------

pub struct EncodeParams<'a> {
    pub dtype: DescriptorType,
    pub binding_tag: Option<[u8; BINDING_BYTES]>,
    pub expires_at_ms: i64,
    pub fields: &'a SdpFields,
    pub commitment: Option<[u8; COMMITMENT_BYTES]>,
}

pub fn encode_descriptor(p: &EncodeParams) -> Result<Vec<u8>, CoreError> {
    match (p.dtype, p.binding_tag) {
        (DescriptorType::Answer, None) => return Err(bad("answer needs an 8-byte binding tag")),
        (DescriptorType::Offer, Some(_)) => return Err(bad("offers do not carry a binding tag")),
        _ => {}
    }
    let f = p.fields;
    if f.ufrag.len() < MIN_UFRAG || f.ufrag.len() > MAX_UFRAG || !is_ice_char(&f.ufrag) {
        return Err(bad("invalid ice-ufrag"));
    }
    if f.pwd.len() < MIN_PWD || f.pwd.len() > MAX_PWD || !is_ice_char(&f.pwd) {
        return Err(bad("invalid ice-pwd"));
    }
    if f.candidates.len() > MAX_CANDIDATES { return Err(bad("too many candidates")); }
    if f.setup > 2 { return Err(bad("invalid DTLS setup role")); }
    if f.max_message_size < 1024 || f.max_message_size > 0x7fff_ffff {
        return Err(bad("max-message-size must be between 1024 and 2^31-1"));
    }

    let minutes_i = (p.expires_at_ms - EPOCH_MS + 59_999).div_euclid(60_000);
    if minutes_i < 0 || minutes_i > MAX_EXPIRY_UNITS as i64 { return Err(bad("expiry out of range")); }
    let minutes = minutes_i as u32;

    // Extensions. Records ascend by type so a descriptor has exactly one spelling.
    let mut ext: Vec<u8> = Vec::new();
    let mms_index = match MMS_ENUM.iter().position(|v| *v == Some(f.max_message_size)) {
        Some(i) => i as u8,
        None => {
            ext.push(EXT_MAX_MESSAGE_SIZE);
            ext.push(4);
            ext.extend_from_slice(&f.max_message_size.to_be_bytes());
            MMS_EXPLICIT
        }
    };
    if ext.len() > MAX_EXT_BYTES { return Err(bad("extension area is too long")); }

    let flags = (p.dtype as u8 & 0x03)
        | ((f.setup & 0x03) << 2)
        | ((mms_index & 0x03) << 4)
        | if p.commitment.is_some() { 0x40 } else { 0 }
        | if ext.is_empty() { 0 } else { 0x80 };

    let mut out: Vec<u8> = Vec::with_capacity(160);
    out.push(SBQ2_VERSION);
    out.push(flags);
    out.push((minutes >> 16) as u8);
    out.push((minutes >> 8) as u8);
    out.push(minutes as u8);
    if let Some(tag) = p.binding_tag { out.extend_from_slice(&tag); }
    out.extend_from_slice(&f.fingerprint);
    out.push(f.ufrag.len() as u8);
    out.extend_from_slice(f.ufrag.as_bytes());
    out.push(f.pwd.len() as u8);
    out.extend_from_slice(f.pwd.as_bytes());
    out.push(f.candidates.len() as u8);
    for c in &f.candidates {
        if c.addr.len() != c.kind.addr_len() { return Err(bad("candidate address length does not match its kind")); }
        out.push(((c.kind as u8) << 4) | (c.tcptype & 0x0f));
        out.extend_from_slice(&c.addr);
        out.extend_from_slice(&c.port.to_be_bytes());
    }
    if let Some(c) = p.commitment { out.extend_from_slice(&c); }
    if !ext.is_empty() { out.push(ext.len() as u8); out.extend_from_slice(&ext); }

    if out.len() > MAX_PAYLOAD_BYTES { return Err(bad("descriptor exceeds the payload limit")); }
    Ok(out)
}

// ---------------------------------------------------------------------------
// decode
// ---------------------------------------------------------------------------

struct Reader<'a> { b: &'a [u8], i: usize }
impl<'a> Reader<'a> {
    fn need(&self, n: usize) -> Result<(), CoreError> {
        if self.i + n > self.b.len() { Err(bad("descriptor is truncated")) } else { Ok(()) }
    }
    fn u8(&mut self) -> Result<u8, CoreError> { self.need(1)?; let v = self.b[self.i]; self.i += 1; Ok(v) }
    fn u16(&mut self) -> Result<u16, CoreError> {
        self.need(2)?; let v = u16::from_be_bytes([self.b[self.i], self.b[self.i + 1]]); self.i += 2; Ok(v)
    }
    fn u24(&mut self) -> Result<u32, CoreError> {
        self.need(3)?;
        let v = ((self.b[self.i] as u32) << 16) | ((self.b[self.i + 1] as u32) << 8) | self.b[self.i + 2] as u32;
        self.i += 3; Ok(v)
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], CoreError> {
        self.need(n)?; let s = &self.b[self.i..self.i + n]; self.i += n; Ok(s)
    }
    fn ascii(&mut self, n: usize) -> Result<String, CoreError> {
        let s = self.bytes(n)?;
        if s.iter().any(|c| *c < 0x20 || *c > 0x7e) { return Err(bad("non-printable byte in a text field")); }
        Ok(String::from_utf8_lossy(s).into_owned())
    }
    fn rest(&self) -> usize { self.b.len() - self.i }
}

/// Parse a descriptor. `now_ms` is the clock the expiry is checked against.
pub fn decode_descriptor(buf: &[u8], now_ms: i64) -> Result<Descriptor, CoreError> {
    if buf.is_empty() { return Err(bad("descriptor is empty")); }
    if buf.len() > MAX_PAYLOAD_BYTES { return Err(bad("descriptor exceeds the payload limit")); }
    let mut r = Reader { b: buf, i: 0 };

    // Version first. A mismatch is an error, never an attempt to parse a
    // different shape — this is what makes downgrade impossible rather than
    // merely unlikely.
    let version = r.u8()?;
    if version != SBQ2_VERSION {
        return Err(bad(format!("unsupported descriptor version 0x{:02x}", version)));
    }

    let flags = r.u8()?;
    let dtype = match flags & 0x03 {
        0 => DescriptorType::Offer,
        1 => DescriptorType::Answer,
        _ => return Err(bad("reserved descriptor type")),
    };
    let setup = (flags >> 2) & 0x03;
    if setup > 2 { return Err(bad("reserved DTLS setup role")); }
    let mms_index = (flags >> 4) & 0x03;
    let has_commitment = flags & 0x40 != 0;
    let has_ext = flags & 0x80 != 0;

    let minutes = r.u24()?;
    let expires_at_ms = EPOCH_MS + minutes as i64 * 60_000;
    if now_ms - CLOCK_SKEW_MS > expires_at_ms {
        let late = (now_ms - expires_at_ms) / 60_000;
        return Err(bad(format!(
            "this code expired {} minute(s) ago. If it was just created, this device's clock \
             or time zone is probably wrong — check the date and time settings.", late)));
    }
    if expires_at_ms - now_ms > (MAX_LIFETIME_MINUTES as i64 * 60_000) + CLOCK_SKEW_MS {
        return Err(bad("descriptor lifetime is implausibly long"));
    }

    let binding_tag = if dtype == DescriptorType::Answer {
        let mut t = [0u8; BINDING_BYTES];
        t.copy_from_slice(r.bytes(BINDING_BYTES)?);
        Some(t)
    } else { None };

    let mut fingerprint = [0u8; FINGERPRINT_BYTES];
    fingerprint.copy_from_slice(r.bytes(FINGERPRINT_BYTES)?);

    let ufrag_len = r.u8()? as usize;
    if !(MIN_UFRAG..=MAX_UFRAG).contains(&ufrag_len) { return Err(bad("ice-ufrag length out of range")); }
    let ufrag = r.ascii(ufrag_len)?;
    if !is_ice_char(&ufrag) { return Err(bad("ice-ufrag contains characters outside the ICE alphabet")); }

    let pwd_len = r.u8()? as usize;
    if !(MIN_PWD..=MAX_PWD).contains(&pwd_len) { return Err(bad("ice-pwd length out of range")); }
    let pwd = r.ascii(pwd_len)?;
    if !is_ice_char(&pwd) { return Err(bad("ice-pwd contains characters outside the ICE alphabet")); }

    let count = r.u8()? as usize;
    if count > MAX_CANDIDATES { return Err(bad("too many candidates")); }
    let mut candidates = Vec::with_capacity(count);
    for _ in 0..count {
        let tag = r.u8()?;
        let kind = Kind::from_u8(tag >> 4).ok_or_else(|| bad(format!("reserved candidate kind {}", tag >> 4)))?;
        let tcptype = tag & 0x0f;
        if tcptype as usize >= TCPTYPE.len() { return Err(bad("reserved TCP candidate type")); }
        let addr = r.bytes(kind.addr_len())?.to_vec();
        let port = r.u16()?;
        if port == 0 { return Err(bad("candidate port must be non-zero")); }
        candidates.push(Candidate { kind, tcptype, addr, port, priority: 0 });
    }

    let commitment = if has_commitment {
        let mut c = [0u8; COMMITMENT_BYTES];
        c.copy_from_slice(r.bytes(COMMITMENT_BYTES)?);
        Some(c)
    } else { None };

    let mut ext_mms: Option<u32> = None;
    if has_ext {
        let ext_len = r.u8()? as usize;
        if ext_len == 0 { return Err(bad("extension area is flagged but empty")); }
        let area = r.bytes(ext_len)?;
        let mut er = Reader { b: area, i: 0 };
        let mut last_type: i32 = -1;
        while er.rest() > 0 {
            let t = er.u8()?;
            let len = er.u8()? as usize;
            let value = er.bytes(len)?;
            if t as i32 <= last_type {
                return Err(bad("extension records must be in ascending type order without duplicates"));
            }
            last_type = t as i32;
            match t {
                EXT_MAX_MESSAGE_SIZE => {
                    if len != 4 { return Err(bad("extension 0x01 must be 4 bytes")); }
                    let v = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                    if !(1024..=0x7fff_ffff).contains(&v) { return Err(bad("extension 0x01 value is out of range")); }
                    if MMS_ENUM.iter().any(|m| *m == Some(v)) {
                        return Err(bad("extension 0x01 duplicates a value the flags already encode"));
                    }
                    ext_mms = Some(v);
                }
                // Deny by default. A decoder that skipped what it does not
                // understand would turn this area into a downgrade channel: an
                // attacker appends a record one side acts on and the other
                // drops, and the two ends disagree while both believe they
                // validated the descriptor.
                other => return Err(bad(format!("unknown extension type 0x{:02x}", other))),
            }
        }
    }

    // Trailing bytes are malformed input, not padding: a decoder that tolerates
    // them lets a second reading of the same QR past whatever hashed the
    // canonical form.
    if r.rest() != 0 { return Err(bad(format!("{} trailing byte(s) after the descriptor", r.rest()))); }

    let max_message_size = if mms_index == MMS_EXPLICIT {
        ext_mms.ok_or_else(|| bad("flags promise an explicit max-message-size but no extension carries it"))?
    } else {
        if ext_mms.is_some() { return Err(bad("extension 0x01 present but the flags do not select it")); }
        MMS_ENUM[mms_index as usize].ok_or_else(|| bad("invalid max-message-size selector"))?
    };

    Ok(Descriptor {
        version, dtype, setup, max_message_size, expires_at_ms,
        binding_tag, fingerprint, ufrag, pwd, candidates, commitment,
    })
}

// ---------------------------------------------------------------------------
// strict SDP serializer
// ---------------------------------------------------------------------------

fn render_addr(kind: Kind, addr: &[u8]) -> String {
    match kind {
        Kind::HostMdns => {
            let h: String = addr.iter().map(|b| format!("{:02x}", b)).collect();
            format!("{}-{}-{}-{}-{}.local", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
        }
        Kind::HostV4 | Kind::SrflxV4 | Kind::RelayV4 =>
            format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]),
        _ => (0..8).map(|i| format!("{:x}", u16::from_be_bytes([addr[i * 2], addr[i * 2 + 1]])))
            .collect::<Vec<_>>().join(":"),
    }
}

fn type_pref(ctype: &str) -> u32 {
    match ctype { "host" => 126, "srflx" => 100, _ => 0 }
}

/// Rebuild an SDP from a decoded descriptor.
///
/// Every value written is either a template constant or a primitive the decoder
/// already range-checked and that is re-rendered from bytes. The only strings
/// echoed through are ufrag and pwd, both constrained to the ICE alphabet, so
/// neither can carry a CRLF and inject an SDP line.
pub fn serialize_sdp(d: &Descriptor) -> String {
    // The default candidate must be real whenever we have one. `m=... 9` with
    // `c=IN IP4 0.0.0.0` is the trickle convention for "nothing gathered yet"
    // (RFC 8840 §4.1) and is false here — measured cost of getting this wrong:
    // 0/4 relay-only connections to Firefox against 4/4 for the browser's own
    // SDP. Preference is relay > srflx > host, the most publicly reachable
    // address, which is the order Chrome uses.
    let rank = |c: &Candidate| match c.kind.ctype() { "relay" => 0, "srflx" => 1, _ => 2 };
    let mut defaults: Vec<&Candidate> = d.candidates.iter()
        .filter(|c| c.kind != Kind::HostMdns && c.tcptype == 0).collect();
    defaults.sort_by_key(|c| rank(c));
    let def = defaults.first().copied();

    let (m_port, c_line) = match def {
        Some(c) => (
            c.port.to_string(),
            format!("c=IN IP{} {}", if c.kind.family() == "v6" { "6" } else { "4" },
                    render_addr(c.kind, &c.addr)),
        ),
        None => ("9".to_string(), "c=IN IP4 0.0.0.0".to_string()),
    };

    let mut cand_lines: Vec<String> = Vec::new();
    for (i, c) in d.candidates.iter().enumerate() {
        let ctype = c.kind.ctype();
        let transport = if c.tcptype == 0 { "udp" } else { "tcp" };
        // RFC 8445 §5.1.2.1, with localPref descending by position so the
        // sender's ordering intent survives at zero cost on the wire.
        let local_pref = 65535u32.saturating_sub(i as u32);
        let priority = type_pref(ctype) * 16_777_216 + local_pref * 256 + 255;
        let foundation = (c.kind as u32) * 4 + c.tcptype as u32 + 1;
        let mut line = format!("a=candidate:{} 1 {} {} {} {} typ {}",
            foundation, transport, priority, render_addr(c.kind, &c.addr), c.port, ctype);
        // rel-addr/rel-port are MANDATORY for srflx/prflx/relay (RFC 8839 §5.1)
        // even though ICE never reads them. Chrome tolerates the omission;
        // Firefox drops the candidate outright.
        if ctype != "host" {
            line.push_str(if c.kind.family() == "v6" { " raddr :: rport 0" } else { " raddr 0.0.0.0 rport 0" });
        }
        if transport == "tcp" { line.push_str(&format!(" tcptype {}", TCPTYPE[c.tcptype as usize])); }
        cand_lines.push(line);
    }
    // Explicitly closes the set (RFC 8838 §14) so the peer stops waiting for
    // more. Note the deliberate absence of `a=ice-options:trickle`: a descriptor
    // is a complete one-shot candidate set with no channel to trickle over.
    cand_lines.push("a=end-of-candidates".to_string());

    let fp = d.fingerprint.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":");
    let mut lines = vec![
        "v=0".to_string(),
        "o=- 1 2 IN IP4 127.0.0.1".to_string(),
        "s=-".to_string(),
        "t=0 0".to_string(),
        "a=group:BUNDLE 0".to_string(),
        "a=msid-semantic: WMS".to_string(),
        format!("m=application {} UDP/DTLS/SCTP webrtc-datachannel", m_port),
        c_line,
    ];
    lines.extend(cand_lines);
    lines.push(format!("a=ice-ufrag:{}", d.ufrag));
    lines.push(format!("a=ice-pwd:{}", d.pwd));
    lines.push(format!("a=fingerprint:sha-256 {}", fp));
    lines.push(format!("a=setup:{}", SETUP[d.setup as usize]));
    lines.push("a=mid:0".to_string());
    lines.push("a=sctp-port:5000".to_string());
    lines.push(format!("a=max-message-size:{}", d.max_message_size));
    format!("{}\r\n", lines.join("\r\n"))
}

// ---------------------------------------------------------------------------
// binding + text transport
// ---------------------------------------------------------------------------

/// 8-byte tag an answer carries so the offerer can confirm it answers THIS
/// offer. Also what makes each offer one-shot.
///
/// LIMITATION, on purpose: 64 bits is not a standalone integrity primitive. Its
/// security comes from the SAS transcript, which covers both descriptors in
/// full. Do not build anything on this tag alone.
pub fn binding_tag(offer_bytes: &[u8]) -> [u8; BINDING_BYTES] {
    let mut h = Sha256::new();
    h.update(b"sbq2/bind\0");
    h.update(offer_bytes);
    let d = h.finalize();
    let mut out = [0u8; BINDING_BYTES];
    out.copy_from_slice(&d[..BINDING_BYTES]);
    out
}

/// 16-byte commitment to the in-band key blob.
pub fn commit_blob(blob: &[u8]) -> [u8; COMMITMENT_BYTES] {
    let mut h = Sha256::new();
    h.update(b"sbq2/blob\0");
    h.update(blob);
    let d = h.finalize();
    let mut out = [0u8; COMMITMENT_BYTES];
    out.copy_from_slice(&d[..COMMITMENT_BYTES]);
    out
}

pub fn encode_text(bytes: &[u8]) -> String {
    format!("{}{}", TEXT_PREFIX, URL_SAFE_NO_PAD.encode(bytes))
}

pub fn decode_text(text: &str) -> Result<Vec<u8>, CoreError> {
    let t = text.trim();
    let body = t.strip_prefix(TEXT_PREFIX).ok_or_else(|| bad("not an SB2 descriptor"))?;
    // Messengers wrap long lines; strip whitespace before validating, then
    // require the alphabet exactly.
    let s: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    if s.len() > (MAX_PAYLOAD_BYTES * 4 / 3) + 4 { return Err(bad("payload is too long")); }
    if !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(bad("payload contains characters outside base64url"));
    }
    URL_SAFE_NO_PAD.decode(s.as_bytes()).map_err(|e| bad(format!("payload is not valid base64url: {}", e)))
}

/// True when a payload announces itself as SBQ2, by text prefix or first byte.
/// The families never collide: SB1 text starts with ASCII 'S' (0x53).
pub fn looks_like_sbq2(payload: &str) -> bool {
    payload.trim_start().starts_with(TEXT_PREFIX) || payload.as_bytes().first() == Some(&SBQ2_VERSION)
}
