//! Passive recovery for PPPoE links. Frames are normalized before decoding, and
//! complete server messages can progress past a missing captured KCP message.
//! Synthetic sequence numbers exist only inside the decoder; nothing is sent.

use std::collections::{BTreeMap, HashMap};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::time::{Duration, Instant};

const GAP_GRACE: Duration = Duration::from_millis(250);
const IDLE_EXPIRY: Duration = Duration::from_secs(300);
const MAX_FLOWS: usize = 64;
const MAX_SEGMENTS: usize = 4096;

pub struct Frame {
    pub source: u64,
    pub data: Vec<u8>,
}

struct Udp<'a> {
    source: u64,
    src: u16,
    dst: u16,
    payload: &'a [u8],
}

fn be16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(o..o + 2)?.try_into().ok()?))
}

/// Handles Ethernet, stacked VLANs, PPPoE Session and IPv6 extension headers.
fn udp(frame: &[u8]) -> Option<Udp<'_>> {
    let mut kind = be16(frame, 12)?;
    let mut ip = 14;
    let mut limit = frame.len();
    while matches!(kind, 0x8100 | 0x88a8) {
        kind = be16(frame, ip + 2)?;
        ip += 4;
    }
    if kind == 0x8864 {
        if *frame.get(ip)? != 0x11 || *frame.get(ip + 1)? != 0 {
            return None;
        }
        limit = ip.checked_add(6 + be16(frame, ip + 4)? as usize)?;
        if limit > frame.len() {
            return None;
        }
        kind = match be16(frame, ip + 6)? {
            0x21 => 0x0800,
            0x57 => 0x86dd,
            _ => return None,
        };
        ip += 8;
    }
    let b = frame.get(..limit)?;
    let (offset, addresses) = match kind {
        0x0800 => {
            let ihl = (b.get(ip)? & 15) as usize * 4;
            if b[ip] >> 4 != 4 || ihl < 20 || *b.get(ip + 9)? != 17 || be16(b, ip + 6)? & 0x3fff != 0 {
                return None;
            }
            let end = ip.checked_add(be16(b, ip + 2)? as usize)?;
            if end > limit {
                return None;
            }
            limit = end;
            (ip + ihl, b.get(ip + 12..ip + 20)?)
        }
        0x86dd => {
            if b.get(ip)? >> 4 != 6 {
                return None;
            }
            let end = ip.checked_add(40 + be16(b, ip + 4)? as usize)?;
            if end > limit {
                return None;
            }
            limit = end;
            let mut next = *b.get(ip + 6)?;
            let mut offset = ip + 40;
            for _ in 0..8 {
                if next == 17 {
                    break;
                }
                let length = match next {
                    0 | 43 | 60 => (usize::from(*b.get(offset + 1)?) + 1) * 8,
                    44 => {
                        if be16(b, offset + 2)? & 0xfff9 != 0 {
                            return None;
                        }
                        8
                    }
                    _ => return None,
                };
                next = *b.get(offset)?;
                offset = offset.checked_add(length)?;
                if offset > limit {
                    return None;
                }
            }
            if next != 17 {
                return None;
            }
            (offset, b.get(ip + 8..ip + 40)?)
        }
        _ => return None,
    };
    let src = be16(b, offset)?;
    let dst = be16(b, offset + 2)?;
    // The exporter consumes server replies and notifications. Keeping the
    // receive direction also avoids a client packet racing the new session key.
    if !matches!(src, 23301 | 23302) {
        return None;
    }
    let length = be16(b, offset + 4)? as usize;
    if length < 8 || offset.checked_add(length)? > limit {
        return None;
    }
    let mut hasher = DefaultHasher::new();
    (addresses, src, dst).hash(&mut hasher);
    Some(Udp {
        source: hasher.finish(),
        src,
        dst,
        payload: b.get(offset + 8..offset + length)?,
    })
}

fn ethernet(src: u16, dst: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0; 42 + payload.len()];
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
    frame[22] = 64;
    frame[23] = 17;
    frame[26..34].copy_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
    frame[34..36].copy_from_slice(&src.to_be_bytes());
    frame[36..38].copy_from_slice(&dst.to_be_bytes());
    frame[38..40].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    frame[42..].copy_from_slice(payload);
    frame
}

struct Conversation {
    source: u64,
    src: u16,
    dst: u16,
    segments: BTreeMap<u32, Vec<u8>>,
    original_next: u32,
    synthetic_next: u32,
    handshake: bool,
    gap_since: Option<Instant>,
    last_seen: Instant,
}

impl Conversation {
    fn drain(&mut self, now: Instant, force: bool) -> Vec<Frame> {
        let mut out = Vec::new();
        // A capture may begin in an older connection. Its token reply and key
        // are already gone, so wait for sequence zero of a fresh connection.
        if self.synthetic_next == 0 && !self.segments.contains_key(&0) {
            return out;
        }
        while let Some((&first, segment)) = self.segments.first_key_value() {
            let end = first.saturating_add(u32::from(segment[9]));
            let complete = (first..=end).all(|sn| self.segments.get(&sn).is_some_and(|s| u32::from(s[9]) == end - sn));
            if first != self.original_next || !complete {
                let since = *self.gap_since.get_or_insert(now);
                if !force && now.saturating_duration_since(since) < GAP_GRACE {
                    break;
                }
                tracing::warn!(
                    from = self.original_next,
                    to = if complete { first } else { end.saturating_add(1) },
                    "Recovering complete server messages after a capture gap"
                );
                if !complete {
                    self.segments.retain(|sn, _| *sn > end);
                    self.original_next = end.saturating_add(1);
                    self.gap_since = None;
                    continue;
                }
            }
            for sn in first..=end {
                let mut s = self.segments.remove(&sn).unwrap();
                s[16..20].copy_from_slice(&self.synthetic_next.to_le_bytes());
                s[20..24].fill(0);
                self.synthetic_next = self.synthetic_next.wrapping_add(1);
                out.push(Frame {
                    source: self.source,
                    data: ethernet(self.src, self.dst, &s),
                });
            }
            self.original_next = end.saturating_add(1);
            self.gap_since = None;
        }
        out
    }
}

#[derive(Default)]
pub struct Recovery {
    conversations: HashMap<(u64, u32), Conversation>,
}

impl Recovery {
    pub fn push(&mut self, bytes: &[u8], now: Instant) -> Vec<Frame> {
        let Some(p) = udp(bytes) else {
            return Vec::new();
        };
        let data = p.payload;
        if data.len() < 8 {
            return Vec::new();
        }
        self.conversations
            .retain(|_, c| now.saturating_duration_since(c.last_seen) < IDLE_EXPIRY);
        let control = data.len() == 20;
        if control && u32::from_be_bytes(data[..4].try_into().unwrap()) != 0x145 {
            return Vec::new();
        }
        let conv = if control {
            u32::from_be_bytes(data[4..8].try_into().unwrap())
        } else {
            u32::from_le_bytes(data[..4].try_into().unwrap())
        };
        if !self.conversations.contains_key(&(p.source, conv)) && self.conversations.len() >= MAX_FLOWS {
            return Vec::new();
        }
        let c = self.conversations.entry((p.source, conv)).or_insert_with(|| Conversation {
            source: p.source,
            src: p.src,
            dst: p.dst,
            segments: BTreeMap::new(),
            original_next: 0,
            synthetic_next: 0,
            handshake: false,
            gap_since: None,
            last_seen: now,
        });
        c.last_seen = now;
        if control {
            if c.handshake || c.synthetic_next > 0 {
                return Vec::new();
            }
            c.handshake = true;
            return vec![Frame {
                source: c.source,
                data: ethernet(p.src, p.dst, data),
            }];
        }
        let mut offset = 0;
        while offset + 28 <= data.len() {
            let segment = &data[offset..];
            let len = u32::from_le_bytes(segment[24..28].try_into().unwrap()) as usize;
            let Some(end) = offset
                .checked_add(28)
                .and_then(|n| n.checked_add(len))
                .filter(|end| *end <= data.len())
            else {
                break;
            };
            if segment[8] == 81 && u32::from_le_bytes(segment[..4].try_into().unwrap()) == conv {
                let sn = u32::from_le_bytes(segment[16..20].try_into().unwrap());
                if sn >= c.original_next && c.segments.len() < MAX_SEGMENTS {
                    c.segments.entry(sn).or_insert_with(|| data[offset..end].to_vec());
                }
            }
            offset = end;
        }
        c.drain(now, false)
    }

    pub fn flush(&mut self, now: Instant, force: bool) -> Vec<Frame> {
        self.conversations.values_mut().flat_map(|c| c.drain(now, force)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn segment(sn: u32, frg: u8) -> Vec<u8> {
        let mut s = vec![0; 29];
        s[..4].copy_from_slice(&7u32.to_le_bytes());
        s[8] = 81;
        s[9] = frg;
        s[16..20].copy_from_slice(&sn.to_le_bytes());
        s[24..28].copy_from_slice(&1u32.to_le_bytes());
        s[28] = sn as u8;
        s
    }
    #[test]
    fn pppoe_ipv6_server_reply_and_truncated_frames() {
        let mut f = vec![0; 14 + 8 + 40 + 8 + 20];
        f[12..14].copy_from_slice(&0x8864u16.to_be_bytes());
        f[14] = 0x11;
        f[18..20].copy_from_slice(&70u16.to_be_bytes());
        f[20..22].copy_from_slice(&0x57u16.to_be_bytes());
        f[22] = 0x60;
        f[26..28].copy_from_slice(&28u16.to_be_bytes());
        f[28] = 17;
        f[62..64].copy_from_slice(&23301u16.to_be_bytes());
        f[64..66].copy_from_slice(&50000u16.to_be_bytes());
        f[66..68].copy_from_slice(&28u16.to_be_bytes());
        assert_eq!(udp(&f).unwrap().payload.len(), 20);
        for n in 0..f.len() {
            assert!(udp(&f[..n]).is_none());
        }
    }
    #[test]
    fn reordered_fragments_and_duplicate_components_deliver_once() {
        let mut r = Recovery::default();
        let t = Instant::now();
        assert!(r.push(&ethernet(23301, 50000, &segment(1, 0)), t).is_empty());
        let out = r.push(&ethernet(23301, 50000, &segment(0, 1)), t);
        assert_eq!(out.len(), 2);
        assert!(r.push(&ethernet(23301, 50000, &segment(1, 0)), t).is_empty());
    }
    #[test]
    fn missing_message_recovers_after_grace_and_keeps_sequence_contiguous() {
        let mut r = Recovery::default();
        let t = Instant::now();
        assert_eq!(r.push(&ethernet(23301, 50000, &segment(0, 0)), t).len(), 1);
        assert!(r.push(&ethernet(23301, 50000, &segment(2, 1)), t).is_empty());
        assert!(r.push(&ethernet(23301, 50000, &segment(4, 0)), t).is_empty());
        let out = r.flush(t + GAP_GRACE, false);
        assert_eq!(out.len(), 1);
        assert_eq!(u32::from_le_bytes(out[0].data[58..62].try_into().unwrap()), 1);
    }
    #[test]
    fn capture_started_mid_connection_waits_for_a_fresh_login() {
        let mut r = Recovery::default();
        let t = Instant::now();
        assert!(r.push(&ethernet(23301, 50000, &segment(10, 0)), t).is_empty());
        assert!(r.flush(t + GAP_GRACE, true).is_empty());
    }
}
