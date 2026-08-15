//! Frame and datagram codecs for Pulse wire v2.

pub const MAX_FULL_TX_BODY: usize = 1 << 16; // 64 KiB cap

/// Wire protocol version carried by the stream preamble.
pub const WIRE_VERSION: u8 = crate::protocol::WIRE_VERSION as u8;

/// Written once at the head of every full-tx unidirectional stream, before any
/// frame. `b"PLS2"` then version then a reserved flags byte.
///
/// This exists because a per-frame version byte cannot work: byte 0 of a v1
/// body is `slot.to_le_bytes()[0]`, which takes all 256 values roughly every
/// 100 seconds. A v1 stream's first byte, by contrast, is always `0x00` — the
/// high byte of a u32 big-endian length prefix on a frame capped at 64 KiB —
/// so a non-zero magic is unambiguous.
pub const PREAMBLE: &[u8; 6] = b"PLS2\x02\x00";

// ---- frame message types ---------------------------------------------------

pub const MSG_TX: u8 = 1;
pub const MSG_HEARTBEAT: u8 = 2;
/// Wire v2 assigns this message type to shed notices but does not emit them.
pub const MSG_SHED: u8 = 3;

// ---- frame flags (per-frame booleans, NOT a TLV presence bitmap) ------------

/// The ALT address set on this frame may be incomplete.
pub const FLAG_ALT_INCOMPLETE: u8 = 0x01;

// ---- TLV types -------------------------------------------------------------

pub const TLV_LOADED_WRITABLE: u8 = 1;
pub const TLV_LOADED_READONLY: u8 = 2;
pub const TLV_SERVER_TS_MS: u8 = 3;
pub const TLV_HIGHEST_SEQ: u8 = 4;

#[derive(Debug, PartialEq, Eq)]
pub struct FrameError;

/// Appends one `u8 type | u16 LE len | value` record.
///
/// `len` is `u16` because a loaded-address list is 32 bytes per address and
/// ALT-heavy transactions load dozens; a `u8` length would cap at 7.
pub fn put_tlv(buf: &mut Vec<u8>, t: u8, value: &[u8]) {
    debug_assert!(value.len() <= u16::MAX as usize);
    buf.push(t);
    buf.extend_from_slice(&(value.len() as u16).to_le_bytes());
    buf.extend_from_slice(value);
}

/// Parses a TLV trailer to the end of `src`.
///
/// Unknown types are returned to the caller rather than rejected — skipping
/// them is what makes new fields additive. A duplicate type IS rejected:
/// silently preferring first or last is the kind of ambiguity that produces two
/// implementations which disagree.
pub fn parse_tlvs(src: &[u8]) -> Result<Vec<(u8, &[u8])>, FrameError> {
    let mut out: Vec<(u8, &[u8])> = Vec::new();
    let mut off = 0usize;
    while off < src.len() {
        let t = *src.get(off).ok_or(FrameError)?;
        let lo = *src.get(off + 1).ok_or(FrameError)?;
        let hi = *src.get(off + 2).ok_or(FrameError)?;
        let len = u16::from_le_bytes([lo, hi]) as usize;
        let start = off.checked_add(3).ok_or(FrameError)?;
        let end = start.checked_add(len).ok_or(FrameError)?;
        let value = src.get(start..end).ok_or(FrameError)?;
        if out.iter().any(|(seen, _)| *seen == t) {
            return Err(FrameError);
        }
        out.push((t, value));
        off = end;
    }
    Ok(out)
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FullInstruction {
    pub program_id_index: u32,
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FullAtl {
    pub account_key: [u8; 32],
    pub writable_indexes: Vec<u8>,
    pub readonly_indexes: Vec<u8>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FullTx {
    pub slot: u64,
    pub versioned: bool,
    pub num_required_signatures: u32,
    pub num_readonly_signed_accounts: u32,
    pub num_readonly_unsigned_accounts: u32,
    pub recent_blockhash: [u8; 32],
    pub signatures: Vec<[u8; 64]>,
    pub account_keys: Vec<[u8; 32]>,
    pub instructions: Vec<FullInstruction>,
    pub address_table_lookups: Vec<FullAtl>,
}

/// Encodes a FullTx into the length-delimited binary body (the reliable-stream
/// writer prepends a u32 length).
pub fn encode_full_tx(ft: &FullTx) -> Vec<u8> {
    let mut b = Vec::with_capacity(256);
    b.extend_from_slice(&ft.slot.to_le_bytes());
    b.push(ft.num_required_signatures as u8);
    b.push(ft.num_readonly_signed_accounts as u8);
    b.push(ft.num_readonly_unsigned_accounts as u8);
    b.push(ft.versioned as u8);
    b.extend_from_slice(&ft.recent_blockhash);

    put_u16(&mut b, ft.signatures.len());
    for s in &ft.signatures {
        b.extend_from_slice(s);
    }
    put_u16(&mut b, ft.account_keys.len());
    for k in &ft.account_keys {
        b.extend_from_slice(k);
    }
    put_u16(&mut b, ft.instructions.len());
    for ix in &ft.instructions {
        b.push(ix.program_id_index as u8);
        put_u16(&mut b, ix.accounts.len());
        b.extend_from_slice(&ix.accounts);
        put_u16(&mut b, ix.data.len());
        b.extend_from_slice(&ix.data);
    }
    put_u16(&mut b, ft.address_table_lookups.len());
    for l in &ft.address_table_lookups {
        b.extend_from_slice(&l.account_key);
        put_u16(&mut b, l.writable_indexes.len());
        b.extend_from_slice(&l.writable_indexes);
        put_u16(&mut b, l.readonly_indexes.len());
        b.extend_from_slice(&l.readonly_indexes);
    }
    b
}

/// Decodes a FullTx. Strict: bounds-checked, rejects oversized bodies and any
/// truncation or trailing garbage; never panics on malformed input.
pub fn decode_full_tx(src: &[u8]) -> Result<FullTx, FrameError> {
    let (ft, consumed) = decode_full_tx_prefix(src)?;
    if consumed != src.len() {
        return Err(FrameError); // exact consumption
    }
    Ok(ft)
}

/// Decodes a FullTx body from the front of `src` and returns the cursor offset
/// just past it, without requiring `src` to be fully consumed. This lets a v2
/// frame decode the v1 body and then read whatever follows as a TLV trailer.
///
/// `decode_full_tx` wraps this and enforces exact consumption for the plain
/// v1 case.
pub fn decode_full_tx_prefix(src: &[u8]) -> Result<(FullTx, usize), FrameError> {
    if src.len() > MAX_FULL_TX_BODY {
        return Err(FrameError);
    }
    let mut d = Decoder { b: src, off: 0 };
    let mut ft = FullTx {
        slot: d.u64()?,
        num_required_signatures: d.u8()? as u32,
        num_readonly_signed_accounts: d.u8()? as u32,
        num_readonly_unsigned_accounts: d.u8()? as u32,
        versioned: d.u8()? != 0,
        ..Default::default()
    };
    ft.recent_blockhash.copy_from_slice(d.take(32)?);

    let n = d.count(64)?;
    ft.signatures.reserve(n);
    for _ in 0..n {
        let mut s = [0u8; 64];
        s.copy_from_slice(d.take(64)?);
        ft.signatures.push(s);
    }
    let n = d.count(32)?;
    ft.account_keys.reserve(n);
    for _ in 0..n {
        let mut k = [0u8; 32];
        k.copy_from_slice(d.take(32)?);
        ft.account_keys.push(k);
    }
    let n = d.count(5)?; // min instruction = progIdx(1)+accLen(2)+dataLen(2)
    ft.instructions.reserve(n);
    for _ in 0..n {
        let program_id_index = d.u8()? as u32;
        let alen = d.u16()?;
        let accounts = d.take(alen)?.to_vec();
        let dlen = d.u16()?;
        let data = d.take(dlen)?.to_vec();
        ft.instructions.push(FullInstruction {
            program_id_index,
            accounts,
            data,
        });
    }
    let n = d.count(36)?; // min ATL = key(32)+wLen(2)+rLen(2)
    ft.address_table_lookups.reserve(n);
    for _ in 0..n {
        let mut account_key = [0u8; 32];
        account_key.copy_from_slice(d.take(32)?);
        let wlen = d.u16()?;
        let writable_indexes = d.take(wlen)?.to_vec();
        let rlen = d.u16()?;
        let readonly_indexes = d.take(rlen)?.to_vec();
        ft.address_table_lookups.push(FullAtl {
            account_key,
            writable_indexes,
            readonly_indexes,
        });
    }
    Ok((ft, d.off))
}

/// A decoded v2 transaction frame: the v1 body plus its v2 additions.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FullTxV2 {
    pub tx: FullTx,
    pub alt_incomplete: bool,
    pub loaded_writable: Vec<[u8; 32]>,
    pub loaded_readonly: Vec<[u8; 32]>,
}

/// A decoded v2 frame. `Unknown` carries the message type so a client can skip
/// it deliberately rather than erroring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Tx(FullTxV2),
    Heartbeat { server_ts_ms: u64, highest_seq: u64 },
    Unknown(u8),
}

fn flatten32(addrs: &[[u8; 32]]) -> Vec<u8> {
    let mut v = Vec::with_capacity(addrs.len() * 32);
    for a in addrs {
        v.extend_from_slice(a);
    }
    v
}

fn unflatten32(src: &[u8]) -> Result<Vec<[u8; 32]>, FrameError> {
    if src.len() % 32 != 0 {
        return Err(FrameError);
    }
    let mut out = Vec::with_capacity(src.len() / 32);
    for c in src.chunks_exact(32) {
        out.push(<[u8; 32]>::try_from(c).map_err(|_| FrameError)?);
    }
    Ok(out)
}

/// Encodes a v2 transaction frame: `msg_type | flags | v1 body | TLV trailer`.
///
/// The v1 body is reused byte-for-byte; only the framing around it is new.
/// Pass empty slices for a non-enriched subscriber — the trailer is then empty
/// and the frame costs two bytes more than v1.
pub fn encode_frame_tx(
    ft: &FullTx,
    alt_incomplete: bool,
    loaded_writable: &[[u8; 32]],
    loaded_readonly: &[[u8; 32]],
) -> Vec<u8> {
    let body = encode_full_tx(ft);
    let mut b = Vec::with_capacity(body.len() + 2 + 64);
    b.push(MSG_TX);
    b.push(if alt_incomplete {
        FLAG_ALT_INCOMPLETE
    } else {
        0
    });
    b.extend_from_slice(&body);
    if !loaded_writable.is_empty() {
        put_tlv(&mut b, TLV_LOADED_WRITABLE, &flatten32(loaded_writable));
    }
    if !loaded_readonly.is_empty() {
        put_tlv(&mut b, TLV_LOADED_READONLY, &flatten32(loaded_readonly));
    }
    b
}

/// Decodes one v2 frame (the caller has already stripped the u32 BE length
/// prefix). Bounds-checked; never panics.
pub fn decode_frame(src: &[u8]) -> Result<Frame, FrameError> {
    let msg_type = *src.first().ok_or(FrameError)?;
    let flags = *src.get(1).ok_or(FrameError)?;
    let rest = src.get(2..).ok_or(FrameError)?;

    match msg_type {
        MSG_TX => {
            if flags & !FLAG_ALT_INCOMPLETE != 0 {
                return Err(FrameError); // reserved bits must be zero
            }
            // The v1 body is self-delimiting: decode it, then treat whatever
            // follows as the TLV trailer.
            let (tx, consumed) = decode_full_tx_prefix(rest)?;
            let tlvs = parse_tlvs(rest.get(consumed..).ok_or(FrameError)?)?;
            let mut v2 = FullTxV2 {
                tx,
                alt_incomplete: flags & FLAG_ALT_INCOMPLETE != 0,
                loaded_writable: Vec::new(),
                loaded_readonly: Vec::new(),
            };
            for (t, value) in tlvs {
                match t {
                    TLV_LOADED_WRITABLE => v2.loaded_writable = unflatten32(value)?,
                    TLV_LOADED_READONLY => v2.loaded_readonly = unflatten32(value)?,
                    _ => {} // unknown TLV: skip, do not error
                }
            }
            Ok(Frame::Tx(v2))
        }
        MSG_HEARTBEAT => {
            // alt_incomplete (bit 0) is a tx-frame-only concept, so unlike
            // MSG_TX there is no bit this message type defines: all 8 bits
            // are reserved here and MUST be zero. Do not reuse the MSG_TX
            // `!FLAG_ALT_INCOMPLETE` mask — that would silently accept bit 0
            // on a frame kind where it has no meaning.
            if flags != 0 {
                return Err(FrameError);
            }
            let tlvs = parse_tlvs(rest)?;
            let mut server_ts_ms = 0u64;
            let mut highest_seq = 0u64;
            for (t, value) in tlvs {
                match t {
                    TLV_SERVER_TS_MS => {
                        server_ts_ms =
                            u64::from_le_bytes(<[u8; 8]>::try_from(value).map_err(|_| FrameError)?)
                    }
                    TLV_HIGHEST_SEQ => {
                        highest_seq =
                            u64::from_le_bytes(<[u8; 8]>::try_from(value).map_err(|_| FrameError)?)
                    }
                    _ => {}
                }
            }
            Ok(Frame::Heartbeat {
                server_ts_ms,
                highest_seq,
            })
        }
        other => Ok(Frame::Unknown(other)),
    }
}

// ---- typed datagrams -------------------------------------------------------

pub const DG_SIG_FIRST: u8 = 1;
pub const DG_HEARTBEAT: u8 = 2;

/// `u8 type | u64 slot | u64 seq | 64B signature`
pub const DG_SIG_FIRST_MIN: usize = 1 + 8 + 8 + 64;
/// `u8 type | u64 server_ts_ms | u64 highest_seq`
pub const DG_HEARTBEAT_MIN: usize = 1 + 8 + 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Datagram {
    SigFirst {
        slot: u64,
        seq: u64,
        signature: [u8; 64],
    },
    Heartbeat {
        server_ts_ms: u64,
        highest_seq: u64,
    },
    Unknown(u8),
}

pub fn encode_dg_sig_first(buf: &mut [u8; DG_SIG_FIRST_MIN], slot: u64, seq: u64, sig: &[u8; 64]) {
    buf[0] = DG_SIG_FIRST;
    buf[1..9].copy_from_slice(&slot.to_le_bytes());
    buf[9..17].copy_from_slice(&seq.to_le_bytes());
    buf[17..81].copy_from_slice(sig);
}

pub fn encode_dg_heartbeat(buf: &mut [u8; DG_HEARTBEAT_MIN], server_ts_ms: u64, highest_seq: u64) {
    buf[0] = DG_HEARTBEAT;
    buf[1..9].copy_from_slice(&server_ts_ms.to_le_bytes());
    buf[9..17].copy_from_slice(&highest_seq.to_le_bytes());
}

/// Decodes a datagram by its type tag.
///
/// **Each type declares a MINIMUM length, not an exact one.** A known type that
/// is long enough parses, and trailing bytes are ignored — that is what lets a
/// later version add a field without breaking this decoder. An unknown type is
/// reported so the caller can skip it deliberately.
pub fn decode_datagram(src: &[u8]) -> Option<Datagram> {
    match *src.first()? {
        DG_SIG_FIRST if src.len() >= DG_SIG_FIRST_MIN => Some(Datagram::SigFirst {
            slot: u64::from_le_bytes(src.get(1..9)?.try_into().ok()?),
            seq: u64::from_le_bytes(src.get(9..17)?.try_into().ok()?),
            signature: src.get(17..81)?.try_into().ok()?,
        }),
        DG_HEARTBEAT if src.len() >= DG_HEARTBEAT_MIN => Some(Datagram::Heartbeat {
            server_ts_ms: u64::from_le_bytes(src.get(1..9)?.try_into().ok()?),
            highest_seq: u64::from_le_bytes(src.get(9..17)?.try_into().ok()?),
        }),
        DG_SIG_FIRST | DG_HEARTBEAT => None, // known type, too short
        other => Some(Datagram::Unknown(other)),
    }
}

fn put_u16(b: &mut Vec<u8>, n: usize) {
    b.extend_from_slice(&(n as u16).to_le_bytes());
}

struct Decoder<'a> {
    b: &'a [u8],
    off: usize,
}

impl<'a> Decoder<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], FrameError> {
        let end = self.off.checked_add(n).ok_or(FrameError)?;
        if end > self.b.len() {
            return Err(FrameError);
        }
        let s = &self.b[self.off..end];
        self.off = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, FrameError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<usize, FrameError> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]) as usize)
    }
    fn u64(&mut self) -> Result<u64, FrameError> {
        let s = self.take(8)?;
        Ok(u64::from_le_bytes(s.try_into().unwrap()))
    }
    /// Reads a u16 count and rejects it before allocating if that many elements
    /// of at least `min_elem` bytes cannot fit in the remaining frame.
    fn count(&mut self, min_elem: usize) -> Result<usize, FrameError> {
        let n = self.u16()?;
        if min_elem == 0 || n > (self.b.len() - self.off) / min_elem {
            return Err(FrameError);
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(versioned: bool) -> FullTx {
        FullTx {
            slot: 7,
            versioned,
            num_required_signatures: 1,
            recent_blockhash: [0xCC; 32],
            signatures: vec![[7u8; 64]],
            account_keys: vec![[0xA1; 32]],
            instructions: vec![FullInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: vec![0xDE, 0xAD, 0xBE],
            }],
            address_table_lookups: if versioned {
                vec![FullAtl {
                    account_key: [0xEE; 32],
                    writable_indexes: vec![5],
                    readonly_indexes: vec![7],
                }]
            } else {
                vec![]
            },
            ..Default::default()
        }
    }

    #[test]
    fn full_tx_round_trip_legacy_and_v0() {
        for versioned in [false, true] {
            let ft = sample(versioned);
            let body = encode_full_tx(&ft);
            let got = decode_full_tx(&body).unwrap();
            assert_eq!(got, ft);
        }
    }

    #[test]
    fn full_tx_rejects_truncated() {
        let body = encode_full_tx(&sample(true));
        assert_eq!(decode_full_tx(&body[..body.len() - 3]), Err(FrameError));
    }

    #[test]
    fn preamble_is_six_bytes_and_starts_nonzero() {
        // A v1 stream's first byte is ALWAYS 0x00 (u32 BE length prefix, frames
        // <= 64 KiB), so a non-zero first byte is what makes the preamble
        // unambiguous. Guard that property.
        assert_eq!(PREAMBLE.len(), 6);
        assert_ne!(PREAMBLE[0], 0x00);
        assert_eq!(&PREAMBLE[0..4], b"PLS2");
        assert_eq!(PREAMBLE[4], WIRE_VERSION);
        assert_eq!(PREAMBLE[5], 0);
    }

    #[test]
    fn tlv_round_trips_in_order() {
        let mut b = Vec::new();
        put_tlv(&mut b, TLV_LOADED_WRITABLE, &[1u8; 64]);
        put_tlv(&mut b, TLV_LOADED_READONLY, &[2u8; 32]);
        let got = parse_tlvs(&b).expect("valid");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, TLV_LOADED_WRITABLE);
        assert_eq!(got[0].1, &[1u8; 64][..]);
        assert_eq!(got[1].0, TLV_LOADED_READONLY);
        assert_eq!(got[1].1, &[2u8; 32][..]);
    }

    #[test]
    fn tlv_length_is_u16_so_a_large_value_fits() {
        // 100 addresses x 32 bytes = 3200 — impossible with a u8 length.
        let big = vec![7u8; 3200];
        let mut b = Vec::new();
        put_tlv(&mut b, TLV_LOADED_WRITABLE, &big);
        let got = parse_tlvs(&b).expect("valid");
        assert_eq!(got[0].1.len(), 3200);
    }

    #[test]
    fn tlv_unknown_type_is_kept_for_the_caller_to_skip() {
        let mut b = Vec::new();
        put_tlv(&mut b, 200, &[9u8; 4]);
        let got = parse_tlvs(&b).expect("unknown types parse fine");
        assert_eq!(got[0].0, 200);
    }

    #[test]
    fn tlv_duplicate_type_is_rejected() {
        let mut b = Vec::new();
        put_tlv(&mut b, TLV_LOADED_WRITABLE, &[1u8; 32]);
        put_tlv(&mut b, TLV_LOADED_WRITABLE, &[2u8; 32]);
        assert_eq!(parse_tlvs(&b), Err(FrameError));
    }

    #[test]
    fn tlv_truncated_is_rejected() {
        let mut b = Vec::new();
        put_tlv(&mut b, TLV_LOADED_WRITABLE, &[1u8; 32]);
        for cut in 1..b.len() {
            assert_eq!(parse_tlvs(&b[..cut]), Err(FrameError), "cut={cut}");
        }
        assert_eq!(parse_tlvs(&[]), Ok(Vec::new()));
    }

    #[test]
    fn tlv_length_overrunning_the_buffer_is_rejected() {
        // type=1, len=0xFFFF, but no payload
        let b = vec![1u8, 0xFF, 0xFF];
        assert_eq!(parse_tlvs(&b), Err(FrameError));
    }

    fn sample_fulltx() -> FullTx {
        FullTx {
            slot: 438_690_000,
            versioned: true,
            num_required_signatures: 1,
            num_readonly_signed_accounts: 0,
            num_readonly_unsigned_accounts: 1,
            recent_blockhash: [0xCC; 32],
            signatures: vec![[7u8; 64]],
            account_keys: vec![[0xA1; 32], [0xB2; 32]],
            instructions: vec![FullInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: vec![9, 9],
            }],
            address_table_lookups: vec![FullAtl {
                account_key: [0xEE; 32],
                writable_indexes: vec![0],
                readonly_indexes: vec![1],
            }],
        }
    }

    #[test]
    fn v2_tx_frame_round_trips_bare() {
        let tx = sample_fulltx();
        let enc = encode_frame_tx(&tx, false, &[], &[]);
        assert_eq!(enc[0], MSG_TX);
        assert_eq!(enc[1], 0, "no flags set");
        match decode_frame(&enc).expect("valid") {
            Frame::Tx(v2) => {
                assert_eq!(v2.tx, tx);
                assert!(!v2.alt_incomplete);
                assert!(v2.loaded_writable.is_empty());
                assert!(v2.loaded_readonly.is_empty());
            }
            other => panic!("expected Tx, got {other:?}"),
        }
    }

    #[test]
    fn v2_tx_frame_round_trips_enriched() {
        let tx = sample_fulltx();
        let w = [[0x11u8; 32], [0x22u8; 32]];
        let r = [[0x33u8; 32]];
        let enc = encode_frame_tx(&tx, true, &w, &r);
        assert_eq!(enc[1] & FLAG_ALT_INCOMPLETE, FLAG_ALT_INCOMPLETE);
        match decode_frame(&enc).expect("valid") {
            Frame::Tx(v2) => {
                assert!(v2.alt_incomplete);
                assert_eq!(v2.loaded_writable, w.to_vec());
                assert_eq!(v2.loaded_readonly, r.to_vec());
            }
            other => panic!("expected Tx, got {other:?}"),
        }
    }

    #[test]
    fn v2_body_is_byte_identical_to_v1_encoding() {
        // The v1 positional body is reused unchanged; only the framing is new.
        let tx = sample_fulltx();
        let v1 = encode_full_tx(&tx);
        let v2 = encode_frame_tx(&tx, false, &[], &[]);
        assert_eq!(&v2[2..2 + v1.len()], &v1[..]);
    }

    #[test]
    fn unknown_msg_type_is_reported_not_rejected() {
        let mut enc = encode_frame_tx(&sample_fulltx(), false, &[], &[]);
        enc[0] = 99;
        match decode_frame(&enc).expect("unknown type must not error") {
            Frame::Unknown(99) => {}
            other => panic!("expected Unknown(99), got {other:?}"),
        }
    }

    #[test]
    fn reserved_flag_bits_are_rejected() {
        let mut enc = encode_frame_tx(&sample_fulltx(), false, &[], &[]);
        enc[1] = 0x02; // bit 1 reserved
        assert_eq!(decode_frame(&enc), Err(FrameError));
    }

    #[test]
    fn loaded_address_tlv_with_a_non_multiple_of_32_is_rejected() {
        let mut enc = Vec::new();
        enc.push(MSG_TX);
        enc.push(0);
        enc.extend_from_slice(&encode_full_tx(&sample_fulltx()));
        put_tlv(&mut enc, TLV_LOADED_WRITABLE, &[0u8; 33]);
        assert_eq!(decode_frame(&enc), Err(FrameError));
    }

    #[test]
    fn heartbeat_frame_round_trips() {
        let mut enc = Vec::new();
        enc.push(MSG_HEARTBEAT);
        enc.push(0);
        put_tlv(
            &mut enc,
            TLV_SERVER_TS_MS,
            &1_700_000_000_123u64.to_le_bytes(),
        );
        put_tlv(&mut enc, TLV_HIGHEST_SEQ, &4242u64.to_le_bytes());
        match decode_frame(&enc).expect("valid") {
            Frame::Heartbeat {
                server_ts_ms,
                highest_seq,
            } => {
                assert_eq!(server_ts_ms, 1_700_000_000_123);
                assert_eq!(highest_seq, 4242);
            }
            other => panic!("expected Heartbeat, got {other:?}"),
        }
    }

    #[test]
    fn heartbeat_frame_rejects_any_nonzero_flags() {
        // Unlike MSG_TX, alt_incomplete (bit 0) has no meaning on a heartbeat,
        // so every bit is reserved for this message type — not just bits 1-7.
        for flags in [FLAG_ALT_INCOMPLETE, 0x02, 0xFF] {
            let mut enc = Vec::new();
            enc.push(MSG_HEARTBEAT);
            enc.push(flags);
            put_tlv(&mut enc, TLV_SERVER_TS_MS, &1u64.to_le_bytes());
            assert_eq!(decode_frame(&enc), Err(FrameError), "flags={flags:#x}");
        }
    }

    #[test]
    fn frame_too_short_is_rejected() {
        assert_eq!(decode_frame(&[]), Err(FrameError));
        assert_eq!(decode_frame(&[MSG_TX]), Err(FrameError));
    }

    #[test]
    fn dg_sig_first_round_trips() {
        let mut buf = [0u8; DG_SIG_FIRST_MIN];
        encode_dg_sig_first(&mut buf, 438_690_000, 12345, &[9u8; 64]);
        assert_eq!(buf[0], DG_SIG_FIRST);
        match decode_datagram(&buf).expect("valid") {
            Datagram::SigFirst {
                slot,
                seq,
                signature,
            } => {
                assert_eq!(slot, 438_690_000);
                assert_eq!(seq, 12345);
                assert_eq!(signature, [9u8; 64]);
            }
            other => panic!("expected SigFirst, got {other:?}"),
        }
    }

    #[test]
    fn dg_heartbeat_round_trips() {
        let mut buf = [0u8; DG_HEARTBEAT_MIN];
        encode_dg_heartbeat(&mut buf, 1_700_000_000_123, 999);
        match decode_datagram(&buf).expect("valid") {
            Datagram::Heartbeat {
                server_ts_ms,
                highest_seq,
            } => {
                assert_eq!(server_ts_ms, 1_700_000_000_123);
                assert_eq!(highest_seq, 999);
            }
            other => panic!("expected Heartbeat, got {other:?}"),
        }
    }

    #[test]
    fn dg_minimum_length_not_exact_length() {
        // THE forward-compatibility rule: a longer datagram of a known type
        // must parse, ignoring the trailing bytes. Without this, v2 re-freezes
        // the format exactly as v1 did and the next field is another break.
        let mut buf = [0u8; DG_SIG_FIRST_MIN];
        encode_dg_sig_first(&mut buf, 7, 8, &[3u8; 64]);
        let mut longer = buf.to_vec();
        longer.extend_from_slice(&[0xAB; 16]);
        match decode_datagram(&longer).expect("trailing bytes must be ignored") {
            Datagram::SigFirst { slot, seq, .. } => {
                assert_eq!(slot, 7);
                assert_eq!(seq, 8);
            }
            other => panic!("expected SigFirst, got {other:?}"),
        }
    }

    #[test]
    fn dg_below_minimum_is_rejected() {
        let mut buf = [0u8; DG_SIG_FIRST_MIN];
        encode_dg_sig_first(&mut buf, 1, 2, &[0u8; 64]);
        assert!(decode_datagram(&buf[..DG_SIG_FIRST_MIN - 1]).is_none());
        let mut hb = [0u8; DG_HEARTBEAT_MIN];
        encode_dg_heartbeat(&mut hb, 1, 2);
        assert!(decode_datagram(&hb[..DG_HEARTBEAT_MIN - 1]).is_none());
        assert!(decode_datagram(&[]).is_none());
    }

    #[test]
    fn dg_unknown_type_is_reported_not_rejected() {
        let buf = [200u8, 1, 2, 3];
        match decode_datagram(&buf).expect("unknown type must not be an error") {
            Datagram::Unknown(200) => {}
            other => panic!("expected Unknown(200), got {other:?}"),
        }
    }

    #[test]
    fn a_v1_72_byte_datagram_is_rejected_by_the_length_rule() {
        // v1 datagrams began with the low byte of the slot, so their first byte
        // can be 1 — colliding with DG_SIG_FIRST. The length rule is what
        // separates them: 72 < DG_SIG_FIRST_MIN (81), so a known type that is
        // too short returns None rather than a garbage decode.
        let v1 = [1u8; 72];
        assert_eq!(decode_datagram(&v1), None);
    }
}
