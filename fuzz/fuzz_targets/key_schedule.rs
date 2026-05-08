//! Fuzz `key_schedule` with arbitrary mode bytes, shared secrets, info, and
//! PSK material. The function must validate inputs and either succeed or
//! return `Err`; panics are bugs.

#![no_main]

use libfuzzer_sys::fuzz_target;

use hpke_ng::{ChaCha20Poly1305, DhKemX25519HkdfSha256, HkdfSha256, __test_only::key_schedule};

/// Consume a length-prefixed slice from the front of `rest`. The first byte is
/// the length (clamped to the remaining buffer); the next `len` bytes are the
/// payload. If `rest` is empty, returns an empty slice.
fn take_lp<'a>(rest: &mut &'a [u8]) -> &'a [u8] {
    if rest.is_empty() {
        return &[];
    }
    let len = (rest[0] as usize).min(rest.len() - 1);
    let (out, tail) = rest[1..].split_at(len);
    *rest = tail;
    out
}

fuzz_target!(|data: &[u8]| {
    // Layout: mode(1) || shared_secret(32) || lp(info) || lp(psk) || lp(psk_id)
    if data.len() < 1 + 32 {
        return;
    }
    let mode = data[0];
    let shared_secret = &data[1..33];
    let mut rest = &data[33..];
    let info = take_lp(&mut rest);
    let psk = take_lp(&mut rest);
    let psk_id = take_lp(&mut rest);

    let _ = key_schedule::<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>(
        mode,
        shared_secret,
        info,
        psk,
        psk_id,
    );
});
