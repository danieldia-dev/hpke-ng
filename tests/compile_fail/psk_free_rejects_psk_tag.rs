use hpke_ng::*;

// `key_schedule_psk_free` requires M: PskFreeMode.
// PskModeTag implements PskMode, not PskFreeMode. Must fail compilation.
fn main() {
	let _ = hpke_ng::__test_only::key_schedule_psk_free::<
		PskModeTag,
		DhKemX25519HkdfSha256,
		HkdfSha256,
		ChaCha20Poly1305,
	>(&[0u8; 32], b"info");
}
