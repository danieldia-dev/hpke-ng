# Changelog

## [0.1.0-rc.3] - 2026-05-09

- Performance: cache the recipient's serialized public key in `DhPrivateKey<D>` so DH `decap`/`auth_decap` skip the per-call base-point scalar multiplication (X25519 decap −41%, P-curve decap proportionally larger).
- Performance: cache the expanded `x_wing::DecapsulationKey` in `XWingPrivateKey` (X-Wing decap −38% — same trick as ML-KEM, previously missed for X-Wing).
- Performance: cache the parsed `EncapsulationKey` in PQ public-key wrappers (ML-KEM encap −30% to −37%, X-Wing encap −14%).
- Performance: `Aead` trait now exposes a cached `Cipher` associated type built once via `Aead::init` at key schedule time; AES-GCM `Context::seal` skips the per-call key schedule + GHash precompute. Sealed trait — no external impact.
- Performance: `Kdf::extract` / `expand` accept piecewise slices (`&[&[u8]]`) to avoid materialising labeled-IKM/info `Vec`s. Sealed trait — no external impact.
- Across 62 head-to-head benchmarks vs `hpke-rs`, hpke-ng now wins 43 (was 27), ties 14, loses 5 — losses are all on `derive_key_pair`/`generate` paths the one-time cost paid for the per-call decap/encap savings.

## [0.1.0-rc.2] - 2026-05-08

- Expose `sk_to_bytes` which serializes a private key to bytes (zeroized on drop).

## [0.1.0-rc.1] - 2026-05-08

- First release candidate.
