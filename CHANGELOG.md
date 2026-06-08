# Changelog

## [0.1.0]

### Security & correctness

- **Breaking: `Context` is split into one-directional `SenderContext` and `ReceiverContext`.** `setup_sender_*` now returns `SenderContext` (exposes `seal` + `export`); `setup_receiver_*` returns `ReceiverContext` (exposes `open` + `export`). Neither implements `Clone`. A sender and the matching receiver derive the identical `(key, base_nonce)`, so a single type that could both seal and open made using one session in both directions a catastrophic AEAD `(key, nonce)` reuse — the split turns that misuse into a compile error. For a bidirectional channel, run a separate HPKE setup per direction or derive independent per-direction keys via `export` (RFC 9180 §9.8).
- New `HpkeError::InvalidKeyMaterial` variant. ML-KEM-768/1024 `derive_key_pair` requires exactly 64 bytes of `(d, z)` seed (draft-connolly-cfrg-hpke-mlkem §3.2); any other IKM length now returns `InvalidKeyMaterial` rather than a less specific error.
- Internal hardening: the key schedule is split into PSK-free (Base/Auth) and PSK-bearing (PSK/AuthPSK) fast paths selected by sealed `PskFreeMode` / `PskMode` marker tags instead of a raw `u8` mode byte. Routing a PSK mode through the PSK-free path (or vice versa) is now a compile error. The tags are `#[doc(hidden)]` and not part of the public API.

### Performance

- Auth encap/decap no longer heap-allocate the concatenated DH inputs. A piecewise `extract_and_expand_pieces` feeds `dh1`/`dh2` and the KEM context directly into HKDF-Extract/Expand, removing the per-call `Vec` build-and-copy across all four auth paths. `base_nonce` is now stack-allocated and the hot-path KEM helpers are inlined.

### Dependencies

- `ml-kem` upgraded `0.3.0-rc.0` → `0.3.2`, replacing a release-candidate dependency with a stable release. `hkdf` 0.12 → 0.13, `sha2` 0.10 → 0.11, `sha3` 0.10 → 0.12; a new optional `shake` dependency is pulled in by the `pq` feature. The `std` feature no longer force-enables the hash crates' own `std` features.

### Testing & benchmarks

- A `trybuild` compile-fail suite locks in the misuse-resistant API: a `SenderContext` cannot `open`, a `ReceiverContext` cannot `seal`, contexts are not `Clone`, export-only ciphersuites cannot seal, external crates cannot implement the sealed traits, PQ KEMs cannot be used in auth modes, and each key-schedule path rejects the wrong mode tag.
- Fuzzing is wired into GitHub CI; the key-schedule fuzz target was updated for the typed mode-tag API.
- `rust-hpke` (rozbb) added as a third head-to-head benchmark target. Coverage is now 137 benchmark cells (76 vs `hpke-rs`, 61 vs `rust-hpke`); hpke-ng wins 99, ties 20, loses 18 — losses concentrated against `rust-hpke` on large-payload AES-GCM seal and key-generation paths. `CONTRIBUTORS.md` added.

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
