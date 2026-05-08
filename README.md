# hpke-ng

[![CI](https://github.com/symbolicsoft/hpke-ng/actions/workflows/ci.yml/badge.svg)](https://github.com/symbolicsoft/hpke-ng/actions)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue)](#license)

A clean-slate Rust implementation of [HPKE (RFC 9180)](https://www.rfc-editor.org/rfc/rfc9180.html) with type-driven ciphersuite selection.

```rust
use hpke_ng::*;
use rand_core::OsRng;

type Suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>;

let mut os = OsRng;
let mut rng = os.unwrap_mut();
let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng)?;
let (enc, ct)  = Suite::seal_base(&mut rng, &pk_r, b"info", b"aad", b"hello")?;
let pt         = Suite::open_base(&enc, &sk_r, b"info", b"aad", &ct)?;
assert_eq!(pt, b"hello");
# Ok::<_, hpke_ng::HpkeError>(())
```

## Design highlights

- **Type-parameterized API.** `Hpke<K, F, A>` is zero-sized; the ciphersuite lives in the type system. Mismatched primitives are compile errors.
- **Four explicit methods per mode.** `seal_base`, `seal_psk`, `seal_auth`, `seal_auth_psk` — no `Option<&[u8]>` parameters for required-by-mode arguments.
- **Auth restricted to DHKEMs at the type level.** `Hpke::<XWingDraft06, ...>::seal_auth(...)` does not compile.
- **Export-only restricted at the type level.** `Hpke::<_, _, ExportOnly>::seal_base(...)` does not compile; only `*_export*` methods are available.
- **Caller-provided RNG.** No PRNG owned by the configuration.
- **`no_std` + `alloc`** by default. `std` feature for `std::error::Error` impl on `HpkeError`.
- **One provider stack.** All primitives from RustCrypto-org crates.

## Supported ciphersuites

| Component | Variants |
|---|---|
| KEMs | `DhKemX25519HkdfSha256`, `DhKemX448HkdfSha512`, `DhKemP256HkdfSha256`, `DhKemP384HkdfSha384`, `DhKemP521HkdfSha512`, `DhKemK256HkdfSha256` |
| KEMs (post-quantum, `pq` feature) | `XWingDraft06`, `MlKem768`, `MlKem1024` |
| KDFs | `HkdfSha256`, `HkdfSha384`, `HkdfSha512` |
| AEADs | `Aes128Gcm`, `Aes256Gcm`, `ChaCha20Poly1305`, `ExportOnly` |
| Modes | Base, Psk, Auth, AuthPsk |

## Constant-time considerations

This crate composes RustCrypto primitives. Constant-time properties are inherited from those crates:

| Primitive | CT property |
|---|---|
| X25519, X448 | CT by construction. |
| P-256, P-384, P-521, secp256k1 | CT in `arithmetic` mode (pinned). |
| HKDF-SHA-{256,384,512} | CT (deterministic; no secret-dependent branches). |
| ChaCha20-Poly1305 | CT by construction. |
| AES-128-GCM, AES-256-GCM | **CT only with hardware AES-NI/PCLMULQDQ.** Prefer `ChaCha20Poly1305` on platforms without these instructions. |
| ML-KEM, X-Wing | CT per upstream documentation; both crates are pre-1.0. |

The post-DH all-zeros check (RFC 9180 §7.1.4) uses `subtle::ConstantTimeEq` for X25519 and X448.

## Performance

Build with `RUSTFLAGS="-C target-cpu=native"` for AES-NI / SHA-NI instructions where available. The `[profile.bench]` in `Cargo.toml` enables `lto = "thin"` and `codegen-units = 1`.

For head-to-head numbers vs `hpke-rs`, run `cargo bench --features comparative --bench comparative` locally.

## Testing

```bash
cargo test                                              # library + roundtrip
cargo test --features pq                                # + post-quantum tests
cargo test --features pq,kat-internals                  # + RFC 9180 KAT
cargo test --features pq,differential,kat-internals     # + cross-impl differential vs hpke-rs
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
