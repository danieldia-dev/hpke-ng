# hpke-ng

[![CI](https://github.com/symbolicsoft/hpke-ng/actions/workflows/ci.yml/badge.svg)](https://github.com/symbolicsoft/hpke-ng/actions)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue)](#license)

A clean-slate Rust implementation of [HPKE (RFC 9180)](https://www.rfc-editor.org/rfc/rfc9180.html) with type-driven ciphersuite selection.

> Read the announcement: **[hpke-ng: Faster, Smaller, Harder HPKE for Rust](https://symbolic.software/blog/2026-05-08-hpke-ng/)** — for the full design rationale, benchmarks, and migration notes.

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

## Why a new HPKE crate?

`hpke-ng` exists because three friction points in the existing Rust HPKE story kept producing real bugs and real overhead:

1. **Provider abstraction overhead.** A trait-based pluggable backend pushes dispatch costs into hot paths and inflates the `Hpke` struct to hundreds of bytes — for a value the type system already knows.
2. **Struct-owned PRNG hazard.** When the `Hpke` instance owns its RNG, cloning silently aliases randomness state. The fix is structural: don't own it.
3. **Type-system gaps.** `Option<&[u8]>` for mode-specific parameters turns missing-PSK and wrong-mode into runtime errors that should be compile errors.

The design takes one position on each: **no provider abstraction, no owned RNG, type parameters instead of mode enums.** The math is a solved problem; the surrounding library is where the engineering still has slack.

## Design highlights

- **Type-parameterized API.** `Hpke<K, F, A>` is zero-sized; the ciphersuite lives in the type system. Mismatched primitives are compile errors.
- **Four explicit methods per mode.** `seal_base`, `seal_psk`, `seal_auth`, `seal_auth_psk` — no `Option<&[u8]>` parameters for required-by-mode arguments.
- **Auth restricted to DHKEMs at the type level.** `Hpke::<XWingDraft06, ...>::seal_auth(...)` does not compile.
- **Export-only restricted at the type level.** `Hpke::<_, _, ExportOnly>::seal_base(...)` does not compile; only `*_export*` methods are available.
- **Type-tagged keys.** Private keys carry their KEM in their type, so passing a `DhKemP256` key into an X25519 suite is rejected by the compiler, not at runtime.
- **Caller-provided RNG.** No PRNG owned by the configuration; cloning cannot alias randomness.
- **Structural nonce-reuse prevention.** `Context` is non-cloneable and refuses to encrypt at `seq == u64::MAX`.
- **`no_std` + `alloc`** by default. `std` feature for `std::error::Error` impl on `HpkeError`.
- **One provider stack.** All primitives from RustCrypto-org crates.

## Compile-time guarantees

| Operation                                | Elsewhere       | hpke-ng                        |
|------------------------------------------|-----------------|--------------------------------|
| Calling `seal_auth` on a non-DH KEM      | Runtime error   | Compile error                  |
| Using a wrong-KEM private key            | Runtime mismatch| Compile error (type-tagged)    |
| Base-mode call with a PSK supplied       | Runtime error   | Compile error (no PSK param)   |
| Encrypt with an `ExportOnly` AEAD        | Runtime error   | Compile error                  |

## Supported ciphersuites

| Component | Variants |
|---|---|
| KEMs | `DhKemX25519HkdfSha256`, `DhKemX448HkdfSha512`, `DhKemP256HkdfSha256`, `DhKemP384HkdfSha384`, `DhKemP521HkdfSha512`, `DhKemK256HkdfSha256` |
| KEMs (post-quantum, `pq` feature) | `XWingDraft06`, `MlKem768`, `MlKem1024` |
| KDFs | `HkdfSha256`, `HkdfSha384`, `HkdfSha512` |
| AEADs | `Aes128Gcm`, `Aes256Gcm`, `ChaCha20Poly1305`, `ExportOnly` |
| Modes | Base, Psk, Auth, AuthPsk |

## Performance

Across **132 head-to-head benchmarks** against the two major Rust HPKE libraries — `hpke-rs` and `rust-hpke` — `hpke-ng` lands **100 wins, 12 ties, 20 losses**. Broken out: vs `hpke-rs` (76 cells) it's **63W / 8T / 5L**; vs `rust-hpke` (56 cells; no standalone ML-KEM-768/ML-KEM-1024, no secp256k1 support) it's **37W / 4T / 15L**. The largest deltas are on the post-quantum decap path — ML-KEM-768 and ML-KEM-1024 land 53–55% faster, X-Wing decap 37% faster — because `hpke-ng` caches the expanded FIPS 203 decapsulation key in the `PrivateKey` while `hpke-rs` rebuilds it from the seed on every `setup_receiver`. The same idea applied to classical KEMs — caching the recipient's serialized public key alongside the secret — eliminates a redundant base-point scalar multiplication on every decap, lifting **X25519 decap to −41% vs `hpke-rs` / −31% vs `rust-hpke`**, ML-KEM encap to 38–40%, X-Wing encap to 16% vs `hpke-rs` and to roughly parity vs `rust-hpke`. X-Wing `setup_receiver` is also roughly equivalent to `rust-hpke`'s (which wraps raw decap in full HPKE setup). Single-shot open is **26–42% faster vs `hpke-rs`** and **22–35% faster vs `rust-hpke`** across payload sizes; AES-128-GCM single-shot seal 6–22% faster against both across payloads ≤ 16 KiB. **Export is 72–76% faster vs `hpke-rs`** across all five output lengths — the largest sustained delta in the suite (`rust-hpke` excluded: its `export()` API allocates in a way that would bias the comparison). Post-setup `Context::seal` at 64 B is 14% faster vs `hpke-rs` and tied with `rust-hpke`. **End-to-end roundtrip on a 1 KiB message is 30% faster vs both libraries.**

Memory and binary footprint:

| Quantity                                       | hpke-rs   | hpke-ng                     |
|------------------------------------------------|-----------|-----------------------------|
| `Hpke<K, F, A>` struct                         | 320 bytes | **0 bytes** (`PhantomData`) |
| `Context<_, _, ChaCha20Poly1305>` struct       | 400 bytes | **88 bytes**                |
| `Context<_, _, ExportOnly>` struct             | n/a       | **56 bytes**                |
| `Context<_, _, Aes128Gcm>` struct              | 400 bytes | 792 bytes                   |
| `Context<_, _, Aes256Gcm>` struct              | 400 bytes | 1,048 bytes                 |
| Minimal release binary                         | 561 KB    | **392 KB** (~30% smaller)   |

The AES-GCM `Context` rows are larger than `hpke-rs` because the cipher's expanded round keys + GHash table are cached inline — that is what eliminates the per-call AES key-schedule cost in `Context::seal`. Streaming applications using AES-GCM trade memory for throughput here; ChaCha20-Poly1305 is unaffected.

Build with `RUSTFLAGS="-C target-cpu=native"` for AES-NI / SHA-NI where available. The `[profile.bench]` in `Cargo.toml` enables `lto = "thin"` and `codegen-units = 1`. For head-to-head numbers, run `cargo bench --features comparative --bench comparative` locally; the comparative bench loads both `hpke-rs` (with its `experimental` feature so the post-quantum KEM stubs are wired up) and `rust-hpke` (pinned to a v0.14 pre-release commit for X-Wing support) as dev-dependencies, and produces side-by-side criterion results for every supported ciphersuite. KEM-op rows for `hpke-rs` and `rust-hpke` carry an `_via_setup_*` suffix because neither library exposes raw `encap` / `decap` separable from setup; the suffix marks rows that are explicitly *not* apples-to-apples with `hpke-ng`'s bare-operation rows.

## Security posture

The library responds to two classes of issue observed in prior implementations:

- **Zero shared-secret check (RFC 9180 §7.1.4).** Enforced for X25519 and X448 using `subtle::ConstantTimeEq`.
- **Nonce counter wraparound.** Prevented structurally: `Context` uses a `u64` sequence number, refuses to encrypt at `u64::MAX`, and is non-cloneable so a counter cannot fork.

The post-DH all-zeros check is constant-time. `Context` cannot be `Clone`d, so two ciphertexts cannot be produced under the same `(key, nonce)` from two copies of the same context.

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

## Testing

```bash
cargo test                                             # library + roundtrip
cargo test --features pq                               # + post-quantum tests
cargo test --features pq --test compile_fail           # + compile-time invariant tests
cargo test --features pq,kat-internals                 # + RFC 9180 KAT
cargo test --features pq,differential,kat-internals    # + cross-impl differential vs hpke-rs
```

To regenerate the compile-fail `.stderr` fixtures after an intentional change (e.g. a toolchain bump), run:
```bash
TRYBUILD=overwrite cargo test --features pq --test compile_fail
```
This rewrites the fixtures unconditionally and should not be used as the normal test invocation.

Coverage includes 59 macro-generated roundtrip tests across every ciphersuite × mode combination, four `cargo-fuzz` targets (panics treated as bugs), differential testing against `hpke-rs` for wire-format interop, compile-fail tests that lock in type-system invariants (`Context` is non-cloneable, `ExportOnly` cannot seal, PQ KEMs cannot authenticate), and unit tests that directly verify the RFC 9180 §5.2 nonce derivation formula (`nonce = base_nonce XOR I2OSP(seq, Nn)`) across specific sequence number boundary values. The full suite (without differential) runs in under two seconds.

## Migration from `hpke-rs`

Three mechanical steps, typically under an hour for a real codebase:

1. Define a `type Suite = Hpke<K, F, A>;` alias for the ciphersuite you use.
2. Replace `hpke.seal(...)` calls with the explicit mode method: `Suite::seal_base`, `seal_psk`, `seal_auth`, or `seal_auth_psk`.
3. Thread `&mut rng` through call sites — the configuration no longer owns one.

See the [announcement post](https://symbolic.software/blog/2026-05-08-hpke-ng/) for a worked example.

## Authors

hpke-ng is a joint project between [Nadim Kobeissi](https://nadim.computer) and [Daniel Dia](https://danieldia.me).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
