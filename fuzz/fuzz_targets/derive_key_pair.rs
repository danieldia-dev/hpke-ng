//! Fuzz `Kem::derive_key_pair` for every supported KEM. The function must
//! never panic on arbitrary input; it either produces a valid key pair or
//! returns an error (e.g. `DeriveKeyPairError`).
//!
//! Coverage targets:
//!   - NIST/secp256k1 rejection-sampling loop in `derive_p_curve_sk`.
//!   - X25519/X448 single-shot `LabeledExpand` then clamp.
//!   - X-Wing SHAKE-256(ikm, 32) seed expansion.
//!   - ML-KEM strict 64-byte seed length enforcement (and rejection of
//!     other lengths).

#![no_main]

use libfuzzer_sys::fuzz_target;

use hpke_ng::{
    DhKemK256HkdfSha256, DhKemP256HkdfSha256, DhKemP384HkdfSha384, DhKemP521HkdfSha512,
    DhKemX25519HkdfSha256, DhKemX448HkdfSha512, Kem, MlKem768, MlKem1024, XWingDraft06,
};

fuzz_target!(|data: &[u8]| {
    let _ = <DhKemX25519HkdfSha256 as Kem>::derive_key_pair(data);
    let _ = <DhKemX448HkdfSha512 as Kem>::derive_key_pair(data);
    let _ = <DhKemP256HkdfSha256 as Kem>::derive_key_pair(data);
    let _ = <DhKemP384HkdfSha384 as Kem>::derive_key_pair(data);
    let _ = <DhKemP521HkdfSha512 as Kem>::derive_key_pair(data);
    let _ = <DhKemK256HkdfSha256 as Kem>::derive_key_pair(data);
    let _ = <XWingDraft06 as Kem>::derive_key_pair(data);
    let _ = <MlKem768 as Kem>::derive_key_pair(data);
    let _ = <MlKem1024 as Kem>::derive_key_pair(data);
});
