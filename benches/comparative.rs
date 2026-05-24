//! Head-to-head comparative benchmarks vs hpke-rs.
//!
//! Run with:
//! ```
//! RUSTFLAGS="-C target-cpu=native" \
//!   cargo bench --features comparative --bench comparative
//! ```
//!
//! Coverage:
//! - **KEM ops**: generate / derive_key_pair / encap / decap, across X25519,
//!   P-256, K256, X-Wing (draft-06), ML-KEM-768, and ML-KEM-1024.
//! - **Setup paths**: setup_sender_* / setup_receiver_* across multiple
//!   ciphersuites and modes (Base + Psk).
//! - **Single-shot seal/open**: 8 payload sizes (16 B → 256 KiB), multiple
//!   ciphersuites, both directions.
//! - **Context seal/open**: post-setup hot path.
//! - **Export**: 5 output lengths.
//! - **End-to-end round-trip**: total cost of encrypt-then-decrypt one message.
//!
//! Each benchmark group has two members with parallel names — `hpke_ng/...`
//! and `hpke_rs/...` — so criterion's report renders them side-by-side.
//!
//! Note: we seed the hpke-rs PRNG before each iteration because the
//! `hpke-test-prng` dev-dependency activates a deterministic-PRNG mode
//! that otherwise exhausts its fixed-size buffer across iterations.

#![cfg(feature = "comparative")]

use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use hpke_ng::{self as ng, Kem as _};

use hpke_rs::{Hpke as HpkeRs, Mode};
use hpke_rs_crypto::types as rs_types;
use hpke_rs_rust_crypto::HpkeRustCrypto;

use hpke::{
	Kem as RustHpkeKem, OpModeR, OpModeS,
	aead::{AesGcm128 as RhAes128, AesGcm256 as RhAes256, ChaCha20Poly1305 as RhChaCha20},
	kdf::HkdfSha256 as RhHkdfSha256,
	kem::{DhP256HkdfSha256 as RhP256, X25519HkdfSha256 as RhX25519},
};

use rand_core::{OsRng, TryRngCore as _};

/// Seed bytes: 4 KiB is enough for any single hpke-rs operation.
const SEED: &[u8] = &[0x5Eu8; 4096];

const PAYLOAD_SIZES: &[usize] = &[16, 64, 256, 1024, 4096, 16384, 65536, 262144];
const EXPORT_LENGTHS: &[usize] = &[16, 32, 64, 128, 256];

fn quick(c: &mut Criterion) -> Criterion {
	// Override globally? No — just fall through, tune per-group below.
	let _ = c;
	Criterion::default()
		.sample_size(60)
		.measurement_time(Duration::from_secs(3))
		.warm_up_time(Duration::from_secs(1))
}

// =============================================================================
//  KEM operations: generate / derive_key_pair / encap / decap
//  Across X25519, P-256, K256 (all three KEMs hpke-rs/RustCrypto supports).
// =============================================================================

fn bench_kem_x25519(c: &mut Criterion) {
	let mut g = c.benchmark_group("kem/x25519");
	let mut os = OsRng;

	// generate
	g.bench_function("hpke_ng/generate", |b| {
		b.iter(|| {
			let mut os = OsRng;
			ng::DhKemX25519HkdfSha256::generate(&mut os.unwrap_mut()).unwrap()
		})
	});
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::DhKem25519,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		g.bench_function("hpke_rs/generate", |b| {
			b.iter(|| {
				rs.seed(SEED).unwrap();
				rs.generate_key_pair().unwrap()
			})
		});
	}
	g.bench_function("rust_hpke/generate", |b| {
		b.iter(|| RhX25519::gen_keypair(&mut os.unwrap_mut()))
	});

	// derive_key_pair (deterministic, no PRNG)
	let ikm = [0x99u8; 32];
	g.bench_function("hpke_ng/derive_key_pair", |b| {
		b.iter(|| ng::DhKemX25519HkdfSha256::derive_key_pair(black_box(&ikm)).unwrap())
	});
	{
		let rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::DhKem25519,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		g.bench_function("hpke_rs/derive_key_pair", |b| {
			b.iter(|| rs.derive_key_pair(black_box(&ikm)).unwrap())
		});
	}

	// encap
	{
		let (_, pk_ng) = ng::DhKemX25519HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();
		g.bench_function("hpke_ng/encap", |b| {
			b.iter(|| {
				let mut os = OsRng;
				ng::DhKemX25519HkdfSha256::encap(&mut os.unwrap_mut(), black_box(&pk_ng)).unwrap()
			})
		});
	}

	// hpke-rs has no public direct encap; the closest analog is setup_sender_base.
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::DhKem25519,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		let (_sk, pk) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();
		g.bench_function("hpke_rs/encap_via_setup_sender", |b| {
			b.iter(|| {
				rs.seed(SEED).unwrap();
				rs.setup_sender(black_box(&pk), b"", None, None, None)
					.unwrap()
			})
		});
	}

	// decap
	{
		let mut os = OsRng;
		let (sk_ng, pk_ng) = ng::DhKemX25519HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();
		let (_, enc_ng) = ng::DhKemX25519HkdfSha256::encap(&mut os.unwrap_mut(), &pk_ng).unwrap();
		g.bench_function("hpke_ng/decap", |b| {
			b.iter(|| ng::DhKemX25519HkdfSha256::decap(black_box(&enc_ng), &sk_ng).unwrap())
		});
	}
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::DhKem25519,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		let (sk, pk) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();
		rs.seed(SEED).unwrap();
		let (enc, _ctx) = rs.setup_sender(&pk, b"", None, None, None).unwrap();
		g.bench_function("hpke_rs/decap_via_setup_receiver", |b| {
			b.iter(|| {
				rs.setup_receiver(black_box(&enc), &sk, b"", None, None, None)
					.unwrap()
			})
		});
	}

	// encap via `setup_sender`
	{
		let (_, pk) = RhX25519::gen_keypair(&mut os.unwrap_mut());
		g.bench_function("rust_hpke/encap_via_setup_sender", |b| {
			b.iter(|| {
				let mut os = OsRng;
				hpke::setup_sender::<RhChaCha20, RhHkdfSha256, RhX25519, _>(
					&OpModeS::Base,
					black_box(&pk),
					b"",
					&mut os.unwrap_mut(),
				)
				.unwrap()
			})
		});
	}

	// decap via `setup_receiver`
	{
		let (sk, pk) = RhX25519::gen_keypair(&mut os.unwrap_mut());
		let (enc, _) = hpke::setup_sender::<RhChaCha20, RhHkdfSha256, RhX25519, _>(
			&OpModeS::Base,
			&pk,
			b"",
			&mut os.unwrap_mut(),
		)
		.unwrap();
		g.bench_function("rust_hpke/decap_via_setup_receiver", |b| {
			b.iter(|| {
				hpke::setup_receiver::<RhChaCha20, RhHkdfSha256, RhX25519>(
					&OpModeR::Base,
					black_box(&sk),
					black_box(&enc),
					b"",
				)
				.unwrap()
			})
		});
	}
	g.finish();
}

fn bench_kem_p256(c: &mut Criterion) {
	let mut g = c.benchmark_group("kem/p256");

	g.bench_function("hpke_ng/generate", |b| {
		b.iter(|| {
			let mut os = OsRng;
			ng::DhKemP256HkdfSha256::generate(&mut os.unwrap_mut()).unwrap()
		})
	});
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::DhKemP256,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::Aes128Gcm,
		);
		g.bench_function("hpke_rs/generate", |b| {
			b.iter(|| {
				rs.seed(SEED).unwrap();
				rs.generate_key_pair().unwrap()
			})
		});
	}

	let ikm = [0x99u8; 32];
	g.bench_function("hpke_ng/derive_key_pair", |b| {
		b.iter(|| ng::DhKemP256HkdfSha256::derive_key_pair(black_box(&ikm)).unwrap())
	});
	{
		let rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::DhKemP256,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::Aes128Gcm,
		);
		g.bench_function("hpke_rs/derive_key_pair", |b| {
			b.iter(|| rs.derive_key_pair(black_box(&ikm)).unwrap())
		});
	}

	{
		let mut os = OsRng;
		let (_, pk_ng) = ng::DhKemP256HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();
		g.bench_function("hpke_ng/encap", |b| {
			b.iter(|| {
				let mut os = OsRng;
				ng::DhKemP256HkdfSha256::encap(&mut os.unwrap_mut(), black_box(&pk_ng)).unwrap()
			})
		});
	}
	{
		let mut os = OsRng;
		let (sk_ng, pk_ng) = ng::DhKemP256HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();
		let (_, enc_ng) = ng::DhKemP256HkdfSha256::encap(&mut os.unwrap_mut(), &pk_ng).unwrap();
		g.bench_function("hpke_ng/decap", |b| {
			b.iter(|| ng::DhKemP256HkdfSha256::decap(black_box(&enc_ng), &sk_ng).unwrap())
		});
	}

	{
		let mut os = OsRng;
		g.bench_function("rust_hpke/generate", |b| {
			b.iter(|| RhP256::gen_keypair(&mut os.unwrap_mut()))
		});
		g.bench_function("rust_hpke/derive_key_pair", |b| {
			b.iter(|| RhP256::derive_keypair(black_box(&ikm)))
		});
		let (_, pk) = RhP256::gen_keypair(&mut os.unwrap_mut());
		g.bench_function("rust_hpke/encap_via_setup_sender", |b| {
			b.iter(|| {
				let mut os = OsRng;
				hpke::setup_sender::<RhAes128, RhHkdfSha256, RhP256, _>(
					&OpModeS::Base,
					black_box(&pk),
					b"",
					&mut os.unwrap_mut(),
				)
				.unwrap()
			})
		});
		let (sk, pk) = RhP256::gen_keypair(&mut os.unwrap_mut());
		let (enc, _) = hpke::setup_sender::<RhAes128, RhHkdfSha256, RhP256, _>(
			&OpModeS::Base,
			&pk,
			b"",
			&mut os.unwrap_mut(),
		)
		.unwrap();
		g.bench_function("rust_hpke/decap_via_setup_receiver", |b| {
			b.iter(|| {
				hpke::setup_receiver::<RhAes128, RhHkdfSha256, RhP256>(
					&OpModeR::Base,
					black_box(&sk),
					black_box(&enc),
					b"",
				)
				.unwrap()
			})
		});
	}

	g.finish();
}

fn bench_kem_k256(c: &mut Criterion) {
	let mut g = c.benchmark_group("kem/k256");

	g.bench_function("hpke_ng/generate", |b| {
		b.iter(|| {
			let mut os = OsRng;
			ng::DhKemK256HkdfSha256::generate(&mut os.unwrap_mut()).unwrap()
		})
	});
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::DhKemK256,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		g.bench_function("hpke_rs/generate", |b| {
			b.iter(|| {
				rs.seed(SEED).unwrap();
				rs.generate_key_pair().unwrap()
			})
		});
	}

	let ikm = [0x99u8; 32];
	g.bench_function("hpke_ng/derive_key_pair", |b| {
		b.iter(|| ng::DhKemK256HkdfSha256::derive_key_pair(black_box(&ikm)).unwrap())
	});
	{
		let rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::DhKemK256,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		g.bench_function("hpke_rs/derive_key_pair", |b| {
			b.iter(|| rs.derive_key_pair(black_box(&ikm)).unwrap())
		});
	}

	{
		let mut os = OsRng;
		let (_, pk_ng) = ng::DhKemK256HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();
		g.bench_function("hpke_ng/encap", |b| {
			b.iter(|| {
				let mut os = OsRng;
				ng::DhKemK256HkdfSha256::encap(&mut os.unwrap_mut(), black_box(&pk_ng)).unwrap()
			})
		});
	}
	{
		let mut os = OsRng;
		let (sk_ng, pk_ng) = ng::DhKemK256HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();
		let (_, enc_ng) = ng::DhKemK256HkdfSha256::encap(&mut os.unwrap_mut(), &pk_ng).unwrap();
		g.bench_function("hpke_ng/decap", |b| {
			b.iter(|| ng::DhKemK256HkdfSha256::decap(black_box(&enc_ng), &sk_ng).unwrap())
		});
	}

	g.finish();
}

fn bench_kem_xwing(c: &mut Criterion) {
	let mut g = c.benchmark_group("kem/xwing");

	g.bench_function("hpke_ng/generate", |b| {
		b.iter(|| {
			let mut os = OsRng;
			ng::XWingDraft06::generate(&mut os.unwrap_mut()).unwrap()
		})
	});
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::XWingDraft06,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		g.bench_function("hpke_rs/generate", |b| {
			b.iter(|| {
				rs.seed(SEED).unwrap();
				rs.generate_key_pair().unwrap()
			})
		});
	}

	let ikm = [0x99u8; 32];
	g.bench_function("hpke_ng/derive_key_pair", |b| {
		b.iter(|| ng::XWingDraft06::derive_key_pair(black_box(&ikm)).unwrap())
	});
	{
		let rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::XWingDraft06,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		g.bench_function("hpke_rs/derive_key_pair", |b| {
			b.iter(|| rs.derive_key_pair(black_box(&ikm)).unwrap())
		});
	}

	{
		let mut os = OsRng;
		let (_, pk_ng) = ng::XWingDraft06::generate(&mut os.unwrap_mut()).unwrap();
		g.bench_function("hpke_ng/encap", |b| {
			b.iter(|| {
				let mut os = OsRng;
				ng::XWingDraft06::encap(&mut os.unwrap_mut(), black_box(&pk_ng)).unwrap()
			})
		});
	}
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::XWingDraft06,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		let (_sk, pk) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();
		g.bench_function("hpke_rs/encap_via_setup_sender", |b| {
			b.iter(|| {
				rs.seed(SEED).unwrap();
				rs.setup_sender(black_box(&pk), b"", None, None, None)
					.unwrap()
			})
		});
	}

	{
		let mut os = OsRng;
		let (sk_ng, pk_ng) = ng::XWingDraft06::generate(&mut os.unwrap_mut()).unwrap();
		let (_, enc_ng) = ng::XWingDraft06::encap(&mut os.unwrap_mut(), &pk_ng).unwrap();
		g.bench_function("hpke_ng/decap", |b| {
			b.iter(|| ng::XWingDraft06::decap(black_box(&enc_ng), &sk_ng).unwrap())
		});
	}
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::XWingDraft06,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		let (sk, pk) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();
		rs.seed(SEED).unwrap();
		let (enc, _ctx) = rs.setup_sender(&pk, b"", None, None, None).unwrap();
		g.bench_function("hpke_rs/decap_via_setup_receiver", |b| {
			b.iter(|| {
				rs.setup_receiver(black_box(&enc), &sk, b"", None, None, None)
					.unwrap()
			})
		});
	}

	g.finish();
}

fn bench_kem_mlkem768(c: &mut Criterion) {
	let mut g = c.benchmark_group("kem/mlkem768");

	g.bench_function("hpke_ng/generate", |b| {
		b.iter(|| {
			let mut os = OsRng;
			ng::MlKem768::generate(&mut os.unwrap_mut()).unwrap()
		})
	});
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::MlKem768,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		g.bench_function("hpke_rs/generate", |b| {
			b.iter(|| {
				rs.seed(SEED).unwrap();
				rs.generate_key_pair().unwrap()
			})
		});
	}

	// hpke-ng ML-KEM derive_key_pair requires a 64-byte (d || z) seed
	// per draft-connolly-cfrg-hpke-mlkem-04 §3.2. hpke-rs SHAKE-256s the
	// IKM down to 64, so a 64-byte IKM works for both.
	let ikm = [0x99u8; 64];
	g.bench_function("hpke_ng/derive_key_pair", |b| {
		b.iter(|| ng::MlKem768::derive_key_pair(black_box(&ikm)).unwrap())
	});
	{
		let rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::MlKem768,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		g.bench_function("hpke_rs/derive_key_pair", |b| {
			b.iter(|| rs.derive_key_pair(black_box(&ikm)).unwrap())
		});
	}

	{
		let mut os = OsRng;
		let (_, pk_ng) = ng::MlKem768::generate(&mut os.unwrap_mut()).unwrap();
		g.bench_function("hpke_ng/encap", |b| {
			b.iter(|| {
				let mut os = OsRng;
				ng::MlKem768::encap(&mut os.unwrap_mut(), black_box(&pk_ng)).unwrap()
			})
		});
	}
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::MlKem768,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		let (_sk, pk) = rs.derive_key_pair(&[0x42u8; 64]).unwrap().into_keys();
		g.bench_function("hpke_rs/encap_via_setup_sender", |b| {
			b.iter(|| {
				rs.seed(SEED).unwrap();
				rs.setup_sender(black_box(&pk), b"", None, None, None)
					.unwrap()
			})
		});
	}

	{
		let mut os = OsRng;
		let (sk_ng, pk_ng) = ng::MlKem768::generate(&mut os.unwrap_mut()).unwrap();
		let (_, enc_ng) = ng::MlKem768::encap(&mut os.unwrap_mut(), &pk_ng).unwrap();
		g.bench_function("hpke_ng/decap", |b| {
			b.iter(|| ng::MlKem768::decap(black_box(&enc_ng), &sk_ng).unwrap())
		});
	}
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::MlKem768,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		let (sk, pk) = rs.derive_key_pair(&[0x42u8; 64]).unwrap().into_keys();
		rs.seed(SEED).unwrap();
		let (enc, _ctx) = rs.setup_sender(&pk, b"", None, None, None).unwrap();
		g.bench_function("hpke_rs/decap_via_setup_receiver", |b| {
			b.iter(|| {
				rs.setup_receiver(black_box(&enc), &sk, b"", None, None, None)
					.unwrap()
			})
		});
	}

	g.finish();
}

fn bench_kem_mlkem1024(c: &mut Criterion) {
	let mut g = c.benchmark_group("kem/mlkem1024");

	g.bench_function("hpke_ng/generate", |b| {
		b.iter(|| {
			let mut os = OsRng;
			ng::MlKem1024::generate(&mut os.unwrap_mut()).unwrap()
		})
	});
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::MlKem1024,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		g.bench_function("hpke_rs/generate", |b| {
			b.iter(|| {
				rs.seed(SEED).unwrap();
				rs.generate_key_pair().unwrap()
			})
		});
	}

	let ikm = [0x99u8; 64];
	g.bench_function("hpke_ng/derive_key_pair", |b| {
		b.iter(|| ng::MlKem1024::derive_key_pair(black_box(&ikm)).unwrap())
	});
	{
		let rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::MlKem1024,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		g.bench_function("hpke_rs/derive_key_pair", |b| {
			b.iter(|| rs.derive_key_pair(black_box(&ikm)).unwrap())
		});
	}

	{
		let mut os = OsRng;
		let (_, pk_ng) = ng::MlKem1024::generate(&mut os.unwrap_mut()).unwrap();
		g.bench_function("hpke_ng/encap", |b| {
			b.iter(|| {
				let mut os = OsRng;
				ng::MlKem1024::encap(&mut os.unwrap_mut(), black_box(&pk_ng)).unwrap()
			})
		});
	}
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::MlKem1024,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		let (_sk, pk) = rs.derive_key_pair(&[0x42u8; 64]).unwrap().into_keys();
		g.bench_function("hpke_rs/encap_via_setup_sender", |b| {
			b.iter(|| {
				rs.seed(SEED).unwrap();
				rs.setup_sender(black_box(&pk), b"", None, None, None)
					.unwrap()
			})
		});
	}

	{
		let mut os = OsRng;
		let (sk_ng, pk_ng) = ng::MlKem1024::generate(&mut os.unwrap_mut()).unwrap();
		let (_, enc_ng) = ng::MlKem1024::encap(&mut os.unwrap_mut(), &pk_ng).unwrap();
		g.bench_function("hpke_ng/decap", |b| {
			b.iter(|| ng::MlKem1024::decap(black_box(&enc_ng), &sk_ng).unwrap())
		});
	}
	{
		let mut rs = HpkeRs::<HpkeRustCrypto>::new(
			Mode::Base,
			rs_types::KemAlgorithm::MlKem1024,
			rs_types::KdfAlgorithm::HkdfSha256,
			rs_types::AeadAlgorithm::ChaCha20Poly1305,
		);
		let (sk, pk) = rs.derive_key_pair(&[0x42u8; 64]).unwrap().into_keys();
		rs.seed(SEED).unwrap();
		let (enc, _ctx) = rs.setup_sender(&pk, b"", None, None, None).unwrap();
		g.bench_function("hpke_rs/decap_via_setup_receiver", |b| {
			b.iter(|| {
				rs.setup_receiver(black_box(&enc), &sk, b"", None, None, None)
					.unwrap()
			})
		});
	}

	g.finish();
}

// =============================================================================
//  Setup paths: setup_sender / setup_receiver across ciphersuites
// =============================================================================

fn bench_setup_x25519_chacha(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::DhKemX25519HkdfSha256, ng::HkdfSha256, ng::ChaCha20Poly1305>;
	let mut os = OsRng;
	let (sk_ng, pk_ng) = ng::DhKemX25519HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();
	let (enc_ng, _ctx_ng) =
		Suite::setup_sender_base(&mut os.unwrap_mut(), &pk_ng, b"info").unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKem25519,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::ChaCha20Poly1305,
	);
	let (sk_rs, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();
	rs.seed(SEED).unwrap();
	let (enc_rs, _ctx_rs) = rs.setup_sender(&pk_rs, b"info", None, None, None).unwrap();

	let (_, pk) = RhX25519::gen_keypair(&mut os.unwrap_mut());

	let mut g = c.benchmark_group("x25519_chacha20/setup_sender_base");

	// `setup_sender` group
	g.bench_function("hpke_ng", |b| {
		b.iter(|| {
			let mut os = OsRng;
			Suite::setup_sender_base(&mut os.unwrap_mut(), black_box(&pk_ng), b"info").unwrap()
		})
	});
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.seed(SEED).unwrap();
			rs.setup_sender(black_box(&pk_rs), b"info", None, None, None)
				.unwrap()
		})
	});
	g.bench_function("rust_hpke", |b| {
		b.iter(|| {
			let mut os = OsRng;
			hpke::setup_sender::<RhChaCha20, RhHkdfSha256, RhX25519, _>(
				&OpModeS::Base,
				black_box(&pk),
				b"info",
				&mut os.unwrap_mut(),
			)
			.unwrap()
		})
	});
	g.finish();

	let mut g = c.benchmark_group("x25519_chacha20/setup_receiver_base");

	// `setup_receiver` group
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_receiver_base(black_box(&enc_ng), &sk_ng, b"info").unwrap())
	});
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.setup_receiver(black_box(&enc_rs), &sk_rs, b"info", None, None, None)
				.unwrap()
		})
	});
	{
		let (sk, pk) = RhX25519::gen_keypair(&mut os.unwrap_mut());
		let (enc, _) = hpke::setup_sender::<RhChaCha20, RhHkdfSha256, RhX25519, _>(
			&OpModeS::Base,
			&pk,
			b"info",
			&mut os.unwrap_mut(),
		)
		.unwrap();
		g.bench_function("rust_hpke", |b| {
			b.iter(|| {
				hpke::setup_receiver::<RhChaCha20, RhHkdfSha256, RhX25519>(
					&OpModeR::Base,
					black_box(&sk),
					black_box(&enc),
					b"info",
				)
				.unwrap()
			})
		});
	}
	g.finish();

	// PSK mode setup (Base + Psk = 2 most-common modes)
	let psk = [0xAAu8; 32];
	let psk_id = b"psk-id";
	let mut rs_psk = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Psk,
		rs_types::KemAlgorithm::DhKem25519,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::ChaCha20Poly1305,
	);
	let (_sk_psk_rs, pk_psk_rs) = rs_psk.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();
	let mut g = c.benchmark_group("x25519_chacha20/setup_sender_psk");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| {
			let mut os = OsRng;
			Suite::setup_sender_psk(
				&mut os.unwrap_mut(),
				black_box(&pk_ng),
				b"info",
				&psk,
				psk_id,
			)
			.unwrap()
		})
	});
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs_psk.seed(SEED).unwrap();
			rs_psk
				.setup_sender(
					black_box(&pk_psk_rs),
					b"info",
					Some(&psk),
					Some(psk_id),
					None,
				)
				.unwrap()
		})
	});
	g.finish();
}

fn bench_setup_x25519_aes128(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::DhKemX25519HkdfSha256, ng::HkdfSha256, ng::Aes128Gcm>;
	let mut os = OsRng;
	let (_, pk_ng) = ng::DhKemX25519HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKem25519,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::Aes128Gcm,
	);
	let (_, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();

	let (_, pk) = RhX25519::gen_keypair(&mut os.unwrap_mut());

	let mut g = c.benchmark_group("x25519_aes128/setup_sender_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| {
			let mut os = OsRng;
			Suite::setup_sender_base(&mut os.unwrap_mut(), black_box(&pk_ng), b"info").unwrap()
		})
	});
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.seed(SEED).unwrap();
			rs.setup_sender(black_box(&pk_rs), b"info", None, None, None)
				.unwrap()
		})
	});
	g.bench_function("rust_hpke", |b| {
		b.iter(|| {
			let mut os = OsRng;
			hpke::setup_sender::<RhAes128, RhHkdfSha256, RhX25519, _>(
				&OpModeS::Base,
				black_box(&pk),
				b"info",
				&mut os.unwrap_mut(),
			)
			.unwrap()
		})
	});
	g.finish();
}

fn bench_setup_x25519_aes256(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::DhKemX25519HkdfSha256, ng::HkdfSha256, ng::Aes256Gcm>;
	let mut os = OsRng;
	let (_, pk_ng) = ng::DhKemX25519HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKem25519,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::Aes256Gcm,
	);
	let (_, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();

	let (_, pk) = RhX25519::gen_keypair(&mut os.unwrap_mut());

	let mut g = c.benchmark_group("x25519_aes256/setup_sender_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| {
			let mut os = OsRng;
			Suite::setup_sender_base(&mut os.unwrap_mut(), black_box(&pk_ng), b"info").unwrap()
		})
	});
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.seed(SEED).unwrap();
			rs.setup_sender(black_box(&pk_rs), b"info", None, None, None)
				.unwrap()
		})
	});
	g.bench_function("rust_hpke", |b| {
		b.iter(|| {
			let mut os = OsRng;
			hpke::setup_sender::<RhAes256, RhHkdfSha256, RhX25519, _>(
				&OpModeS::Base,
				black_box(&pk),
				b"info",
				&mut os.unwrap_mut(),
			)
			.unwrap()
		})
	});
	g.finish();
}

fn bench_setup_p256_aes128(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::DhKemP256HkdfSha256, ng::HkdfSha256, ng::Aes128Gcm>;
	let mut os = OsRng;
	let (_, pk_ng) = ng::DhKemP256HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKemP256,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::Aes128Gcm,
	);
	let (_, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();

	let (_, pk) = RhP256::gen_keypair(&mut os.unwrap_mut());

	let mut g = c.benchmark_group("p256_aes128/setup_sender_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| {
			let mut os = OsRng;
			Suite::setup_sender_base(&mut os.unwrap_mut(), black_box(&pk_ng), b"info").unwrap()
		})
	});
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.seed(SEED).unwrap();
			rs.setup_sender(black_box(&pk_rs), b"info", None, None, None)
				.unwrap()
		})
	});
	g.bench_function("rust_hpke", |b| {
		b.iter(|| {
			let mut os = OsRng;
			hpke::setup_sender::<RhAes128, RhHkdfSha256, RhP256, _>(
				&OpModeS::Base,
				black_box(&pk),
				b"info",
				&mut os.unwrap_mut(),
			)
			.unwrap()
		})
	});
	g.finish();
}

fn bench_setup_p256_aes256(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::DhKemP256HkdfSha256, ng::HkdfSha256, ng::Aes256Gcm>;
	let mut os = OsRng;
	let (_, pk_ng) = ng::DhKemP256HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKemP256,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::Aes256Gcm,
	);
	let (_, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();

	let (_, pk) = RhP256::gen_keypair(&mut os.unwrap_mut());

	let mut g = c.benchmark_group("p256_aes256/setup_sender_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| {
			let mut os = OsRng;
			Suite::setup_sender_base(&mut os.unwrap_mut(), black_box(&pk_ng), b"info").unwrap()
		})
	});
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.seed(SEED).unwrap();
			rs.setup_sender(black_box(&pk_rs), b"info", None, None, None)
				.unwrap()
		})
	});
	g.bench_function("rust_hpke", |b| {
		b.iter(|| {
			let mut os = OsRng;
			hpke::setup_sender::<RhAes256, RhHkdfSha256, RhP256, _>(
				&OpModeS::Base,
				black_box(&pk),
				b"info",
				&mut os.unwrap_mut(),
			)
			.unwrap()
		})
	});
	g.finish();
}

fn bench_setup_k256_chacha(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::DhKemK256HkdfSha256, ng::HkdfSha256, ng::ChaCha20Poly1305>;
	let mut os = OsRng;
	let (_, pk_ng) = ng::DhKemK256HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKemK256,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::ChaCha20Poly1305,
	);
	let (_, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();

	let mut g = c.benchmark_group("k256_chacha20/setup_sender_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| {
			let mut os = OsRng;
			Suite::setup_sender_base(&mut os.unwrap_mut(), black_box(&pk_ng), b"info").unwrap()
		})
	});
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.seed(SEED).unwrap();
			rs.setup_sender(black_box(&pk_rs), b"info", None, None, None)
				.unwrap()
		})
	});
	g.finish();
}

fn bench_setup_xwing_chacha(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::XWingDraft06, ng::HkdfSha256, ng::ChaCha20Poly1305>;
	let mut os = OsRng;
	let (sk_ng, pk_ng) = ng::XWingDraft06::generate(&mut os.unwrap_mut()).unwrap();
	let (enc_ng, _ctx_ng) =
		Suite::setup_sender_base(&mut os.unwrap_mut(), &pk_ng, b"info").unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::XWingDraft06,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::ChaCha20Poly1305,
	);
	let (sk_rs, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();
	rs.seed(SEED).unwrap();
	let (enc_rs, _ctx_rs) = rs.setup_sender(&pk_rs, b"info", None, None, None).unwrap();

	let mut g = c.benchmark_group("xwing_chacha20/setup_sender_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| {
			let mut os = OsRng;
			Suite::setup_sender_base(&mut os.unwrap_mut(), black_box(&pk_ng), b"info").unwrap()
		})
	});
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.seed(SEED).unwrap();
			rs.setup_sender(black_box(&pk_rs), b"info", None, None, None)
				.unwrap()
		})
	});
	g.finish();

	let mut g = c.benchmark_group("xwing_chacha20/setup_receiver_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_receiver_base(black_box(&enc_ng), &sk_ng, b"info").unwrap())
	});
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.setup_receiver(black_box(&enc_rs), &sk_rs, b"info", None, None, None)
				.unwrap()
		})
	});
	g.finish();
}

fn bench_setup_mlkem768_chacha(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::MlKem768, ng::HkdfSha256, ng::ChaCha20Poly1305>;
	let mut os = OsRng;
	let (sk_ng, pk_ng) = ng::MlKem768::generate(&mut os.unwrap_mut()).unwrap();
	let (enc_ng, _ctx_ng) =
		Suite::setup_sender_base(&mut os.unwrap_mut(), &pk_ng, b"info").unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::MlKem768,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::ChaCha20Poly1305,
	);
	let (sk_rs, pk_rs) = rs.derive_key_pair(&[0x42u8; 64]).unwrap().into_keys();
	rs.seed(SEED).unwrap();
	let (enc_rs, _ctx_rs) = rs.setup_sender(&pk_rs, b"info", None, None, None).unwrap();

	let mut g = c.benchmark_group("mlkem768_chacha20/setup_sender_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| {
			let mut os = OsRng;
			Suite::setup_sender_base(&mut os.unwrap_mut(), black_box(&pk_ng), b"info").unwrap()
		})
	});
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.seed(SEED).unwrap();
			rs.setup_sender(black_box(&pk_rs), b"info", None, None, None)
				.unwrap()
		})
	});
	g.finish();

	let mut g = c.benchmark_group("mlkem768_chacha20/setup_receiver_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_receiver_base(black_box(&enc_ng), &sk_ng, b"info").unwrap())
	});
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.setup_receiver(black_box(&enc_rs), &sk_rs, b"info", None, None, None)
				.unwrap()
		})
	});
	g.finish();
}

fn bench_setup_mlkem1024_chacha(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::MlKem1024, ng::HkdfSha256, ng::ChaCha20Poly1305>;
	let mut os = OsRng;
	let (sk_ng, pk_ng) = ng::MlKem1024::generate(&mut os.unwrap_mut()).unwrap();
	let (enc_ng, _ctx_ng) =
		Suite::setup_sender_base(&mut os.unwrap_mut(), &pk_ng, b"info").unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::MlKem1024,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::ChaCha20Poly1305,
	);
	let (sk_rs, pk_rs) = rs.derive_key_pair(&[0x42u8; 64]).unwrap().into_keys();
	rs.seed(SEED).unwrap();
	let (enc_rs, _ctx_rs) = rs.setup_sender(&pk_rs, b"info", None, None, None).unwrap();

	let mut g = c.benchmark_group("mlkem1024_chacha20/setup_sender_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| {
			let mut os = OsRng;
			Suite::setup_sender_base(&mut os.unwrap_mut(), black_box(&pk_ng), b"info").unwrap()
		})
	});
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.seed(SEED).unwrap();
			rs.setup_sender(black_box(&pk_rs), b"info", None, None, None)
				.unwrap()
		})
	});
	g.finish();

	let mut g = c.benchmark_group("mlkem1024_chacha20/setup_receiver_base");
	g.bench_function("hpke_ng", |b| {
		b.iter(|| Suite::setup_receiver_base(black_box(&enc_ng), &sk_ng, b"info").unwrap())
	});
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.setup_receiver(black_box(&enc_rs), &sk_rs, b"info", None, None, None)
				.unwrap()
		})
	});
	g.finish();
}

// =============================================================================
//  Single-shot seal: throughput across many payload sizes
//  (the marquee chart — log-scale payload axis)
// =============================================================================

fn bench_seal_x25519_chacha_payload_sweep(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::DhKemX25519HkdfSha256, ng::HkdfSha256, ng::ChaCha20Poly1305>;
	let mut os = OsRng;
	let (_, pk_ng) = ng::DhKemX25519HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKem25519,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::ChaCha20Poly1305,
	);
	let (_, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();

	let (_, pk) = RhX25519::gen_keypair(&mut os.unwrap_mut());

	let mut g = c.benchmark_group("x25519_chacha20_seal_sweep");
	g.measurement_time(Duration::from_secs(2));
	g.sample_size(40);

	for &size in PAYLOAD_SIZES {
		let pt = vec![0xAAu8; size];
		g.throughput(Throughput::Bytes(size as u64));
		g.bench_with_input(BenchmarkId::new("hpke_ng", size), &size, |b, _| {
			b.iter(|| {
				let mut os = OsRng;
				Suite::seal_base(
					&mut os.unwrap_mut(),
					&pk_ng,
					b"info",
					b"aad",
					black_box(&pt),
				)
				.unwrap()
			})
		});
		g.bench_with_input(BenchmarkId::new("hpke_rs", size), &size, |b, _| {
			b.iter(|| {
				rs.seed(SEED).unwrap();
				rs.seal(&pk_rs, b"info", b"aad", black_box(&pt), None, None, None)
					.unwrap()
			})
		});
		g.bench_with_input(BenchmarkId::new("rust_hpke", size), &size, |b, _| {
			b.iter(|| {
				let mut os = OsRng;
				let (_enc, mut ctx) = hpke::setup_sender::<RhChaCha20, RhHkdfSha256, RhX25519, _>(
					&OpModeS::Base,
					&pk,
					b"info",
					&mut os.unwrap_mut(),
				)
				.unwrap();
				ctx.seal(black_box(&pt), b"aad").unwrap()
			})
		});
	}
	g.finish();
}

// Same sweep with AES-128-GCM (different AEAD primitive)
fn bench_seal_x25519_aes128_payload_sweep(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::DhKemX25519HkdfSha256, ng::HkdfSha256, ng::Aes128Gcm>;
	let mut os = OsRng;
	let (_, pk_ng) = ng::DhKemX25519HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKem25519,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::Aes128Gcm,
	);
	let (_, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();

	let (_, pk) = RhX25519::gen_keypair(&mut os.unwrap_mut());

	let mut g = c.benchmark_group("x25519_aes128_seal_sweep");
	g.measurement_time(Duration::from_secs(2));
	g.sample_size(40);
	for &size in &[64usize, 256, 1024, 4096, 16384, 65536] {
		let pt = vec![0xAAu8; size];
		g.throughput(Throughput::Bytes(size as u64));
		g.bench_with_input(BenchmarkId::new("hpke_ng", size), &size, |b, _| {
			b.iter(|| {
				let mut os = OsRng;
				Suite::seal_base(
					&mut os.unwrap_mut(),
					&pk_ng,
					b"info",
					b"aad",
					black_box(&pt),
				)
				.unwrap()
			})
		});
		g.bench_with_input(BenchmarkId::new("hpke_rs", size), &size, |b, _| {
			b.iter(|| {
				rs.seed(SEED).unwrap();
				rs.seal(&pk_rs, b"info", b"aad", black_box(&pt), None, None, None)
					.unwrap()
			})
		});
		g.bench_with_input(BenchmarkId::new("rust_hpke", size), &size, |b, _| {
			b.iter(|| {
				let mut os = OsRng;
				let (_enc, mut ctx) = hpke::setup_sender::<RhAes128, RhHkdfSha256, RhX25519, _>(
					&OpModeS::Base,
					&pk,
					b"info",
					&mut os.unwrap_mut(),
				)
				.unwrap();
				ctx.seal(black_box(&pt), b"aad").unwrap()
			})
		});
	}
	g.finish();
}

// =============================================================================
//  Single-shot open path
// =============================================================================

fn bench_open_x25519_chacha_payload_sweep(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::DhKemX25519HkdfSha256, ng::HkdfSha256, ng::ChaCha20Poly1305>;

	let mut os = OsRng;
	let (sk_ng, pk_ng) = ng::DhKemX25519HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKem25519,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::ChaCha20Poly1305,
	);
	let (sk_rs, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();

	let (sk, pk) = RhX25519::gen_keypair(&mut os.unwrap_mut());

	let mut g = c.benchmark_group("x25519_chacha20_open_sweep");
	g.measurement_time(Duration::from_secs(2));
	g.sample_size(40);
	for &size in &[64usize, 256, 1024, 4096, 16384, 65536] {
		let pt = vec![0xAAu8; size];
		// Pre-seal one message with each library to use as the open input.
		let (enc_ng, ct_ng) =
			Suite::seal_base(&mut os.unwrap_mut(), &pk_ng, b"info", b"aad", &pt).unwrap();

		rs.seed(SEED).unwrap();
		let (enc_rs, ct_rs) = rs
			.seal(&pk_rs, b"info", b"aad", &pt, None, None, None)
			.unwrap();

		let (enc, mut ctx_s) = hpke::setup_sender::<RhChaCha20, RhHkdfSha256, RhX25519, _>(
			&OpModeS::Base,
			&pk,
			b"info",
			&mut os.unwrap_mut(),
		)
		.unwrap();
		let ct = ctx_s.seal(&pt, b"aad").unwrap();

		g.throughput(Throughput::Bytes(size as u64));
		g.bench_with_input(BenchmarkId::new("hpke_ng", size), &size, |b, _| {
			b.iter(|| {
				Suite::open_base(
					black_box(&enc_ng),
					&sk_ng,
					b"info",
					b"aad",
					black_box(&ct_ng),
				)
				.unwrap()
			})
		});
		g.bench_with_input(BenchmarkId::new("hpke_rs", size), &size, |b, _| {
			b.iter(|| {
				let mut ctx = rs
					.setup_receiver(black_box(&enc_rs), &sk_rs, b"info", None, None, None)
					.unwrap();
				ctx.open(b"aad", black_box(&ct_rs)).unwrap()
			})
		});
		g.bench_with_input(BenchmarkId::new("rust_hpke", size), &size, |b, _| {
			b.iter(|| {
				let mut ctx_r = hpke::setup_receiver::<RhChaCha20, RhHkdfSha256, RhX25519>(
					&OpModeR::Base,
					black_box(&sk),
					black_box(&enc),
					b"info",
				)
				.unwrap();
				ctx_r.open(black_box(&ct), b"aad").unwrap()
			})
		});
	}
	g.finish();
}

// =============================================================================
//  Context seal (post-setup, pure framing+AEAD path)
// =============================================================================

fn bench_context_seal_x25519_chacha(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::DhKemX25519HkdfSha256, ng::HkdfSha256, ng::ChaCha20Poly1305>;
	let mut os = OsRng;
	let (_, pk_ng) = ng::DhKemX25519HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();
	let (_, mut ctx_ng) = Suite::setup_sender_base(&mut os.unwrap_mut(), &pk_ng, b"info").unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKem25519,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::ChaCha20Poly1305,
	);
	let (_, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();
	rs.seed(SEED).unwrap();
	let (_enc, mut ctx_rs) = rs.setup_sender(&pk_rs, b"info", None, None, None).unwrap();

	let (_, pk) = RhX25519::gen_keypair(&mut os.unwrap_mut());
	let (_, mut ctx_rh) = hpke::setup_sender::<RhChaCha20, RhHkdfSha256, RhX25519, _>(
		&OpModeS::Base,
		&pk,
		b"info",
		&mut os.unwrap_mut(),
	)
	.unwrap();

	let mut g = c.benchmark_group("x25519_chacha20_context_seal");
	g.measurement_time(Duration::from_secs(2));
	g.sample_size(50);
	for &size in &[64usize, 1024, 16384, 65536] {
		let pt = vec![0xAAu8; size];
		g.throughput(Throughput::Bytes(size as u64));
		g.bench_with_input(BenchmarkId::new("hpke_ng", size), &size, |b, _| {
			b.iter(|| ctx_ng.seal(b"aad", black_box(&pt)).unwrap())
		});
		g.bench_with_input(BenchmarkId::new("hpke_rs", size), &size, |b, _| {
			b.iter(|| ctx_rs.seal(b"aad", black_box(&pt)).unwrap())
		});
		g.bench_with_input(BenchmarkId::new("rust_hpke", size), &size, |b, _| {
			b.iter(|| ctx_rh.seal(black_box(&pt), b"aad").unwrap())
		});
	}
	g.finish();
}

// =============================================================================
//  Export
// =============================================================================

fn bench_export(c: &mut Criterion) {
	// Note that export in `rust-hpke` is done via `AeadCtxS::export`,
	// which takes a label and a mutable output buffer, not a length, making
	// its export API is incompatible. `rust-hpke` will be omitted from this benchmark.
	type Suite = ng::Hpke<ng::DhKemX25519HkdfSha256, ng::HkdfSha256, ng::ChaCha20Poly1305>;
	let mut os = OsRng;
	let (_, pk_ng) = ng::DhKemX25519HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();
	let (_enc, ctx_ng) = Suite::setup_sender_base(&mut os.unwrap_mut(), &pk_ng, b"info").unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKem25519,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::ChaCha20Poly1305,
	);
	let (_, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();
	rs.seed(SEED).unwrap();
	let (_enc_rs, ctx_rs) = rs.setup_sender(&pk_rs, b"info", None, None, None).unwrap();

	let mut g = c.benchmark_group("x25519_chacha20_export");
	g.measurement_time(Duration::from_secs(2));
	g.sample_size(60);
	for &len in EXPORT_LENGTHS {
		g.bench_with_input(BenchmarkId::new("hpke_ng", len), &len, |b, _| {
			b.iter(|| ctx_ng.export(b"export-context", *black_box(&len)).unwrap())
		});
		g.bench_with_input(BenchmarkId::new("hpke_rs", len), &len, |b, _| {
			b.iter(|| ctx_rs.export(b"export-context", *black_box(&len)).unwrap())
		});
	}
	g.finish();
}

// =============================================================================
//  End-to-end round-trip: encrypt + decrypt one 1 KiB message
// =============================================================================

fn bench_roundtrip(c: &mut Criterion) {
	type Suite = ng::Hpke<ng::DhKemX25519HkdfSha256, ng::HkdfSha256, ng::ChaCha20Poly1305>;
	let mut os = OsRng;
	let (sk_ng, pk_ng) = ng::DhKemX25519HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();

	let mut rs = HpkeRs::<HpkeRustCrypto>::new(
		Mode::Base,
		rs_types::KemAlgorithm::DhKem25519,
		rs_types::KdfAlgorithm::HkdfSha256,
		rs_types::AeadAlgorithm::ChaCha20Poly1305,
	);
	let (sk_rs, pk_rs) = rs.derive_key_pair(&[0x42u8; 32]).unwrap().into_keys();

	let (sk, pk) = RhX25519::gen_keypair(&mut os.unwrap_mut());

	let pt = vec![0xAAu8; 1024];

	let mut g = c.benchmark_group("x25519_chacha20_roundtrip_1k");
	g.measurement_time(Duration::from_secs(3));
	g.sample_size(50);
	g.bench_function("hpke_ng", |b| {
		b.iter(|| {
			let mut os = OsRng;
			let (enc, ct) = Suite::seal_base(
				&mut os.unwrap_mut(),
				&pk_ng,
				b"info",
				b"aad",
				black_box(&pt),
			)
			.unwrap();
			Suite::open_base(&enc, &sk_ng, b"info", b"aad", &ct).unwrap()
		})
	});
	g.bench_function("hpke_rs", |b| {
		b.iter(|| {
			rs.seed(SEED).unwrap();
			let (enc, ct) = rs
				.seal(&pk_rs, b"info", b"aad", black_box(&pt), None, None, None)
				.unwrap();
			let mut ctx = rs
				.setup_receiver(&enc, &sk_rs, b"info", None, None, None)
				.unwrap();
			ctx.open(b"aad", &ct).unwrap()
		})
	});
	g.bench_function("rust_hpke", |b| {
		b.iter(|| {
			let mut os = OsRng;
			let (enc, mut ctx_s) = hpke::setup_sender::<RhChaCha20, RhHkdfSha256, RhX25519, _>(
				&OpModeS::Base,
				&pk,
				b"info",
				&mut os.unwrap_mut(),
			)
			.unwrap();
			let ct = ctx_s.seal(black_box(&pt), b"aad").unwrap();
			let mut ctx_r = hpke::setup_receiver::<RhChaCha20, RhHkdfSha256, RhX25519>(
				&OpModeR::Base,
				&sk,
				&enc,
				b"info",
			)
			.unwrap();
			ctx_r.open(&ct, b"aad").unwrap()
		})
	});
	g.finish();
}

criterion_group! {
	name = benches;
	config = quick(&mut Criterion::default());
	targets =
		bench_kem_x25519,
		bench_kem_p256,
		bench_kem_k256,
		bench_kem_xwing,
		bench_kem_mlkem768,
		bench_kem_mlkem1024,
		bench_setup_x25519_chacha,
		bench_setup_x25519_aes128,
		bench_setup_x25519_aes256,
		bench_setup_p256_aes128,
		bench_setup_p256_aes256,
		bench_setup_k256_chacha,
		bench_setup_xwing_chacha,
		bench_setup_mlkem768_chacha,
		bench_setup_mlkem1024_chacha,
		bench_seal_x25519_chacha_payload_sweep,
		bench_seal_x25519_aes128_payload_sweep,
		bench_open_x25519_chacha_payload_sweep,
		bench_context_seal_x25519_chacha,
		bench_export,
		bench_roundtrip,
}
criterion_main!(benches);
