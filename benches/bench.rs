//! Criterion benchmark suite for hpke-ng.
//!
//! Mirrors the operation list and input sizes from
//! `hpke-rs/benches/manual_benches.rs` so reports are directly comparable.
//!
//! Run with: `cargo bench --bench bench`.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use hpke_ng::{kem::AuthKem, *};
use rand_core::{OsRng, TryRngCore as _};

type X25519Suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>;

fn bench_kem(c: &mut Criterion) {
	let mut g = c.benchmark_group("kem");

	g.bench_function("x25519/generate", |b| {
		b.iter(|| {
			let mut os = OsRng;
			DhKemX25519HkdfSha256::generate(&mut os.unwrap_mut()).unwrap()
		})
	});

	g.bench_function("x25519/derive_key_pair", |b| {
		let ikm = [0u8; 32];
		b.iter(|| DhKemX25519HkdfSha256::derive_key_pair(black_box(&ikm)).unwrap())
	});

	{
		let mut os = OsRng;
		let (_, pk) = DhKemX25519HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();
		g.bench_function("x25519/encap", |b| {
			b.iter(|| {
				let mut os = OsRng;
				DhKemX25519HkdfSha256::encap(&mut os.unwrap_mut(), black_box(&pk)).unwrap()
			})
		});

		let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();
		let (_, enc) = DhKemX25519HkdfSha256::encap(&mut os.unwrap_mut(), &pk_r).unwrap();
		g.bench_function("x25519/decap", |b| {
			b.iter(|| DhKemX25519HkdfSha256::decap(black_box(&enc), &sk_r).unwrap())
		});
	}

	{
		let mut os = OsRng;
		let (sk_s, _) = DhKemX25519HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();
		let (_, pk_r) = DhKemX25519HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();
		g.bench_function("x25519/auth_encap", |b| {
			b.iter(|| {
				let mut os = OsRng;
				DhKemX25519HkdfSha256::auth_encap(&mut os.unwrap_mut(), black_box(&pk_r), &sk_s)
					.unwrap()
			})
		});

		let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();
		let (sk_s, pk_s) = DhKemX25519HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();
		let (_, enc) =
			DhKemX25519HkdfSha256::auth_encap(&mut os.unwrap_mut(), &pk_r, &sk_s).unwrap();
		g.bench_function("x25519/auth_decap", |b| {
			b.iter(|| DhKemX25519HkdfSha256::auth_decap(black_box(&enc), &sk_r, &pk_s).unwrap())
		});
	}

	g.bench_function("p256/generate", |b| {
		b.iter(|| {
			let mut os = OsRng;
			DhKemP256HkdfSha256::generate(&mut os.unwrap_mut()).unwrap()
		})
	});

	{
		let mut os = OsRng;
		let (_, pk) = DhKemP256HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();
		g.bench_function("p256/encap", |b| {
			b.iter(|| {
				let mut os = OsRng;
				DhKemP256HkdfSha256::encap(&mut os.unwrap_mut(), black_box(&pk)).unwrap()
			})
		});
	}

	g.finish();
}

fn bench_setup(c: &mut Criterion) {
	let mut g = c.benchmark_group("setup");
	let mut os = OsRng;
	let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();

	g.bench_function("x25519_chacha/setup_sender_base", |b| {
		b.iter(|| {
			let mut os = OsRng;
			X25519Suite::setup_sender_base(&mut os.unwrap_mut(), &pk_r, b"info").unwrap()
		})
	});

	{
		let (enc, _ctx) =
			X25519Suite::setup_sender_base(&mut os.unwrap_mut(), &pk_r, b"info").unwrap();
		g.bench_function("x25519_chacha/setup_receiver_base", |b| {
			b.iter(|| X25519Suite::setup_receiver_base(black_box(&enc), &sk_r, b"info").unwrap())
		});
	}

	g.finish();
}

fn bench_seal_open(c: &mut Criterion) {
	let mut g = c.benchmark_group("seal_open");
	let mut os = OsRng;
	let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();

	for &size in &[64usize, 1024, 16384] {
		let pt = vec![0xAAu8; size];

		g.throughput(Throughput::Bytes(size as u64));
		g.bench_with_input(
			BenchmarkId::new("x25519_chacha/seal", size),
			&pt,
			|b, pt| {
				b.iter(|| {
					let mut os = OsRng;
					X25519Suite::seal_base(
						&mut os.unwrap_mut(),
						&pk_r,
						b"info",
						b"aad",
						black_box(pt),
					)
					.unwrap()
				})
			},
		);

		let (enc, ct) =
			X25519Suite::seal_base(&mut os.unwrap_mut(), &pk_r, b"info", b"aad", &pt).unwrap();
		g.bench_with_input(
			BenchmarkId::new("x25519_chacha/open", size),
			&ct,
			|b, ct| {
				b.iter(|| {
					X25519Suite::open_base(black_box(&enc), &sk_r, b"info", b"aad", black_box(ct))
						.unwrap()
				})
			},
		);
	}

	{
		let (_, mut sender) =
			X25519Suite::setup_sender_base(&mut os.unwrap_mut(), &pk_r, b"info").unwrap();
		for &size in &[64usize, 1024, 16384] {
			let pt = vec![0xAAu8; size];
			g.throughput(Throughput::Bytes(size as u64));
			g.bench_with_input(
				BenchmarkId::new("x25519_chacha/ctx_seal", size),
				&pt,
				|b, pt| b.iter(|| sender.seal(b"aad", black_box(pt)).unwrap()),
			);
		}
	}

	g.finish();
}

fn bench_export(c: &mut Criterion) {
	let mut g = c.benchmark_group("export");
	let mut os = OsRng;
	let (_sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut os.unwrap_mut()).unwrap();
	let (_enc, ctx) = X25519Suite::setup_sender_base(&mut os.unwrap_mut(), &pk_r, b"info").unwrap();

	for &len in &[32usize, 64, 128] {
		g.bench_with_input(
			BenchmarkId::new("x25519_chacha/export", len),
			&len,
			|b, l| b.iter(|| ctx.export(b"ctx", *l).unwrap()),
		);
	}

	g.finish();
}

criterion_group!(
	benches,
	bench_kem,
	bench_setup,
	bench_seal_open,
	bench_export
);
criterion_main!(benches);
