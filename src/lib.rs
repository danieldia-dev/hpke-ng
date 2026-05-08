//! `hpke-ng` — RFC 9180 HPKE implementation.
//!
//! ## Example
//!
//! ```
//! use hpke_ng::*;
//! use rand_core::{OsRng, TryRngCore as _};
//!
//! type Suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>;
//!
//! let mut os = OsRng;
//! let mut rng = os.unwrap_mut();
//! let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
//! let (enc, ct) =
//!     Suite::seal_base(&mut rng, &pk_r, b"info", b"aad", b"hello").unwrap();
//! let pt = Suite::open_base(&enc, &sk_r, b"info", b"aad", &ct).unwrap();
//! assert_eq!(pt, b"hello");
//! ```
//!
//! See the [Readme](https://github.com/symbolicsoft/hpke-ng) for design notes
//! and the constant-time disclosure table.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code, unstable_features)]
#![deny(
	missing_docs,
	rustdoc::broken_intra_doc_links,
	rustdoc::private_intra_doc_links,
	trivial_casts,
	trivial_numeric_casts,
	unused_must_use,
	unused_import_braces,
	unused_qualifications,
	clippy::pedantic
)]
#![allow(
	clippy::module_name_repetitions,
	clippy::missing_errors_doc,
	clippy::type_complexity,
	unused_extern_crates
)]

extern crate alloc;

mod aead;
mod error;
mod kdf;
mod sealed;

pub mod kem;

pub use aead::{Aead, Aes128Gcm, Aes256Gcm, ChaCha20Poly1305, ExportOnly, SealingAead};
pub use error::HpkeError;
pub use kdf::{HkdfSha256, HkdfSha384, HkdfSha512, Kdf};
pub use kem::{
	AuthKem, Kem,
	dh::{
		DhKemK256HkdfSha256, DhKemP256HkdfSha256, DhKemP384HkdfSha384, DhKemP521HkdfSha512,
		DhKemX448HkdfSha512, DhKemX25519HkdfSha256,
	},
};

#[cfg(feature = "pq")]
pub use kem::pq::{MlKem768, MlKem1024, XWingDraft06};

mod context;

pub use context::Context;

use alloc::vec::Vec;
use core::marker::PhantomData;

use zeroize::Zeroizing;

use crate::kdf::{labeled_expand, labeled_extract};

/// HPKE configuration parameterized over a KEM, KDF, and AEAD.
///
/// `Hpke` is a zero-sized type. All operations are associated functions; there
/// is no instance state and no PRNG owned by the configuration.
///
/// # Example
///
/// ```no_run
/// use hpke_ng::*;
/// use rand_core::{OsRng, TryRngCore as _};
///
/// type Suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>;
///
/// let mut os = OsRng;
/// let mut rng = os.unwrap_mut();
/// let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
/// let (enc, ct) =
///     Suite::seal_base(&mut rng, &pk_r, b"info", b"aad", b"hello").unwrap();
/// let pt = Suite::open_base(&enc, &sk_r, b"info", b"aad", &ct).unwrap();
/// assert_eq!(pt, b"hello");
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Hpke<K: Kem, F: Kdf, A: Aead>(PhantomData<(K, F, A)>);

pub(crate) mod modes {
	pub const BASE: u8 = 0x00;
	pub const PSK: u8 = 0x01;
	pub const AUTH: u8 = 0x02;
	pub const AUTH_PSK: u8 = 0x03;
}

#[inline]
pub(crate) fn ciphersuite<K: Kem, F: Kdf, A: Aead>() -> [u8; 10] {
	let mut s = [0u8; 10];
	s[..4].copy_from_slice(b"HPKE");
	s[4..6].copy_from_slice(&K::ID.to_be_bytes());
	s[6..8].copy_from_slice(&F::ID.to_be_bytes());
	s[8..10].copy_from_slice(&A::ID.to_be_bytes());
	s
}

#[inline]
fn verify_psk_inputs(mode: u8, psk: &[u8], psk_id: &[u8]) -> Result<(), HpkeError> {
	let got_psk = !psk.is_empty();
	let got_psk_id = !psk_id.is_empty();
	if got_psk != got_psk_id {
		return Err(HpkeError::InconsistentPsk);
	}
	if got_psk && (mode == modes::BASE || mode == modes::AUTH) {
		return Err(HpkeError::UnnecessaryPsk);
	}
	if !got_psk && (mode == modes::PSK || mode == modes::AUTH_PSK) {
		return Err(HpkeError::MissingPsk);
	}
	if got_psk && psk.len() < 32 {
		return Err(HpkeError::InsecurePsk);
	}
	Ok(())
}

#[cfg(not(feature = "kat-internals"))]
pub(crate) fn key_schedule<K: Kem, F: Kdf, A: Aead>(
	mode: u8,
	shared_secret: &[u8],
	info: &[u8],
	psk: &[u8],
	psk_id: &[u8],
) -> Result<Context<K, F, A>, HpkeError> {
	key_schedule_inner::<K, F, A>(mode, shared_secret, info, psk, psk_id)
}

#[cfg(feature = "kat-internals")]
#[doc(hidden)]
pub fn key_schedule<K: Kem, F: Kdf, A: Aead>(
	mode: u8,
	shared_secret: &[u8],
	info: &[u8],
	psk: &[u8],
	psk_id: &[u8],
) -> Result<Context<K, F, A>, HpkeError> {
	key_schedule_inner::<K, F, A>(mode, shared_secret, info, psk, psk_id)
}

fn key_schedule_inner<K: Kem, F: Kdf, A: Aead>(
	mode: u8,
	shared_secret: &[u8],
	info: &[u8],
	psk: &[u8],
	psk_id: &[u8],
) -> Result<Context<K, F, A>, HpkeError> {
	verify_psk_inputs(mode, psk, psk_id)?;
	let suite = ciphersuite::<K, F, A>();
	let psk_id_hash = labeled_extract::<F>(&[], &suite, b"psk_id_hash", psk_id);
	let info_hash = labeled_extract::<F>(&[], &suite, b"info_hash", info);

	let mut ks_ctx = Vec::with_capacity(1 + psk_id_hash.len() + info_hash.len());
	ks_ctx.push(mode);
	ks_ctx.extend_from_slice(&psk_id_hash);
	ks_ctx.extend_from_slice(&info_hash);

	let secret = Zeroizing::new(labeled_extract::<F>(shared_secret, &suite, b"secret", psk));
	let key = labeled_expand::<F>(&secret, &suite, b"key", &ks_ctx, A::KEY_LEN)?;
	let base_nonce = labeled_expand::<F>(&secret, &suite, b"base_nonce", &ks_ctx, A::NONCE_LEN)?;
	let exporter_secret = labeled_expand::<F>(&secret, &suite, b"exp", &ks_ctx, F::HASH_LEN)?;

	Ok(Context::new(key, base_nonce, exporter_secret))
}

#[cfg(test)]
mod ks_tests {
	use super::*;

	#[test]
	fn psk_validation_inconsistent() {
		let r = verify_psk_inputs(modes::PSK, b"", b"some_id");
		assert_eq!(r, Err(HpkeError::InconsistentPsk));
		let r = verify_psk_inputs(modes::PSK, &[0u8; 32], b"");
		assert_eq!(r, Err(HpkeError::InconsistentPsk));
	}

	#[test]
	fn psk_validation_missing() {
		let r = verify_psk_inputs(modes::PSK, b"", b"");
		assert_eq!(r, Err(HpkeError::MissingPsk));
	}

	#[test]
	fn psk_validation_unnecessary() {
		let r = verify_psk_inputs(modes::BASE, &[0u8; 32], b"id");
		assert_eq!(r, Err(HpkeError::UnnecessaryPsk));
	}

	#[test]
	fn psk_validation_too_short() {
		let r = verify_psk_inputs(modes::PSK, b"too short", b"id");
		assert_eq!(r, Err(HpkeError::InsecurePsk));
	}

	#[test]
	fn psk_validation_ok() {
		assert!(verify_psk_inputs(modes::BASE, b"", b"").is_ok());
		assert!(verify_psk_inputs(modes::PSK, &[0u8; 32], b"id").is_ok());
	}
}

use rand_core::{CryptoRng, RngCore};

impl<K: Kem, F: Kdf, A: Aead> Hpke<K, F, A> {
	/// `SetupBaseS` (RFC 9180 §5.1.1).
	pub fn setup_sender_base<R: CryptoRng + RngCore>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
	) -> Result<(K::EncappedKey, Context<K, F, A>), HpkeError> {
		let (ss, enc) = K::encap(rng, pk_r)?;
		let ctx = key_schedule::<K, F, A>(modes::BASE, ss.as_ref(), info, &[], &[])?;
		Ok((enc, ctx))
	}

	/// `SetupBaseR` (RFC 9180 §5.1.1).
	pub fn setup_receiver_base(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
	) -> Result<Context<K, F, A>, HpkeError> {
		let ss = K::decap(enc, sk_r)?;
		key_schedule::<K, F, A>(modes::BASE, ss.as_ref(), info, &[], &[])
	}

	/// `SetupPSKS` (RFC 9180 §5.1.2).
	///
	/// `psk` MUST be at least 32 bytes of high-entropy random data. Length is
	/// enforced; entropy is the caller's responsibility — see
	/// [`HpkeError::InsecurePsk`].
	pub fn setup_sender_psk<R: CryptoRng + RngCore>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		psk: &[u8],
		psk_id: &[u8],
	) -> Result<(K::EncappedKey, Context<K, F, A>), HpkeError> {
		let (ss, enc) = K::encap(rng, pk_r)?;
		let ctx = key_schedule::<K, F, A>(modes::PSK, ss.as_ref(), info, psk, psk_id)?;
		Ok((enc, ctx))
	}

	/// `SetupPSKR` (RFC 9180 §5.1.2).
	///
	/// `psk` MUST be at least 32 bytes of high-entropy random data. Length is
	/// enforced; entropy is the caller's responsibility — see
	/// [`HpkeError::InsecurePsk`].
	pub fn setup_receiver_psk(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		psk: &[u8],
		psk_id: &[u8],
	) -> Result<Context<K, F, A>, HpkeError> {
		let ss = K::decap(enc, sk_r)?;
		key_schedule::<K, F, A>(modes::PSK, ss.as_ref(), info, psk, psk_id)
	}
}

impl<K: Kem, F: Kdf, A: SealingAead> Hpke<K, F, A> {
	/// Single-shot Base-mode encrypt (RFC 9180 §6.1).
	pub fn seal_base<R: CryptoRng + RngCore>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		aad: &[u8],
		pt: &[u8],
	) -> Result<(K::EncappedKey, Vec<u8>), HpkeError> {
		let (enc, mut ctx) = Self::setup_sender_base(rng, pk_r, info)?;
		let ct = ctx.seal(aad, pt)?;
		Ok((enc, ct))
	}

	/// Single-shot Base-mode decrypt (RFC 9180 §6.1).
	pub fn open_base(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		aad: &[u8],
		ct: &[u8],
	) -> Result<Vec<u8>, HpkeError> {
		let mut ctx = Self::setup_receiver_base(enc, sk_r, info)?;
		ctx.open(aad, ct)
	}

	/// Single-shot Psk-mode encrypt (RFC 9180 §6.1).
	#[allow(clippy::too_many_arguments)]
	pub fn seal_psk<R: CryptoRng + RngCore>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		aad: &[u8],
		pt: &[u8],
		psk: &[u8],
		psk_id: &[u8],
	) -> Result<(K::EncappedKey, Vec<u8>), HpkeError> {
		let (enc, mut ctx) = Self::setup_sender_psk(rng, pk_r, info, psk, psk_id)?;
		let ct = ctx.seal(aad, pt)?;
		Ok((enc, ct))
	}

	/// Single-shot Psk-mode decrypt (RFC 9180 §6.1).
	#[allow(clippy::too_many_arguments)]
	pub fn open_psk(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		aad: &[u8],
		ct: &[u8],
		psk: &[u8],
		psk_id: &[u8],
	) -> Result<Vec<u8>, HpkeError> {
		let mut ctx = Self::setup_receiver_psk(enc, sk_r, info, psk, psk_id)?;
		ctx.open(aad, ct)
	}
}

impl<K: AuthKem, F: Kdf, A: SealingAead> Hpke<K, F, A> {
	/// Single-shot Auth-mode encrypt (RFC 9180 §6.1).
	pub fn seal_auth<R: CryptoRng + RngCore>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		aad: &[u8],
		pt: &[u8],
		sk_s: &K::PrivateKey,
	) -> Result<(K::EncappedKey, Vec<u8>), HpkeError> {
		let (enc, mut ctx) = Self::setup_sender_auth(rng, pk_r, info, sk_s)?;
		let ct = ctx.seal(aad, pt)?;
		Ok((enc, ct))
	}

	/// Single-shot Auth-mode decrypt (RFC 9180 §6.1).
	pub fn open_auth(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		aad: &[u8],
		ct: &[u8],
		pk_s: &K::PublicKey,
	) -> Result<Vec<u8>, HpkeError> {
		let mut ctx = Self::setup_receiver_auth(enc, sk_r, info, pk_s)?;
		ctx.open(aad, ct)
	}

	/// Single-shot AuthPsk-mode encrypt (RFC 9180 §6.1).
	#[allow(clippy::too_many_arguments)]
	pub fn seal_auth_psk<R: CryptoRng + RngCore>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		aad: &[u8],
		pt: &[u8],
		psk: &[u8],
		psk_id: &[u8],
		sk_s: &K::PrivateKey,
	) -> Result<(K::EncappedKey, Vec<u8>), HpkeError> {
		let (enc, mut ctx) = Self::setup_sender_auth_psk(rng, pk_r, info, psk, psk_id, sk_s)?;
		let ct = ctx.seal(aad, pt)?;
		Ok((enc, ct))
	}

	/// Single-shot AuthPsk-mode decrypt (RFC 9180 §6.1).
	#[allow(clippy::too_many_arguments)]
	pub fn open_auth_psk(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		aad: &[u8],
		ct: &[u8],
		psk: &[u8],
		psk_id: &[u8],
		pk_s: &K::PublicKey,
	) -> Result<Vec<u8>, HpkeError> {
		let mut ctx = Self::setup_receiver_auth_psk(enc, sk_r, info, psk, psk_id, pk_s)?;
		ctx.open(aad, ct)
	}
}

impl<K: Kem, F: Kdf, A: Aead> Hpke<K, F, A> {
	/// Sender-side single-shot export — Base mode (RFC 9180 §6.2).
	pub fn send_export_base<R: CryptoRng + RngCore>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		exporter_context: &[u8],
		length: usize,
	) -> Result<(K::EncappedKey, Vec<u8>), HpkeError> {
		let (enc, ctx) = Self::setup_sender_base(rng, pk_r, info)?;
		Ok((enc, ctx.export(exporter_context, length)?))
	}

	/// Receiver-side single-shot export — Base mode.
	pub fn receiver_export_base(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		exporter_context: &[u8],
		length: usize,
	) -> Result<Vec<u8>, HpkeError> {
		let ctx = Self::setup_receiver_base(enc, sk_r, info)?;
		ctx.export(exporter_context, length)
	}

	/// Sender-side single-shot export — Psk mode.
	#[allow(clippy::too_many_arguments)]
	pub fn send_export_psk<R: CryptoRng + RngCore>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		psk: &[u8],
		psk_id: &[u8],
		exporter_context: &[u8],
		length: usize,
	) -> Result<(K::EncappedKey, Vec<u8>), HpkeError> {
		let (enc, ctx) = Self::setup_sender_psk(rng, pk_r, info, psk, psk_id)?;
		Ok((enc, ctx.export(exporter_context, length)?))
	}

	/// Receiver-side single-shot export — Psk mode.
	#[allow(clippy::too_many_arguments)]
	pub fn receiver_export_psk(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		psk: &[u8],
		psk_id: &[u8],
		exporter_context: &[u8],
		length: usize,
	) -> Result<Vec<u8>, HpkeError> {
		let ctx = Self::setup_receiver_psk(enc, sk_r, info, psk, psk_id)?;
		ctx.export(exporter_context, length)
	}
}

impl<K: AuthKem, F: Kdf, A: Aead> Hpke<K, F, A> {
	/// Sender-side single-shot export — Auth mode.
	pub fn send_export_auth<R: CryptoRng + RngCore>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		sk_s: &K::PrivateKey,
		exporter_context: &[u8],
		length: usize,
	) -> Result<(K::EncappedKey, Vec<u8>), HpkeError> {
		let (enc, ctx) = Self::setup_sender_auth(rng, pk_r, info, sk_s)?;
		Ok((enc, ctx.export(exporter_context, length)?))
	}

	/// Receiver-side single-shot export — Auth mode.
	pub fn receiver_export_auth(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		pk_s: &K::PublicKey,
		exporter_context: &[u8],
		length: usize,
	) -> Result<Vec<u8>, HpkeError> {
		let ctx = Self::setup_receiver_auth(enc, sk_r, info, pk_s)?;
		ctx.export(exporter_context, length)
	}

	/// Sender-side single-shot export — `AuthPsk` mode.
	#[allow(clippy::too_many_arguments)]
	pub fn send_export_auth_psk<R: CryptoRng + RngCore>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		psk: &[u8],
		psk_id: &[u8],
		sk_s: &K::PrivateKey,
		exporter_context: &[u8],
		length: usize,
	) -> Result<(K::EncappedKey, Vec<u8>), HpkeError> {
		let (enc, ctx) = Self::setup_sender_auth_psk(rng, pk_r, info, psk, psk_id, sk_s)?;
		Ok((enc, ctx.export(exporter_context, length)?))
	}

	/// Receiver-side single-shot export — `AuthPsk` mode.
	#[allow(clippy::too_many_arguments)]
	pub fn receiver_export_auth_psk(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		psk: &[u8],
		psk_id: &[u8],
		pk_s: &K::PublicKey,
		exporter_context: &[u8],
		length: usize,
	) -> Result<Vec<u8>, HpkeError> {
		let ctx = Self::setup_receiver_auth_psk(enc, sk_r, info, psk, psk_id, pk_s)?;
		ctx.export(exporter_context, length)
	}
}

impl<K: AuthKem, F: Kdf, A: Aead> Hpke<K, F, A> {
	/// `SetupAuthS` (RFC 9180 §5.1.3).
	pub fn setup_sender_auth<R: CryptoRng + RngCore>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		sk_s: &K::PrivateKey,
	) -> Result<(K::EncappedKey, Context<K, F, A>), HpkeError> {
		let (ss, enc) = K::auth_encap(rng, pk_r, sk_s)?;
		let ctx = key_schedule::<K, F, A>(modes::AUTH, ss.as_ref(), info, &[], &[])?;
		Ok((enc, ctx))
	}

	/// `SetupAuthR` (RFC 9180 §5.1.3).
	pub fn setup_receiver_auth(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		pk_s: &K::PublicKey,
	) -> Result<Context<K, F, A>, HpkeError> {
		let ss = K::auth_decap(enc, sk_r, pk_s)?;
		key_schedule::<K, F, A>(modes::AUTH, ss.as_ref(), info, &[], &[])
	}

	/// `SetupAuthPSKS` (RFC 9180 §5.1.4).
	///
	/// `psk` MUST be at least 32 bytes of high-entropy random data. Length is
	/// enforced; entropy is the caller's responsibility — see
	/// [`HpkeError::InsecurePsk`].
	pub fn setup_sender_auth_psk<R: CryptoRng + RngCore>(
		rng: &mut R,
		pk_r: &K::PublicKey,
		info: &[u8],
		psk: &[u8],
		psk_id: &[u8],
		sk_s: &K::PrivateKey,
	) -> Result<(K::EncappedKey, Context<K, F, A>), HpkeError> {
		let (ss, enc) = K::auth_encap(rng, pk_r, sk_s)?;
		let ctx = key_schedule::<K, F, A>(modes::AUTH_PSK, ss.as_ref(), info, psk, psk_id)?;
		Ok((enc, ctx))
	}

	/// `SetupAuthPSKR` (RFC 9180 §5.1.4).
	///
	/// `psk` MUST be at least 32 bytes of high-entropy random data. Length is
	/// enforced; entropy is the caller's responsibility — see
	/// [`HpkeError::InsecurePsk`].
	pub fn setup_receiver_auth_psk(
		enc: &K::EncappedKey,
		sk_r: &K::PrivateKey,
		info: &[u8],
		psk: &[u8],
		psk_id: &[u8],
		pk_s: &K::PublicKey,
	) -> Result<Context<K, F, A>, HpkeError> {
		let ss = K::auth_decap(enc, sk_r, pk_s)?;
		key_schedule::<K, F, A>(modes::AUTH_PSK, ss.as_ref(), info, psk, psk_id)
	}
}

#[cfg(feature = "kat-internals")]
#[doc(hidden)]
pub mod __test_only {
	pub use crate::key_schedule;
}

#[cfg(test)]
mod hpke_tests {
	use super::*;
	use rand_core::{OsRng, TryRngCore as _};

	type Suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>;

	#[test]
	fn setup_base_roundtrip_x25519_chacha() {
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
		let (enc, mut sender) = Suite::setup_sender_base(&mut rng, &pk_r, b"info").unwrap();
		let mut receiver = Suite::setup_receiver_base(&enc, &sk_r, b"info").unwrap();

		let ct = sender.seal(b"aad", b"plaintext").unwrap();
		let pt = receiver.open(b"aad", &ct).unwrap();
		assert_eq!(pt, b"plaintext");
	}

	#[test]
	fn setup_psk_roundtrip() {
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
		let psk = [0xAAu8; 32];
		let psk_id = b"id";
		let (enc, mut s) = Suite::setup_sender_psk(&mut rng, &pk_r, b"info", &psk, psk_id).unwrap();
		let mut r = Suite::setup_receiver_psk(&enc, &sk_r, b"info", &psk, psk_id).unwrap();
		let ct = s.seal(b"aad", b"hi").unwrap();
		assert_eq!(r.open(b"aad", &ct).unwrap(), b"hi");
	}

	#[test]
	fn setup_auth_roundtrip() {
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
		let (sk_s, pk_s) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
		let (enc, mut s) = Suite::setup_sender_auth(&mut rng, &pk_r, b"info", &sk_s).unwrap();
		let mut r = Suite::setup_receiver_auth(&enc, &sk_r, b"info", &pk_s).unwrap();
		let ct = s.seal(b"aad", b"auth").unwrap();
		assert_eq!(r.open(b"aad", &ct).unwrap(), b"auth");
	}

	#[test]
	fn setup_auth_psk_roundtrip() {
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
		let (sk_s, pk_s) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
		let psk = [0xBBu8; 32];
		let (enc, mut s) =
			Suite::setup_sender_auth_psk(&mut rng, &pk_r, b"info", &psk, b"id", &sk_s).unwrap();
		let mut r =
			Suite::setup_receiver_auth_psk(&enc, &sk_r, b"info", &psk, b"id", &pk_s).unwrap();
		let ct = s.seal(b"aad", b"auth-psk").unwrap();
		assert_eq!(r.open(b"aad", &ct).unwrap(), b"auth-psk");
	}

	#[test]
	fn single_shot_base_roundtrip() {
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
		let (enc, ct) = Suite::seal_base(&mut rng, &pk_r, b"info", b"aad", b"hi").unwrap();
		assert_eq!(
			Suite::open_base(&enc, &sk_r, b"info", b"aad", &ct).unwrap(),
			b"hi"
		);
	}

	#[test]
	fn single_shot_psk_roundtrip() {
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
		let psk = [0u8; 32];
		let (enc, ct) = Suite::seal_psk(&mut rng, &pk_r, b"i", b"a", b"p", &psk, b"id").unwrap();
		assert_eq!(
			Suite::open_psk(&enc, &sk_r, b"i", b"a", &ct, &psk, b"id").unwrap(),
			b"p",
		);
	}

	#[test]
	fn single_shot_auth_roundtrip() {
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
		let (sk_s, pk_s) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
		let (enc, ct) = Suite::seal_auth(&mut rng, &pk_r, b"i", b"a", b"p", &sk_s).unwrap();
		assert_eq!(
			Suite::open_auth(&enc, &sk_r, b"i", b"a", &ct, &pk_s).unwrap(),
			b"p",
		);
	}

	#[test]
	fn single_shot_auth_psk_roundtrip() {
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
		let (sk_s, pk_s) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
		let psk = [0u8; 32];
		let (enc, ct) =
			Suite::seal_auth_psk(&mut rng, &pk_r, b"i", b"a", b"p", &psk, b"id", &sk_s).unwrap();
		assert_eq!(
			Suite::open_auth_psk(&enc, &sk_r, b"i", b"a", &ct, &psk, b"id", &pk_s).unwrap(),
			b"p",
		);
	}

	#[test]
	fn export_sender_receiver_match_base() {
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
		let (enc, sender_secret) =
			Suite::send_export_base(&mut rng, &pk_r, b"info", b"ctx", 32).unwrap();
		let receiver_secret =
			Suite::receiver_export_base(&enc, &sk_r, b"info", b"ctx", 32).unwrap();
		assert_eq!(sender_secret, receiver_secret);
		assert_eq!(sender_secret.len(), 32);
	}

	/// `ExportOnly` suites have export methods but `seal_*` / `open_*` are
	/// uninstantiable because `A: SealingAead` is not satisfied — verified by
	/// the fact that this function compiles.
	#[test]
	fn export_only_suite_compiles() {
		type ExportSuite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, ExportOnly>;
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
		let (enc, sec) =
			ExportSuite::send_export_base(&mut rng, &pk_r, b"info", b"ctx", 32).unwrap();
		let recv = ExportSuite::receiver_export_base(&enc, &sk_r, b"info", b"ctx", 32).unwrap();
		assert_eq!(sec, recv);
	}

	#[test]
	fn export_sender_receiver_match_psk() {
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
		let psk = [0x33u8; 32];
		let (enc, sec) =
			Suite::send_export_psk(&mut rng, &pk_r, b"info", &psk, b"id", b"ctx", 64).unwrap();
		let recv =
			Suite::receiver_export_psk(&enc, &sk_r, b"info", &psk, b"id", b"ctx", 64).unwrap();
		assert_eq!(sec, recv);
		assert_eq!(sec.len(), 64);
	}

	#[test]
	fn export_sender_receiver_match_auth() {
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
		let (sk_s, pk_s) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
		let (enc, sec) =
			Suite::send_export_auth(&mut rng, &pk_r, b"info", &sk_s, b"ctx", 48).unwrap();
		let recv = Suite::receiver_export_auth(&enc, &sk_r, b"info", &pk_s, b"ctx", 48).unwrap();
		assert_eq!(sec, recv);
		assert_eq!(sec.len(), 48);
	}

	#[test]
	fn export_sender_receiver_match_auth_psk() {
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (sk_r, pk_r) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
		let (sk_s, pk_s) = DhKemX25519HkdfSha256::generate(&mut rng).unwrap();
		let psk = [0x77u8; 32];
		let (enc, sec) =
			Suite::send_export_auth_psk(&mut rng, &pk_r, b"info", &psk, b"id", &sk_s, b"ctx", 32)
				.unwrap();
		let recv =
			Suite::receiver_export_auth_psk(&enc, &sk_r, b"info", &psk, b"id", &pk_s, b"ctx", 32)
				.unwrap();
		assert_eq!(sec, recv);
		assert_eq!(sec.len(), 32);
	}
}
