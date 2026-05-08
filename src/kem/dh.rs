//! DHKEM (RFC 9180 §4.1).

use alloc::vec::Vec;
use core::marker::PhantomData;

use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::HpkeError;
use crate::kdf::{Kdf, labeled_expand, labeled_extract};
use crate::kem::{AuthKem, Kem};
use crate::sealed::Sealed;

mod rand_compat {
	use rand_core::{CryptoRng, RngCore};

	/// Wraps a `rand_core 0.9` RNG so it satisfies `rand_core 0.6` traits used
	/// by older `RustCrypto` curve crates (`p256`, `p384`, `p521`, `k256`).
	pub(crate) struct RngCompat<'a, R: RngCore + CryptoRng>(pub(crate) &'a mut R);

	impl<R: RngCore + CryptoRng> rand_core_06::RngCore for RngCompat<'_, R> {
		fn next_u32(&mut self) -> u32 {
			self.0.next_u32()
		}
		fn next_u64(&mut self) -> u64 {
			self.0.next_u64()
		}
		fn fill_bytes(&mut self, dest: &mut [u8]) {
			self.0.fill_bytes(dest);
		}
		fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
			self.fill_bytes(dest);
			Ok(())
		}
	}
	impl<R: RngCore + CryptoRng> rand_core_06::CryptoRng for RngCompat<'_, R> {}
}

/// Internal Diffie-Hellman primitive trait. Each curve provides one impl.
///
/// Sealed via the crate's `Sealed` marker trait; downstream crates cannot implement.
pub trait DiffieHellman: Sealed + 'static {
	/// IANA KEM ID for `DHKEM(this group, ?)`.
	const ID: u16;
	/// Serialized length of a public key in bytes.
	const PUBLIC_KEY_LEN: usize;
	/// Serialized length of a private key in bytes.
	const PRIVATE_KEY_LEN: usize;
	/// Length of the DH shared secret in bytes.
	const SHARED_SECRET_LEN: usize;

	/// Public key type for this group.
	type PublicKey: AsRef<[u8]> + Clone;
	/// Private key type for this group.
	type PrivateKey: Zeroize + ZeroizeOnDrop;

	/// Generate a fresh key pair using the provided RNG.
	fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> (Self::PrivateKey, Self::PublicKey);
	/// Deterministically derive a key pair from input keying material.
	fn derive(ikm: &[u8]) -> Result<(Self::PrivateKey, Self::PublicKey), HpkeError>;
	/// Perform the Diffie-Hellman operation.
	fn dh(sk: &Self::PrivateKey, pk: &Self::PublicKey) -> Result<Vec<u8>, HpkeError>;
	/// Deserialize a public key from bytes.
	fn pk_from_bytes(b: &[u8]) -> Result<Self::PublicKey, HpkeError>;
	/// Deserialize a private key from bytes.
	fn sk_from_bytes(b: &[u8]) -> Result<Self::PrivateKey, HpkeError>;
	/// Serialize a public key to bytes.
	fn pk_to_bytes(pk: &Self::PublicKey) -> Vec<u8>;
	/// Derive the public key from a private key.
	fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey;
}

/// `DHKEM(DH, KDF)` — a generic DHKEM (RFC 9180 §4.1).
#[derive(Debug, Clone, Copy, Default)]
pub struct DhKem<D: DiffieHellman, H: Kdf>(PhantomData<(D, H)>);

impl<D: DiffieHellman, H: Kdf> Sealed for DhKem<D, H> {}

/// Public-key wrapper holding the curve's bytes.
pub struct DhPublicKey<D: DiffieHellman>(pub(crate) D::PublicKey);
impl<D: DiffieHellman> Clone for DhPublicKey<D> {
	fn clone(&self) -> Self {
		DhPublicKey(self.0.clone())
	}
}
impl<D: DiffieHellman> core::fmt::Debug for DhPublicKey<D> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		// Public keys aren't secret, but emitting them through `Debug` (which
		// typically routes to logs) is a smell. Redact bytes by default; if a
		// caller needs the wire form, they should call `Kem::pk_to_bytes`.
		f.debug_tuple("DhPublicKey")
			.field(&format_args!("<{} bytes>", self.0.as_ref().len()))
			.finish()
	}
}
impl<D: DiffieHellman> AsRef<[u8]> for DhPublicKey<D> {
	fn as_ref(&self) -> &[u8] {
		self.0.as_ref()
	}
}

/// Private-key wrapper holding the curve's secret bytes.
pub struct DhPrivateKey<D: DiffieHellman>(pub(crate) D::PrivateKey);
impl<D: DiffieHellman> Zeroize for DhPrivateKey<D> {
	fn zeroize(&mut self) {
		self.0.zeroize();
	}
}
impl<D: DiffieHellman> ZeroizeOnDrop for DhPrivateKey<D> {}
impl<D: DiffieHellman> Drop for DhPrivateKey<D> {
	fn drop(&mut self) {
		self.zeroize();
	}
}

/// Encapsulated key wrapper (just the public-key wire bytes).
#[derive(Clone, Debug)]
pub struct DhEncappedKey(pub(crate) Vec<u8>);
impl AsRef<[u8]> for DhEncappedKey {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

/// Shared secret wrapper — zeroized on drop.
pub struct DhSharedSecret(pub(crate) Vec<u8>);
impl AsRef<[u8]> for DhSharedSecret {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}
impl Zeroize for DhSharedSecret {
	fn zeroize(&mut self) {
		self.0.zeroize();
	}
}
impl Drop for DhSharedSecret {
	fn drop(&mut self) {
		self.zeroize();
	}
}

#[inline]
fn suite_id<D: DiffieHellman>() -> [u8; 5] {
	let mut s = [0u8; 5];
	s[..3].copy_from_slice(b"KEM");
	s[3..].copy_from_slice(&D::ID.to_be_bytes());
	s
}

fn extract_and_expand<D: DiffieHellman, H: Kdf>(
	dh: &[u8],
	kem_context: &[u8],
) -> Result<Vec<u8>, HpkeError> {
	let suite = suite_id::<D>();
	// `eae_prk` is the PRK derived from the raw DH output; treat it as secret.
	let eae_prk = Zeroizing::new(labeled_extract::<H>(&[], &suite, b"eae_prk", dh));
	labeled_expand::<H>(
		&eae_prk,
		&suite,
		b"shared_secret",
		kem_context,
		D::SHARED_SECRET_LEN,
	)
}

/// RFC 9180 §7.1.3 `DeriveKeyPair` rejection-sampling loop for NIST P-curves
/// and secp256k1.
///
/// Returns the first `nsk`-byte sequence whose `D::sk_from_bytes` succeeds.
fn derive_p_curve_sk<D: DiffieHellman, H: Kdf>(
	ikm: &[u8],
	nsk: usize,
	bitmask: u8,
) -> Result<Zeroizing<Vec<u8>>, HpkeError> {
	let suite = suite_id::<D>();
	let dkp_prk = Zeroizing::new(labeled_extract::<H>(&[], &suite, b"dkp_prk", ikm));
	for counter in 0u8..=255 {
		let mut bytes = Zeroizing::new(labeled_expand::<H>(
			&dkp_prk,
			&suite,
			b"candidate",
			&[counter],
			nsk,
		)?);
		bytes[0] &= bitmask;
		if D::sk_from_bytes(&bytes).is_ok() {
			return Ok(bytes);
		}
	}
	Err(HpkeError::DeriveKeyPairError)
}

/// Emit a [`DiffieHellman`] impl plus public/private key wrappers for a NIST
/// or secp256k1-style curve backed by a uniform `RustCrypto` `SecretKey` /
/// `PublicKey` + ECDH/SEC1 API. Parameters: marker ident, display name (used
/// in doc strings), curve crate ident, HPKE KDF, IANA KEM ID, `Nsk`,
/// `Nsecret`, top-byte mask for `DeriveKeyPair` (`0xFF` for 256/384-bit fields,
/// `0x01` for P-521 per RFC 9180 §7.1.3), and the public/private wrapper +
/// helper names to emit.
macro_rules! nist_curve {
	(
		$marker:ident, $display:literal, $cn:ident, $kdf:ty,
		$id:expr, $nsk:expr, $nsecret:expr, $bitmask:expr,
		$pk_wrap:ident, $sk_wrap:ident, $make_pk:ident $(,)?
	) => {
		#[doc = concat!(
			"`",
			$display,
			"` group used by HPKE DHKEM (RFC 9180 §7.1 / IANA HPKE KEM registry)."
		)]
		#[derive(Debug, Clone, Copy)]
		pub struct $marker;

		impl Sealed for $marker {}

		impl DiffieHellman for $marker {
			const ID: u16 = $id;
			const PUBLIC_KEY_LEN: usize = 1 + 2 * $nsk;
			const PRIVATE_KEY_LEN: usize = $nsk;
			const SHARED_SECRET_LEN: usize = $nsecret;

			type PublicKey = $pk_wrap;
			type PrivateKey = $sk_wrap;

			fn generate<R: CryptoRng + RngCore>(
				rng: &mut R,
			) -> (Self::PrivateKey, Self::PublicKey) {
				let sk = $cn::SecretKey::random(&mut rand_compat::RngCompat(rng));
				let pk = sk.public_key();
				($sk_wrap(sk), $make_pk(pk))
			}

			fn derive(ikm: &[u8]) -> Result<(Self::PrivateKey, Self::PublicKey), HpkeError> {
				let bytes = derive_p_curve_sk::<Self, $kdf>(ikm, $nsk, $bitmask)?;
				let sk = $cn::SecretKey::from_bytes($cn::FieldBytes::from_slice(&bytes))
					.map_err(|_| HpkeError::InvalidPrivateKey)?;
				let pk = sk.public_key();
				Ok(($sk_wrap(sk), $make_pk(pk)))
			}

			fn dh(sk: &Self::PrivateKey, pk: &Self::PublicKey) -> Result<Vec<u8>, HpkeError> {
				use subtle::ConstantTimeEq;
				let shared = $cn::ecdh::diffie_hellman(
					sk.0.to_nonzero_scalar(),
					pk.pk.as_affine(),
				);
				let bytes = shared.raw_secret_bytes();
				// RFC 9180 §7.1.4: senders and recipients MUST ensure the DH
				// shared secret is not the point at infinity. For prime-order
				// curves with validated public keys and non-zero scalars this
				// cannot occur; the explicit CT check is defense-in-depth and
				// parity with the X25519/X448 paths.
				let zero = [0u8; $nsk];
				if bool::from(bytes.as_slice().ct_eq(&zero)) {
					return Err(HpkeError::EncapError);
				}
				Ok(bytes.to_vec())
			}

			fn pk_from_bytes(b: &[u8]) -> Result<Self::PublicKey, HpkeError> {
				// RFC 9180 §7.1.1: DeserializePublicKey is the *uncompressed*
				// SEC1 conversion. Reject compressed/compact/identity/hybrid by
				// requiring exact uncompressed length and a 0x04 tag byte.
				if b.len() != Self::PUBLIC_KEY_LEN || b[0] != 0x04 {
					return Err(HpkeError::InvalidPublicKey);
				}
				$cn::PublicKey::from_sec1_bytes(b)
					.map($make_pk)
					.map_err(|_| HpkeError::InvalidPublicKey)
			}

			fn sk_from_bytes(b: &[u8]) -> Result<Self::PrivateKey, HpkeError> {
				if b.len() != $nsk {
					return Err(HpkeError::InvalidPrivateKey);
				}
				$cn::SecretKey::from_bytes($cn::FieldBytes::from_slice(b))
					.map($sk_wrap)
					.map_err(|_| HpkeError::InvalidPrivateKey)
			}

			fn pk_to_bytes(pk: &Self::PublicKey) -> Vec<u8> {
				pk.encoded.clone()
			}

			fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey {
				$make_pk(sk.0.public_key())
			}
		}

		#[doc = concat!("Public key wrapper for `", $display, "` (decoded key + cached SEC1 bytes).")]
		#[derive(Clone, Debug)]
		pub struct $pk_wrap {
			pk: $cn::PublicKey,
			encoded: Vec<u8>,
		}

		impl AsRef<[u8]> for $pk_wrap {
			fn as_ref(&self) -> &[u8] {
				&self.encoded
			}
		}

		fn $make_pk(pk: $cn::PublicKey) -> $pk_wrap {
			use $cn::elliptic_curve::sec1::ToEncodedPoint;
			let encoded = pk.to_encoded_point(false).as_bytes().to_vec();
			$pk_wrap { pk, encoded }
		}

		#[doc = concat!("Private key wrapper for `", $display, "`; the inner `SecretKey` zeroizes on drop.")]
		pub struct $sk_wrap($cn::SecretKey);

		impl Zeroize for $sk_wrap {
			fn zeroize(&mut self) {
				// elliptic-curve 0.13's `SecretKey` has no public `Zeroize`
				// impl; rely on its `Drop` by replacing `self.0` with a
				// dummy non-zero scalar (= 1). Dropping the old value
				// invokes its zeroize-on-drop.
				let mut dummy = [0u8; $nsk];
				dummy[$nsk - 1] = 1;
				let d = $cn::SecretKey::from_bytes($cn::FieldBytes::from_slice(&dummy))
					.expect("scalar 1 is a valid secret key");
				let _ = core::mem::replace(&mut self.0, d);
			}
		}

		impl ZeroizeOnDrop for $sk_wrap {}
	};
}

impl<D: DiffieHellman, H: Kdf> Kem for DhKem<D, H> {
	const ID: u16 = D::ID;
	const ENCAPPED_KEY_LEN: usize = D::PUBLIC_KEY_LEN;
	const PUBLIC_KEY_LEN: usize = D::PUBLIC_KEY_LEN;
	const PRIVATE_KEY_LEN: usize = D::PRIVATE_KEY_LEN;
	const SHARED_SECRET_LEN: usize = D::SHARED_SECRET_LEN;

	type PublicKey = DhPublicKey<D>;
	type PrivateKey = DhPrivateKey<D>;
	type EncappedKey = DhEncappedKey;
	type SharedSecret = DhSharedSecret;

	fn generate<R: CryptoRng + RngCore>(
		rng: &mut R,
	) -> Result<(Self::PrivateKey, Self::PublicKey), HpkeError> {
		let (sk, pk) = D::generate(rng);
		Ok((DhPrivateKey(sk), DhPublicKey(pk)))
	}

	fn derive_key_pair(ikm: &[u8]) -> Result<(Self::PrivateKey, Self::PublicKey), HpkeError> {
		let (sk, pk) = D::derive(ikm)?;
		Ok((DhPrivateKey(sk), DhPublicKey(pk)))
	}

	fn encap<R: CryptoRng + RngCore>(
		rng: &mut R,
		pk_r: &Self::PublicKey,
	) -> Result<(Self::SharedSecret, Self::EncappedKey), HpkeError> {
		encap_with::<D, H, R>(rng, pk_r, None)
	}

	fn decap(
		enc: &Self::EncappedKey,
		sk_r: &Self::PrivateKey,
	) -> Result<Self::SharedSecret, HpkeError> {
		let pk_e = D::pk_from_bytes(&enc.0)?;
		let dh = Zeroizing::new(D::dh(&sk_r.0, &pk_e)?);
		let pk_rm = D::pk_to_bytes(&D::sk_to_pk(&sk_r.0));
		let mut kem_ctx = Vec::with_capacity(enc.0.len() + pk_rm.len());
		kem_ctx.extend_from_slice(&enc.0);
		kem_ctx.extend_from_slice(&pk_rm);
		Ok(DhSharedSecret(extract_and_expand::<D, H>(&dh, &kem_ctx)?))
	}

	fn pk_from_bytes(b: &[u8]) -> Result<Self::PublicKey, HpkeError> {
		Ok(DhPublicKey(D::pk_from_bytes(b)?))
	}
	fn sk_from_bytes(b: &[u8]) -> Result<Self::PrivateKey, HpkeError> {
		Ok(DhPrivateKey(D::sk_from_bytes(b)?))
	}
	fn enc_from_bytes(b: &[u8]) -> Result<Self::EncappedKey, HpkeError> {
		if b.len() != D::PUBLIC_KEY_LEN {
			return Err(HpkeError::InvalidEncappedKey);
		}
		Ok(DhEncappedKey(b.to_vec()))
	}
	fn pk_to_bytes(pk: &Self::PublicKey) -> Vec<u8> {
		D::pk_to_bytes(&pk.0)
	}
}

impl<D: DiffieHellman, H: Kdf> AuthKem for DhKem<D, H> {
	fn auth_encap<R: CryptoRng + RngCore>(
		rng: &mut R,
		pk_r: &Self::PublicKey,
		sk_s: &Self::PrivateKey,
	) -> Result<(Self::SharedSecret, Self::EncappedKey), HpkeError> {
		encap_with::<D, H, R>(rng, pk_r, Some(&sk_s.0))
	}

	fn auth_decap(
		enc: &Self::EncappedKey,
		sk_r: &Self::PrivateKey,
		pk_s: &Self::PublicKey,
	) -> Result<Self::SharedSecret, HpkeError> {
		let pk_e = D::pk_from_bytes(&enc.0)?;
		let dh1 = Zeroizing::new(D::dh(&sk_r.0, &pk_e)?);
		let dh2 = Zeroizing::new(D::dh(&sk_r.0, &pk_s.0)?);
		let mut dh = Zeroizing::new(Vec::with_capacity(dh1.len() + dh2.len()));
		dh.extend_from_slice(&dh1);
		dh.extend_from_slice(&dh2);

		let pk_recipient = D::pk_to_bytes(&D::sk_to_pk(&sk_r.0));
		let pk_sender = D::pk_to_bytes(&pk_s.0);
		let mut kem_ctx = Vec::with_capacity(enc.0.len() + pk_recipient.len() + pk_sender.len());
		kem_ctx.extend_from_slice(&enc.0);
		kem_ctx.extend_from_slice(&pk_recipient);
		kem_ctx.extend_from_slice(&pk_sender);
		Ok(DhSharedSecret(extract_and_expand::<D, H>(&dh, &kem_ctx)?))
	}
}

fn encap_with<D: DiffieHellman, H: Kdf, R: CryptoRng + RngCore>(
	rng: &mut R,
	pk_r: &DhPublicKey<D>,
	sk_s_authed: Option<&D::PrivateKey>,
) -> Result<(DhSharedSecret, DhEncappedKey), HpkeError> {
	let (sk_e, pk_e) = D::generate(rng);
	let dh1 = Zeroizing::new(D::dh(&sk_e, &pk_r.0)?);
	let enc = D::pk_to_bytes(&pk_e);
	let pk_recipient = D::pk_to_bytes(&pk_r.0);

	let (dh, kem_ctx) = match sk_s_authed {
		None => {
			let mut ctx = Vec::with_capacity(enc.len() + pk_recipient.len());
			ctx.extend_from_slice(&enc);
			ctx.extend_from_slice(&pk_recipient);
			(dh1, ctx)
		}
		Some(sk_s) => {
			let dh2 = Zeroizing::new(D::dh(sk_s, &pk_r.0)?);
			let mut dh = Zeroizing::new(Vec::with_capacity(dh1.len() + dh2.len()));
			dh.extend_from_slice(&dh1);
			dh.extend_from_slice(&dh2);
			let pk_sender = D::pk_to_bytes(&D::sk_to_pk(sk_s));
			let mut ctx = Vec::with_capacity(enc.len() + pk_recipient.len() + pk_sender.len());
			ctx.extend_from_slice(&enc);
			ctx.extend_from_slice(&pk_recipient);
			ctx.extend_from_slice(&pk_sender);
			(dh, ctx)
		}
	};

	let ss = extract_and_expand::<D, H>(&dh, &kem_ctx)?;
	Ok((DhSharedSecret(ss), DhEncappedKey(enc)))
}

/// Test-only API: encap with a caller-supplied IKM for the ephemeral key, used
/// by KAT and differential test harnesses.
#[cfg(any(test, feature = "kat-internals", feature = "differential"))]
#[allow(dead_code)]
pub(crate) fn encap_with_ikm<D: DiffieHellman, H: Kdf>(
	pk_r: &DhPublicKey<D>,
	ikm_e: &[u8],
) -> Result<(DhSharedSecret, DhEncappedKey), HpkeError> {
	let (sk_e, pk_e) = D::derive(ikm_e)?;
	let dh = Zeroizing::new(D::dh(&sk_e, &pk_r.0)?);
	let enc = D::pk_to_bytes(&pk_e);
	let pk_rm = D::pk_to_bytes(&pk_r.0);
	let mut kem_ctx = Vec::with_capacity(enc.len() + pk_rm.len());
	kem_ctx.extend_from_slice(&enc);
	kem_ctx.extend_from_slice(&pk_rm);
	Ok((
		DhSharedSecret(extract_and_expand::<D, H>(&dh, &kem_ctx)?),
		DhEncappedKey(enc),
	))
}

#[cfg(any(test, feature = "kat-internals", feature = "differential"))]
#[allow(dead_code)]
pub(crate) fn auth_encap_with_ikm<D: DiffieHellman, H: Kdf>(
	pk_r: &DhPublicKey<D>,
	sk_s: &D::PrivateKey,
	ikm_e: &[u8],
) -> Result<(DhSharedSecret, DhEncappedKey), HpkeError> {
	let (sk_e, pk_e) = D::derive(ikm_e)?;
	let dh1 = Zeroizing::new(D::dh(&sk_e, &pk_r.0)?);
	let dh2 = Zeroizing::new(D::dh(sk_s, &pk_r.0)?);
	let mut dh = Zeroizing::new(Vec::with_capacity(dh1.len() + dh2.len()));
	dh.extend_from_slice(&dh1);
	dh.extend_from_slice(&dh2);
	let enc = D::pk_to_bytes(&pk_e);
	let pk_recipient = D::pk_to_bytes(&pk_r.0);
	let pk_sender = D::pk_to_bytes(&D::sk_to_pk(sk_s));
	let mut ctx = Vec::with_capacity(enc.len() + pk_recipient.len() + pk_sender.len());
	ctx.extend_from_slice(&enc);
	ctx.extend_from_slice(&pk_recipient);
	ctx.extend_from_slice(&pk_sender);
	Ok((
		DhSharedSecret(extract_and_expand::<D, H>(&dh, &ctx)?),
		DhEncappedKey(enc),
	))
}

#[cfg(any(test, feature = "kat-internals", feature = "differential"))]
impl<D: DiffieHellman, H: Kdf> DhKem<D, H> {
	/// Test-only: encap with a caller-supplied ephemeral IKM (deterministic).
	pub fn encap_with_ikm(
		pk_r: &<Self as Kem>::PublicKey,
		ikm_e: &[u8],
	) -> Result<(<Self as Kem>::SharedSecret, <Self as Kem>::EncappedKey), HpkeError> {
		encap_with_ikm::<D, H>(pk_r, ikm_e)
	}

	/// Test-only: auth-encap with a caller-supplied ephemeral IKM.
	pub fn auth_encap_with_ikm(
		pk_r: &<Self as Kem>::PublicKey,
		sk_s: &<Self as Kem>::PrivateKey,
		ikm_e: &[u8],
	) -> Result<(<Self as Kem>::SharedSecret, <Self as Kem>::EncappedKey), HpkeError> {
		auth_encap_with_ikm::<D, H>(pk_r, &sk_s.0, ikm_e)
	}
}

// ---------------------------------------------------------------------------
// X25519 (RFC 9180 §7.1, ID 0x0020). DHKEM(X25519, HKDF-SHA-256).
// ---------------------------------------------------------------------------

/// X25519 group, used by `DHKEM(X25519, HKDF-SHA256)` (ID `0x0020`).
#[derive(Debug, Clone, Copy)]
pub struct X25519;

impl Sealed for X25519 {}

impl DiffieHellman for X25519 {
	const ID: u16 = 0x0020;
	const PUBLIC_KEY_LEN: usize = 32;
	const PRIVATE_KEY_LEN: usize = 32;
	const SHARED_SECRET_LEN: usize = 32;

	type PublicKey = X25519PublicKeyWrap;
	type PrivateKey = X25519PrivateKeyWrap;

	fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> (Self::PrivateKey, Self::PublicKey) {
		let mut bytes = Zeroizing::new([0u8; 32]);
		rng.fill_bytes(&mut bytes[..]);
		let sk = x25519_dalek::StaticSecret::from(*bytes);
		let pk = x25519_dalek::PublicKey::from(&sk);
		(X25519PrivateKeyWrap(sk), X25519PublicKeyWrap(pk.to_bytes()))
	}

	fn derive(ikm: &[u8]) -> Result<(Self::PrivateKey, Self::PublicKey), HpkeError> {
		let suite = suite_id::<Self>();
		let dkp_prk = Zeroizing::new(labeled_extract::<crate::HkdfSha256>(
			&[],
			&suite,
			b"dkp_prk",
			ikm,
		));
		let sk_bytes = Zeroizing::new(labeled_expand::<crate::HkdfSha256>(
			&dkp_prk,
			&suite,
			b"sk",
			&[],
			32,
		)?);
		let mut arr = Zeroizing::new([0u8; 32]);
		arr.copy_from_slice(&sk_bytes);
		let sk = x25519_dalek::StaticSecret::from(*arr);
		let pk = x25519_dalek::PublicKey::from(&sk);
		Ok((X25519PrivateKeyWrap(sk), X25519PublicKeyWrap(pk.to_bytes())))
	}

	fn dh(sk: &Self::PrivateKey, pk: &Self::PublicKey) -> Result<Vec<u8>, HpkeError> {
		use subtle::ConstantTimeEq;
		let pk_dalek = x25519_dalek::PublicKey::from(pk.0);
		let shared = sk.0.diffie_hellman(&pk_dalek);
		// RFC 9180 §7.1.4: constant-time reject of the all-zeros DH output.
		let zero = [0u8; 32];
		if shared.as_bytes().ct_eq(&zero).into() {
			return Err(HpkeError::EncapError);
		}
		Ok(shared.as_bytes().to_vec())
	}

	fn pk_from_bytes(b: &[u8]) -> Result<Self::PublicKey, HpkeError> {
		if b.len() != 32 {
			return Err(HpkeError::InvalidPublicKey);
		}
		let mut arr = [0u8; 32];
		arr.copy_from_slice(b);
		// RFC 7748 §5: implementations of X25519 (but not X448) MUST mask the
		// most-significant bit of the final byte of received public keys. This
		// makes the deserialised wire form a stable canonical representation
		// and prevents asymmetric DH outputs between peers that differ only in
		// bit 255 of the public key.
		arr[31] &= 0x7F;
		Ok(X25519PublicKeyWrap(arr))
	}

	fn sk_from_bytes(b: &[u8]) -> Result<Self::PrivateKey, HpkeError> {
		if b.len() != 32 {
			return Err(HpkeError::InvalidPrivateKey);
		}
		let mut arr = [0u8; 32];
		arr.copy_from_slice(b);
		// RFC 9180 §7.1.2 / RFC 7748 §5: clamp the X25519 scalar.
		// x25519-dalek defers clamping to operation time (`mul_clamped`), but
		// the RFC requires the deserialized representation itself be clamped.
		arr[0] &= 0xF8;
		arr[31] &= 0x7F;
		arr[31] |= 0x40;
		Ok(X25519PrivateKeyWrap(x25519_dalek::StaticSecret::from(arr)))
	}

	fn pk_to_bytes(pk: &Self::PublicKey) -> Vec<u8> {
		pk.0.to_vec()
	}

	fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey {
		let pk = x25519_dalek::PublicKey::from(&sk.0);
		X25519PublicKeyWrap(pk.to_bytes())
	}
}

/// Public key wrapper for X25519.
#[derive(Clone, Debug)]
pub struct X25519PublicKeyWrap([u8; 32]);

impl AsRef<[u8]> for X25519PublicKeyWrap {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

/// Private key wrapper for X25519; zeroized on drop via `x25519_dalek`.
pub struct X25519PrivateKeyWrap(x25519_dalek::StaticSecret);

impl Zeroize for X25519PrivateKeyWrap {
	fn zeroize(&mut self) {
		self.0.zeroize();
	}
}

impl ZeroizeOnDrop for X25519PrivateKeyWrap {}

// ---------------------------------------------------------------------------
// NIST P-256 / P-384 / P-521 (RFC 9180 §7.1) and secp256k1 (post-RFC IANA).
// All four share a uniform RustCrypto SecretKey/PublicKey + ECDH/SEC1 API,
// so the trait impl + wrapper structs are emitted by `nist_curve!`.
// ---------------------------------------------------------------------------

nist_curve!(
	P256,
	"P-256",
	p256,
	crate::HkdfSha256,
	0x0010,
	32,
	32,
	0xFF,
	P256PublicKeyWrap,
	P256PrivateKeyWrap,
	make_p256_pk
);

nist_curve!(
	P384,
	"P-384",
	p384,
	crate::HkdfSha384,
	0x0011,
	48,
	48,
	0xFF,
	P384PublicKeyWrap,
	P384PrivateKeyWrap,
	make_p384_pk
);

// P-521: bitmask `0x01` clears the top 7 bits of byte 0 (RFC 9180 §7.1.3);
// `Nsk = 66`, `Nsecret = 64` (HKDF-SHA-512 output).
nist_curve!(
	P521,
	"P-521",
	p521,
	crate::HkdfSha512,
	0x0012,
	66,
	64,
	0x01,
	P521PublicKeyWrap,
	P521PrivateKeyWrap,
	make_p521_pk
);

nist_curve!(
	K256,
	"secp256k1",
	k256,
	crate::HkdfSha256,
	0x0016,
	32,
	32,
	0xFF,
	K256PublicKeyWrap,
	K256PrivateKeyWrap,
	make_k256_pk
);

// ---------------------------------------------------------------------------
// X448 (RFC 9180 §7.1, ID 0x0021). DHKEM(X448, HKDF-SHA-512).
// ---------------------------------------------------------------------------

/// Perform scalar * G (base-point multiplication) using the X448 Montgomery ladder.
///
/// `sk` must already be clamped per RFC 7748 §5.
fn x448_scalar_mult_base(sk: &[u8; 56]) -> [u8; 56] {
	use ed448_goldilocks::{
		EdwardsScalar, MontgomeryPoint,
		elliptic_curve::{bigint::U448, scalar::FromUintUnchecked as _},
	};
	let scalar = EdwardsScalar::from_uint_unchecked(U448::from_le_slice(sk));
	let result = &MontgomeryPoint::GENERATOR * &scalar;
	*result.as_bytes()
}

/// Perform scalar * point (variable-base multiplication) using the X448 Montgomery ladder.
///
/// `sk` must already be clamped per RFC 7748 §5.
fn x448_scalar_mult(sk: &[u8; 56], pk: &[u8; 56]) -> [u8; 56] {
	use ed448_goldilocks::{
		EdwardsScalar, MontgomeryPoint,
		elliptic_curve::{bigint::U448, scalar::FromUintUnchecked as _},
	};
	let scalar = EdwardsScalar::from_uint_unchecked(U448::from_le_slice(sk));
	let point = MontgomeryPoint(*pk);
	let result = &point * &scalar;
	*result.as_bytes()
}

/// X448 group, used by `DHKEM(X448, HKDF-SHA512)` (ID `0x0021`).
#[derive(Debug, Clone, Copy)]
pub struct X448;

impl Sealed for X448 {}

impl DiffieHellman for X448 {
	const ID: u16 = 0x0021;
	const PUBLIC_KEY_LEN: usize = 56;
	const PRIVATE_KEY_LEN: usize = 56;
	const SHARED_SECRET_LEN: usize = 64;

	type PublicKey = X448PublicKeyWrap;
	type PrivateKey = X448PrivateKeyWrap;

	fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> (Self::PrivateKey, Self::PublicKey) {
		let mut sk = Zeroizing::new([0u8; 56]);
		rng.fill_bytes(&mut sk[..]);
		// RFC 7748 §5: clamp the X448 scalar.
		sk[0] &= 0xfc;
		sk[55] |= 0x80;
		let pk = x448_scalar_mult_base(&sk);
		(X448PrivateKeyWrap(*sk), X448PublicKeyWrap(pk))
	}

	fn derive(ikm: &[u8]) -> Result<(Self::PrivateKey, Self::PublicKey), HpkeError> {
		let suite = suite_id::<Self>();
		let prk = Zeroizing::new(labeled_extract::<crate::HkdfSha512>(
			&[],
			&suite,
			b"dkp_prk",
			ikm,
		));
		let bytes = Zeroizing::new(labeled_expand::<crate::HkdfSha512>(
			&prk,
			&suite,
			b"sk",
			&[],
			56,
		)?);
		let mut sk = Zeroizing::new([0u8; 56]);
		sk.copy_from_slice(&bytes);
		// RFC 7748 §5: clamp the X448 scalar.
		sk[0] &= 0xfc;
		sk[55] |= 0x80;
		let pk = x448_scalar_mult_base(&sk);
		Ok((X448PrivateKeyWrap(*sk), X448PublicKeyWrap(pk)))
	}

	fn dh(sk: &Self::PrivateKey, pk: &Self::PublicKey) -> Result<Vec<u8>, HpkeError> {
		use subtle::ConstantTimeEq;
		let shared = x448_scalar_mult(&sk.0, &pk.0);
		// RFC 9180 §7.1.4: constant-time reject of the all-zeros DH output.
		let zero = [0u8; 56];
		if shared.ct_eq(&zero).into() {
			return Err(HpkeError::EncapError);
		}
		Ok(shared.to_vec())
	}

	fn pk_from_bytes(b: &[u8]) -> Result<Self::PublicKey, HpkeError> {
		if b.len() != 56 {
			return Err(HpkeError::InvalidPublicKey);
		}
		let mut arr = [0u8; 56];
		arr.copy_from_slice(b);
		Ok(X448PublicKeyWrap(arr))
	}

	fn sk_from_bytes(b: &[u8]) -> Result<Self::PrivateKey, HpkeError> {
		if b.len() != 56 {
			return Err(HpkeError::InvalidPrivateKey);
		}
		let mut arr = [0u8; 56];
		arr.copy_from_slice(b);
		// RFC 7748 §5: clamp the X448 scalar. The internal scalar-mult helpers
		// assume a clamped scalar. `generate` and `derive` already clamp;
		// wire-loaded keys must be clamped here so that all paths agree.
		arr[0] &= 0xFC;
		arr[55] |= 0x80;
		Ok(X448PrivateKeyWrap(arr))
	}

	fn pk_to_bytes(pk: &Self::PublicKey) -> Vec<u8> {
		pk.0.to_vec()
	}

	fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey {
		X448PublicKeyWrap(x448_scalar_mult_base(&sk.0))
	}
}

/// Public key wrapper for X448.
#[derive(Clone, Debug)]
pub struct X448PublicKeyWrap([u8; 56]);

impl AsRef<[u8]> for X448PublicKeyWrap {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

/// Private key wrapper for X448; zeroized on drop.
pub struct X448PrivateKeyWrap([u8; 56]);

impl Zeroize for X448PrivateKeyWrap {
	fn zeroize(&mut self) {
		self.0.zeroize();
	}
}

impl ZeroizeOnDrop for X448PrivateKeyWrap {}

impl Drop for X448PrivateKeyWrap {
	fn drop(&mut self) {
		self.zeroize();
	}
}

// ---------------------------------------------------------------------------
// Public DHKEM type aliases (RFC 9180 §7.1).
// ---------------------------------------------------------------------------

/// `DHKEM(X25519, HKDF-SHA256)` — RFC 9180 ID `0x0020`.
pub type DhKemX25519HkdfSha256 = DhKem<X25519, crate::HkdfSha256>;

/// `DHKEM(P-256, HKDF-SHA256)` — RFC 9180 ID `0x0010`.
pub type DhKemP256HkdfSha256 = DhKem<P256, crate::HkdfSha256>;

/// `DHKEM(P-384, HKDF-SHA384)` — RFC 9180 ID `0x0011`.
pub type DhKemP384HkdfSha384 = DhKem<P384, crate::HkdfSha384>;

/// `DHKEM(P-521, HKDF-SHA512)` — RFC 9180 ID `0x0012`.
pub type DhKemP521HkdfSha512 = DhKem<P521, crate::HkdfSha512>;

/// `DHKEM(secp256k1, HKDF-SHA256)` — IANA HPKE KEM ID `0x0016` (post-RFC-9180).
pub type DhKemK256HkdfSha256 = DhKem<K256, crate::HkdfSha256>;

/// `DHKEM(X448, HKDF-SHA512)` — RFC 9180 ID `0x0021`.
pub type DhKemX448HkdfSha512 = DhKem<X448, crate::HkdfSha512>;

#[cfg(test)]
mod tests {
	use super::*;
	use rand_core::{OsRng, TryRngCore as _};

	#[test]
	fn dhkem_x25519_sha256_roundtrip() {
		type Suite = DhKem<X25519, crate::HkdfSha256>;
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (sk_r, pk_r) = Suite::generate(&mut rng).unwrap();
		let (ss_e, enc) = Suite::encap(&mut rng, &pk_r).unwrap();
		let ss_d = Suite::decap(&enc, &sk_r).unwrap();
		assert_eq!(ss_e.as_ref(), ss_d.as_ref());
		assert_eq!(ss_e.as_ref().len(), 32);
	}

	#[test]
	fn dhkem_x25519_auth_roundtrip() {
		type Suite = DhKem<X25519, crate::HkdfSha256>;
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (sk_r, pk_r) = Suite::generate(&mut rng).unwrap();
		let (sk_s, pk_s) = Suite::generate(&mut rng).unwrap();
		let (ss_e, enc) = Suite::auth_encap(&mut rng, &pk_r, &sk_s).unwrap();
		let ss_d = Suite::auth_decap(&enc, &sk_r, &pk_s).unwrap();
		assert_eq!(ss_e.as_ref(), ss_d.as_ref());
	}

	#[test]
	fn x25519_rejects_small_order_zero_pk() {
		type Suite = DhKem<X25519, crate::HkdfSha256>;
		let pk_zero = Suite::pk_from_bytes(&[0u8; 32]).unwrap();
		let mut os_rng = OsRng;
		let r = Suite::encap(&mut os_rng.unwrap_mut(), &pk_zero);
		assert_eq!(r.err(), Some(HpkeError::EncapError));
	}

	#[test]
	fn dhkem_p256_sha256_roundtrip() {
		type Suite = DhKem<P256, crate::HkdfSha256>;
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (sk_r, pk_r) = Suite::generate(&mut rng).unwrap();
		let (ss_e, enc) = Suite::encap(&mut rng, &pk_r).unwrap();
		let ss_d = Suite::decap(&enc, &sk_r).unwrap();
		assert_eq!(ss_e.as_ref(), ss_d.as_ref());
		assert_eq!(ss_e.as_ref().len(), 32);
		assert_eq!(enc.as_ref().len(), 65);
	}

	#[test]
	fn dhkem_p256_auth_roundtrip() {
		type Suite = DhKem<P256, crate::HkdfSha256>;
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (sk_r, pk_r) = Suite::generate(&mut rng).unwrap();
		let (sk_s, pk_s) = Suite::generate(&mut rng).unwrap();
		let (ss_e, enc) = Suite::auth_encap(&mut rng, &pk_r, &sk_s).unwrap();
		let ss_d = Suite::auth_decap(&enc, &sk_r, &pk_s).unwrap();
		assert_eq!(ss_e.as_ref(), ss_d.as_ref());
	}

	#[test]
	fn dhkem_p384_sha384_roundtrip() {
		type Suite = DhKem<P384, crate::HkdfSha384>;
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (sk_r, pk_r) = Suite::generate(&mut rng).unwrap();
		let (ss_e, enc) = Suite::encap(&mut rng, &pk_r).unwrap();
		let ss_d = Suite::decap(&enc, &sk_r).unwrap();
		assert_eq!(ss_e.as_ref(), ss_d.as_ref());
		assert_eq!(ss_e.as_ref().len(), 48);
		assert_eq!(enc.as_ref().len(), 97);
	}

	#[test]
	fn dhkem_p521_sha512_roundtrip() {
		type Suite = DhKem<P521, crate::HkdfSha512>;
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (sk_r, pk_r) = Suite::generate(&mut rng).unwrap();
		let (ss_e, enc) = Suite::encap(&mut rng, &pk_r).unwrap();
		let ss_d = Suite::decap(&enc, &sk_r).unwrap();
		assert_eq!(ss_e.as_ref(), ss_d.as_ref());
		assert_eq!(ss_e.as_ref().len(), 64);
		assert_eq!(enc.as_ref().len(), 133);
	}

	#[test]
	fn dhkem_k256_sha256_roundtrip() {
		type Suite = DhKem<K256, crate::HkdfSha256>;
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (sk_r, pk_r) = Suite::generate(&mut rng).unwrap();
		let (ss_e, enc) = Suite::encap(&mut rng, &pk_r).unwrap();
		let ss_d = Suite::decap(&enc, &sk_r).unwrap();
		assert_eq!(ss_e.as_ref(), ss_d.as_ref());
	}

	#[test]
	fn dhkem_x448_sha512_roundtrip() {
		type Suite = DhKem<X448, crate::HkdfSha512>;
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (sk_r, pk_r) = Suite::generate(&mut rng).unwrap();
		let (ss_e, enc) = Suite::encap(&mut rng, &pk_r).unwrap();
		let ss_d = Suite::decap(&enc, &sk_r).unwrap();
		assert_eq!(ss_e.as_ref(), ss_d.as_ref());
		assert_eq!(ss_e.as_ref().len(), 64);
	}

	/// Behavioural test for X448 clamping in `sk_from_bytes`: load the same
	/// scalar with and without manual pre-clamping; `sk_to_pk` and `dh` must
	/// agree on both, proving the unclamped wire bytes were clamped on load.
	#[test]
	fn x448_sk_from_bytes_clamps_per_rfc7748() {
		let mut unclamped = [0x55u8; 56];
		unclamped[0] = 0xFF;
		unclamped[55] = 0x55;
		let mut clamped = unclamped;
		clamped[0] &= 0xFC;
		clamped[55] |= 0x80;
		assert_ne!(unclamped[0], clamped[0]);
		assert_ne!(unclamped[55], clamped[55]);

		let sk_unclamped = X448::sk_from_bytes(&unclamped).unwrap();
		let sk_clamped = X448::sk_from_bytes(&clamped).unwrap();
		assert_eq!(
			X448::sk_to_pk(&sk_unclamped).as_ref(),
			X448::sk_to_pk(&sk_clamped).as_ref(),
		);

		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (_sk_peer, pk_peer) = X448::generate(&mut rng);
		assert_eq!(
			X448::dh(&sk_unclamped, &pk_peer).unwrap(),
			X448::dh(&sk_clamped, &pk_peer).unwrap(),
		);
	}

	#[test]
	fn aliases_implement_kem_and_authkem() {
		fn assert_both<K: Kem + AuthKem>() {}
		assert_both::<DhKemX25519HkdfSha256>();
		assert_both::<DhKemP256HkdfSha256>();
		assert_both::<DhKemP384HkdfSha384>();
		assert_both::<DhKemP521HkdfSha512>();
		assert_both::<DhKemK256HkdfSha256>();
		assert_both::<DhKemX448HkdfSha512>();
	}

	/// RFC 7748 §5 mandates masking bit 7 of byte 31 on receive. Without this,
	/// a sender holding a `pk_r` with the high bit set computes a different
	/// `kem_context` than a receiver who derives `pk_r` from `sk_r` (which is
	/// always canonical with bit 255 = 0).
	#[test]
	fn x25519_pk_from_bytes_masks_high_bit() {
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (_, pk_canonical) = X25519::generate(&mut rng);
		let mut tampered = [0u8; 32];
		tampered.copy_from_slice(pk_canonical.as_ref());
		tampered[31] |= 0x80;
		let pk_loaded = X25519::pk_from_bytes(&tampered).unwrap();
		assert_eq!(pk_loaded.as_ref(), pk_canonical.as_ref());
	}

	// RFC 9180 §7.1.1 — for P-256, P-384, P-521, secp256k1, DeserializePublicKey
	// is the *uncompressed* SEC1 conversion. Compressed (0x02/0x03) and compact
	// (0x05) tags MUST be rejected even though `from_sec1_bytes` would accept
	// them; the kem_context binding then depends on a canonical encoding.

	#[test]
	fn p256_pk_from_bytes_rejects_compressed() {
		use p256::elliptic_curve::sec1::ToEncodedPoint;
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (_, pk) = P256::generate(&mut rng);
		let compressed = pk.pk.to_encoded_point(true);
		assert_eq!(compressed.as_bytes().len(), 33);
		assert!(matches!(
			P256::pk_from_bytes(compressed.as_bytes()),
			Err(HpkeError::InvalidPublicKey)
		));
	}

	#[test]
	fn p384_pk_from_bytes_rejects_compressed() {
		use p384::elliptic_curve::sec1::ToEncodedPoint;
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (_, pk) = P384::generate(&mut rng);
		let compressed = pk.pk.to_encoded_point(true);
		assert_eq!(compressed.as_bytes().len(), 49);
		assert!(matches!(
			P384::pk_from_bytes(compressed.as_bytes()),
			Err(HpkeError::InvalidPublicKey)
		));
	}

	#[test]
	fn p521_pk_from_bytes_rejects_compressed() {
		use p521::elliptic_curve::sec1::ToEncodedPoint;
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (_, pk) = P521::generate(&mut rng);
		let compressed = pk.pk.to_encoded_point(true);
		assert_eq!(compressed.as_bytes().len(), 67);
		assert!(matches!(
			P521::pk_from_bytes(compressed.as_bytes()),
			Err(HpkeError::InvalidPublicKey)
		));
	}

	#[test]
	fn k256_pk_from_bytes_rejects_compressed() {
		use k256::elliptic_curve::sec1::ToEncodedPoint;
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (_, pk) = K256::generate(&mut rng);
		let compressed = pk.pk.to_encoded_point(true);
		assert_eq!(compressed.as_bytes().len(), 33);
		assert!(matches!(
			K256::pk_from_bytes(compressed.as_bytes()),
			Err(HpkeError::InvalidPublicKey)
		));
	}

	/// Wrong-length inputs — short, oversized, identity tag (1-byte 0x00) —
	/// must all be rejected before reaching the curve library.
	#[test]
	fn p256_pk_from_bytes_rejects_wrong_length() {
		assert!(matches!(
			P256::pk_from_bytes(&[]),
			Err(HpkeError::InvalidPublicKey)
		));
		assert!(matches!(
			P256::pk_from_bytes(&[0u8]),
			Err(HpkeError::InvalidPublicKey)
		));
		assert!(matches!(
			P256::pk_from_bytes(&[0u8; 64]),
			Err(HpkeError::InvalidPublicKey)
		));
		assert!(matches!(
			P256::pk_from_bytes(&[0u8; 66]),
			Err(HpkeError::InvalidPublicKey)
		));
	}

	/// Right length but wrong tag byte (anything other than 0x04) must fail.
	#[test]
	fn p256_pk_from_bytes_rejects_wrong_tag() {
		use p256::elliptic_curve::sec1::ToEncodedPoint;
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (_, pk) = P256::generate(&mut rng);
		let mut tampered = pk.pk.to_encoded_point(false).as_bytes().to_vec();
		assert_eq!(tampered.len(), 65);
		assert_eq!(tampered[0], 0x04);
		// Hybrid (0x06/0x07) has the same length as uncompressed but is not
		// `Tag::Uncompressed`. RFC 9180 says uncompressed-only.
		tampered[0] = 0x06;
		assert!(matches!(
			P256::pk_from_bytes(&tampered),
			Err(HpkeError::InvalidPublicKey)
		));
		tampered[0] = 0x07;
		assert!(matches!(
			P256::pk_from_bytes(&tampered),
			Err(HpkeError::InvalidPublicKey)
		));
	}
}
