//! Post-quantum KEMs (X-Wing, ML-KEM-768, ML-KEM-1024).
//!
//! Available only with the `pq` feature. These KEMs intentionally do **not**
//! implement [`AuthKem`](crate::kem::AuthKem); HPKE Auth/AuthPsk modes are
//! defined only for DHKEMs.

use alloc::vec::Vec;

use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::HpkeError;
use crate::kem::Kem;
use crate::sealed::Sealed;

// ---------------------------------------------------------------------------
// RNG compatibility shim: rand_core 0.9 -> rand_core 0.10
// ---------------------------------------------------------------------------
//
// x-wing depends on `rand_core 0.10`, which has different trait definitions
// than the `rand_core 0.9` used by the rest of hpke-ng. This wrapper bridges
// the two so that our callers' RNGs (0.9 traits) can be passed into x-wing's
// API (0.10 traits).

struct RngCompat10<'a, R: RngCore + CryptoRng>(pub(crate) &'a mut R);

impl<R: RngCore + CryptoRng> rand_core_10::TryRng for RngCompat10<'_, R> {
	type Error = core::convert::Infallible;

	fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
		Ok(self.0.next_u32())
	}

	fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
		Ok(self.0.next_u64())
	}

	fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
		self.0.fill_bytes(dest);
		Ok(())
	}
}

// TryCryptoRng is a marker trait; blanket impl applies automatically because
// rand_core_10::CryptoRng is blanket-impl'd for all TryCryptoRng<Error=Infallible>.
impl<R: RngCore + CryptoRng> rand_core_10::TryCryptoRng for RngCompat10<'_, R> {}

// ---------------------------------------------------------------------------
// X-Wing (draft-connolly-cfrg-xwing-kem-06; IANA KEM ID 0x647A).
// ---------------------------------------------------------------------------

/// X-Wing KEM (draft 06).
///
/// Hybrid X25519 + ML-KEM-768. Implements [`Kem`] only — no auth variant.
#[derive(Debug, Clone, Copy, Default)]
pub struct XWingDraft06;

impl Sealed for XWingDraft06 {}

/// Public (encapsulation) key for X-Wing.
///
/// Wire format: 1184 bytes ML-KEM-768 encapsulation key || 32 bytes X25519 public key.
#[derive(Clone, Debug)]
pub struct XWingPublicKey(Vec<u8>);

impl AsRef<[u8]> for XWingPublicKey {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

/// Private (decapsulation) key for X-Wing — a 32-byte seed.
///
/// The full ML-KEM-768 and X25519 key material is derived from this seed
/// via SHAKE-256 by the x-wing crate.
pub struct XWingPrivateKey {
	seed: [u8; 32],
}

impl Zeroize for XWingPrivateKey {
	fn zeroize(&mut self) {
		self.seed.zeroize();
	}
}

impl ZeroizeOnDrop for XWingPrivateKey {}

impl Drop for XWingPrivateKey {
	fn drop(&mut self) {
		self.zeroize();
	}
}

/// Encapsulated key (ciphertext) for X-Wing.
///
/// Wire format: 1088 bytes ML-KEM-768 ciphertext || 32 bytes X25519 ciphertext.
#[derive(Clone, Debug)]
pub struct XWingEncappedKey(Vec<u8>);

impl AsRef<[u8]> for XWingEncappedKey {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

/// Shared secret produced by X-Wing encap/decap.
pub struct XWingSharedSecret([u8; 32]);

impl AsRef<[u8]> for XWingSharedSecret {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl Zeroize for XWingSharedSecret {
	fn zeroize(&mut self) {
		self.0.zeroize();
	}
}

impl Drop for XWingSharedSecret {
	fn drop(&mut self) {
		self.zeroize();
	}
}

impl Kem for XWingDraft06 {
	const ID: u16 = 0x647A;
	const ENCAPPED_KEY_LEN: usize = x_wing::CIPHERTEXT_SIZE;
	const PUBLIC_KEY_LEN: usize = x_wing::ENCAPSULATION_KEY_SIZE;
	const PRIVATE_KEY_LEN: usize = x_wing::DECAPSULATION_KEY_SIZE;
	const SHARED_SECRET_LEN: usize = 32;

	type PublicKey = XWingPublicKey;
	type PrivateKey = XWingPrivateKey;
	type EncappedKey = XWingEncappedKey;
	type SharedSecret = XWingSharedSecret;

	fn generate<R: CryptoRng + RngCore>(
		rng: &mut R,
	) -> Result<(Self::PrivateKey, Self::PublicKey), HpkeError> {
		let mut seed = [0u8; 32];
		rng.fill_bytes(&mut seed);
		Ok(keypair_from_seed(seed))
	}

	fn derive_key_pair(ikm: &[u8]) -> Result<(Self::PrivateKey, Self::PublicKey), HpkeError> {
		// X-Wing draft-06 specifies raw SHAKE-256(ikm, 32) for DeriveKeyPair.
		use sha3::digest::{ExtendableOutput, Update, XofReader};
		let mut hasher = sha3::Shake256::default();
		hasher.update(ikm);
		let mut reader = hasher.finalize_xof();
		let mut seed = [0u8; 32];
		reader.read(&mut seed);
		Ok(keypair_from_seed(seed))
	}

	fn encap<R: CryptoRng + RngCore>(
		rng: &mut R,
		pk_r: &Self::PublicKey,
	) -> Result<(Self::SharedSecret, Self::EncappedKey), HpkeError> {
		use x_wing::Encapsulate;
		let ek = x_wing::EncapsulationKey::try_from(pk_r.0.as_slice())
			.map_err(|_| HpkeError::InvalidPublicKey)?;
		let mut compat = RngCompat10(rng);
		let (ct, ss) = ek.encapsulate_with_rng(&mut compat);
		let mut ss_bytes = [0u8; 32];
		ss_bytes.copy_from_slice(ss.as_ref());
		let ct_vec: Vec<u8> = ct.iter().copied().collect();
		Ok((XWingSharedSecret(ss_bytes), XWingEncappedKey(ct_vec)))
	}

	fn decap(
		enc: &Self::EncappedKey,
		sk_r: &Self::PrivateKey,
	) -> Result<Self::SharedSecret, HpkeError> {
		use x_wing::Decapsulate;
		let dk = x_wing::DecapsulationKey::from(sk_r.seed);
		let ss = dk
			.decapsulate_slice(enc.0.as_slice())
			.map_err(|_| HpkeError::InvalidEncappedKey)?;
		let mut ss_bytes = [0u8; 32];
		ss_bytes.copy_from_slice(ss.as_ref());
		Ok(XWingSharedSecret(ss_bytes))
	}

	fn pk_from_bytes(b: &[u8]) -> Result<Self::PublicKey, HpkeError> {
		if b.len() != Self::PUBLIC_KEY_LEN {
			return Err(HpkeError::InvalidPublicKey);
		}
		Ok(XWingPublicKey(b.to_vec()))
	}

	fn sk_from_bytes(b: &[u8]) -> Result<Self::PrivateKey, HpkeError> {
		if b.len() != 32 {
			return Err(HpkeError::InvalidPrivateKey);
		}
		let mut seed = [0u8; 32];
		seed.copy_from_slice(b);
		Ok(XWingPrivateKey { seed })
	}

	fn enc_from_bytes(b: &[u8]) -> Result<Self::EncappedKey, HpkeError> {
		if b.len() != Self::ENCAPPED_KEY_LEN {
			return Err(HpkeError::InvalidEncappedKey);
		}
		Ok(XWingEncappedKey(b.to_vec()))
	}

	fn pk_to_bytes(pk: &Self::PublicKey) -> Vec<u8> {
		pk.0.clone()
	}
}

/// Derive an X-Wing keypair from a 32-byte seed.
fn keypair_from_seed(seed: [u8; 32]) -> (XWingPrivateKey, XWingPublicKey) {
	use x_wing::{DecapsulationKey, Decapsulator, KeyExport};

	let dk = DecapsulationKey::from(seed);
	let ek = dk.encapsulation_key();
	let pk_bytes = ek.to_bytes().to_vec();

	(XWingPrivateKey { seed }, XWingPublicKey(pk_bytes))
}

// ---------------------------------------------------------------------------
// ML-KEM-768 / ML-KEM-1024 (draft-connolly-cfrg-hpke-mlkem; not in RFC 9180).
// Both parameter sets share a uniform FIPS 203 / ml-kem 0.3 API surface, so
// the wrappers + Kem impl + seed→keypair helper are emitted by `ml_kem_variant!`.
// `MlKemSharedSecret` is shared (same 32-byte output size for both variants).
// ---------------------------------------------------------------------------

/// Shared secret produced by ML-KEM encap/decap (32 bytes); same wire size for
/// ML-KEM-768 and ML-KEM-1024.
pub struct MlKemSharedSecret(Vec<u8>);

impl AsRef<[u8]> for MlKemSharedSecret {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl Zeroize for MlKemSharedSecret {
	fn zeroize(&mut self) {
		self.0.zeroize();
	}
}

impl Drop for MlKemSharedSecret {
	fn drop(&mut self) {
		self.zeroize();
	}
}

/// Emit a [`Kem`] impl plus public/private/encapsulated-key wrappers and a
/// `from_seed` helper for an ML-KEM parameter set. Parameters: marker ident,
/// display name (used in doc strings), IANA KEM ID, `Nenc`, `Npk`, the
/// ml-kem `DecapsulationKey<P>` / `EncapsulationKey<P>` / `Ciphertext<P>`
/// concrete types, and the wrapper / helper names to emit.
macro_rules! ml_kem_variant {
	(
		$marker:ident, $variant:literal, $id:expr, $nenc:expr, $npk:expr,
		$dk:ty, $ek:ty, $ct:ty,
		$pk_wrap:ident, $sk_wrap:ident, $enc_wrap:ident, $from_seed:ident $(,)?
	) => {
		#[doc = concat!("`", $variant, "` (FIPS 203). Private keys are stored as the 64-byte (d, z) seed; the expanded decapsulation key is rebuilt from it.")]
		#[derive(Debug, Clone, Copy, Default)]
		pub struct $marker;

		impl Sealed for $marker {}

		#[doc = concat!("Public (encapsulation) key for `", $variant, "`.")]
		#[derive(Clone, Debug)]
		pub struct $pk_wrap(Vec<u8>);

		impl AsRef<[u8]> for $pk_wrap {
			fn as_ref(&self) -> &[u8] {
				&self.0
			}
		}

		#[doc = concat!("Private (decapsulation) key for `", $variant, "` — 64-byte `d || z` seed plus expanded `dk`.")]
		pub struct $sk_wrap {
			dk: $dk,
			seed: [u8; 64],
		}

		impl Zeroize for $sk_wrap {
			fn zeroize(&mut self) {
				self.seed.zeroize();
				// The expanded `dk` zeroizes via its own `Drop`
				// (requires the `ml-kem/zeroize` feature, enabled in Cargo.toml).
			}
		}

		impl ZeroizeOnDrop for $sk_wrap {}

		impl Drop for $sk_wrap {
			fn drop(&mut self) {
				self.zeroize();
			}
		}

		#[doc = concat!("Encapsulated key (ciphertext) for `", $variant, "`.")]
		#[derive(Clone, Debug)]
		pub struct $enc_wrap(Vec<u8>);

		impl AsRef<[u8]> for $enc_wrap {
			fn as_ref(&self) -> &[u8] {
				&self.0
			}
		}

		impl Kem for $marker {
			const ID: u16 = $id;
			const ENCAPPED_KEY_LEN: usize = $nenc;
			const PUBLIC_KEY_LEN: usize = $npk;
			const PRIVATE_KEY_LEN: usize = 64;
			const SHARED_SECRET_LEN: usize = 32;

			type PublicKey = $pk_wrap;
			type PrivateKey = $sk_wrap;
			type EncappedKey = $enc_wrap;
			type SharedSecret = MlKemSharedSecret;

			fn generate<R: CryptoRng + RngCore>(
				rng: &mut R,
			) -> Result<(Self::PrivateKey, Self::PublicKey), HpkeError> {
				let mut seed = [0u8; 64];
				rng.fill_bytes(&mut seed);
				Ok($from_seed(seed))
			}

			fn derive_key_pair(
				ikm: &[u8],
			) -> Result<(Self::PrivateKey, Self::PublicKey), HpkeError> {
				// draft-connolly-cfrg-hpke-mlkem-04 §3.2: `ikm` is the 64-byte
				// (d, z) seed passed directly to FIPS 203 KeyGen_internal.
				// Domain separation across parameter sets is provided by the
				// KEM itself: KeyGen_internal mixes `k` (3 vs 4) into G(d || k).
				if ikm.len() != 64 {
					return Err(HpkeError::DeriveKeyPairError);
				}
				let mut seed = [0u8; 64];
				seed.copy_from_slice(ikm);
				Ok($from_seed(seed))
			}

			fn encap<R: CryptoRng + RngCore>(
				rng: &mut R,
				pk_r: &Self::PublicKey,
			) -> Result<(Self::SharedSecret, Self::EncappedKey), HpkeError> {
				use ml_kem::kem::Encapsulate as _;
				let ek_bytes: ml_kem::kem::Key<$ek> = pk_r
					.0
					.as_slice()
					.try_into()
					.map_err(|_| HpkeError::InvalidPublicKey)?;
				let ek = <$ek>::new(&ek_bytes).map_err(|_| HpkeError::InvalidPublicKey)?;
				let mut compat = RngCompat10(rng);
				let (ct, ss) = ek.encapsulate_with_rng(&mut compat);
				Ok((
					MlKemSharedSecret(ss.iter().copied().collect()),
					$enc_wrap(ct.iter().copied().collect()),
				))
			}

			fn decap(
				enc: &Self::EncappedKey,
				sk_r: &Self::PrivateKey,
			) -> Result<Self::SharedSecret, HpkeError> {
				use ml_kem::kem::Decapsulate as _;
				let ct: $ct = enc
					.0
					.as_slice()
					.try_into()
					.map_err(|_| HpkeError::InvalidEncappedKey)?;
				let ss = sk_r.dk.decapsulate(&ct);
				Ok(MlKemSharedSecret(ss.iter().copied().collect()))
			}

			fn pk_from_bytes(b: &[u8]) -> Result<Self::PublicKey, HpkeError> {
				if b.len() != Self::PUBLIC_KEY_LEN {
					return Err(HpkeError::InvalidPublicKey);
				}
				Ok($pk_wrap(b.to_vec()))
			}

			fn sk_from_bytes(b: &[u8]) -> Result<Self::PrivateKey, HpkeError> {
				if b.len() != 64 {
					return Err(HpkeError::InvalidPrivateKey);
				}
				let mut seed = [0u8; 64];
				seed.copy_from_slice(b);
				let (sk, _pk) = $from_seed(seed);
				Ok(sk)
			}

			fn enc_from_bytes(b: &[u8]) -> Result<Self::EncappedKey, HpkeError> {
				if b.len() != Self::ENCAPPED_KEY_LEN {
					return Err(HpkeError::InvalidEncappedKey);
				}
				Ok($enc_wrap(b.to_vec()))
			}

			fn pk_to_bytes(pk: &Self::PublicKey) -> Vec<u8> {
				pk.0.clone()
			}
		}

		fn $from_seed(seed: [u8; 64]) -> ($sk_wrap, $pk_wrap) {
			use ml_kem::kem::KeyExport as _;
			let ml_seed: ml_kem::Seed = seed.into();
			let dk = <$dk>::from_seed(ml_seed);
			let ek = dk.encapsulation_key();
			let ek_bytes: Vec<u8> = ek.to_bytes().iter().copied().collect();
			($sk_wrap { dk, seed }, $pk_wrap(ek_bytes))
		}
	};
}

ml_kem_variant!(
	MlKem768,
	"ML-KEM-768",
	0x0041,
	1088,
	1184,
	ml_kem::DecapsulationKey768,
	ml_kem::EncapsulationKey768,
	ml_kem::ml_kem_768::Ciphertext,
	MlKem768PublicKey,
	MlKem768PrivateKey,
	MlKem768EncappedKey,
	ml_kem_768_from_seed,
);

ml_kem_variant!(
	MlKem1024,
	"ML-KEM-1024",
	0x0042,
	1568,
	1568,
	ml_kem::DecapsulationKey1024,
	ml_kem::EncapsulationKey1024,
	ml_kem::ml_kem_1024::Ciphertext,
	MlKem1024PublicKey,
	MlKem1024PrivateKey,
	MlKem1024EncappedKey,
	ml_kem_1024_from_seed,
);

#[cfg(test)]
mod tests {
	use super::*;
	use rand_core::{OsRng, TryRngCore as _};

	#[test]
	fn xwing_roundtrip() {
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (sk_r, pk_r) = XWingDraft06::generate(&mut rng).unwrap();
		let (ss_e, enc) = XWingDraft06::encap(&mut rng, &pk_r).unwrap();
		let ss_d = XWingDraft06::decap(&enc, &sk_r).unwrap();
		assert_eq!(ss_e.as_ref(), ss_d.as_ref());
		assert_eq!(ss_e.as_ref().len(), 32);
		assert_eq!(enc.as_ref().len(), 1120);
		assert_eq!(pk_r.as_ref().len(), 1216);
	}

	#[test]
	fn xwing_derive_key_pair_roundtrip() {
		let ikm = b"test input keying material for xwing derive";
		let (sk_r, pk_r) = XWingDraft06::derive_key_pair(ikm).unwrap();
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (ss_e, enc) = XWingDraft06::encap(&mut rng, &pk_r).unwrap();
		let ss_d = XWingDraft06::decap(&enc, &sk_r).unwrap();
		assert_eq!(ss_e.as_ref(), ss_d.as_ref());
	}

	#[test]
	fn xwing_sk_from_to_bytes() {
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (sk_r, pk_r) = XWingDraft06::generate(&mut rng).unwrap();
		let sk_bytes: [u8; 32] = sk_r.seed;
		let sk_r2 = XWingDraft06::sk_from_bytes(&sk_bytes).unwrap();
		let pk_bytes1 = XWingDraft06::pk_to_bytes(&pk_r);
		let (_, pk_r2) = keypair_from_seed(sk_r2.seed);
		let pk_bytes2 = XWingDraft06::pk_to_bytes(&pk_r2);
		assert_eq!(pk_bytes1, pk_bytes2);
	}

	#[test]
	fn ml_kem_768_roundtrip() {
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (sk_r, pk_r) = MlKem768::generate(&mut rng).unwrap();
		let (ss_e, enc) = MlKem768::encap(&mut rng, &pk_r).unwrap();
		let ss_d = MlKem768::decap(&enc, &sk_r).unwrap();
		assert_eq!(ss_e.as_ref(), ss_d.as_ref());
		assert_eq!(ss_e.as_ref().len(), 32);
		assert_eq!(enc.as_ref().len(), 1088);
		assert_eq!(pk_r.as_ref().len(), 1184);
	}

	#[test]
	fn ml_kem_1024_roundtrip() {
		let mut os_rng = OsRng;
		let mut rng = os_rng.unwrap_mut();
		let (sk_r, pk_r) = MlKem1024::generate(&mut rng).unwrap();
		let (ss_e, enc) = MlKem1024::encap(&mut rng, &pk_r).unwrap();
		let ss_d = MlKem1024::decap(&enc, &sk_r).unwrap();
		assert_eq!(ss_e.as_ref(), ss_d.as_ref());
		assert_eq!(ss_e.as_ref().len(), 32);
		assert_eq!(enc.as_ref().len(), 1568);
		assert_eq!(pk_r.as_ref().len(), 1568);
	}

	/// Even with the same 64-byte (d, z) seed, ML-KEM-768 and ML-KEM-1024 produce
	/// different keys: FIPS 203 Algorithm 13 mixes the parameter `k` (3 vs 4)
	/// into G(d || k) when expanding the matrix seed and noise PRF, so the two
	/// parameter sets are cryptographically independent for any shared seed.
	#[test]
	fn ml_kem_768_and_1024_derive_distinct_keys_from_same_ikm() {
		let ikm = [0x5Au8; 64];
		let (_, pk_768) = MlKem768::derive_key_pair(&ikm).unwrap();
		let (_, pk_1024) = MlKem1024::derive_key_pair(&ikm).unwrap();
		let n = pk_768.as_ref().len().min(pk_1024.as_ref().len());
		assert_ne!(&pk_768.as_ref()[..n], &pk_1024.as_ref()[..n]);
	}

	/// `MlKem768::derive_key_pair(ikm)` must be deterministic — the same ikm
	/// always produces the same key pair.
	#[test]
	fn ml_kem_768_derive_is_deterministic() {
		let ikm = [0x33u8; 64];
		let (_, pk1) = MlKem768::derive_key_pair(&ikm).unwrap();
		let (_, pk2) = MlKem768::derive_key_pair(&ikm).unwrap();
		assert_eq!(pk1.as_ref(), pk2.as_ref());
	}

	/// draft-connolly-cfrg-hpke-mlkem-04 §3.2: `ikm` is the 64-byte (d, z) seed
	/// passed to `ML-KEM.KeyGen_internal(d, z)`. Reject any other length.
	#[test]
	fn ml_kem_768_derive_rejects_non_64_byte_ikm() {
		assert!(matches!(
			MlKem768::derive_key_pair(b""),
			Err(HpkeError::DeriveKeyPairError)
		));
		assert!(matches!(
			MlKem768::derive_key_pair(&[0u8; 32]),
			Err(HpkeError::DeriveKeyPairError)
		));
		assert!(matches!(
			MlKem768::derive_key_pair(&[0u8; 63]),
			Err(HpkeError::DeriveKeyPairError)
		));
		assert!(matches!(
			MlKem768::derive_key_pair(&[0u8; 65]),
			Err(HpkeError::DeriveKeyPairError)
		));
	}

	/// Same as the 768 case for ML-KEM-1024.
	#[test]
	fn ml_kem_1024_derive_rejects_non_64_byte_ikm() {
		assert!(matches!(
			MlKem1024::derive_key_pair(b""),
			Err(HpkeError::DeriveKeyPairError)
		));
		assert!(matches!(
			MlKem1024::derive_key_pair(&[0u8; 63]),
			Err(HpkeError::DeriveKeyPairError)
		));
		assert!(matches!(
			MlKem1024::derive_key_pair(&[0u8; 65]),
			Err(HpkeError::DeriveKeyPairError)
		));
	}

	/// draft-connolly-cfrg-hpke-mlkem-04 §3.2 mandates that the 64-byte `ikm`
	/// IS the (d, z) seed, with no transformation. Verify the seed stored in
	/// the private key equals the input ikm exactly.
	#[test]
	fn ml_kem_768_derive_uses_ikm_as_seed_unchanged() {
		let ikm: [u8; 64] = core::array::from_fn(|i| u8::try_from(i).unwrap());
		let (sk, _) = MlKem768::derive_key_pair(&ikm).unwrap();
		assert_eq!(sk.seed, ikm);
	}

	#[test]
	fn ml_kem_1024_derive_uses_ikm_as_seed_unchanged() {
		let ikm: [u8; 64] = core::array::from_fn(|i| u8::try_from(i).unwrap().wrapping_add(1));
		let (sk, _) = MlKem1024::derive_key_pair(&ikm).unwrap();
		assert_eq!(sk.seed, ikm);
	}
}
