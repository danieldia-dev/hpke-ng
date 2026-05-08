//! HPKE Key Derivation Functions (RFC 9180 §4 + RFC 5869).

use alloc::vec::Vec;

use hkdf::Hkdf;
use sha2::{Sha256, Sha384, Sha512};
use zeroize::Zeroizing;

use crate::HpkeError;
use crate::sealed::Sealed;

/// Sealed trait for HPKE-supported KDFs.
pub trait Kdf: Sealed {
	/// IANA KDF ID (RFC 9180 §7.2).
	const ID: u16;
	/// Underlying hash output length in bytes (`Nh`).
	const HASH_LEN: usize;
	/// HKDF-Extract: returns a pseudorandom key of length `HASH_LEN`.
	fn extract(salt: &[u8], ikm: &[u8]) -> Vec<u8>;
	/// HKDF-Expand: returns `out_len` bytes derived from `prk` and `info`.
	fn expand(prk: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>, HpkeError>;
}

/// HKDF-SHA-256 (RFC 9180 §7.2, ID `0x0001`).
#[derive(Debug, Clone, Copy, Default)]
pub struct HkdfSha256;

impl Sealed for HkdfSha256 {}
impl Kdf for HkdfSha256 {
	const ID: u16 = 0x0001;
	const HASH_LEN: usize = 32;

	fn extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
		let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
		prk.to_vec()
	}

	fn expand(prk: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>, HpkeError> {
		let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| HpkeError::DeriveKeyPairError)?;
		let mut out = alloc::vec![0u8; out_len];
		hk.expand(info, &mut out)
			.map_err(|_| HpkeError::ExportLengthExceeded)?;
		Ok(out)
	}
}

/// HKDF-SHA-384 (RFC 9180 §7.2, ID `0x0002`).
#[derive(Debug, Clone, Copy, Default)]
pub struct HkdfSha384;

impl Sealed for HkdfSha384 {}
impl Kdf for HkdfSha384 {
	const ID: u16 = 0x0002;
	const HASH_LEN: usize = 48;

	fn extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
		let (prk, _) = Hkdf::<Sha384>::extract(Some(salt), ikm);
		prk.to_vec()
	}

	fn expand(prk: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>, HpkeError> {
		let hk = Hkdf::<Sha384>::from_prk(prk).map_err(|_| HpkeError::DeriveKeyPairError)?;
		let mut out = alloc::vec![0u8; out_len];
		hk.expand(info, &mut out)
			.map_err(|_| HpkeError::ExportLengthExceeded)?;
		Ok(out)
	}
}

/// HKDF-SHA-512 (RFC 9180 §7.2, ID `0x0003`).
#[derive(Debug, Clone, Copy, Default)]
pub struct HkdfSha512;

impl Sealed for HkdfSha512 {}
impl Kdf for HkdfSha512 {
	const ID: u16 = 0x0003;
	const HASH_LEN: usize = 64;

	fn extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
		let (prk, _) = Hkdf::<Sha512>::extract(Some(salt), ikm);
		prk.to_vec()
	}

	fn expand(prk: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>, HpkeError> {
		let hk = Hkdf::<Sha512>::from_prk(prk).map_err(|_| HpkeError::DeriveKeyPairError)?;
		let mut out = alloc::vec![0u8; out_len];
		hk.expand(info, &mut out)
			.map_err(|_| HpkeError::ExportLengthExceeded)?;
		Ok(out)
	}
}

/// HPKE `LabeledExtract` (RFC 9180 §4).
///
/// `labeled_ikm` is `Zeroizing` because at some call sites `ikm` is secret
/// material (raw DH output, PSK, derive-key-pair IKM).
#[allow(dead_code)]
pub(crate) fn labeled_extract<F: Kdf>(
	salt: &[u8],
	suite_id: &[u8],
	label: &[u8],
	ikm: &[u8],
) -> Vec<u8> {
	let mut labeled_ikm = Zeroizing::new(Vec::with_capacity(
		7 + suite_id.len() + label.len() + ikm.len(),
	));
	labeled_ikm.extend_from_slice(b"HPKE-v1");
	labeled_ikm.extend_from_slice(suite_id);
	labeled_ikm.extend_from_slice(label);
	labeled_ikm.extend_from_slice(ikm);
	F::extract(salt, &labeled_ikm)
}

/// HPKE `LabeledExpand` (RFC 9180 §4).
#[allow(dead_code)]
pub(crate) fn labeled_expand<F: Kdf>(
	prk: &[u8],
	suite_id: &[u8],
	label: &[u8],
	info: &[u8],
	out_len: usize,
) -> Result<Vec<u8>, HpkeError> {
	let l_u16: u16 = out_len
		.try_into()
		.map_err(|_| HpkeError::ExportLengthExceeded)?;
	let mut labeled_info = Zeroizing::new(Vec::with_capacity(
		2 + 7 + suite_id.len() + label.len() + info.len(),
	));
	labeled_info.extend_from_slice(&l_u16.to_be_bytes());
	labeled_info.extend_from_slice(b"HPKE-v1");
	labeled_info.extend_from_slice(suite_id);
	labeled_info.extend_from_slice(label);
	labeled_info.extend_from_slice(info);
	F::expand(prk, &labeled_info, out_len)
}

#[cfg(test)]
mod tests {
	use super::*;
	use hex::FromHex;

	/// RFC 5869 Appendix A.1 — Basic test case with SHA-256.
	#[test]
	fn rfc5869_a1_extract_expand_sha256() {
		let ikm = Vec::from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
		let salt = Vec::from_hex("000102030405060708090a0b0c").unwrap();
		let info = Vec::from_hex("f0f1f2f3f4f5f6f7f8f9").unwrap();
		let l = 42;
		let expected_prk =
			Vec::from_hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
				.unwrap();
		let expected_okm = Vec::from_hex(
			"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
		)
		.unwrap();

		let prk = HkdfSha256::extract(&salt, &ikm);
		assert_eq!(prk, expected_prk);

		let okm = HkdfSha256::expand(&prk, &info, l).unwrap();
		assert_eq!(okm, expected_okm);
	}

	#[test]
	fn expand_rejects_oversize() {
		let prk = [0u8; 32];
		assert_eq!(
			HkdfSha256::expand(&prk, b"info", 8161),
			Err(HpkeError::ExportLengthExceeded)
		);
	}

	#[test]
	fn sha384_extract_expand_roundtrip() {
		let prk = HkdfSha384::extract(b"salt", b"ikm");
		assert_eq!(prk.len(), 48);
		let okm = HkdfSha384::expand(&prk, b"info", 48).unwrap();
		assert_eq!(okm.len(), 48);
		let okm2 = HkdfSha384::expand(&prk, b"info", 48).unwrap();
		assert_eq!(okm, okm2);
	}

	#[test]
	fn sha512_extract_expand_roundtrip() {
		let prk = HkdfSha512::extract(b"salt", b"ikm");
		assert_eq!(prk.len(), 64);
		let okm = HkdfSha512::expand(&prk, b"info", 64).unwrap();
		assert_eq!(okm.len(), 64);
	}

	#[test]
	fn expand_max_lengths() {
		let prk384 = HkdfSha384::extract(&[], b"ikm");
		assert!(HkdfSha384::expand(&prk384, b"info", 255 * 48).is_ok());
		assert_eq!(
			HkdfSha384::expand(&prk384, b"info", 255 * 48 + 1),
			Err(HpkeError::ExportLengthExceeded)
		);
	}

	#[test]
	fn labeled_helpers_compose() {
		let suite_id = b"KEM\x00\x20";
		let prk = labeled_extract::<HkdfSha256>(&[], suite_id, b"eae_prk", b"shared_secret_bytes");
		assert_eq!(prk.len(), 32);
		let okm =
			labeled_expand::<HkdfSha256>(&prk, suite_id, b"shared_secret", b"context", 32).unwrap();
		assert_eq!(okm.len(), 32);
		let okm2 =
			labeled_expand::<HkdfSha256>(&prk, suite_id, b"shared_secret", b"context", 32).unwrap();
		assert_eq!(okm, okm2);
	}

	#[test]
	fn labeled_expand_rejects_u16_overflow() {
		let prk = [0u8; 32];
		let r = labeled_expand::<HkdfSha256>(&prk, b"", b"", b"", 65_536);
		assert_eq!(r, Err(HpkeError::ExportLengthExceeded));
	}
}
