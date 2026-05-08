//! HPKE AEAD primitives (RFC 9180 §7.3).

use alloc::vec::Vec;

use crate::HpkeError;
use crate::sealed::Sealed;

/// Sealed trait for HPKE-supported AEAD ciphersuite components.
///
/// Implementors expose the IANA ID and length parameters. Sealing/opening live
/// on the [`SealingAead`] subtrait so that export-only configurations cannot
/// be passed to `seal_*`/`open_*` methods.
pub trait Aead: Sealed {
	/// IANA AEAD ID (RFC 9180 §7.3).
	const ID: u16;
	/// Key length in bytes (`Nk`).
	const KEY_LEN: usize;
	/// Nonce length in bytes (`Nn`).
	const NONCE_LEN: usize;
	/// Authentication tag length in bytes (`Nt`).
	const TAG_LEN: usize;
}

/// Marker subtrait for AEADs that actually encrypt (i.e. not export-only).
///
/// Both `seal` and `open` collapse all underlying-cipher errors into a single
/// typed error per direction (`SealError` / `OpenError`) — including the
/// otherwise-unreachable "wrong key length" path. This keeps `open` failures
/// indistinguishable to an attacker regardless of failure cause.
pub trait SealingAead: Aead {
	/// Encrypt `pt` with `key`, `nonce`, and `aad`. Output is `pt.len() + TAG_LEN` bytes.
	fn seal(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, HpkeError>;
	/// Decrypt `ct` (which includes the tag) with `key`, `nonce`, and `aad`.
	fn open(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, HpkeError>;
}

/// ChaCha20-Poly1305 (RFC 9180 §7.3, ID `0x0003`).
#[derive(Debug, Clone, Copy, Default)]
pub struct ChaCha20Poly1305;

impl Sealed for ChaCha20Poly1305 {}
impl Aead for ChaCha20Poly1305 {
	const ID: u16 = 0x0003;
	const KEY_LEN: usize = 32;
	const NONCE_LEN: usize = 12;
	const TAG_LEN: usize = 16;
}
impl SealingAead for ChaCha20Poly1305 {
	fn seal(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, HpkeError> {
		use chacha20poly1305::{
			KeyInit, Nonce,
			aead::{Aead as _, Payload},
		};
		let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
			.map_err(|_| HpkeError::SealError)?;
		let nonce = Nonce::from_slice(nonce);
		cipher
			.encrypt(nonce, Payload { msg: pt, aad })
			.map_err(|_| HpkeError::SealError)
	}
	fn open(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, HpkeError> {
		use chacha20poly1305::{
			KeyInit, Nonce,
			aead::{Aead as _, Payload},
		};
		let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
			.map_err(|_| HpkeError::OpenError)?;
		let nonce = Nonce::from_slice(nonce);
		cipher
			.decrypt(nonce, Payload { msg: ct, aad })
			.map_err(|_| HpkeError::OpenError)
	}
}

/// AES-128-GCM (RFC 9180 §7.3, ID `0x0001`).
///
/// Constant-time only on platforms with hardware AES-NI/PCLMULQDQ. Prefer
/// [`ChaCha20Poly1305`] on platforms without these instructions.
#[derive(Debug, Clone, Copy, Default)]
pub struct Aes128Gcm;

impl Sealed for Aes128Gcm {}
impl Aead for Aes128Gcm {
	const ID: u16 = 0x0001;
	const KEY_LEN: usize = 16;
	const NONCE_LEN: usize = 12;
	const TAG_LEN: usize = 16;
}
impl SealingAead for Aes128Gcm {
	fn seal(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, HpkeError> {
		use aes_gcm::{KeyInit, aead::Aead as _};
		let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).map_err(|_| HpkeError::SealError)?;
		let nonce = aes_gcm::Nonce::from_slice(nonce);
		cipher
			.encrypt(nonce, aead::Payload { msg: pt, aad })
			.map_err(|_| HpkeError::SealError)
	}
	fn open(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, HpkeError> {
		use aes_gcm::{KeyInit, aead::Aead as _};
		let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).map_err(|_| HpkeError::OpenError)?;
		let nonce = aes_gcm::Nonce::from_slice(nonce);
		cipher
			.decrypt(nonce, aead::Payload { msg: ct, aad })
			.map_err(|_| HpkeError::OpenError)
	}
}

/// AES-256-GCM (RFC 9180 §7.3, ID `0x0002`).
///
/// Constant-time only on platforms with hardware AES-NI/PCLMULQDQ.
#[derive(Debug, Clone, Copy, Default)]
pub struct Aes256Gcm;

impl Sealed for Aes256Gcm {}
impl Aead for Aes256Gcm {
	const ID: u16 = 0x0002;
	const KEY_LEN: usize = 32;
	const NONCE_LEN: usize = 12;
	const TAG_LEN: usize = 16;
}
impl SealingAead for Aes256Gcm {
	fn seal(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, HpkeError> {
		use aes_gcm::{KeyInit, aead::Aead as _};
		let cipher = aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|_| HpkeError::SealError)?;
		let nonce = aes_gcm::Nonce::from_slice(nonce);
		cipher
			.encrypt(nonce, aead::Payload { msg: pt, aad })
			.map_err(|_| HpkeError::SealError)
	}
	fn open(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, HpkeError> {
		use aes_gcm::{KeyInit, aead::Aead as _};
		let cipher = aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|_| HpkeError::OpenError)?;
		let nonce = aes_gcm::Nonce::from_slice(nonce);
		cipher
			.decrypt(nonce, aead::Payload { msg: ct, aad })
			.map_err(|_| HpkeError::OpenError)
	}
}

/// Export-only "AEAD" marker (RFC 9180 §7.3, ID `0xFFFF`).
///
/// Configurations parameterized over `ExportOnly` cannot encrypt or decrypt;
/// only the export methods are available, because `ExportOnly` does not
/// implement [`SealingAead`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ExportOnly;

impl Sealed for ExportOnly {}
impl Aead for ExportOnly {
	const ID: u16 = 0xFFFF;
	const KEY_LEN: usize = 0;
	const NONCE_LEN: usize = 0;
	const TAG_LEN: usize = 0;
}

#[cfg(test)]
mod tests {
	use super::*;
	use hex::FromHex;

	/// RFC 8439 §2.8.2 test vector.
	#[test]
	fn rfc8439_chacha20poly1305_test_vector() {
		let key = Vec::from_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
			.unwrap();
		let nonce = Vec::from_hex("070000004041424344454647").unwrap();
		let aad = Vec::from_hex("50515253c0c1c2c3c4c5c6c7").unwrap();
		let pt = b"Ladies and Gentlemen of the class of '99: \
                   If I could offer you only one tip for the future, sunscreen would be it.";

		let ct = ChaCha20Poly1305::seal(&key, &nonce, &aad, pt).unwrap();
		let recovered = ChaCha20Poly1305::open(&key, &nonce, &aad, &ct).unwrap();
		assert_eq!(recovered, pt);

		let mut bad = ct.clone();
		bad[0] ^= 1;
		assert_eq!(
			ChaCha20Poly1305::open(&key, &nonce, &aad, &bad),
			Err(HpkeError::OpenError)
		);
	}

	#[test]
	fn aes128gcm_roundtrip_short() {
		let key = [0u8; 16];
		let nonce = [0u8; 12];
		let aad = b"";
		let pt = b"hello";
		let ct = Aes128Gcm::seal(&key, &nonce, aad, pt).unwrap();
		assert_eq!(ct.len(), pt.len() + 16);
		assert_eq!(Aes128Gcm::open(&key, &nonce, aad, &ct).unwrap(), pt);
	}

	#[test]
	fn aes256gcm_roundtrip_short() {
		let key = [0u8; 32];
		let nonce = [0u8; 12];
		let pt = b"world";
		let ct = Aes256Gcm::seal(&key, &nonce, b"aad", pt).unwrap();
		assert_eq!(Aes256Gcm::open(&key, &nonce, b"aad", &ct).unwrap(), pt);
	}

	#[test]
	fn aes128gcm_rejects_bad_key_len() {
		let r = Aes128Gcm::seal(&[0u8; 15], &[0u8; 12], b"", b"");
		assert!(r.is_err());
	}

	#[test]
	fn export_only_implements_aead_only() {
		fn assert_aead<A: Aead>() {}
		assert_aead::<ExportOnly>();
		assert_eq!(ExportOnly::ID, 0xFFFF);
		assert_eq!(ExportOnly::KEY_LEN, 0);
		assert_eq!(ExportOnly::NONCE_LEN, 0);
		assert_eq!(ExportOnly::TAG_LEN, 0);
	}
}
