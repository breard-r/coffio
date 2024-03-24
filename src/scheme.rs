#[cfg(feature = "encryption")]
use crate::encrypted_data::EncryptedData;
#[cfg(feature = "encryption")]
use crate::error::Result;
#[cfg(feature = "encryption")]
use crate::kdf::KdfFunction;
use crate::Error;

#[cfg(feature = "encryption")]
mod aes;
#[cfg(feature = "encryption")]
mod blake3;
#[cfg(feature = "encryption")]
mod sha2;
#[cfg(feature = "encryption")]
mod xchacha20poly1305;

#[cfg(feature = "encryption")]
pub(crate) type DecryptionFunction = dyn Fn(&[u8], &EncryptedData, &str) -> Result<Vec<u8>>;
#[cfg(feature = "encryption")]
pub(crate) type EncryptionFunction = dyn Fn(&[u8], &[u8], &[u8], &str) -> Result<EncryptedData>;
#[cfg(feature = "encryption")]
pub(crate) type GenNonceFunction = dyn Fn() -> Result<Vec<u8>>;
pub(crate) type SchemeSerializeType = u32;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Scheme {
	XChaCha20Poly1305WithBlake3 = 1,
	Aes128GcmWithSha256 = 2,
}

impl Scheme {
	pub(crate) fn get_ikm_size(&self) -> usize {
		match self {
			Scheme::XChaCha20Poly1305WithBlake3 => 32,
			Scheme::Aes128GcmWithSha256 => 32,
		}
	}
}

#[cfg(feature = "encryption")]
impl Scheme {
	pub(crate) fn get_kdf(&self) -> Box<KdfFunction> {
		match self {
			Scheme::XChaCha20Poly1305WithBlake3 => Box::new(blake3::blake3_derive),
			Scheme::Aes128GcmWithSha256 => Box::new(sha2::sha256_derive),
		}
	}

	pub(crate) fn get_decryption(&self) -> Box<DecryptionFunction> {
		match self {
			Scheme::XChaCha20Poly1305WithBlake3 => {
				Box::new(xchacha20poly1305::xchacha20poly1305_decrypt)
			}
			Scheme::Aes128GcmWithSha256 => Box::new(aes::aes128gcm_decrypt),
		}
	}

	pub(crate) fn get_encryption(&self) -> Box<EncryptionFunction> {
		match self {
			Scheme::XChaCha20Poly1305WithBlake3 => {
				Box::new(xchacha20poly1305::xchacha20poly1305_encrypt)
			}
			Scheme::Aes128GcmWithSha256 => Box::new(aes::aes128gcm_encrypt),
		}
	}

	pub(crate) fn get_gen_nonce(&self) -> Box<GenNonceFunction> {
		match self {
			Scheme::XChaCha20Poly1305WithBlake3 => {
				Box::new(xchacha20poly1305::xchacha20poly1305_gen_nonce)
			}
			Scheme::Aes128GcmWithSha256 => Box::new(aes::aes128gcm_gen_nonce),
		}
	}
}

impl TryFrom<SchemeSerializeType> for Scheme {
	type Error = Error;

	fn try_from(value: SchemeSerializeType) -> Result<Self, Self::Error> {
		match value {
			1 => Ok(Scheme::XChaCha20Poly1305WithBlake3),
			2 => Ok(Scheme::Aes128GcmWithSha256),
			_ => Err(Error::ParsingSchemeUnknownScheme(value)),
		}
	}
}
