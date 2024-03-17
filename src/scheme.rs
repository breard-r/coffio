#[cfg(feature = "encryption")]
use crate::encrypted_data::EncryptedData;
#[cfg(feature = "encryption")]
use crate::error::Result;
#[cfg(feature = "encryption")]
use crate::kdf::KdfFunction;
use crate::Error;

#[cfg(feature = "encryption")]
mod blake3;
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
}

impl Scheme {
	pub(crate) fn get_ikm_size(&self) -> usize {
		match self {
			Scheme::XChaCha20Poly1305WithBlake3 => 32,
		}
	}
}

#[cfg(feature = "encryption")]
impl Scheme {
	pub(crate) fn get_kdf(&self) -> Box<KdfFunction> {
		match self {
			Scheme::XChaCha20Poly1305WithBlake3 => Box::new(blake3::blake3_derive),
		}
	}

	pub(crate) fn get_decryption(&self) -> Box<DecryptionFunction> {
		match self {
			Scheme::XChaCha20Poly1305WithBlake3 => {
				Box::new(xchacha20poly1305::xchacha20poly1305_decrypt)
			}
		}
	}

	pub(crate) fn get_encryption(&self) -> Box<EncryptionFunction> {
		match self {
			Scheme::XChaCha20Poly1305WithBlake3 => {
				Box::new(xchacha20poly1305::xchacha20poly1305_encrypt)
			}
		}
	}

	pub(crate) fn get_gen_nonce(&self) -> Box<GenNonceFunction> {
		match self {
			Scheme::XChaCha20Poly1305WithBlake3 => {
				Box::new(xchacha20poly1305::xchacha20poly1305_gen_nonce)
			}
		}
	}
}

impl TryFrom<SchemeSerializeType> for Scheme {
	type Error = Error;

	fn try_from(value: SchemeSerializeType) -> Result<Self, Self::Error> {
		match value {
			1 => Ok(Scheme::XChaCha20Poly1305WithBlake3),
			_ => Err(Error::ParsingSchemeUnknownScheme(value)),
		}
	}
}
