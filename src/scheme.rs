use crate::encryption::{DecryptionFunction, EncryptionFunction};
use crate::kdf::KdfFunction;
use crate::Error;

mod blake3;
mod xchacha20poly1305;

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
