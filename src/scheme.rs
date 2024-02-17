use crate::encryption::EncryptionFunction;
use crate::kdf::KdfFunction;
use crate::Error;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Scheme {
	XChaCha20Poly1305WithBlake3 = 1,
}

impl Scheme {
	pub(crate) fn get_kdf(&self) -> Box<KdfFunction> {
		match self {
			Scheme::XChaCha20Poly1305WithBlake3 => Box::new(crate::kdf::blake3_derive),
		}
	}

	pub(crate) fn get_encryption(&self) -> Box<EncryptionFunction> {
		match self {
			Scheme::XChaCha20Poly1305WithBlake3 => {
				Box::new(crate::encryption::xchacha20poly1305_encrypt)
			}
		}
	}
}

impl TryFrom<u32> for Scheme {
	type Error = Error;

	fn try_from(value: u32) -> Result<Self, Self::Error> {
		match value {
			1 => Ok(Scheme::XChaCha20Poly1305WithBlake3),
			_ => Err(Error::ParsingUnknownScheme(value)),
		}
	}
}
