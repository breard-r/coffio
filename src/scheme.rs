use crate::Error;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Scheme {
	XChaCha20Poly1305WithBlake3 = 1,
}

impl Scheme {
	pub(crate) fn canonicalization_hasher(&self) -> impl digest::Digest {
		match self {
			Scheme::XChaCha20Poly1305WithBlake3 => blake3::Hasher::new(),
		}
	}

	pub(crate) fn get_kdf(&self) -> impl Fn(&[u8], &[u8]) -> Vec<u8> {
		match self {
			Scheme::XChaCha20Poly1305WithBlake3 => crate::kdf::blake3_derive,
		}
	}

	pub(crate) fn key_size(&self) -> usize {
		match self {
			Scheme::XChaCha20Poly1305WithBlake3 => 32,
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
