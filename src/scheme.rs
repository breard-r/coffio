use crate::Error;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Scheme {
	XChaCha20Poly1305WithBlake3 = 1,
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
