use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
	#[error("ikm error: no input key material available")]
	IkmNoneAvailable,
	#[error("ikm error: {0}: input key material not found")]
	IkmNotFound(u32),
	#[error("parsing error: invalid base64-urlsafe-nopadding data: {0}")]
	ParsingBase64Error(base64ct::Error),
	#[error("parsing error: invalid data length: {0} bytes")]
	ParsingInvalidLength(usize),
	#[error("parsing error: {0}: unknown scheme")]
	ParsingUnknownScheme(u32),
	#[error("unable to generate random values: {0}")]
	RandomSourceError(getrandom::Error),
	#[error("system time error: {0}")]
	SystemTimeError(std::time::SystemTimeError),
	#[error("system time error: {0}: unable to represent this timestamp as a system time")]
	SystemTimeReprError(u64),
}

impl From<base64ct::Error> for Error {
	fn from(error: base64ct::Error) -> Self {
		Error::ParsingBase64Error(error)
	}
}

impl From<getrandom::Error> for Error {
	fn from(error: getrandom::Error) -> Self {
		Error::RandomSourceError(error)
	}
}

impl From<std::time::SystemTimeError> for Error {
	fn from(error: std::time::SystemTimeError) -> Self {
		Error::SystemTimeError(error)
	}
}