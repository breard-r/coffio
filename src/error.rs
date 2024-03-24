pub(crate) type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
	#[error("cipher error: {0}")]
	ChaCha20Poly1305Error(chacha20poly1305::Error),
	#[error("ikm error: no input key material available")]
	IkmNoneAvailable,
	#[error("ikm error: {0}: input key material not found")]
	IkmNotFound(crate::ikm::IkmId),
	#[error("encoded data: invalid nonce size: got {1} instead of {0}")]
	InvalidNonceSize(usize, usize),
	#[error("parsing error: invalid base64-urlsafe-nopadding data: {0}")]
	ParsingBase64Error(base64ct::Error),
	#[error("parsing error: encoded data: empty nonce")]
	ParsingEncodedDataEmptyNonce,
	#[error("parsing error: encoded data: empty ciphertext")]
	ParsingEncodedDataEmptyCiphertext,
	#[error("parsing error: encoded data: invalid IKM id: {0:?}")]
	ParsingEncodedDataInvalidIkmId(Vec<u8>),
	#[error("parsing error: encoded data: invalid IKM length{0}")]
	ParsingEncodedDataInvalidIkmLen(usize),
	#[error("parsing error: encoded data: invalid IKM list id: {0:?}")]
	ParsingEncodedDataInvalidIkmListId(Vec<u8>),
	#[error("parsing error: encoded data: invalid IKM list length{0}")]
	ParsingEncodedDataInvalidIkmListLen(usize),
	#[error("parsing error: encoded data: invalid number of parts: got {1} instead of {0}")]
	ParsingEncodedDataInvalidPartLen(usize, usize),
	#[error("parsing error: encoded data: invalid timestamp: {0:?}")]
	ParsingEncodedDataInvalidTimestamp(Vec<u8>),
	#[error("parsing error: scheme: {0}: unknown scheme")]
	ParsingSchemeUnknownScheme(crate::scheme::SchemeSerializeType),
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

impl From<chacha20poly1305::Error> for Error {
	fn from(error: chacha20poly1305::Error) -> Self {
		Error::ChaCha20Poly1305Error(error)
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
