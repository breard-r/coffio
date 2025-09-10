pub(crate) type Result<T, E = Error> = core::result::Result<T, E>;

/// An error type representing all the things that can go wrong.
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
	/// Something went wrong during the encryption or decryption using AES-GCM.
	#[cfg(feature = "aes")]
	#[error("cipher error: {0}")]
	AesGcmError(aes_gcm::Error),
	/// Something went wrong during the encryption or decryption using (X)ChaCha-poly1305.
	#[cfg(feature = "chacha")]
	#[error("cipher error: {0}")]
	ChaCha20Poly1305Error(chacha20poly1305::Error),
	/// The IKM list does not contain any usable IKM.
	#[error("ikm error: no input key material available")]
	IkmNoneAvailable,
	/// The requested IKM has not been found in the list.
	#[error("ikm error: {0}: input key material not found")]
	IkmNotFound(crate::ikm::IkmId),
	/// The nonce does not meet the required size.
	#[error("encoded data: invalid nonce size: got {1} instead of {0}")]
	InvalidNonceSize(usize, usize),
	/// Something went wrong when encoding or decoding in base64.
	#[error("parsing error: invalid base64-urlsafe-nopadding data: {0}")]
	ParsingBase64Error(base64ct::Error),
	/// When parsing some encoded data, an empty nonce has been encountered.
	#[error("parsing error: encoded data: empty nonce")]
	ParsingEncodedDataEmptyNonce,
	/// When parsing some encoded data, an empty ciphertext has been encountered.
	#[error("parsing error: encoded data: empty ciphertext")]
	ParsingEncodedDataEmptyCiphertext,
	/// When parsing some encoded data, an invalid IKM id has been encountered.
	#[error("parsing error: encoded data: invalid IKM id: {0:?}")]
	ParsingEncodedDataInvalidIkmId(Vec<u8>),
	/// When parsing some encoded data, an invalid IKM length has been encountered.
	#[error("parsing error: encoded data: invalid IKM length: {0}")]
	ParsingEncodedDataInvalidIkmLen(usize),
	/// When parsing some encoded data, an invalid IKM list id has been encountered.
	#[error("parsing error: encoded data: invalid IKM list id: {0:?}")]
	ParsingEncodedDataInvalidIkmListId(Vec<u8>),
	/// When parsing some encoded data, an invalid IKM list length has been encountered.
	#[error("parsing error: encoded data: invalid IKM list length: {0}")]
	ParsingEncodedDataInvalidIkmListLen(usize),
	/// When parsing some encoded data, an invalid number of parts has been encountered.
	#[error("parsing error: encoded data: invalid number of parts: got {1} instead of {0}")]
	ParsingEncodedDataInvalidPartLen(usize, usize),
	/// When parsing some encoded data, an invalid timestamp has been encountered.
	#[error("parsing error: encoded data: invalid timestamp: {0:?}")]
	ParsingEncodedDataInvalidTimestamp(Vec<u8>),
	/// When parsing some encoded data, an invalid IKM list version has been encountered.
	#[error("parsing error: encoded data: invalid IKML version")]
	ParsingEncodedDataInvalidIkmlVersion,
	/// When parsing some encoded data, an invalid encrypted data version has been encountered.
	#[error("parsing error: encoded data: invalid encrypted data version")]
	ParsingEncodedDataInvalidEncVersion,
	/// An invalid scheme has been encountered.
	#[error("parsing error: scheme: {0}: unknown scheme")]
	ParsingSchemeUnknownScheme(crate::scheme::SchemeSerializeType),
	/// Attempting to decrypt data previously encrypted using IKM before its validity period while
	/// policy denies it.
	#[error("policy error: decryption: encrypted using an early IKM")]
	PolicyDecryptionEarly,
	/// Attempting to decrypt data previously encrypted using an expired IKM while policy denies
	/// it.
	#[error("policy error: decryption: encrypted using an expired IKM")]
	PolicyDecryptionExpiredEnc,
	/// Attempting to decrypt data previously encrypted using a now expired IKM while policy denies
	/// it.
	#[error("policy error: decryption: currently expired IKM")]
	PolicyDecryptionExpiredNow,
	/// Attempting to decrypt data previously encrypted using a time period located in the future
	/// while policy denies it.
	#[error("policy error: decryption: data encrypted in the future")]
	PolicyDecryptionFuture,
	/// Attempting to decrypt data previously encrypted using a now revoked IKM while policy denies
	/// it.
	#[error("policy error: decryption: currently revoked IKM")]
	PolicyDecryptionRevoked,
	/// Something went wrong when retrieving random data from the system.
	#[error("unable to generate random values: {0}")]
	RandomSourceError(getrandom::Error),
	/// A `std::time::SystemTimeError` has been encountered.
	#[error("system time error: {0}")]
	SystemTimeError(String),
	/// Something went wrong when trying to parse a timestamp.
	#[error("system time error: {0}: unable to represent this timestamp as a system time")]
	SystemTimeReprError(u64),
}

impl From<base64ct::Error> for Error {
	fn from(error: base64ct::Error) -> Self {
		Error::ParsingBase64Error(error)
	}
}

#[cfg(all(feature = "aes", not(feature = "chacha")))]
impl From<aes_gcm::Error> for Error {
	fn from(error: aes_gcm::Error) -> Self {
		Error::AesGcmError(error)
	}
}

#[cfg(feature = "chacha")]
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
		Error::SystemTimeError(error.to_string())
	}
}
