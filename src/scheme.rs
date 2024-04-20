#[cfg(feature = "encryption")]
use crate::encrypted_data::EncryptedData;
#[cfg(feature = "encryption")]
use crate::error::Result;
#[cfg(feature = "encryption")]
use crate::kdf::KdfFunction;
use crate::Error;

#[cfg(feature = "aes")]
mod aes;
#[cfg(feature = "chacha")]
mod blake3;
#[cfg(feature = "aes")]
mod sha2;
#[cfg(feature = "chacha")]
mod xchacha20poly1305;

#[cfg(feature = "encryption")]
pub(crate) type DecryptionFunction = dyn Fn(&[u8], &EncryptedData, &str) -> Result<Vec<u8>>;
#[cfg(feature = "encryption")]
pub(crate) type EncryptionFunction = dyn Fn(&[u8], &[u8], &[u8], &str) -> Result<EncryptedData>;
#[cfg(feature = "encryption")]
pub(crate) type GenNonceFunction = dyn Fn() -> Result<Vec<u8>>;
pub(crate) type SchemeSerializeType = u32;

/// The cryptographic primitives used to encrypt the data.
///
/// Coffio does not impose an unique way to encrypt data. You can therefore choose between one of
/// the supported scheme. Each scheme has advantages and drawbacks.
///
/// Before choosing a scheme, you should run the benchmark on the hardware where the encryption and
/// decryption process will take place. Some scheme may have hardware optimizations that you want
/// to take advantage of. Regarding the key length, the following website may help you choose one
/// that suits your requirements: [https://www.keylength.com/](https://www.keylength.com/)
///
/// In the following scheme description, the following terms are used:
/// - `Max data size` describes the maximal size of data that can safely be encrypted using a
/// single key and nonce, which means you should never pass a `data` parameter to
/// [encrypt][crate::Coffio::encrypt] that has a higher size. Coffio will not enforce this
/// limit, it is your responsibility to do so.
/// - `Max invocations` describes the maximal number of times you can safely call
/// [encrypt][crate::Coffio::encrypt] with a single key, which means you should either rotate
/// your IKM or use an appropriate key periodicity before reaching this number. Coffio will neither
/// enforce this limit nor count the number of invocations, it is your responsibility to do so.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Scheme {
	/// `default`
	/// - Key derivation: BLAKE3 derive_key mode
	/// - Encryption: XChaCha20-Poly1305
	/// - Key size: 256 bits
	/// - Nonce size: 192 bits
	/// - Max data size: 256 GB
	/// - Max invocations: no limitation
	/// - Resources: [RFC 7539](https://doi.org/10.17487/RFC7539)
	/// [draft-irtf-cfrg-xchacha](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha)
	#[cfg(feature = "chacha")]
	XChaCha20Poly1305WithBlake3 = 1,
	/// - Key derivation: HKDF-SHA256
	/// - Encryption: AES-GCM
	/// - Key size: 128 bits
	/// - Nonce size: 96 bits
	/// - Max data size: 64 GB
	/// - Max invocations: 2<sup>32</sup>
	/// - Resources: [NIST SP 800-38D](https://doi.org/10.6028/NIST.SP.800-38D)
	#[cfg(feature = "aes")]
	Aes128GcmWithSha256 = 2,
}

impl Scheme {
	pub(crate) fn get_ikm_size(&self) -> usize {
		match self {
			#[cfg(feature = "chacha")]
			Scheme::XChaCha20Poly1305WithBlake3 => 32,
			#[cfg(feature = "aes")]
			Scheme::Aes128GcmWithSha256 => 32,
		}
	}
}

#[cfg(feature = "encryption")]
impl Scheme {
	pub(crate) fn get_kdf(&self) -> Box<KdfFunction> {
		match self {
			#[cfg(feature = "chacha")]
			Scheme::XChaCha20Poly1305WithBlake3 => Box::new(blake3::blake3_derive),
			#[cfg(feature = "aes")]
			Scheme::Aes128GcmWithSha256 => Box::new(sha2::sha256_derive),
		}
	}

	pub(crate) fn get_key_len(&self) -> usize {
		match self {
			#[cfg(feature = "chacha")]
			Scheme::XChaCha20Poly1305WithBlake3 => xchacha20poly1305::KEY_SIZE,
			#[cfg(feature = "aes")]
			Scheme::Aes128GcmWithSha256 => aes::AES128_KEY_SIZE,
		}
	}

	pub(crate) fn get_decryption(&self) -> Box<DecryptionFunction> {
		match self {
			#[cfg(feature = "chacha")]
			Scheme::XChaCha20Poly1305WithBlake3 => Box::new(xchacha20poly1305::xchacha20poly1305_decrypt),
			#[cfg(feature = "aes")]
			Scheme::Aes128GcmWithSha256 => Box::new(aes::aes128gcm_decrypt),
		}
	}

	pub(crate) fn get_encryption(&self) -> Box<EncryptionFunction> {
		match self {
			#[cfg(feature = "chacha")]
			Scheme::XChaCha20Poly1305WithBlake3 => Box::new(xchacha20poly1305::xchacha20poly1305_encrypt),
			#[cfg(feature = "aes")]
			Scheme::Aes128GcmWithSha256 => Box::new(aes::aes128gcm_encrypt),
		}
	}

	pub(crate) fn get_gen_nonce(&self) -> Box<GenNonceFunction> {
		match self {
			#[cfg(feature = "chacha")]
			Scheme::XChaCha20Poly1305WithBlake3 => Box::new(xchacha20poly1305::xchacha20poly1305_gen_nonce),
			#[cfg(feature = "aes")]
			Scheme::Aes128GcmWithSha256 => Box::new(aes::aes128gcm_gen_nonce),
		}
	}
}

impl TryFrom<SchemeSerializeType> for Scheme {
	type Error = Error;

	fn try_from(value: SchemeSerializeType) -> Result<Self, Self::Error> {
		match value {
			#[cfg(feature = "chacha")]
			1 => Ok(Scheme::XChaCha20Poly1305WithBlake3),
			#[cfg(feature = "aes")]
			2 => Ok(Scheme::Aes128GcmWithSha256),
			_ => Err(Error::ParsingSchemeUnknownScheme(value)),
		}
	}
}
