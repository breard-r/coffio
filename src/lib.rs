#[cfg(feature = "encryption")]
mod canonicalization;
#[cfg(feature = "encryption")]
mod coffio;
#[cfg(feature = "encryption")]
mod context;
#[cfg(feature = "encryption")]
mod encrypted_data;
#[cfg(any(feature = "encryption", feature = "ikm-management"))]
mod error;
#[cfg(any(feature = "encryption", feature = "ikm-management"))]
mod ikm;
#[cfg(feature = "encryption")]
mod kdf;
#[cfg(any(feature = "encryption", feature = "ikm-management"))]
mod scheme;
#[cfg(any(feature = "encryption", feature = "ikm-management"))]
mod storage;

#[cfg(feature = "encryption")]
pub use crate::coffio::Coffio;
#[cfg(feature = "encryption")]
pub use context::{DataContext, KeyContext};
#[cfg(any(feature = "encryption", feature = "ikm-management"))]
pub use error::Error;
#[cfg(any(feature = "encryption", feature = "ikm-management"))]
pub use ikm::{IkmId, InputKeyMaterial, InputKeyMaterialList};
#[cfg(any(feature = "encryption", feature = "ikm-management"))]
pub use scheme::Scheme;

/// Default amount of time during which the input key material will be considered valid once it has
/// been generated. This value is expressed in seconds.
///
/// Considering that a day is composed of 86400 seconds (60×60×24) and a year is 365.24219 days
/// (approximate value of the [mean tropical year][tropical_year]), this value is equivalent to 10
/// years.
///
/// [tropical_year]: https://en.wikipedia.org/wiki/Tropical_year
#[cfg(feature = "ikm-management")]
pub const DEFAULT_IKM_DURATION: u64 = 315_569_252;
/// Default amount of time during which a key is valid.
/// This is used for automatic periodic key rotation.
/// This value is expressed in seconds.
///
/// Considering that a day is composed of 86400 seconds (60×60×24) and a year is 365.24219 days
/// (approximate value of the [mean tropical year][tropical_year]), this value is equivalent to 1
/// year.
///
/// [tropical_year]: https://en.wikipedia.org/wiki/Tropical_year
#[cfg(feature = "encryption")]
pub const DEFAULT_KEY_CTX_PERIODICITY: u64 = 31_556_925;
/// Default scheme used when adding a new IKM. The value is `XChaCha20Poly1305WithBlake3` if the
/// `chacha` feature is enabled, then `Aes128GcmWithSha256` if the `aes` feature is enabled.
#[cfg(all(feature = "ikm-management", feature = "chacha"))]
pub const DEFAULT_SCHEME: Scheme = Scheme::XChaCha20Poly1305WithBlake3;
#[cfg(all(feature = "ikm-management", feature = "aes", not(feature = "chacha")))]
pub const DEFAULT_SCHEME: Scheme = Scheme::Aes128GcmWithSha256;
