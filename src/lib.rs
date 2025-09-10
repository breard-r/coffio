#![warn(missing_docs)]

//! # Supported use case
//!
//! Coffio has been made to encrypt data of moderate size (less than 1/3 of the available memory)
//! using a secret key.
//!
//! # Unsupported use cases
//!
//! Coffio cannot:
//! - encrypt data using a password
//! - handle files that cannot fit into 1/3 of the available memory
//! - be used in a communication protocol
//! - be used as a key exchange
//! - etc.
//!
//! # The IKM list
//!
//! The encryption keys are automatically derived from a random seed called input key material
//! (IKM). Because an IKM is bound to a specific encryption algorithm, is limited to a time period
//! and can be revoked, Coffio requires a list of IKM, although the list could have only one.
//!
//! Therefore, before encrypting data, you have to generate an IKM list. Most of the time, you
//! might want to generate it outside of your application and handle it as you would handle a
//! secret key.
//!
//! # Features
//!
//! The following features allows you to control which interfaces are exposed.
//!
//! - `encryption` (default): interfaces related to data encryption and decryption
//! - `ikm-management` (default): interfaces related to the IKM list management
//! - `encrypt-at` (default): add a function allowing to encrypt data using a specified timestamp
//!
//! The following features allows you to control which encryption algorithms are activated.
//!
//! - `chacha` (default): [Scheme::XChaCha20Poly1305WithBlake3]
//! - `aes` (default): [Scheme::Aes128GcmWithSha256]
//!
//! Other features are:
//!
//! - `benchmark`: useful only to run the benchmark
//!
//! # Examples
//!
//! ## Generating an IKM list.
//!
//! ```
//! use coffio::InputKeyMaterialList;
//!
//! let mut ikml = InputKeyMaterialList::new();
//! let _ = ikml.add_ikm()?;
//! let ikml_str = ikml.export()?;
//!
//! println!("Generated IKM list: {ikml_str}");
//!
//! # Ok::<(), coffio::Error>(())
//! ```
//!
//! ## Encrypting and decrypting data.
//!
//! ```
//! use coffio::{Coffio, DataContext, InputKeyMaterialList, KeyContext};
//!
//! let ikml_raw = "ikml-v1:AQAAAA:AQAAAAEAAAC_vYEw1ujVG5i-CtoPYSzik_6xaAq59odjPm5ij01-e6zz4mUAAAAALJGBiwAAAAAA";
//! let ikm_list = InputKeyMaterialList::import(ikml_raw)?;
//! let my_key_ctx: KeyContext = [
//!     "db name",
//!     "table name",
//!     "column name",
//! ].into();
//! let my_data_ctx: DataContext = [
//!     "694c721a-29e8-4793-b7a4-46a4a0bf1a70",
//!     "some username",
//! ].into();
//! let data = b"Hello, World!";
//!
//! let coffio = Coffio::new(&ikm_list);
//! let encrypted_data = coffio.encrypt(&my_key_ctx, &my_data_ctx, data)?;
//! let decrypted_data = coffio.decrypt(&my_key_ctx, &my_data_ctx, &encrypted_data)?;
//!
//! assert_eq!(data, decrypted_data.as_slice());
//!
//! # Ok::<(), coffio::Error>(())
//! ```

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
#[cfg(feature = "encryption")]
mod policy;
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
#[cfg(feature = "encryption")]
pub use policy::{DecryptionPolicy, DecryptionPolicyAction};
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
