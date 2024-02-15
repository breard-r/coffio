#[cfg(feature = "encryption")]
mod encryption;
mod error;
#[cfg(any(feature = "encryption", feature = "ikm-management"))]
mod ikm;
#[cfg(any(feature = "encryption", feature = "ikm-management"))]
mod scheme;

#[cfg(feature = "encryption")]
pub use encryption::{decrypt, encrypt};
pub use error::Error;
#[cfg(any(feature = "encryption", feature = "ikm-management"))]
pub use ikm::InputKeyMaterialList;
#[cfg(any(feature = "encryption", feature = "ikm-management"))]
pub use scheme::Scheme;

#[cfg(feature = "ikm-management")]
const DEFAULT_IKM_DURATION: u64 = 60 * 60 * 24 * 365; // In seconds
#[cfg(feature = "ikm-management")]
const DEFAULT_SCHEME: Scheme = Scheme::XChaCha20Poly1305WithBlake3;

#[cfg(not(feature = "i-understand-and-accept-the-risks"))]
compile_error!("This crate is experimental and therefore comes with absolutely no security guaranty. To use it anyway, enable the \"i-understand-and-accept-the-risks\" feature.");
