mod ikm;
mod scheme;

pub use ikm::InputKeyMaterialList;
pub use scheme::Scheme;

const DEFAULT_IKM_DURATION: u64 = 60 * 60 * 24 * 365; // In seconds
const DEFAULT_SCHEME: Scheme = Scheme::XChaCha20Poly1305WithBlake3;
