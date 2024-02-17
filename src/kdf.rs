use crate::canonicalization::canonicalize;
use crate::ikm::InputKeyMaterial;

pub(crate) type KdfFunction = dyn Fn(&str, &[u8]) -> Vec<u8>;

pub(crate) fn derive_key(ikm: &InputKeyMaterial, key_context: &[&str]) -> Vec<u8> {
	let key_context = canonicalize(key_context);
	let kdf = ikm.scheme.get_kdf();
	kdf(&key_context, &ikm.content)
}

pub(crate) fn blake3_derive(context: &str, ikm: &[u8]) -> Vec<u8> {
	blake3::derive_key(context, ikm).to_vec()
}
