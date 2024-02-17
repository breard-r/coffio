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

#[cfg(test)]
mod tests {
	use crate::ikm::InputKeyMaterial;

	#[test]
	fn derive_key() {
		let ikm_raw = [
			0x0a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x7b, 0x85, 0x27, 0xef, 0xf2, 0xbd,
			0x58, 0x9f, 0x6e, 0xb1, 0x7b, 0x71, 0xc3, 0x1e, 0xf6, 0xfd, 0x7f, 0x90, 0xdb, 0xc6,
			0x43, 0xea, 0xe9, 0x9c, 0xa3, 0xb5, 0xee, 0xcc, 0xb6, 0xb6, 0x28, 0x6a, 0xbd, 0xe4,
			0xd0, 0x65, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x82, 0x6f, 0x8b, 0x00, 0x00, 0x00, 0x00,
			0x00,
		];
		let ikm = InputKeyMaterial::from_bytes(ikm_raw).unwrap();

		let ctx = ["some", "context"];
		assert_eq!(
			super::derive_key(&ikm, &ctx),
			vec![
				0xc1, 0xd2, 0xf0, 0xa7, 0x4d, 0xc5, 0x32, 0x6e, 0x89, 0x86, 0x85, 0xae, 0x3f, 0xdf,
				0x16, 0x0b, 0xec, 0xe6, 0x63, 0x46, 0x41, 0x8a, 0x28, 0x2b, 0x04, 0xa1, 0x23, 0x20,
				0x36, 0xe3, 0x2f, 0x0a
			]
		);
	}

	#[test]
	fn blake3_derive() {
		assert_eq!(
			super::blake3_derive("this is a context", b"7b47db8f365e5b602fd956d35985e9e1"),
			vec![
				0xc4, 0xf4, 0x6c, 0xf2, 0x03, 0xd9, 0x2d, 0x7b, 0x72, 0xe8, 0xe7, 0x90, 0xa3, 0x62,
				0x2a, 0xf4, 0x3c, 0x2a, 0xab, 0x27, 0xc6, 0xb1, 0x8b, 0x46, 0x9d, 0x40, 0x61, 0x56,
				0x19, 0x76, 0x88, 0xc4
			]
		);
	}
}