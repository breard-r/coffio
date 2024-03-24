use hkdf::Hkdf;
use sha2::Sha256;

pub(crate) fn sha256_derive(context: &str, ikm: &[u8]) -> Vec<u8> {
	let mut buff = [0u8; 16];
	let hkdf = Hkdf::<Sha256>::new(None, ikm);
	hkdf.expand(context.as_bytes(), &mut buff).unwrap();
	buff.to_vec()
}

#[cfg(test)]
mod tests {
	#[test]
	fn sha256_derive() {
		assert_eq!(
			super::sha256_derive("this is a context", b"7b47db8f365e5b602fd956d35985e9e1"),
			vec![
				0xad, 0xf2, 0xcd, 0x3a, 0x52, 0xfd, 0xf6, 0xad, 0x12, 0xce, 0xdd, 0x9a, 0x4d, 0x9e,
				0xcd, 0x4b,
			]
		);
	}
}
