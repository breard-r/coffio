use crate::encryption::EncryptedData;
use crate::error::{Error, Result};
use crate::ikm::IkmId;
use base64ct::{Base64UrlUnpadded, Encoding};

const STORAGE_SEPARATOR: &str = ":";
const NB_PARTS: usize = 3;

#[inline]
fn encode_data(data: &[u8]) -> String {
	Base64UrlUnpadded::encode_string(data)
}

#[inline]
fn decode_data(s: &str) -> Result<Vec<u8>> {
	Ok(Base64UrlUnpadded::decode_vec(s)?)
}

pub(crate) fn encode(ikm_id: IkmId, encrypted_data: &EncryptedData) -> String {
	let mut ret = String::new();
	ret += &encode_data(&ikm_id.to_le_bytes());
	ret += STORAGE_SEPARATOR;
	ret += &encode_data(&encrypted_data.nonce);
	ret += STORAGE_SEPARATOR;
	ret += &encode_data(&encrypted_data.ciphertext);
	ret
}

pub(crate) fn decode(data: &str) -> Result<(IkmId, EncryptedData)> {
	let v: Vec<&str> = data.split(STORAGE_SEPARATOR).collect();
	if v.len() != NB_PARTS {
		return Err(Error::ParsingEncodedDataInvalidPartLen(NB_PARTS, v.len()));
	}
	let id_raw = decode_data(v[0])?;
	let id_raw: [u8; 4] = id_raw
		.clone()
		.try_into()
		.map_err(|_| Error::ParsingEncodedDataInvalidIkmId(id_raw))?;
	let id = IkmId::from_le_bytes(id_raw);
	let encrypted_data = EncryptedData {
		nonce: decode_data(v[1])?,
		ciphertext: decode_data(v[2])?,
	};
	Ok((id, encrypted_data))
}

#[cfg(test)]
mod tests {
	use crate::ikm::IkmId;
	use crate::storage::EncryptedData;

	const TEST_STR: &str = "KgAAAA:a5SpjAoqhvuI9n3GPhDKuotqoLbf7_Fb:TI24Wr_g-ZV7_X1oHqVKak9iRlQSneYVOMWB-3Lp-hFHKfxfnY-zR_bN";
	const TEST_IKM_ID: IkmId = 42;
	const TEST_NONCE: &'static [u8] = &[
		0x6b, 0x94, 0xa9, 0x8c, 0x0a, 0x2a, 0x86, 0xfb, 0x88, 0xf6, 0x7d, 0xc6, 0x3e, 0x10, 0xca,
		0xba, 0x8b, 0x6a, 0xa0, 0xb6, 0xdf, 0xef, 0xf1, 0x5b,
	];
	const TEST_CIPHERTEXT: &'static [u8] = &[
		0x4c, 0x8d, 0xb8, 0x5a, 0xbf, 0xe0, 0xf9, 0x95, 0x7b, 0xfd, 0x7d, 0x68, 0x1e, 0xa5, 0x4a,
		0x6a, 0x4f, 0x62, 0x46, 0x54, 0x12, 0x9d, 0xe6, 0x15, 0x38, 0xc5, 0x81, 0xfb, 0x72, 0xe9,
		0xfa, 0x11, 0x47, 0x29, 0xfc, 0x5f, 0x9d, 0x8f, 0xb3, 0x47, 0xf6, 0xcd,
	];

	#[test]
	fn encode() {
		let data = EncryptedData {
			nonce: TEST_NONCE.into(),
			ciphertext: TEST_CIPHERTEXT.into(),
		};
		let s = super::encode(TEST_IKM_ID, &data);
		assert_eq!(&s, TEST_STR);
	}

	#[test]
	fn decode() {
		let res = super::decode(TEST_STR);
		assert!(res.is_ok());
		let (id, data) = res.unwrap();
		assert_eq!(id, TEST_IKM_ID);
		assert_eq!(data.nonce, TEST_NONCE);
		assert_eq!(data.ciphertext, TEST_CIPHERTEXT);
	}

	#[test]
	fn encode_decode() {
		let data = EncryptedData {
			nonce: TEST_NONCE.into(),
			ciphertext: TEST_CIPHERTEXT.into(),
		};
		let s = super::encode(TEST_IKM_ID, &data);
		let (id, decoded_data) = super::decode(&s).unwrap();
		assert_eq!(id, TEST_IKM_ID);
		assert_eq!(decoded_data.nonce, data.nonce);
		assert_eq!(decoded_data.ciphertext, data.ciphertext);
	}

	#[test]
	fn decode_encode() {
		let (id, data) = super::decode(TEST_STR).unwrap();
		let s = super::encode(id, &data);
		assert_eq!(&s, TEST_STR);
	}
}
