use crate::encryption::EncryptedData;
use crate::error::{Error, Result};
use crate::ikm::{CounterId, IkmId, InputKeyMaterial, InputKeyMaterialList, IKM_BASE_STRUCT_SIZE};
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

pub(crate) fn encode_ikm_list(ikml: &InputKeyMaterialList) -> Result<String> {
	let data_size = (ikml.ikm_lst.iter().fold(0, |acc, ikm| {
		acc + IKM_BASE_STRUCT_SIZE + ikm.scheme.get_ikm_size()
	})) + 4;
	let mut ret = String::with_capacity(data_size);
	ret += &encode_data(&ikml.id_counter.to_le_bytes());
	for ikm in &ikml.ikm_lst {
		ret += STORAGE_SEPARATOR;
		ret += &encode_data(&ikm.as_bytes()?);
	}
	Ok(ret)
}

pub(crate) fn encode_cipher(
	ikm_id: IkmId,
	encrypted_data: &EncryptedData,
	time_period: Option<u64>,
) -> String {
	let mut ret = String::new();
	ret += &encode_data(&ikm_id.to_le_bytes());
	ret += STORAGE_SEPARATOR;
	ret += &encode_data(&encrypted_data.nonce);
	ret += STORAGE_SEPARATOR;
	ret += &encode_data(&encrypted_data.ciphertext);
	if let Some(time_period) = time_period {
		ret += STORAGE_SEPARATOR;
		ret += &encode_data(&time_period.to_le_bytes());
	}
	ret
}

pub(crate) fn decode_ikm_list(data: &str) -> Result<InputKeyMaterialList> {
	let v: Vec<&str> = data.split(STORAGE_SEPARATOR).collect();
	if v.is_empty() {
		return Err(Error::ParsingEncodedDataInvalidIkmListLen(v.len()));
	}
	let id_data = decode_data(v[0])?;
	let id_counter = CounterId::from_le_bytes(id_data[0..4].try_into().unwrap());
	let mut ikm_lst = Vec::with_capacity(v.len() - 1);
	for ikm_str in &v[1..] {
		let raw_ikm = decode_data(ikm_str)?;
		let ikm = InputKeyMaterial::from_bytes(&raw_ikm)?;
		ikm_lst.push(ikm);
	}
	Ok(InputKeyMaterialList {
		ikm_lst,
		id_counter,
	})
}

pub(crate) fn decode_cipher(data: &str) -> Result<(IkmId, EncryptedData, Option<u64>)> {
	let mut v: Vec<&str> = data.split(STORAGE_SEPARATOR).collect();
	let time_period = if v.len() == NB_PARTS + 1 {
		match v.pop() {
			Some(tp_raw) => {
				let tp_raw = decode_data(tp_raw)?;
				let tp_raw: [u8; 8] = tp_raw
					.clone()
					.try_into()
					.map_err(|_| Error::ParsingEncodedDataInvalidTimestamp(tp_raw))?;
				Some(u64::from_le_bytes(tp_raw))
			}
			None => None,
		}
	} else {
		None
	};
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
	if encrypted_data.nonce.is_empty() {
		return Err(Error::ParsingEncodedDataEmptyNonce);
	}
	if encrypted_data.ciphertext.is_empty() {
		return Err(Error::ParsingEncodedDataEmptyCiphertext);
	}
	Ok((id, encrypted_data, time_period))
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
	fn encode_cipher() {
		let data = EncryptedData {
			nonce: TEST_NONCE.into(),
			ciphertext: TEST_CIPHERTEXT.into(),
		};
		let s = super::encode_cipher(TEST_IKM_ID, &data, None);
		assert_eq!(&s, TEST_STR);
	}

	#[test]
	fn decode_cipher() {
		let res = super::decode_cipher(TEST_STR);
		assert!(res.is_ok(), "res: {res:?}");
		let (id, data, tp) = res.unwrap();
		assert_eq!(id, TEST_IKM_ID);
		assert_eq!(data.nonce, TEST_NONCE);
		assert_eq!(data.ciphertext, TEST_CIPHERTEXT);
		assert_eq!(tp, None);
	}

	#[test]
	fn encode_decode_cipher() {
		let data = EncryptedData {
			nonce: TEST_NONCE.into(),
			ciphertext: TEST_CIPHERTEXT.into(),
		};
		let s = super::encode_cipher(TEST_IKM_ID, &data, None);
		let (id, decoded_data, tp) = super::decode_cipher(&s).unwrap();
		assert_eq!(id, TEST_IKM_ID);
		assert_eq!(decoded_data.nonce, data.nonce);
		assert_eq!(decoded_data.ciphertext, data.ciphertext);
		assert_eq!(tp, None);
	}

	#[test]
	fn decode_encode_cipher() {
		let (id, data, tp) = super::decode_cipher(TEST_STR).unwrap();
		let s = super::encode_cipher(id, &data, tp);
		assert_eq!(&s, TEST_STR);
	}

	#[test]
	fn decode_invalid_cipher() {
		let tests = &[
			// Missing parts
			("", "empty data 1"),
			(":", "empty data 2"),
			("::", "empty data 3"),
			(":a5SpjAoqhvuI9n3GPhDKuotqoLbf7_Fb:TI24Wr_g-ZV7_X1oHqVKak9iRlQSneYVOMWB-3Lp-hFHKfxfnY-zR_bN", "missing ikm id 1"),
			("a5SpjAoqhvuI9n3GPhDKuotqoLbf7_Fb:TI24Wr_g-ZV7_X1oHqVKak9iRlQSneYVOMWB-3Lp-hFHKfxfnY-zR_bN", "missing ikm id 2"),
			("KgAAAA:TI24Wr_g-ZV7_X1oHqVKak9iRlQSneYVOMWB-3Lp-hFHKfxfnY-zR_bN", "missing nonce 1"),
			("KgAAAA::TI24Wr_g-ZV7_X1oHqVKak9iRlQSneYVOMWB-3Lp-hFHKfxfnY-zR_bN", "missing nonce 2"),
			("KgAAAA:a5SpjAoqhvuI9n3GPhDKuotqoLbf7_Fb", "missing ciphertext 1"),
			("KgAAAA:a5SpjAoqhvuI9n3GPhDKuotqoLbf7_Fb:", "missing ciphertext 2"),

			// Invalid base64 parts
			("KgAA.A:a5SpjAoqhvuI9n3GPhDKuotqoLbf7_Fb:TI24Wr_g-ZV7_X1oHqVKak9iRlQSneYVOMWB-3Lp-hFHKfxfnY-zR_bN", "invalid base64 ikm id"),
			("KgAAAA:a5SpjAoqhvuI9n3GPhDKu@tqoLbf7_Fb:TI24Wr_g-ZV7_X1oHqVKak9iRlQSneYVOMWB-3Lp-hFHKfxfnY-zR_bN", "invalid base64 nonce"),
			("KgAAAA:a5SpjAoqhvuI9n3GPhDKuotqoLbf7_Fb:TI24Wr_g-ZV7_X1oHqVKak9iRlQSneYVOMWB-3Lp-hFHK/xfnY-zR_bN", "invalid base64 ciphertext"),

			// Invalid data length
			("KgAAA:a5SpjAoqhvuI9n3GPhDKuotqoLbf7_Fb:TI24Wr_g-ZV7_X1oHqVKak9iRlQSneYVOMWB-3Lp-hFHKfxfnY-zR_bN", "invalid ikm id data length"),
			("KgAAAA:a5SpjAoqhvuI9n3GPhDKuotqoLbf7:TI24Wr_g-ZV7_X1oHqVKak9iRlQSneYVOMWB-3Lp-hFHKfxfnY-zR_bN", "invalid nonce data length"),
			("KgAAAA:a5SpjAoqhvuI9n3GPhDKuotqoLbf7_Fb:TI24Wr_g-ZV7_X1oHqVKak9iRlQSneYVOMWB-3Lp-hFHKfxfnY-zR", "invalid ciphertext data length"),
		];
		for (ciphertext, error_str) in tests {
			let res = super::decode_cipher(ciphertext);
			assert!(res.is_err(), "failed error detection: {error_str}");
		}
	}
}
