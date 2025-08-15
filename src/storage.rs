#[cfg(feature = "encryption")]
use crate::encrypted_data::EncryptedData;
use crate::error::{Error, Result};
#[cfg(feature = "ikm-management")]
use crate::ikm::IKM_BASE_STRUCT_SIZE;
#[cfg(feature = "encryption")]
use crate::ikm::IkmId;
use crate::ikm::{CounterId, InputKeyMaterial, InputKeyMaterialList};
use base64ct::{Base64UrlUnpadded, Encoding};
use std::fmt;

const STORAGE_SEPARATOR: &str = ":";
#[cfg(feature = "encryption")]
const NB_PARTS: usize = 3;

#[derive(Clone, Copy, Debug, Default)]
enum EncodedIkmlStorageVersion {
	#[default]
	V1,
}

impl EncodedIkmlStorageVersion {
	fn strip_prefix(data: &str) -> Result<(Self, &str)> {
		if let Some(d) = data.strip_prefix(&EncodedIkmlStorageVersion::V1.to_string()) {
			return Ok((EncodedIkmlStorageVersion::V1, d));
		}
		Err(Error::ParsingEncodedDataInvalidIkmlVersion)
	}
}

impl fmt::Display for EncodedIkmlStorageVersion {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::V1 => write!(f, "ikml-v1:"),
		}
	}
}

#[derive(Clone, Copy, Debug, Default)]
enum EncodedDataStorageVersion {
	#[default]
	V1,
}

impl EncodedDataStorageVersion {
	fn strip_prefix(data: &str) -> Result<(Self, &str)> {
		if let Some(d) = data.strip_prefix(&EncodedDataStorageVersion::V1.to_string()) {
			return Ok((EncodedDataStorageVersion::V1, d));
		}
		Err(Error::ParsingEncodedDataInvalidEncVersion)
	}
}

impl fmt::Display for EncodedDataStorageVersion {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::V1 => write!(f, "enc-v1:"),
		}
	}
}

#[inline]
fn encode_data(data: &[u8]) -> String {
	Base64UrlUnpadded::encode_string(data)
}

#[inline]
fn decode_data(s: &str) -> Result<Vec<u8>> {
	Ok(Base64UrlUnpadded::decode_vec(s)?)
}

#[cfg(feature = "ikm-management")]
pub(crate) fn encode_ikm_list(ikml: &InputKeyMaterialList) -> Result<String> {
	let version = EncodedIkmlStorageVersion::default().to_string();
	let data_size = (ikml.ikm_lst.iter().fold(0, |acc, ikm| {
		version.len() + acc + IKM_BASE_STRUCT_SIZE + ikm.scheme.get_ikm_size()
	})) + 4;
	let mut ret = String::with_capacity(data_size);
	ret += &version;
	ret += &encode_data(&ikml.id_counter.to_le_bytes());
	for ikm in &ikml.ikm_lst {
		ret += STORAGE_SEPARATOR;
		ret += &encode_data(&ikm.as_bytes()?);
	}
	Ok(ret)
}

#[cfg(feature = "encryption")]
pub(crate) fn encode_cipher(
	ikm_id: IkmId,
	encrypted_data: &EncryptedData,
	time_period: Option<u64>,
) -> String {
	let mut ret = EncodedDataStorageVersion::default().to_string();
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
	let (_version, data) = EncodedIkmlStorageVersion::strip_prefix(data)?;
	let v: Vec<&str> = data.split(STORAGE_SEPARATOR).collect();
	if v.is_empty() {
		return Err(Error::ParsingEncodedDataInvalidIkmListLen(v.len()));
	}
	let id_data = decode_data(v[0])?;
	if id_data.len() != 4 {
		return Err(Error::ParsingEncodedDataInvalidIkmListId(id_data));
	}
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

#[cfg(feature = "encryption")]
pub(crate) fn decode_cipher(data: &str) -> Result<(IkmId, EncryptedData, Option<u64>)> {
	let (_version, data) = EncodedDataStorageVersion::strip_prefix(data)?;
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

#[cfg(all(test, feature = "ikm-management"))]
mod ikm_lst {
	const TEST_STR: &str = "ikml-v1:BgAAAA:AQAAAAEAAACUAPcqngJ46_HMtJSdIw-WeUtImcCVxOA47n6UIN5K2TbmoVwAAAAANmuEXgAAAAAB:AgAAAAEAAADf7CR8vl_aWOUyfsO0ek0YQr_Yi7L_sJmF2nIt_XOaCzYNal4AAAAAtkBLYAAAAAAA:AwAAAAEAAAAMoNIW9gIGkzegUDEsU3N1Rf_Zz0OMuylUSiQjUzLXqzY0MmAAAAAANsk0iwEAAAAA:BAAAAAEAAABbwRrMz3x3DkfOEFg1BHfLLRHoNqg6d_xGWwdh48hH8rZm9mEAAAAANjy9YwAAAAAA:BQAAAAEAAAA2LwnTgDUF7qn7dy79VA24JSSgo6vllAtU5zmhrxNJu7YIz4sBAAAANoUMjgEAAAAB:BgAAAAEAAAAn0Vqe2f9YRXBt6xVYaeSLs0Gf0S0_5B-hk-a2b0rhlraCJbwAAAAAtlErjAEAAAAA";
	const TEST_CTN_0: &[u8] = &[
		0x94, 0x00, 0xf7, 0x2a, 0x9e, 0x02, 0x78, 0xeb, 0xf1, 0xcc, 0xb4, 0x94, 0x9d, 0x23, 0x0f,
		0x96, 0x79, 0x4b, 0x48, 0x99, 0xc0, 0x95, 0xc4, 0xe0, 0x38, 0xee, 0x7e, 0x94, 0x20, 0xde,
		0x4a, 0xd9,
	];
	const TEST_CTN_1: &[u8] = &[
		0xdf, 0xec, 0x24, 0x7c, 0xbe, 0x5f, 0xda, 0x58, 0xe5, 0x32, 0x7e, 0xc3, 0xb4, 0x7a, 0x4d,
		0x18, 0x42, 0xbf, 0xd8, 0x8b, 0xb2, 0xff, 0xb0, 0x99, 0x85, 0xda, 0x72, 0x2d, 0xfd, 0x73,
		0x9a, 0x0b,
	];
	const TEST_CTN_2: &[u8] = &[
		0x0c, 0xa0, 0xd2, 0x16, 0xf6, 0x02, 0x06, 0x93, 0x37, 0xa0, 0x50, 0x31, 0x2c, 0x53, 0x73,
		0x75, 0x45, 0xff, 0xd9, 0xcf, 0x43, 0x8c, 0xbb, 0x29, 0x54, 0x4a, 0x24, 0x23, 0x53, 0x32,
		0xd7, 0xab,
	];
	const TEST_CTN_3: &[u8] = &[
		0x5b, 0xc1, 0x1a, 0xcc, 0xcf, 0x7c, 0x77, 0x0e, 0x47, 0xce, 0x10, 0x58, 0x35, 0x04, 0x77,
		0xcb, 0x2d, 0x11, 0xe8, 0x36, 0xa8, 0x3a, 0x77, 0xfc, 0x46, 0x5b, 0x07, 0x61, 0xe3, 0xc8,
		0x47, 0xf2,
	];
	const TEST_CTN_4: &[u8] = &[
		0x36, 0x2f, 0x09, 0xd3, 0x80, 0x35, 0x05, 0xee, 0xa9, 0xfb, 0x77, 0x2e, 0xfd, 0x54, 0x0d,
		0xb8, 0x25, 0x24, 0xa0, 0xa3, 0xab, 0xe5, 0x94, 0x0b, 0x54, 0xe7, 0x39, 0xa1, 0xaf, 0x13,
		0x49, 0xbb,
	];
	const TEST_CTN_5: &[u8] = &[
		0x27, 0xd1, 0x5a, 0x9e, 0xd9, 0xff, 0x58, 0x45, 0x70, 0x6d, 0xeb, 0x15, 0x58, 0x69, 0xe4,
		0x8b, 0xb3, 0x41, 0x9f, 0xd1, 0x2d, 0x3f, 0xe4, 0x1f, 0xa1, 0x93, 0xe6, 0xb6, 0x6f, 0x4a,
		0xe1, 0x96,
	];

	macro_rules! as_ts {
		($systime: expr) => {
			$systime
				.duration_since(std::time::SystemTime::UNIX_EPOCH)
				.unwrap()
				.as_secs()
		};
	}

	#[test]
	#[cfg(all(feature = "ikm-management", feature = "chacha"))]
	fn encode() {
		use std::time::{Duration, SystemTime};
		let bytes_to_system_time = |ts: u64| {
			SystemTime::UNIX_EPOCH
				.checked_add(Duration::from_secs(ts))
				.unwrap()
		};
		let mut lst = crate::InputKeyMaterialList::new();
		let _ = lst.add_ikm();
		lst.ikm_lst[0].content = TEST_CTN_0.to_vec();
		lst.ikm_lst[0].not_before = bytes_to_system_time(1554114102);
		lst.ikm_lst[0].not_after = bytes_to_system_time(1585736502);
		lst.ikm_lst[0].is_revoked = true;
		let _ = lst.add_ikm();
		lst.ikm_lst[1].content = TEST_CTN_1.to_vec();
		lst.ikm_lst[1].not_before = bytes_to_system_time(1584008502);
		lst.ikm_lst[1].not_after = bytes_to_system_time(1615544502);
		let _ = lst.add_ikm();
		lst.ikm_lst[2].content = TEST_CTN_2.to_vec();
		lst.ikm_lst[2].not_before = bytes_to_system_time(1613902902);
		lst.ikm_lst[2].not_after = bytes_to_system_time(6630459702);
		let _ = lst.add_ikm();
		lst.ikm_lst[3].content = TEST_CTN_3.to_vec();
		lst.ikm_lst[3].not_before = bytes_to_system_time(1643538102);
		lst.ikm_lst[3].not_after = bytes_to_system_time(1673346102);
		let _ = lst.add_ikm();
		lst.ikm_lst[4].content = TEST_CTN_4.to_vec();
		lst.ikm_lst[4].not_before = bytes_to_system_time(6640568502);
		lst.ikm_lst[4].not_after = bytes_to_system_time(6678152502);
		lst.ikm_lst[4].is_revoked = true;
		let _ = lst.add_ikm();
		lst.ikm_lst[5].content = TEST_CTN_5.to_vec();
		lst.ikm_lst[5].not_before = bytes_to_system_time(3156574902);
		lst.ikm_lst[5].not_after = bytes_to_system_time(6646616502);

		let s = super::encode_ikm_list(&lst).unwrap();
		assert_eq!(s, TEST_STR);
	}

	#[test]
	#[cfg(feature = "chacha")]
	fn decode() {
		let res = super::decode_ikm_list(TEST_STR);
		assert!(res.is_ok(), "res: {res:?}");
		let lst = res.unwrap();
		assert_eq!(lst.id_counter, 6);
		assert_eq!(lst.ikm_lst[0].id, 1);
		assert_eq!(lst.ikm_lst[0].content, TEST_CTN_0);
		assert_eq!(as_ts!(lst.ikm_lst[0].not_before), 1554114102);
		assert_eq!(as_ts!(lst.ikm_lst[0].not_after), 1585736502);
		assert_eq!(lst.ikm_lst[0].is_revoked, true);
		assert_eq!(lst.ikm_lst[1].id, 2);
		assert_eq!(lst.ikm_lst[1].content, TEST_CTN_1);
		assert_eq!(as_ts!(lst.ikm_lst[1].not_before), 1584008502);
		assert_eq!(as_ts!(lst.ikm_lst[1].not_after), 1615544502);
		assert_eq!(lst.ikm_lst[1].is_revoked, false);
		assert_eq!(lst.ikm_lst[2].id, 3);
		assert_eq!(lst.ikm_lst[2].content, TEST_CTN_2);
		assert_eq!(as_ts!(lst.ikm_lst[2].not_before), 1613902902);
		assert_eq!(as_ts!(lst.ikm_lst[2].not_after), 6630459702);
		assert_eq!(lst.ikm_lst[2].is_revoked, false);
		assert_eq!(lst.ikm_lst[3].id, 4);
		assert_eq!(lst.ikm_lst[3].content, TEST_CTN_3);
		assert_eq!(as_ts!(lst.ikm_lst[3].not_before), 1643538102);
		assert_eq!(as_ts!(lst.ikm_lst[3].not_after), 1673346102);
		assert_eq!(lst.ikm_lst[3].is_revoked, false);
		assert_eq!(lst.ikm_lst[4].id, 5);
		assert_eq!(lst.ikm_lst[4].content, TEST_CTN_4);
		assert_eq!(as_ts!(lst.ikm_lst[4].not_before), 6640568502);
		assert_eq!(as_ts!(lst.ikm_lst[4].not_after), 6678152502);
		assert_eq!(lst.ikm_lst[4].is_revoked, true);
		assert_eq!(lst.ikm_lst[5].id, 6);
		assert_eq!(lst.ikm_lst[5].content, TEST_CTN_5);
		assert_eq!(as_ts!(lst.ikm_lst[5].not_before), 3156574902);
		assert_eq!(as_ts!(lst.ikm_lst[5].not_after), 6646616502);
		assert_eq!(lst.ikm_lst[5].is_revoked, false);
	}

	#[test]
	#[cfg(feature = "ikm-management")]
	fn encode_decode() {
		let mut lst = crate::InputKeyMaterialList::new();
		let _ = lst.add_ikm();
		let _ = lst.add_ikm();
		let _ = lst.add_ikm();

		let res = super::encode_ikm_list(&lst);
		assert!(res.is_ok(), "res: {res:?}");
		let s = res.unwrap();
		assert!(s.starts_with("ikml-v1:AwAAAA:"));
		assert_eq!(s.len(), 245);

		let res = super::decode_ikm_list(&s);
		assert!(res.is_ok(), "res: {res:?}");
		let lst2 = res.unwrap();
		assert_eq!(lst.id_counter, lst2.id_counter);
		for i in 0..3 {
			assert_eq!(lst.ikm_lst[i].id, lst2.ikm_lst[i].id);
			assert_eq!(lst.ikm_lst[i].scheme, lst2.ikm_lst[i].scheme);
			assert_eq!(lst.ikm_lst[i].content, lst2.ikm_lst[i].content);
			assert_eq!(
				as_ts!(lst.ikm_lst[i].not_before),
				as_ts!(lst2.ikm_lst[i].not_before)
			);
			assert_eq!(
				as_ts!(lst.ikm_lst[i].not_after),
				as_ts!(lst2.ikm_lst[i].not_after)
			);
			assert_eq!(lst.ikm_lst[i].is_revoked, lst2.ikm_lst[i].is_revoked);
		}
	}

	#[test]
	fn decode_invalid() {
		let tests = &[
			("", "empty string"),
			("ikml-v1:", "empty ikm content"),
			(
				"ikml-v1:AAAA:AQAAAAEAAACUAPcqngJ46_HMtJSdIw-WeUtImcCVxOA47n6UIN5K2TbmoVwAAAAANmuEXgAAAAAB",
				"invalid id",
			),
			(
				"ikml-v1::AQAAAAEAAACUAPcqngJ46_HMtJSdIw-WeUtImcCVxOA47n6UIN5K2TbmoVwAAAAANmuEXgAAAAAB",
				"empty id",
			),
			(
				"ikml-v1:AQAAAAEAAACUAPcqngJ46_HMtJSdIw-WeUtImcCVxOA47n6UIN5K2TbmoVwAAAAANmuEXgAAAAAB",
				"no id",
			),
			(
				"ikml-v1:BgAAAA:AQAAAAEAAACUAPcqngJ46_HMtJSdIw-WeUtImcCVxOA47",
				"invalid ikm",
			),
			("ikml-v1:BgAAAA:", "empty ikm"),
		];
		for (s, error_str) in tests {
			let res = super::decode_ikm_list(s);
			assert!(res.is_err(), "failed error detection: {error_str}");
		}
	}
}

#[cfg(all(test, feature = "encryption"))]
mod ciphers {
	use crate::ikm::IkmId;
	use crate::storage::EncryptedData;

	const TEST_STR: &str = "enc-v1:KgAAAA:a5SpjAoqhvuI9n3GPhDKuotqoLbf7_Fb:TI24Wr_g-ZV7_X1oHqVKak9iRlQSneYVOMWB-3Lp-hFHKfxfnY-zR_bN";
	const TEST_STR_T: &str = "enc-v1:KgAAAA:a5SpjAoqhvuI9n3GPhDKuotqoLbf7_Fb:TI24Wr_g-ZV7_X1oHqVKak9iRlQSneYVOMWB-3Lp-hFHKfxfnY-zR_bN:NaAAAAAAAAA";
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
		let s = super::encode_cipher(TEST_IKM_ID, &data, None);
		assert_eq!(&s, TEST_STR);
	}

	#[test]
	fn decode() {
		let res = super::decode_cipher(TEST_STR);
		assert!(res.is_ok(), "res: {res:?}");
		let (id, data, tp) = res.unwrap();
		assert_eq!(id, TEST_IKM_ID);
		assert_eq!(data.nonce, TEST_NONCE);
		assert_eq!(data.ciphertext, TEST_CIPHERTEXT);
		assert_eq!(tp, None);

		let res = super::decode_cipher(TEST_STR_T);
		assert!(res.is_ok(), "res: {res:?}");
		let (id, data, tp) = res.unwrap();
		assert_eq!(id, TEST_IKM_ID);
		assert_eq!(data.nonce, TEST_NONCE);
		assert_eq!(data.ciphertext, TEST_CIPHERTEXT);
		assert_eq!(tp, Some(41013));
	}

	#[test]
	fn encode_decode() {
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
	fn decode_encode() {
		let (id, data, tp) = super::decode_cipher(TEST_STR).unwrap();
		let s = super::encode_cipher(id, &data, tp);
		assert_eq!(&s, TEST_STR);
	}

	#[test]
	fn decode_invalid() {
		let invalid_tests = &[
			// Missing parts
			("", "empty data 1"),
			(":", "empty data 2"),
			("::", "empty data 3"),
			("enc-v1::", "empty data 4"),
			("enc-v1:::", "empty data 5"),
			("enc-v1::::", "empty data 6"),
			(
				"enc-v1:a5SpjAoqhvuI9n3GPhDKuotqoLbf7_Fb:TI24Wr_g-ZV7_X1oHqVKak9iRlQSneYVOMWB-3Lp-hFHKfxfnY-zR_bN",
				"missing ikm id",
			),
			(
				"enc-v1:KgAAAA:TI24Wr_g-ZV7_X1oHqVKak9iRlQSneYVOMWB-3Lp-hFHKfxfnY-zR_bN",
				"missing nonce",
			),
			(
				"enc-v1:KgAAAA:a5SpjAoqhvuI9n3GPhDKuotqoLbf7_Fb",
				"missing ciphertext",
			),
			// Empty parts
			(
				"enc-v1::a5SpjAoqhvuI9n3GPhDKuotqoLbf7_Fb:TI24Wr_g-ZV7_X1oHqVKak9iRlQSneYVOMWB-3Lp-hFHKfxfnY-zR_bN",
				"empty ikm id",
			),
			(
				"enc-v1:KgAAAA::TI24Wr_g-ZV7_X1oHqVKak9iRlQSneYVOMWB-3Lp-hFHKfxfnY-zR_bN",
				"empty nonce",
			),
			(
				"enc-v1:KgAAAA:a5SpjAoqhvuI9n3GPhDKuotqoLbf7_Fb:",
				"empty ciphertext",
			),
			(
				"enc-v1:KgAAAA:a5SpjAoqhvuI9n3GPhDKuotqoLbf7_Fb:TI24Wr_g-ZV7_X1oHqVKak9iRlQSneYVOMWB-3Lp-hFHKfxfnY-zR_bN:",
				"empty time period",
			),
			// Invalid base64 parts
			(
				"enc-v1:KgAA.A:a5SpjAoqhvuI9n3GPhDKuotqoLbf7_Fb:TI24Wr_g-ZV7_X1oHqVKak9iRlQSneYVOMWB-3Lp-hFHKfxfnY-zR_bN",
				"invalid base64 ikm id",
			),
			(
				"enc-v1:KgAAAA:a5SpjAoqhvuI9n3GPhDKu@tqoLbf7_Fb:TI24Wr_g-ZV7_X1oHqVKak9iRlQSneYVOMWB-3Lp-hFHKfxfnY-zR_bN",
				"invalid base64 nonce",
			),
			(
				"enc-v1:KgAAAA:a5SpjAoqhvuI9n3GPhDKuotqoLbf7_Fb:TI24Wr_g-ZV7_X1oHqVKak9iRlQSneYVOMWB-3Lp-hFHK/xfnY-zR_bN",
				"invalid base64 ciphertext",
			),
			// Invalid data length
			(
				"enc-v1:KgAAA:a5SpjAoqhvuI9n3GPhDKuotqoLbf7_Fb:TI24Wr_g-ZV7_X1oHqVKak9iRlQSneYVOMWB-3Lp-hFHKfxfnY-zR_bN",
				"invalid ikm id data length",
			),
			(
				"enc-v1:KgAAAA:a5SpjAoqhvuI9n3GPhDKuotqoLbf7:TI24Wr_g-ZV7_X1oHqVKak9iRlQSneYVOMWB-3Lp-hFHKfxfnY-zR_bN",
				"invalid nonce data length",
			),
			(
				"enc-v1:KgAAAA:a5SpjAoqhvuI9n3GPhDKuotqoLbf7_Fb:TI24Wr_g-ZV7_X1oHqVKak9iRlQSneYVOMWB-3Lp-hFHKfxfnY-zR",
				"invalid ciphertext data length",
			),
			(
				"enc-v1:KgAAAA:a5SpjAoqhvuI9n3GPhDKuotqoLbf7_Fb:TI24Wr_g-ZV7_X1oHqVKak9iRlQSneYVOMWB-3Lp-hFHKfxfnY-zR_bN:AQAAAA",
				"invalid time period length",
			),
		];
		for (ciphertext, error_str) in invalid_tests {
			let res = super::decode_cipher(ciphertext);
			assert!(res.is_err(), "failed error detection: {error_str}");
		}
	}
}
