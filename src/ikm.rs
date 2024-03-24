use crate::error::{Error, Result};
use crate::scheme::{Scheme, SchemeSerializeType};
use std::time::{Duration, SystemTime};

pub(crate) const IKM_BASE_STRUCT_SIZE: usize = 25;

pub(crate) type CounterId = u32;
pub type IkmId = u32;

#[derive(Debug)]
pub struct InputKeyMaterial {
	pub id: IkmId,
	pub scheme: Scheme,
	pub(crate) content: Vec<u8>,
	pub created_at: SystemTime,
	pub expire_at: SystemTime,
	pub is_revoked: bool,
}

impl InputKeyMaterial {
	#[cfg(feature = "ikm-management")]
	pub(crate) fn as_bytes(&self) -> Result<Vec<u8>> {
		let mut res = Vec::with_capacity(IKM_BASE_STRUCT_SIZE + self.scheme.get_ikm_size());
		res.extend_from_slice(&self.id.to_le_bytes());
		res.extend_from_slice(&(self.scheme as SchemeSerializeType).to_le_bytes());
		res.extend_from_slice(&self.content);
		res.extend_from_slice(
			&self
				.created_at
				.duration_since(SystemTime::UNIX_EPOCH)?
				.as_secs()
				.to_le_bytes(),
		);
		res.extend_from_slice(
			&self
				.expire_at
				.duration_since(SystemTime::UNIX_EPOCH)?
				.as_secs()
				.to_le_bytes(),
		);
		res.push(self.is_revoked as u8);
		Ok(res)
	}

	pub(crate) fn from_bytes(b: &[u8]) -> Result<Self> {
		if b.len() < IKM_BASE_STRUCT_SIZE {
			return Err(Error::ParsingEncodedDataInvalidIkmLen(b.len()));
		}
		let scheme: Scheme =
			SchemeSerializeType::from_le_bytes(b[4..8].try_into().unwrap()).try_into()?;
		let is = scheme.get_ikm_size();
		if b.len() != IKM_BASE_STRUCT_SIZE + is {
			return Err(Error::ParsingEncodedDataInvalidIkmLen(b.len()));
		}
		Ok(Self {
			id: IkmId::from_le_bytes(b[0..4].try_into().unwrap()),
			scheme,
			content: b[8..8 + is].into(),
			created_at: InputKeyMaterial::bytes_to_system_time(&b[8 + is..8 + is + 8])?,
			expire_at: InputKeyMaterial::bytes_to_system_time(&b[8 + is + 8..8 + is + 8 + 8])?,
			is_revoked: b[8 + is + 8 + 8] != 0,
		})
	}

	fn bytes_to_system_time(ts_slice: &[u8]) -> Result<SystemTime> {
		let ts_array: [u8; 8] = ts_slice.try_into().unwrap();
		let ts = u64::from_le_bytes(ts_array);
		SystemTime::UNIX_EPOCH
			.checked_add(Duration::from_secs(ts))
			.ok_or(Error::SystemTimeReprError(ts))
	}
}

#[derive(Debug, Default)]
pub struct InputKeyMaterialList {
	pub(crate) ikm_lst: Vec<InputKeyMaterial>,
	#[allow(dead_code)]
	pub(crate) id_counter: CounterId,
}

impl InputKeyMaterialList {
	#[cfg(feature = "ikm-management")]
	pub fn new() -> Self {
		Self::default()
	}

	#[cfg(feature = "ikm-management")]
	pub fn add_ikm(&mut self) -> Result<()> {
		self.add_custom_ikm(
			crate::DEFAULT_SCHEME,
			Duration::from_secs(crate::DEFAULT_IKM_DURATION),
		)
	}

	#[cfg(feature = "ikm-management")]
	pub fn add_custom_ikm(&mut self, scheme: Scheme, duration: Duration) -> Result<()> {
		let ikm_len = scheme.get_ikm_size();
		let mut content: Vec<u8> = vec![0; ikm_len];
		getrandom::getrandom(content.as_mut_slice())?;
		let created_at = SystemTime::now();
		self.id_counter += 1;
		self.ikm_lst.push(InputKeyMaterial {
			id: self.id_counter,
			scheme,
			created_at,
			expire_at: created_at + duration,
			is_revoked: false,
			content,
		});
		Ok(())
	}

	#[cfg(feature = "ikm-management")]
	pub fn delete_ikm(&mut self, id: IkmId) {
		self.ikm_lst.retain(|ikm| ikm.id != id);
	}

	#[cfg(feature = "ikm-management")]
	pub fn revoke_ikm(&mut self, id: IkmId) -> Result<()> {
		let ikm = self
			.ikm_lst
			.iter_mut()
			.find(|ikm| ikm.id == id)
			.ok_or(Error::IkmNotFound(id))?;
		ikm.is_revoked = true;
		Ok(())
	}

	#[cfg(feature = "ikm-management")]
	pub fn export(&self) -> Result<String> {
		crate::storage::encode_ikm_list(self)
	}

	pub fn import(s: &str) -> Result<Self> {
		crate::storage::decode_ikm_list(s)
	}

	#[cfg(any(test, feature = "encryption"))]
	pub(crate) fn get_latest_ikm(&self) -> Result<&InputKeyMaterial> {
		let now = SystemTime::now();
		self.ikm_lst
			.iter()
			.rev()
			.find(|&ikm| !ikm.is_revoked && ikm.created_at < now && ikm.expire_at > now)
			.ok_or(Error::IkmNoneAvailable)
	}

	#[cfg(feature = "encryption")]
	pub(crate) fn get_ikm_by_id(&self, id: IkmId) -> Result<&InputKeyMaterial> {
		self.ikm_lst
			.iter()
			.find(|&ikm| ikm.id == id)
			.ok_or(Error::IkmNotFound(id))
	}
}

impl std::str::FromStr for InputKeyMaterialList {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Self::import(s)
	}
}

#[cfg(feature = "ikm-management")]
impl std::ops::Deref for InputKeyMaterialList {
	type Target = Vec<InputKeyMaterial>;

	fn deref(&self) -> &Self::Target {
		&self.ikm_lst
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::str::FromStr;

	#[test]
	fn import() {
		let s =
			"AQAAAA:AQAAAAEAAAC_vYEw1ujVG5i-CtoPYSzik_6xaAq59odjPm5ij01-e6zz4mUAAAAALJGBiwAAAAAA";
		let res = InputKeyMaterialList::import(s);
		assert!(res.is_ok(), "res: {res:?}");
		let lst = res.unwrap();
		assert_eq!(lst.id_counter, 1);
		assert_eq!(lst.ikm_lst.len(), 1);
		let ikm = lst.ikm_lst.first().unwrap();
		assert_eq!(ikm.id, 1);
		assert_eq!(ikm.scheme, Scheme::XChaCha20Poly1305WithBlake3);
		assert_eq!(
			ikm.content,
			[
				191, 189, 129, 48, 214, 232, 213, 27, 152, 190, 10, 218, 15, 97, 44, 226, 147, 254,
				177, 104, 10, 185, 246, 135, 99, 62, 110, 98, 143, 77, 126, 123
			]
		);
		assert_eq!(ikm.is_revoked, false);
	}

	#[test]
	fn from_str() {
		let s =
			"AQAAAA:AQAAAAEAAAC_vYEw1ujVG5i-CtoPYSzik_6xaAq59odjPm5ij01-e6zz4mUAAAAALJGBiwAAAAAA";
		let res = InputKeyMaterialList::from_str(s);
		assert!(res.is_ok(), "res: {res:?}");
		let lst = res.unwrap();
		assert_eq!(lst.id_counter, 1);
		assert_eq!(lst.ikm_lst.len(), 1);
		let ikm = lst.ikm_lst.first().unwrap();
		assert_eq!(ikm.id, 1);
		assert_eq!(ikm.scheme, Scheme::XChaCha20Poly1305WithBlake3);
		assert_eq!(
			ikm.content,
			[
				191, 189, 129, 48, 214, 232, 213, 27, 152, 190, 10, 218, 15, 97, 44, 226, 147, 254,
				177, 104, 10, 185, 246, 135, 99, 62, 110, 98, 143, 77, 126, 123
			]
		);
		assert_eq!(ikm.is_revoked, false);
	}
}

#[cfg(all(test, feature = "ikm-management"))]
mod ikm_management {
	use super::*;

	// This list contains the folowing IKM:
	// 1: * created_at: Monday 1 April 2019 10:21:42
	//    * expire_at: Wednesday 1 April 2020 10:21:42
	//    * is_revoked: true
	// 2: * created_at: Thursday 12 March 2020 10:21:42
	//    * expire_at: Friday 12 March 2021 10:21:42
	//    * is_revoked: false
	// 3: * created_at: Sunday 21 February 2021 10:21:42
	//    * expire_at: Thursday 10 February 2180 10:21:42
	//    * is_revoked: false
	// 4: * created_at: Sunday 30 January 2022 10:21:42
	//    * expire_at: Tuesday 10 January 2023 10:21:42
	//    * is_revoked: false
	// 5: * created_at: Tuesday 2 January 2024 10:21:42
	//    * expire_at: Tuesday 6 June 2180 10:21:42
	//    * is_revoked: true
	// 6: * created_at: Tuesday 15 August 2180 10:21:42
	//    * expire_at: Wednesday 15 August 2181 10:21:42
	//    * is_revoked: false
	const TEST_STR: &str = "BgAAAA:AQAAAAEAAACUAPcqngJ46_HMtJSdIw-WeUtImcCVxOA47n6UIN5K2TbmoVwAAAAANmuEXgAAAAAB:AgAAAAEAAADf7CR8vl_aWOUyfsO0ek0YQr_Yi7L_sJmF2nIt_XOaCzYNal4AAAAAtkBLYAAAAAAA:AwAAAAEAAAAMoNIW9gIGkzegUDEsU3N1Rf_Zz0OMuylUSiQjUzLXqzY0MmAAAAAANsk0iwEAAAAA:BAAAAAEAAABbwRrMz3x3DkfOEFg1BHfLLRHoNqg6d_xGWwdh48hH8rZm9mEAAAAANjy9YwAAAAAA:BQAAAAEAAAA2LwnTgDUF7qn7dy79VA24JSSgo6vllAtU5zmhrxNJu7YIz4sBAAAANoUMjgEAAAAB:BgAAAAEAAAAn0Vqe2f9YRXBt6xVYaeSLs0Gf0S0_5B-hk-a2b0rhlraCJbwAAAAAtlErjAEAAAAA";

	fn round_time(t: SystemTime) -> SystemTime {
		let secs = t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
		SystemTime::UNIX_EPOCH
			.checked_add(Duration::from_secs(secs))
			.unwrap()
	}

	#[test]
	fn gen_ikm_list() {
		let mut lst = InputKeyMaterialList::new();
		assert_eq!(lst.id_counter, 0);
		assert_eq!(lst.ikm_lst.len(), 0);

		let res = lst.add_ikm();
		assert!(res.is_ok(), "res: {res:?}");
		assert_eq!(lst.id_counter, 1);
		assert_eq!(lst.ikm_lst.len(), 1);
		assert!(lst.ikm_lst.first().is_some());
		let el = lst.ikm_lst.first().unwrap();
		assert_eq!(el.id, 1);
		assert_eq!(el.is_revoked, false);

		let res = lst.add_custom_ikm(
			Scheme::XChaCha20Poly1305WithBlake3,
			Duration::from_secs(crate::DEFAULT_IKM_DURATION),
		);
		assert!(res.is_ok(), "res: {res:?}");
		assert_eq!(lst.id_counter, 2);
		assert_eq!(lst.ikm_lst.len(), 2);

		let res = lst.add_ikm();
		assert!(res.is_ok(), "res: {res:?}");
		assert_eq!(lst.id_counter, 3);
		assert_eq!(lst.ikm_lst.len(), 3);
	}

	#[test]
	fn export_empty() {
		let lst = InputKeyMaterialList::new();
		assert_eq!(lst.id_counter, 0);
		assert_eq!(lst.ikm_lst.len(), 0);

		let res = lst.export();
		assert!(res.is_ok(), "res: {res:?}");
		let s = res.unwrap();
		assert_eq!(&s, "AAAAAA");
	}

	#[test]
	fn export() {
		let mut lst = InputKeyMaterialList::new();
		let _ = lst.add_ikm();

		let res = lst.export();
		assert!(res.is_ok(), "res: {res:?}");
		let s = res.unwrap();
		assert_eq!(s.len(), 83);
	}

	#[test]
	fn import() {
		let res = InputKeyMaterialList::import(TEST_STR);
		assert!(res.is_ok(), "res: {res:?}");
		let lst = res.unwrap();
		assert_eq!(lst.id_counter, 6);
		assert_eq!(lst.ikm_lst.len(), 6);
	}

	#[test]
	fn export_import_empty() {
		let lst = InputKeyMaterialList::new();

		let res = lst.export();
		assert!(res.is_ok(), "res: {res:?}");
		let s = res.unwrap();

		let res = InputKeyMaterialList::import(&s);
		assert!(res.is_ok(), "res: {res:?}");
		let lst_bis = res.unwrap();
		assert_eq!(lst_bis.id_counter, lst.id_counter);
		assert_eq!(lst_bis.id_counter, 0);
		assert_eq!(lst_bis.ikm_lst.len(), lst.ikm_lst.len());
		assert_eq!(lst_bis.ikm_lst.len(), 0);
	}

	#[test]
	fn export_import() {
		let mut lst = InputKeyMaterialList::new();
		for _ in 0..10 {
			let _ = lst.add_ikm();
		}

		let res = lst.export();
		assert!(res.is_ok(), "res: {res:?}");
		let s = res.unwrap();

		let res = InputKeyMaterialList::import(&s);
		assert!(res.is_ok(), "res: {res:?}");
		let lst_bis = res.unwrap();
		assert_eq!(lst_bis.id_counter, lst.id_counter);
		assert_eq!(lst_bis.id_counter, 10);
		assert_eq!(lst_bis.ikm_lst.len(), lst.ikm_lst.len());
		assert_eq!(lst_bis.ikm_lst.len(), 10);

		for i in 0..10 {
			let el = &lst.ikm_lst[i];
			let el_bis = &lst_bis.ikm_lst[i];
			assert_eq!(el_bis.id, el.id);
			assert_eq!(el_bis.content, el.content);
			assert_eq!(el_bis.created_at, round_time(el.created_at));
			assert_eq!(el_bis.expire_at, round_time(el.expire_at));
			assert_eq!(el_bis.is_revoked, el.is_revoked);
		}
	}

	#[test]
	fn delete_ikm() {
		let mut lst = InputKeyMaterialList::new();
		let _ = lst.add_ikm();
		let _ = lst.add_ikm();

		let latest_ikm = lst.get_latest_ikm().unwrap();
		assert_eq!(latest_ikm.id, 2);

		lst.delete_ikm(2);
		let latest_ikm = lst.get_latest_ikm().unwrap();
		assert_eq!(latest_ikm.id, 1);

		lst.delete_ikm(1);
		let res = lst.get_latest_ikm();
		assert!(res.is_err());
	}

	#[test]
	fn revoke_ikm() {
		let mut lst = InputKeyMaterialList::new();
		let _ = lst.add_ikm();
		let _ = lst.add_ikm();

		let latest_ikm = lst.get_latest_ikm().unwrap();
		assert_eq!(latest_ikm.id, 2);

		let _ = lst.revoke_ikm(2);
		let latest_ikm = lst.get_latest_ikm().unwrap();
		assert_eq!(latest_ikm.id, 1);

		let _ = lst.revoke_ikm(1);
		let res = lst.get_latest_ikm();
		assert!(res.is_err());
	}

	#[test]
	fn iterate() {
		let mut lst = InputKeyMaterialList::new();
		for _ in 0..10 {
			let _ = lst.add_ikm();
		}
		let mut id = 1;
		for ikm in lst.iter() {
			assert_eq!(id, ikm.id);
			id += 1;
		}
	}

	#[test]
	fn get_latest_ikm() {
		let res = InputKeyMaterialList::import(TEST_STR);
		assert!(res.is_ok(), "res: {res:?}");
		let lst = res.unwrap();
		let res = lst.get_latest_ikm();
		assert!(res.is_ok(), "res: {res:?}");
		let ikm = res.unwrap();
		assert_eq!(ikm.id, 3);
	}
}

#[cfg(all(test, feature = "encryption", feature = "ikm-management"))]
mod encryption {
	use super::*;

	#[test]
	fn get_latest_ikm() {
		let mut lst = InputKeyMaterialList::new();
		let _ = lst.add_ikm();
		let _ = lst.add_ikm();
		let _ = lst.add_custom_ikm(
			Scheme::XChaCha20Poly1305WithBlake3,
			Duration::from_secs(crate::DEFAULT_IKM_DURATION),
		);
		let res = lst.get_latest_ikm();
		assert!(res.is_ok(), "res: {res:?}");
		let latest_ikm = res.unwrap();
		assert_eq!(latest_ikm.id, 3);
		assert_eq!(latest_ikm.scheme, Scheme::XChaCha20Poly1305WithBlake3);
		assert_eq!(latest_ikm.content.len(), 32);
	}

	#[test]
	fn get_latest_ikm_empty() {
		let lst = InputKeyMaterialList::new();
		let res = lst.get_latest_ikm();
		assert!(res.is_err());
	}

	#[test]
	fn get_ikm_by_id() {
		let mut lst = InputKeyMaterialList::new();
		let _ = lst.add_ikm();
		let _ = lst.add_ikm();
		let _ = lst.add_ikm();
		for i in 1..=3 {
			let res = lst.get_ikm_by_id(i);
			assert!(res.is_ok(), "res: {res:?}");
			let latest_ikm = res.unwrap();
			assert_eq!(latest_ikm.id, i);
		}
	}

	#[test]
	fn get_ikm_by_id_noexists() {
		let mut lst = InputKeyMaterialList::new();
		let _ = lst.add_ikm();
		let _ = lst.add_ikm();
		let _ = lst.add_ikm();
		let res = lst.get_ikm_by_id(42);
		assert!(res.is_err());
	}
}
