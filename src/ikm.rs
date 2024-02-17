use crate::{Error, Scheme};
use base64ct::{Base64UrlUnpadded, Encoding};
use std::time::{Duration, SystemTime};

const IKM_STRUCT_SIZE: usize = 57;
const IKM_CONTENT_SIZE: usize = 32;

#[derive(Debug)]
pub(crate) struct InputKeyMaterial {
	pub(crate) id: u32,
	pub(crate) scheme: Scheme,
	pub(crate) content: [u8; IKM_CONTENT_SIZE],
	pub(crate) created_at: SystemTime,
	pub(crate) expire_at: SystemTime,
	pub(crate) is_revoked: bool,
}

impl InputKeyMaterial {
	#[cfg(feature = "ikm-management")]
	fn as_bytes(&self) -> Result<[u8; IKM_STRUCT_SIZE], Error> {
		let mut res = Vec::with_capacity(IKM_STRUCT_SIZE);
		res.extend_from_slice(&self.id.to_le_bytes());
		res.extend_from_slice(&(self.scheme as u32).to_le_bytes());
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
		Ok(res.try_into().unwrap())
	}

	fn from_bytes(b: [u8; IKM_STRUCT_SIZE]) -> Result<Self, Error> {
		Ok(Self {
			id: u32::from_le_bytes(b[0..4].try_into().unwrap()),
			scheme: u32::from_le_bytes(b[4..8].try_into().unwrap()).try_into()?,
			content: b[8..40].try_into().unwrap(),
			created_at: InputKeyMaterial::bytes_to_system_time(&b[40..48])?,
			expire_at: InputKeyMaterial::bytes_to_system_time(&b[48..56])?,
			is_revoked: b[56] != 0,
		})
	}

	fn bytes_to_system_time(ts_slice: &[u8]) -> Result<SystemTime, Error> {
		let ts_array: [u8; 8] = ts_slice.try_into().unwrap();
		let ts = u64::from_le_bytes(ts_array);
		SystemTime::UNIX_EPOCH
			.checked_add(Duration::from_secs(ts))
			.ok_or(Error::SystemTimeReprError(ts))
	}
}

#[derive(Debug, Default)]
pub struct InputKeyMaterialList {
	ikm_lst: Vec<InputKeyMaterial>,
	id_counter: u32,
}

impl InputKeyMaterialList {
	#[cfg(feature = "ikm-management")]
	pub fn new() -> Self {
		Self::default()
	}

	#[cfg(feature = "ikm-management")]
	pub fn add_ikm(&mut self) -> Result<(), Error> {
		self.add_ikm_with_duration(Duration::from_secs(crate::DEFAULT_IKM_DURATION))
	}

	#[cfg(feature = "ikm-management")]
	pub fn add_ikm_with_duration(&mut self, duration: Duration) -> Result<(), Error> {
		let mut content: [u8; 32] = [0; 32];
		getrandom::getrandom(&mut content)?;
		let created_at = SystemTime::now();
		self.id_counter += 1;
		self.ikm_lst.push(InputKeyMaterial {
			id: self.id_counter,
			scheme: crate::DEFAULT_SCHEME,
			created_at,
			expire_at: created_at + duration,
			is_revoked: false,
			content,
		});
		Ok(())
	}

	#[cfg(feature = "ikm-management")]
	pub fn export(&self) -> Result<String, Error> {
		let data_size = (self.ikm_lst.len() * IKM_STRUCT_SIZE) + 4;
		let mut data = Vec::with_capacity(data_size);
		data.extend_from_slice(&self.id_counter.to_le_bytes());
		for ikm in &self.ikm_lst {
			data.extend_from_slice(&ikm.as_bytes()?);
		}
		Ok(Base64UrlUnpadded::encode_string(&data))
	}

	pub fn import(s: &str) -> Result<Self, Error> {
		let data = Base64UrlUnpadded::decode_vec(s)?;
		if data.len() % IKM_STRUCT_SIZE != 4 {
			return Err(Error::ParsingInvalidLength(data.len()));
		}
		let mut ikm_lst = Vec::with_capacity(data.len() / IKM_STRUCT_SIZE);
		for ikm_slice in data[4..].chunks_exact(IKM_STRUCT_SIZE) {
			ikm_lst.push(InputKeyMaterial::from_bytes(ikm_slice.try_into().unwrap())?);
		}
		Ok(Self {
			ikm_lst,
			id_counter: u32::from_le_bytes(data[0..4].try_into().unwrap()),
		})
	}

	#[cfg(feature = "encryption")]
	pub(crate) fn get_latest_ikm(&self) -> Result<&InputKeyMaterial, Error> {
		self.ikm_lst
			.iter()
			.rev()
			.find(|&ikm| !ikm.is_revoked && ikm.created_at < SystemTime::now())
			.ok_or(Error::IkmNoneAvailable)
	}

	#[cfg(feature = "encryption")]
	pub(crate) fn get_ikm_by_id(&self, id: u32) -> Result<&InputKeyMaterial, Error> {
		self.ikm_lst
			.iter()
			.find(|&ikm| ikm.id == id)
			.ok_or(Error::IkmNotFound(id))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[cfg(feature = "ikm-management")]
	fn round_time(t: SystemTime) -> SystemTime {
		let secs = t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
		SystemTime::UNIX_EPOCH
			.checked_add(Duration::from_secs(secs))
			.unwrap()
	}

	#[test]
	#[cfg(feature = "ikm-management")]
	fn gen_ikm_list() {
		let mut lst = InputKeyMaterialList::new();
		assert_eq!(lst.id_counter, 0);
		assert_eq!(lst.ikm_lst.len(), 0);

		let res = lst.add_ikm();
		assert!(res.is_ok());
		assert_eq!(lst.id_counter, 1);
		assert_eq!(lst.ikm_lst.len(), 1);
		assert!(lst.ikm_lst.first().is_some());
		let el = lst.ikm_lst.first().unwrap();
		assert_eq!(el.id, 1);
		assert_eq!(el.is_revoked, false);

		let res = lst.add_ikm();
		assert!(res.is_ok());
		assert_eq!(lst.id_counter, 2);
		assert_eq!(lst.ikm_lst.len(), 2);

		let res = lst.add_ikm();
		assert!(res.is_ok());
		assert_eq!(lst.id_counter, 3);
		assert_eq!(lst.ikm_lst.len(), 3);
	}

	#[test]
	#[cfg(feature = "ikm-management")]
	fn export_empty() {
		let lst = InputKeyMaterialList::new();
		assert_eq!(lst.id_counter, 0);
		assert_eq!(lst.ikm_lst.len(), 0);

		let res = lst.export();
		assert!(res.is_ok());
		let s = res.unwrap();
		assert_eq!(&s, "AAAAAA");
	}

	#[test]
	#[cfg(feature = "ikm-management")]
	fn export() {
		let mut lst = InputKeyMaterialList::new();
		let _ = lst.add_ikm();

		let res = lst.export();
		assert!(res.is_ok());
		let s = res.unwrap();
		assert_eq!(s.len(), 82);
	}

	#[test]
	fn import() {
		let s =
			"AQAAAAEAAAABAAAANGFtbdYEN0s7dzCfMm7dYeQWD64GdmuKsYSiKwppAhmkz81lAAAAACQDr2cAAAAAAA";
		let res = InputKeyMaterialList::import(s);
		assert!(res.is_ok());
		let lst = res.unwrap();
		assert_eq!(lst.id_counter, 1);
		assert_eq!(lst.ikm_lst.len(), 1);
		let ikm = lst.ikm_lst.first().unwrap();
		assert_eq!(ikm.id, 1);
		assert_eq!(ikm.scheme, Scheme::XChaCha20Poly1305WithBlake3);
		assert_eq!(
			ikm.content,
			[
				52, 97, 109, 109, 214, 4, 55, 75, 59, 119, 48, 159, 50, 110, 221, 97, 228, 22, 15,
				174, 6, 118, 107, 138, 177, 132, 162, 43, 10, 105, 2, 25
			]
		);
		assert_eq!(ikm.is_revoked, false);
	}

	#[test]
	#[cfg(feature = "ikm-management")]
	fn export_import_empty() {
		let lst = InputKeyMaterialList::new();

		let res = lst.export();
		assert!(res.is_ok());
		let s = res.unwrap();

		let res = InputKeyMaterialList::import(&s);
		assert!(res.is_ok());
		let lst_bis = res.unwrap();
		assert_eq!(lst_bis.id_counter, lst.id_counter);
		assert_eq!(lst_bis.id_counter, 0);
		assert_eq!(lst_bis.ikm_lst.len(), lst.ikm_lst.len());
		assert_eq!(lst_bis.ikm_lst.len(), 0);
	}

	#[test]
	#[cfg(feature = "ikm-management")]
	fn export_import() {
		let mut lst = InputKeyMaterialList::new();
		for _ in 0..10 {
			let _ = lst.add_ikm();
		}

		let res = lst.export();
		assert!(res.is_ok());
		let s = res.unwrap();

		let res = InputKeyMaterialList::import(&s);
		assert!(res.is_ok());
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
	#[cfg(feature = "encryption")]
	fn get_latest_ikm() {
		let mut lst = InputKeyMaterialList::new();
		let _ = lst.add_ikm();
		let _ = lst.add_ikm();
		let _ = lst.add_ikm();
		let res = lst.get_latest_ikm();
		assert!(res.is_ok());
		let latest_ikm = res.unwrap();
		assert_eq!(latest_ikm.id, 3);
	}

	#[test]
	#[cfg(feature = "encryption")]
	fn get_latest_ikm_empty() {
		let lst = InputKeyMaterialList::new();
		let res = lst.get_latest_ikm();
		assert!(res.is_err());
	}

	#[test]
	#[cfg(feature = "encryption")]
	fn get_ikm_by_id() {
		let mut lst = InputKeyMaterialList::new();
		let _ = lst.add_ikm();
		let _ = lst.add_ikm();
		let _ = lst.add_ikm();
		for i in 1..=3 {
			let res = lst.get_ikm_by_id(i);
			assert!(res.is_ok());
			let latest_ikm = res.unwrap();
			assert_eq!(latest_ikm.id, i);
		}
	}

	#[test]
	#[cfg(feature = "encryption")]
	fn get_ikm_by_id_noexists() {
		let mut lst = InputKeyMaterialList::new();
		let _ = lst.add_ikm();
		let _ = lst.add_ikm();
		let _ = lst.add_ikm();
		let res = lst.get_ikm_by_id(42);
		assert!(res.is_err());
	}
}
