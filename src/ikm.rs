use base64ct::{Base64UrlUnpadded, Encoding};
use std::time::{Duration, SystemTime};

const IKM_STRUCT_SIZE: usize = 53;
const IKM_CONTENT_SIZE: usize = 32;

#[derive(Debug)]
pub struct InputKeyMaterial {
	id: u32,
	content: [u8; IKM_CONTENT_SIZE],
	created_at: SystemTime,
	expire_at: SystemTime,
	is_revoked: bool,
}

impl InputKeyMaterial {
	fn as_bytes(&self) -> [u8; IKM_STRUCT_SIZE] {
		let mut res = Vec::with_capacity(IKM_STRUCT_SIZE);
		res.extend_from_slice(&self.id.to_le_bytes());
		res.extend_from_slice(&self.content);
		res.extend_from_slice(
			&self
				.created_at
				.duration_since(SystemTime::UNIX_EPOCH)
				.unwrap()
				.as_secs()
				.to_le_bytes(),
		);
		res.extend_from_slice(
			&self
				.expire_at
				.duration_since(SystemTime::UNIX_EPOCH)
				.unwrap()
				.as_secs()
				.to_le_bytes(),
		);
		res.push(self.is_revoked as u8);
		res.try_into().unwrap()
	}

	fn from_bytes(b: [u8; IKM_STRUCT_SIZE]) -> Self {
		Self {
			id: u32::from_le_bytes(b[0..4].try_into().unwrap()),
			content: b[4..36].try_into().unwrap(),
			created_at: SystemTime::UNIX_EPOCH
				.checked_add(Duration::from_secs(u64::from_le_bytes(
					b[36..44].try_into().unwrap(),
				)))
				.unwrap(),
			expire_at: SystemTime::UNIX_EPOCH
				.checked_add(Duration::from_secs(u64::from_le_bytes(
					b[44..52].try_into().unwrap(),
				)))
				.unwrap(),
			is_revoked: b[52] != 0,
		}
	}
}

#[derive(Debug, Default)]
pub struct InputKeyMaterialList {
	ikm_lst: Vec<InputKeyMaterial>,
	id_counter: u32,
}

impl InputKeyMaterialList {
	pub fn new() -> Self {
		Self::default()
	}

	pub fn add_ikm(&mut self) -> Result<(), getrandom::Error> {
		self.add_ikm_with_duration(Duration::from_secs(crate::DEFAULT_IKM_DURATION))
	}

	pub fn add_ikm_with_duration(&mut self, duration: Duration) -> Result<(), getrandom::Error> {
		let mut content: [u8; 32] = [0; 32];
		getrandom::getrandom(&mut content)?;
		let created_at = SystemTime::now();
		self.id_counter += 1;
		self.ikm_lst.push(InputKeyMaterial {
			id: self.id_counter,
			created_at,
			expire_at: created_at + duration,
			is_revoked: false,
			content,
		});
		Ok(())
	}

	pub fn export(&self) -> String {
		let data_size = (self.ikm_lst.len() * IKM_STRUCT_SIZE) + 4;
		let mut data = Vec::with_capacity(data_size);
		data.extend_from_slice(&self.id_counter.to_le_bytes());
		for ikm in &self.ikm_lst {
			data.extend_from_slice(&ikm.as_bytes());
		}
		Base64UrlUnpadded::encode_string(&data)
	}

	pub fn import(s: &str) -> Result<Self, String> {
		let data = Base64UrlUnpadded::decode_vec(s).unwrap();
		if data.len() % IKM_STRUCT_SIZE != 4 {
			return Err("Invalid string".to_string());
		}
		let mut ikm_lst = Vec::with_capacity(data.len() / IKM_STRUCT_SIZE);
		for ikm_slice in data[4..].chunks_exact(IKM_STRUCT_SIZE) {
			ikm_lst.push(InputKeyMaterial::from_bytes(ikm_slice.try_into().unwrap()));
		}
		Ok(Self {
			ikm_lst,
			id_counter: u32::from_le_bytes(data[0..4].try_into().unwrap()),
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

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
	fn export_empty() {
		let lst = InputKeyMaterialList::new();
		assert_eq!(lst.id_counter, 0);
		assert_eq!(lst.ikm_lst.len(), 0);

		let s = lst.export();
		assert_eq!(&s, "AAAAAA");
	}

	#[test]
	fn export() {
		let mut lst = InputKeyMaterialList::new();
		let _ = lst.add_ikm();

		let s = lst.export();
		assert_eq!(s.len(), 76);
	}

	#[test]
	fn import() {
		let s = "AQAAAAEAAABucjrrlDwu3T9cIYqsmOg_h6_xO77fia0bahsIYnx9G9QVzWUAAAAAVEmuZwAAAAAA";
		let res = InputKeyMaterialList::import(s);
		assert!(res.is_ok());
		let lst = res.unwrap();
		assert_eq!(lst.id_counter, 1);
		assert_eq!(lst.ikm_lst.len(), 1);
		let ikm = lst.ikm_lst.first().unwrap();
		assert_eq!(ikm.id, 1);
		assert_eq!(
			ikm.content,
			[
				110, 114, 58, 235, 148, 60, 46, 221, 63, 92, 33, 138, 172, 152, 232, 63, 135, 175,
				241, 59, 190, 223, 137, 173, 27, 106, 27, 8, 98, 124, 125, 27
			]
		);
		assert_eq!(ikm.is_revoked, false);
	}

	#[test]
	fn export_import_empty() {
		let lst = InputKeyMaterialList::new();

		let s = lst.export();
		let res = InputKeyMaterialList::import(&s);
		assert!(res.is_ok());
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

		let s = lst.export();
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
}
