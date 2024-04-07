use crate::error::{Error, Result};
use crate::scheme::{Scheme, SchemeSerializeType};
use std::time::{Duration, SystemTime};

pub(crate) const IKM_BASE_STRUCT_SIZE: usize = 25;

pub(crate) type CounterId = u32;
/// Abstract type representing the identifier of an [InputKeyMaterial].
pub type IkmId = u32;

/// An input key material (IKM) is a secret random seed that is used to derive cryptographic keys.
///
/// In order to manage your IKMs, each one of them has an unique identifier. An IKM is also tight
/// to a specific context in which it may be used. Keep in mind that an IKM is linked to a specific
/// algorithm, as an expiration date and can be revoked.
///
/// This struct is exposed so you can display its informations when managing your IKMs using an
/// [InputKeyMaterialList]. It it not meant to be used otherwise.
#[derive(Debug)]
pub struct InputKeyMaterial {
	pub(crate) id: IkmId,
	pub(crate) scheme: Scheme,
	pub(crate) content: Vec<u8>,
	pub(crate) not_before: SystemTime,
	pub(crate) not_after: SystemTime,
	pub(crate) is_revoked: bool,
}

impl InputKeyMaterial {
	/// Returns the IKM's identifier.
	#[cfg(feature = "ikm-management")]
	pub fn get_id(&self) -> IkmId {
		self.id
	}

	/// Returns the IKM's scheme.
	#[cfg(feature = "ikm-management")]
	pub fn get_scheme(&self) -> Scheme {
		self.scheme
	}

	/// Returns the date before which the IKM must not be used to encrypt data.
	#[cfg(feature = "ikm-management")]
	pub fn get_not_before(&self) -> SystemTime {
		self.not_before
	}

	/// Returns the date after which the IKM must not be used to encrypt data.
	#[cfg(feature = "ikm-management")]
	pub fn get_not_after(&self) -> SystemTime {
		self.not_after
	}

	/// Check whether or not the IKM has been revoked.
	#[cfg(feature = "ikm-management")]
	pub fn is_revoked(&self) -> bool {
		self.is_revoked
	}

	#[cfg(feature = "ikm-management")]
	pub(crate) fn as_bytes(&self) -> Result<Vec<u8>> {
		let mut res = Vec::with_capacity(IKM_BASE_STRUCT_SIZE + self.scheme.get_ikm_size());
		res.extend_from_slice(&self.id.to_le_bytes());
		res.extend_from_slice(&(self.scheme as SchemeSerializeType).to_le_bytes());
		res.extend_from_slice(&self.content);
		res.extend_from_slice(
			&self
				.not_before
				.duration_since(SystemTime::UNIX_EPOCH)?
				.as_secs()
				.to_le_bytes(),
		);
		res.extend_from_slice(
			&self
				.not_after
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
			not_before: InputKeyMaterial::bytes_to_system_time(&b[8 + is..8 + is + 8])?,
			not_after: InputKeyMaterial::bytes_to_system_time(&b[8 + is + 8..8 + is + 8 + 8])?,
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

/// A list of [InputKeyMaterial] (IKM). This is where you should manage your secrets.
///
/// The way coffio works is quite simple: you generate a secret random seed (an input key material,
/// IKM) that is used to derive cryptographic keys, which are used to encrypt your data. However,
/// if your IKM or any derived key has leaked, or if you wishes to change the encryption algorithm,
/// you need to generate an other IKM. This is why coffio uses a single opaque token capable of
/// containing several IKMs, the [InputKeyMaterialList]. This way, the transition between two IKMs
/// is smooth: you can use the new IKM to encrypt all new secrets and keep the revoked one to
/// decrypt secrets it has already encrypted and you haven't re-encrypted using the new IKM yet.
///
/// This list is ordered. To encrypt new data, coffio will always use the last IKM that is not
/// revoked and is within its validity period.
///
/// Encrypted data contains the [IkmId] of the IKM used to derive the key. To decrypt data, coffio
/// will therefore search for this specific IKM in the [InputKeyMaterialList].
///
/// <div class="warning">
/// Never remove an IKM from the list unless you are absolutely sure that all data encrypted using
/// this IKM have been either deleted or re-encrypted using another IKM.
/// </div>
///
/// # Examples
///
/// ```
/// use coffio::{InputKeyMaterialList, Scheme};
/// use std::time::{Duration, SystemTime};
///
/// // Create an empty IKM list.
/// let mut ikml = InputKeyMaterialList::new();
/// assert_eq!(ikml.len(), 0);
///
/// // Add an IKM to the list with the default settings.
/// let ikm_id_1 = ikml.add_ikm()?;
/// assert_eq!(ikml.len(), 1);
///
/// // Add an IKM to the list with custom settings.
/// let not_before = SystemTime::now();
/// let not_after = not_before + Duration::from_secs(315_569_252);
/// let ikm_id_2 = ikml.add_custom_ikm(
///     Scheme::Aes128GcmWithSha256,
///     not_before,
///     not_after,
/// )?;
/// assert_eq!(ikml.len(), 2);
///
/// // Revoke the first IKM.
/// ikml.revoke_ikm(ikm_id_1);
/// assert_eq!(ikml.len(), 2);
///
/// // Delete the second IKM.
/// ikml.delete_ikm(ikm_id_2);
/// assert_eq!(ikml.len(), 1);
///
/// // Export the IKM list
/// let exported_ikml = ikml.export()?;
/// println!("My secret IKM list: {exported_ikml}");
///
/// // Import an IKM list
/// let ikml2 = InputKeyMaterialList::import(&exported_ikml)?;
/// assert_eq!(ikml2.len(), 1);
/// # Ok::<(), coffio::Error>(())
/// ```
#[derive(Debug, Default)]
pub struct InputKeyMaterialList {
	pub(crate) ikm_lst: Vec<InputKeyMaterial>,
	#[allow(dead_code)]
	pub(crate) id_counter: CounterId,
}

impl InputKeyMaterialList {
	/// Create a new empty IKM list.
	///
	/// # Examples
	///
	/// ```
	/// let ikml = coffio::InputKeyMaterialList::new();
	/// ```
	#[cfg(feature = "ikm-management")]
	pub fn new() -> Self {
		Self::default()
	}

	/// Add a new IKM to the list. The scheme will be set to the value of
	/// [DEFAULT_SCHEME][crate::DEFAULT_SCHEME], the `not_before` field will be set to the current
	/// timestamp and the `not_after` will be set to the current timestamp incremented with the
	/// value of [DEFAULT_IKM_DURATION][crate::DEFAULT_IKM_DURATION].
	///
	/// # Examples
	///
	/// ```
	/// let mut ikml = coffio::InputKeyMaterialList::new();
	/// let _ = ikml.add_ikm()?;
	/// # Ok::<(), coffio::Error>(())
	/// ```
	#[cfg(feature = "ikm-management")]
	pub fn add_ikm(&mut self) -> Result<IkmId> {
		let not_before = SystemTime::now();
		let not_after = not_before + Duration::from_secs(crate::DEFAULT_IKM_DURATION);
		self.add_custom_ikm(crate::DEFAULT_SCHEME, not_before, not_after)
	}

	/// Add a new IKM with a specified scheme, `not_before` and `not_after` fields.
	///
	/// # Examples
	///
	/// ```
	/// use coffio::{InputKeyMaterialList, Scheme};
	/// use std::time::{Duration, SystemTime};
	///
	/// let mut ikml = InputKeyMaterialList::new();
	/// let not_before = SystemTime::now();
	/// let not_after = not_before + Duration::from_secs(315_569_252);
	/// let _ = ikml.add_custom_ikm(
	///     Scheme::XChaCha20Poly1305WithBlake3,
	///     not_before,
	///     not_after,
	/// );
	/// # Ok::<(), coffio::Error>(())
	/// ```
	#[cfg(feature = "ikm-management")]
	pub fn add_custom_ikm(
		&mut self,
		scheme: Scheme,
		not_before: SystemTime,
		not_after: SystemTime,
	) -> Result<IkmId> {
		let ikm_len = scheme.get_ikm_size();
		let mut content: Vec<u8> = vec![0; ikm_len];
		getrandom::getrandom(content.as_mut_slice())?;
		self.id_counter += 1;
		self.ikm_lst.push(InputKeyMaterial {
			id: self.id_counter,
			scheme,
			not_before,
			not_after,
			is_revoked: false,
			content,
		});
		Ok(self.id_counter)
	}

	/// Delete the specified IKM from the list.
	///
	/// # Examples
	///
	/// ```
	/// let mut ikml = coffio::InputKeyMaterialList::new();
	/// let ikm_id = ikml.add_ikm()?;
	/// ikml.delete_ikm(ikm_id)?;
	/// # Ok::<(), coffio::Error>(())
	/// ```
	#[cfg(feature = "ikm-management")]
	pub fn delete_ikm(&mut self, id: IkmId) -> Result<IkmId> {
		let initial_len = self.ikm_lst.len();
		self.ikm_lst.retain(|ikm| ikm.id != id);
		if self.ikm_lst.len() == initial_len {
			Err(Error::IkmNotFound(id))
		} else {
			Ok(id)
		}
	}

	/// Revoke the specified IKM from the list.
	///
	/// # Examples
	///
	/// ```
	/// let mut ikml = coffio::InputKeyMaterialList::new();
	/// let ikm_id = ikml.add_ikm()?;
	/// ikml.revoke_ikm(ikm_id)?;
	/// # Ok::<(), coffio::Error>(())
	/// ```
	#[cfg(feature = "ikm-management")]
	pub fn revoke_ikm(&mut self, id: IkmId) -> Result<IkmId> {
		let ikm = self
			.ikm_lst
			.iter_mut()
			.find(|ikm| ikm.id == id)
			.ok_or(Error::IkmNotFound(id))?;
		ikm.is_revoked = true;
		Ok(id)
	}

	/// Export the IKM list to a displayable string.
	///
	/// # Examples
	///
	/// ```
	/// let mut ikml = coffio::InputKeyMaterialList::new();
	/// let _ = ikml.add_ikm()?;
	/// let exported_ikml = ikml.export()?;
	/// # Ok::<(), coffio::Error>(())
	/// ```
	#[cfg(feature = "ikm-management")]
	pub fn export(&self) -> Result<String> {
		crate::storage::encode_ikm_list(self)
	}

	/// Import an IKM list.
	///
	/// # Examples
	///
	/// ```
	/// let stored_ikml = "AQAAAA:AQAAAAEAAAC_vYEw1ujVG5i-CtoPYSzik_6xaAq59odjPm5ij01-e6zz4mUAAAAALJGBiwAAAAAA";
	/// let mut ikml = coffio::InputKeyMaterialList::import(stored_ikml)?;
	/// # Ok::<(), coffio::Error>(())
	/// ```
	pub fn import(s: &str) -> Result<Self> {
		crate::storage::decode_ikm_list(s)
	}

	#[cfg(any(test, feature = "encryption"))]
	pub(crate) fn get_latest_ikm(&self, encryption_time: SystemTime) -> Result<&InputKeyMaterial> {
		self.ikm_lst
			.iter()
			.rev()
			.find(|&ikm| {
				!ikm.is_revoked
					&& ikm.not_before < encryption_time
					&& ikm.not_after > encryption_time
			})
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

#[cfg(test)]
fn get_default_time_period() -> (SystemTime, SystemTime) {
	let not_before = SystemTime::now();
	let not_after = not_before + Duration::from_secs(crate::DEFAULT_IKM_DURATION);
	(not_before, not_after)
}

#[cfg(all(test, feature = "ikm-management"))]
mod ikm_management {
	use super::*;

	// This list contains the folowing IKM:
	// 1: * not_before: Monday 1 April 2019 10:21:42
	//    * not_after: Wednesday 1 April 2020 10:21:42
	//    * is_revoked: true
	// 2: * not_before: Thursday 12 March 2020 10:21:42
	//    * not_after: Friday 12 March 2021 10:21:42
	//    * is_revoked: false
	// 3: * not_before: Sunday 21 February 2021 10:21:42
	//    * not_after: Thursday 10 February 2180 10:21:42
	//    * is_revoked: false
	// 4: * not_before: Sunday 30 January 2022 10:21:42
	//    * not_after: Tuesday 10 January 2023 10:21:42
	//    * is_revoked: false
	// 5: * not_before: Tuesday 2 January 2024 10:21:42
	//    * not_after: Tuesday 6 June 2180 10:21:42
	//    * is_revoked: true
	// 6: * not_before: Tuesday 15 August 2180 10:21:42
	//    * not_after: Wednesday 15 August 2181 10:21:42
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

		let (not_before, not_after) = get_default_time_period();
		let res = lst.add_custom_ikm(Scheme::XChaCha20Poly1305WithBlake3, not_before, not_after);
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
			assert_eq!(el_bis.not_before, round_time(el.not_before));
			assert_eq!(el_bis.not_after, round_time(el.not_after));
			assert_eq!(el_bis.is_revoked, el.is_revoked);
		}
	}

	#[test]
	fn delete_ikm() {
		let mut lst = InputKeyMaterialList::new();
		let _ = lst.add_ikm();
		let _ = lst.add_ikm();

		let latest_ikm = lst.get_latest_ikm(SystemTime::now()).unwrap();
		assert_eq!(latest_ikm.id, 2);

		let res = lst.delete_ikm(2);
		assert!(res.is_ok(), "res: {res:?}");
		assert_eq!(res.unwrap(), 2);
		let latest_ikm = lst.get_latest_ikm(SystemTime::now()).unwrap();
		assert_eq!(latest_ikm.id, 1);

		let res = lst.delete_ikm(1);
		assert!(res.is_ok(), "res: {res:?}");
		assert_eq!(res.unwrap(), 1);
		let res = lst.get_latest_ikm(SystemTime::now());
		assert!(res.is_err());

		let res = lst.delete_ikm(42);
		assert!(res.is_err(), "res: {res:?}");
	}

	#[test]
	fn revoke_ikm() {
		let mut lst = InputKeyMaterialList::new();
		let _ = lst.add_ikm();
		let _ = lst.add_ikm();

		let latest_ikm = lst.get_latest_ikm(SystemTime::now()).unwrap();
		assert_eq!(latest_ikm.id, 2);

		let res = lst.revoke_ikm(2);
		assert!(res.is_ok(), "res: {res:?}");
		assert_eq!(res.unwrap(), 2);
		let latest_ikm = lst.get_latest_ikm(SystemTime::now()).unwrap();
		assert_eq!(latest_ikm.id, 1);

		let res = lst.revoke_ikm(1);
		assert!(res.is_ok(), "res: {res:?}");
		assert_eq!(res.unwrap(), 1);
		let res = lst.get_latest_ikm(SystemTime::now());
		assert!(res.is_err());

		let res = lst.revoke_ikm(42);
		assert!(res.is_err(), "res: {res:?}");
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
	fn get_latest_ikm_epoch() {
		let res = InputKeyMaterialList::import(TEST_STR);
		assert!(res.is_ok(), "res: {res:?}");
		let lst = res.unwrap();
		let res = lst.get_latest_ikm(SystemTime::UNIX_EPOCH);
		assert_eq!(res.err(), Some(Error::IkmNoneAvailable))
	}

	#[test]
	fn get_latest_ikm_1_712_475_802() {
		let ts = SystemTime::UNIX_EPOCH + Duration::from_secs(1_712_475_802);
		let res = InputKeyMaterialList::import(TEST_STR);
		assert!(res.is_ok(), "res: {res:?}");
		let lst = res.unwrap();
		let res = lst.get_latest_ikm(ts);
		assert!(res.is_ok(), "res: {res:?}");
		let ikm = res.unwrap();
		assert_eq!(ikm.id, 3);
	}

	#[test]
	fn get_latest_ikm_1_592_734_902() {
		let ts = SystemTime::UNIX_EPOCH + Duration::from_secs(1_592_734_902);
		let res = InputKeyMaterialList::import(TEST_STR);
		assert!(res.is_ok(), "res: {res:?}");
		let lst = res.unwrap();
		let res = lst.get_latest_ikm(ts);
		assert!(res.is_ok(), "res: {res:?}");
		let ikm = res.unwrap();
		assert_eq!(ikm.id, 2);
	}
}

#[cfg(all(test, feature = "encryption", feature = "ikm-management"))]
mod encryption {
	use super::*;

	#[test]
	fn get_latest_ikm_xchacha20poly1305_blake3() {
		let mut lst = InputKeyMaterialList::new();
		let _ = lst.add_ikm();
		let _ = lst.add_ikm();
		let (not_before, not_after) = get_default_time_period();
		let _ = lst.add_custom_ikm(Scheme::XChaCha20Poly1305WithBlake3, not_before, not_after);
		let res = lst.get_latest_ikm(SystemTime::now());
		assert!(res.is_ok(), "res: {res:?}");
		let latest_ikm = res.unwrap();
		assert_eq!(latest_ikm.id, 3);
		assert_eq!(latest_ikm.scheme, Scheme::XChaCha20Poly1305WithBlake3);
		assert_eq!(latest_ikm.content.len(), 32);
	}

	#[test]
	fn get_latest_ikm_aes128gcm_sha256() {
		let mut lst = InputKeyMaterialList::new();
		let _ = lst.add_ikm();
		let _ = lst.add_ikm();
		let (not_before, not_after) = get_default_time_period();
		let _ = lst.add_custom_ikm(Scheme::Aes128GcmWithSha256, not_before, not_after);
		let res = lst.get_latest_ikm(SystemTime::now());
		assert!(res.is_ok(), "res: {res:?}");
		let latest_ikm = res.unwrap();
		assert_eq!(latest_ikm.id, 3);
		assert_eq!(latest_ikm.scheme, Scheme::Aes128GcmWithSha256);
		assert_eq!(latest_ikm.content.len(), 32);
	}

	#[test]
	fn get_latest_ikm_empty() {
		let lst = InputKeyMaterialList::new();
		let res = lst.get_latest_ikm(SystemTime::now());
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
