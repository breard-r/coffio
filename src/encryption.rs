use crate::key::derive_key;
use crate::{Error, InputKeyMaterialList};

pub fn encrypt(
	ikml: &InputKeyMaterialList,
	key_context: &[impl AsRef<[u8]>],
	data: impl AsRef<[u8]>,
	data_context: &[impl AsRef<[u8]>],
) -> Result<String, Error> {
	let ikm = ikml.get_latest_ikm()?;
	let key = derive_key(ikm, key_context);
	unimplemented!("encrypt");
}

pub fn decrypt(
	ikml: &InputKeyMaterialList,
	key_context: &[impl AsRef<[u8]>],
	data: impl AsRef<[u8]>,
	data_context: &[impl AsRef<[u8]>],
) -> Result<Vec<u8>, Error> {
	unimplemented!("decrypt");
}
