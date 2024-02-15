use crate::{Error, InputKeyMaterialList};

pub fn encrypt(
	ikml: &InputKeyMaterialList,
	key_context: &[impl AsRef<[u8]>],
	data: impl AsRef<[u8]>,
	data_context: &[impl AsRef<[u8]>],
) -> Result<String, Error> {
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
