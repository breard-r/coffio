use crate::canonicalization::{canonicalize, join_canonicalized_str};
use crate::error::Result;
use crate::kdf::{derive_key, KeyContext};
use crate::{storage, InputKeyMaterialList};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) type DecryptionFunction = dyn Fn(&[u8], &EncryptedData, &str) -> Result<Vec<u8>>;
pub(crate) type EncryptionFunction = dyn Fn(&[u8], &[u8], &str) -> Result<EncryptedData>;

#[derive(Debug)]
pub(crate) struct EncryptedData {
	pub(crate) nonce: Vec<u8>,
	pub(crate) ciphertext: Vec<u8>,
}

#[inline]
fn generate_aad(
	key_context: &KeyContext,
	data_context: &[impl AsRef<[u8]>],
	ts: Option<u64>,
) -> String {
	let key_context_canon = canonicalize(&key_context.get_value(ts));
	let data_context_canon = canonicalize(data_context);
	join_canonicalized_str(&key_context_canon, &data_context_canon)
}

pub fn encrypt(
	ikml: &InputKeyMaterialList,
	key_context: &KeyContext,
	data: impl AsRef<[u8]>,
	data_context: &[impl AsRef<[u8]>],
) -> Result<String> {
	let ts = if key_context.is_periodic() {
		Some(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
	} else {
		None
	};
	let ikm = ikml.get_latest_ikm()?;
	let key = derive_key(ikm, key_context, ts);
	let aad = generate_aad(key_context, data_context, ts);
	let encryption_function = ikm.scheme.get_encryption();
	let encrypted_data = encryption_function(&key, data.as_ref(), &aad)?;
	Ok(storage::encode_cipher(ikm.id, &encrypted_data, ts))
}

pub fn decrypt(
	ikml: &InputKeyMaterialList,
	key_context: &KeyContext,
	stored_data: &str,
	data_context: &[impl AsRef<[u8]>],
) -> Result<Vec<u8>> {
	let (ikm_id, encrypted_data, ts) = storage::decode_cipher(stored_data)?;
	let ikm = ikml.get_ikm_by_id(ikm_id)?;
	let key = derive_key(ikm, key_context, ts);
	let aad = generate_aad(key_context, data_context, ts);
	let decryption_function = ikm.scheme.get_decryption();
	decryption_function(&key, &encrypted_data, &aad)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::KeyContext;

	const TEST_DATA: &[u8] = b"Lorem ipsum dolor sit amet.";
	const TEST_KEY_CTX: [&str; 3] = ["db_name", "table_name", "column_name"];
	const TEST_DATA_CTX: &[&str] = &["018db876-3d9d-79af-9460-55d17da991d8"];
	const EMPTY_DATA_CTX: &[[u8; 0]] = &[];

	fn get_ikm_lst() -> InputKeyMaterialList {
		InputKeyMaterialList::import(
			"AQAAAA:AQAAAAEAAAC_vYEw1ujVG5i-CtoPYSzik_6xaAq59odjPm5ij01-e6zz4mUAAAAALJGBiwAAAAAA",
		)
		.unwrap()
	}

	#[test]
	fn encrypt_decrypt_no_context() {
		let ctx = KeyContext::from([]);

		// Encrypt
		let lst = get_ikm_lst();
		let res = encrypt(&lst, &ctx, TEST_DATA, EMPTY_DATA_CTX);
		assert!(res.is_ok(), "res: {res:?}");
		let ciphertext = res.unwrap();
		assert!(ciphertext.starts_with("AQAAAA:"));
		assert_eq!(ciphertext.len(), 98);

		// Decrypt
		let res = decrypt(&lst, &ctx, &ciphertext, EMPTY_DATA_CTX);
		assert!(res.is_ok(), "res: {res:?}");
		let plaintext = res.unwrap();
		assert_eq!(plaintext, TEST_DATA);
	}

	#[test]
	fn encrypt_decrypt_with_context() {
		// Encrypt
		let lst = get_ikm_lst();
		let res = encrypt(&lst, &TEST_KEY_CTX.into(), TEST_DATA, TEST_DATA_CTX);
		assert!(res.is_ok(), "res: {res:?}");
		let ciphertext = res.unwrap();
		assert!(ciphertext.starts_with("AQAAAA:"));
		assert_eq!(ciphertext.len(), 98);

		// Decrypt
		let res = decrypt(&lst, &TEST_KEY_CTX.into(), &ciphertext, TEST_DATA_CTX);
		assert!(res.is_ok(), "res: {res:?}");
		let plaintext = res.unwrap();
		assert_eq!(plaintext, TEST_DATA);
	}
}
