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
	time_period: Option<u64>,
) -> String {
	let key_context_canon = canonicalize(&key_context.get_value(time_period));
	let data_context_canon = canonicalize(data_context);
	join_canonicalized_str(&key_context_canon, &data_context_canon)
}

pub fn encrypt(
	ikml: &InputKeyMaterialList,
	key_context: &KeyContext,
	data: impl AsRef<[u8]>,
	data_context: &[impl AsRef<[u8]>],
) -> Result<String> {
	let tp = if key_context.is_periodic() {
		let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
		key_context.get_time_period(ts)
	} else {
		None
	};
	let ikm = ikml.get_latest_ikm()?;
	let key = derive_key(ikm, key_context, tp);
	let aad = generate_aad(key_context, data_context, tp);
	let encryption_function = ikm.scheme.get_encryption();
	let encrypted_data = encryption_function(&key, data.as_ref(), &aad)?;
	Ok(storage::encode_cipher(ikm.id, &encrypted_data, tp))
}

pub fn decrypt(
	ikml: &InputKeyMaterialList,
	key_context: &KeyContext,
	stored_data: &str,
	data_context: &[impl AsRef<[u8]>],
) -> Result<Vec<u8>> {
	let (ikm_id, encrypted_data, tp) = storage::decode_cipher(stored_data)?;
	let ikm = ikml.get_ikm_by_id(ikm_id)?;
	let key = derive_key(ikm, key_context, tp);
	let aad = generate_aad(key_context, data_context, tp);
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

	fn get_static_key_ctx() -> KeyContext {
		let mut ctx: KeyContext = TEST_KEY_CTX.into();
		ctx.set_static();
		ctx
	}

	fn get_static_empty_key_ctx() -> KeyContext {
		let mut ctx = KeyContext::from([]);
		ctx.set_static();
		ctx
	}

	fn get_ikm_lst() -> InputKeyMaterialList {
		InputKeyMaterialList::import(
			"AQAAAA:AQAAAAEAAAC_vYEw1ujVG5i-CtoPYSzik_6xaAq59odjPm5ij01-e6zz4mUAAAAALJGBiwAAAAAA",
		)
		.unwrap()
	}

	#[test]
	fn encrypt_decrypt_no_context() {
		let ctx = get_static_empty_key_ctx();

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
	fn encrypt_decrypt_with_static_context() {
		let lst = get_ikm_lst();
		let key_ctx = get_static_key_ctx();

		// Encrypt
		let res = encrypt(&lst, &key_ctx, TEST_DATA, TEST_DATA_CTX);
		assert!(res.is_ok(), "res: {res:?}");
		let ciphertext = res.unwrap();
		assert!(ciphertext.starts_with("AQAAAA:"));
		assert_eq!(ciphertext.len(), 98);

		// Decrypt
		let res = decrypt(&lst, &key_ctx, &ciphertext, TEST_DATA_CTX);
		assert!(res.is_ok(), "res: {res:?}");
		let plaintext = res.unwrap();
		assert_eq!(plaintext, TEST_DATA);
	}

	#[test]
	fn encrypt_decrypt_with_context() {
		let lst = get_ikm_lst();
		let key_ctx = KeyContext::from(TEST_KEY_CTX);

		// Encrypt
		let res = encrypt(&lst, &key_ctx, TEST_DATA, TEST_DATA_CTX);
		assert!(res.is_ok(), "res: {res:?}");
		let ciphertext = res.unwrap();
		assert!(ciphertext.starts_with("AQAAAA:"));
		assert_eq!(ciphertext.len(), 110);

		// Decrypt
		let res = decrypt(&lst, &key_ctx, &ciphertext, TEST_DATA_CTX);
		assert!(res.is_ok(), "res: {res:?}");
		let plaintext = res.unwrap();
		assert_eq!(plaintext, TEST_DATA);
	}
}
