use crate::canonicalization::{canonicalize, join_canonicalized_str};
use crate::error::Result;
use crate::kdf::{derive_key, KeyContext};
use crate::{storage, InputKeyMaterialList};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) type DecryptionFunction = dyn Fn(&[u8], &EncryptedData, &str) -> Result<Vec<u8>>;
pub(crate) type EncryptionFunction = dyn Fn(&[u8], &[u8], &str) -> Result<EncryptedData>;

pub struct DataContext {
	ctx: Vec<String>,
}

impl DataContext {
	pub(crate) fn get_ctx_elems(&self) -> &[String] {
		self.ctx.as_ref()
	}
}

impl<const N: usize> From<[&str; N]> for DataContext {
	fn from(ctx: [&str; N]) -> Self {
		Self {
			ctx: ctx.iter().map(|s| s.to_string()).collect(),
		}
	}
}

#[derive(Debug)]
pub(crate) struct EncryptedData {
	pub(crate) nonce: Vec<u8>,
	pub(crate) ciphertext: Vec<u8>,
}

#[inline]
fn generate_aad(
	key_context: &KeyContext,
	data_context: &DataContext,
	time_period: Option<u64>,
) -> String {
	let elems = key_context.get_ctx_elems(time_period);
	let key_context_canon = canonicalize(&elems);
	let data_context_canon = canonicalize(data_context.get_ctx_elems());
	join_canonicalized_str(&key_context_canon, &data_context_canon)
}

pub fn encrypt(
	ikml: &InputKeyMaterialList,
	key_context: &KeyContext,
	data: impl AsRef<[u8]>,
	data_context: &DataContext,
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
	data_context: &DataContext,
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
	use crate::{DataContext, KeyContext};

	const TEST_CIPHERTEXT: &str = "AQAAAA:elFanOvp5DNewgq75T5U6wLYNn8zzo1n:9izU-8cw4oSIU4lqcYrfEBzOXluS7lVcUbF_KnEg0HFp2srx6xq3Bir91A:NgAAAAAAAAA";
	const TEST_DATA: &[u8] = b"Lorem ipsum dolor sit amet.";
	const TEST_KEY_CTX: [&str; 3] = ["db_name", "table_name", "column_name"];
	const TEST_DATA_CTX: [&str; 1] = ["018db876-3d9d-79af-9460-55d17da991d8"];

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
		let key_ctx = get_static_empty_key_ctx();
		let data_ctx = DataContext::from([]);

		// Encrypt
		let lst = get_ikm_lst();
		let res = encrypt(&lst, &key_ctx, TEST_DATA, &data_ctx);
		assert!(res.is_ok(), "res: {res:?}");
		let ciphertext = res.unwrap();
		assert!(ciphertext.starts_with("AQAAAA:"));
		assert_eq!(ciphertext.len(), 98);

		// Decrypt
		let res = decrypt(&lst, &key_ctx, &ciphertext, &data_ctx);
		assert!(res.is_ok(), "res: {res:?}");
		let plaintext = res.unwrap();
		assert_eq!(plaintext, TEST_DATA);
	}

	#[test]
	fn encrypt_decrypt_with_static_context() {
		let lst = get_ikm_lst();
		let key_ctx = get_static_key_ctx();
		let data_ctx = DataContext::from(TEST_DATA_CTX);

		// Encrypt
		let res = encrypt(&lst, &key_ctx, TEST_DATA, &data_ctx);
		assert!(res.is_ok(), "res: {res:?}");
		let ciphertext = res.unwrap();
		assert!(ciphertext.starts_with("AQAAAA:"));
		assert_eq!(ciphertext.len(), 98);

		// Decrypt
		let res = decrypt(&lst, &key_ctx, &ciphertext, &data_ctx);
		assert!(res.is_ok(), "res: {res:?}");
		let plaintext = res.unwrap();
		assert_eq!(plaintext, TEST_DATA);
	}

	#[test]
	fn encrypt_decrypt_with_context() {
		let lst = get_ikm_lst();
		let key_ctx = KeyContext::from(TEST_KEY_CTX);
		let data_ctx = DataContext::from(TEST_DATA_CTX);

		// Encrypt
		let res = encrypt(&lst, &key_ctx, TEST_DATA, &data_ctx);
		assert!(res.is_ok(), "res: {res:?}");
		let ciphertext = res.unwrap();
		assert!(ciphertext.starts_with("AQAAAA:"));
		assert_eq!(ciphertext.len(), 110);

		// Decrypt
		let res = decrypt(&lst, &key_ctx, &ciphertext, &data_ctx);
		assert!(res.is_ok(), "res: {res:?}");
		let plaintext = res.unwrap();
		assert_eq!(plaintext, TEST_DATA);
	}

	#[test]
	fn decrypt_invalid_ciphertext() {
		let tests = &[
			("", "empty data"),
			("AQAATA:elFanOvp5DNewgq75T5U6wLYNn8zzo1n:9izU-8cw4oSIU4lqcYrfEBzOXluS7lVcUbF_KnEg0HFp2srx6xq3Bir91A:NgAAAAAAAAA", "unknown ikm id"),
			("AQAAAA:MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0:9izU-8cw4oSIU4lqcYrfEBzOXluS7lVcUbF_KnEg0HFp2srx6xq3Bir91A:NgAAAAAAAAA", "invalid nonce"),
			("AQAAAA:elFanOvp5DNewgq75T5U6wLYNn8zzo1n:8izU-8cw4oSIU4lqcYrfEBzOXluS7lVcUbF_KnEg0HFp2srx6xq3Bir91A:NgAAAAAAAAA", "invalid ciphertext"),
			("AQAAAA:elFanOvp5DNewgq75T5U6wLYNn8zzo1n:9izU-8cw4oSIU4lqcYrfEBzOXluS7lVcUbF_KnEg0HFp2srx6xq3Bir91A:NaAAAAAAAAA", "invalid time period"),
			("AQAAAA:elFanOvp5DNewgq75T5U6wLYNn8zzo1n:9izU-8cw4oSIU4lqcYrfEBzOXluS7lVcUbF_KnEg0HFp2srx6xq3Bir91A:", "empty time period"),
			("AQAAAA:elFanOvp5DNewgq75T5U6wLYNn8zzo1n:9izU-8cw4oSIU4lqcYrfEBzOXluS7lVcUbF_KnEg0HFp2srx6xq3Bir91A", "missing time period"),
		];

		let lst = get_ikm_lst();
		let key_ctx = KeyContext::from(TEST_KEY_CTX);
		let data_ctx = DataContext::from(TEST_DATA_CTX);

		// Test if the reference ciphertext used for the tests is actually valid
		let res = decrypt(&lst, &key_ctx, TEST_CIPHERTEXT, &data_ctx);
		assert!(res.is_ok(), "invalid reference ciphertext");

		// Test if altered versions of the reference ciphertext are refused
		for (ciphertext, error_str) in tests {
			let res = decrypt(&lst, &key_ctx, ciphertext, &data_ctx);
			assert!(res.is_err(), "failed error detection: {error_str}");
		}
	}

	#[test]
	fn invalid_context() {
		let lst = get_ikm_lst();
		let key_ctx = KeyContext::from(TEST_KEY_CTX);
		let data_ctx = DataContext::from(TEST_DATA_CTX);

		let res = decrypt(&lst, &key_ctx, TEST_CIPHERTEXT, &data_ctx);
		assert!(res.is_ok(), "invalid reference ciphertext");

		let invalid_key_ctx = KeyContext::from(["invalid", "key", "context"]);
		let res = decrypt(&lst, &invalid_key_ctx, TEST_CIPHERTEXT, &data_ctx);
		assert!(res.is_err(), "failed error detection: invalid key context");

		let invalid_data_ctx = DataContext::from(["invalid", "data", "context"]);
		let res = decrypt(&lst, &key_ctx, TEST_CIPHERTEXT, &invalid_data_ctx);
		assert!(res.is_err(), "failed error detection: invalid key context");
	}
}
