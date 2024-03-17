use crate::canonicalization::{canonicalize, join_canonicalized_str};
use crate::context::{DataContext, KeyContext};
use crate::error::Result;
use crate::kdf::derive_key;
use crate::{storage, IkmId, InputKeyMaterialList};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct CipherBox<'a> {
	ikm_list: &'a InputKeyMaterialList,
}

impl<'a> CipherBox<'a> {
	pub fn new(ikm_list: &'a InputKeyMaterialList) -> Self {
		Self { ikm_list }
	}

	#[inline]
	fn generate_aad(
		ikm_id: IkmId,
		nonce: &[u8],
		key_context: &KeyContext,
		data_context: &DataContext,
		time_period: Option<u64>,
	) -> String {
		let ikm_id_canon = canonicalize(&[ikm_id.to_le_bytes()]);
		let nonce_canon = canonicalize(&[nonce]);
		let elems = key_context.get_ctx_elems(time_period);
		let key_context_canon = canonicalize(&elems);
		let data_context_canon = canonicalize(data_context.get_ctx_elems());
		join_canonicalized_str(&[
			ikm_id_canon,
			nonce_canon,
			key_context_canon,
			data_context_canon,
		])
	}

	pub fn encrypt(
		&self,
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
		let ikm = self.ikm_list.get_latest_ikm()?;
		let key = derive_key(ikm, key_context, tp);
		let gen_nonce_function = ikm.scheme.get_gen_nonce();
		let nonce = gen_nonce_function()?;
		let aad = Self::generate_aad(ikm.id, &nonce, key_context, data_context, tp);
		let encryption_function = ikm.scheme.get_encryption();
		let encrypted_data = encryption_function(&key, &nonce, data.as_ref(), &aad)?;
		Ok(storage::encode_cipher(ikm.id, &encrypted_data, tp))
	}

	pub fn decrypt(
		&self,
		key_context: &KeyContext,
		stored_data: &str,
		data_context: &DataContext,
	) -> Result<Vec<u8>> {
		let (ikm_id, encrypted_data, tp) = storage::decode_cipher(stored_data)?;
		let ikm = self.ikm_list.get_ikm_by_id(ikm_id)?;
		let key = derive_key(ikm, key_context, tp);
		let aad = Self::generate_aad(ikm.id, &encrypted_data.nonce, key_context, data_context, tp);
		let decryption_function = ikm.scheme.get_decryption();
		decryption_function(&key, &encrypted_data, &aad)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{DataContext, KeyContext};

	const TEST_CIPHERTEXT: &str = "AQAAAA:W-nzcGkPU6eWj_JjjqLpQk6WSe_CIUPF:we_HR8yD3XnQ9aaJlZFvqPitnDlQHexw4QPaYaOTzpHSWNW86QQrLRRZOg:NgAAAAAAAAA";
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
		let lst = get_ikm_lst();
		let key_ctx = get_static_empty_key_ctx();
		let data_ctx = DataContext::from([]);
		let cb = CipherBox::new(&lst);

		// Encrypt
		let res = cb.encrypt(&key_ctx, TEST_DATA, &data_ctx);
		assert!(res.is_ok(), "res: {res:?}");
		let ciphertext = res.unwrap();
		assert!(ciphertext.starts_with("AQAAAA:"));
		assert_eq!(ciphertext.len(), 98);

		// Decrypt
		let res = cb.decrypt(&key_ctx, &ciphertext, &data_ctx);
		assert!(res.is_ok(), "res: {res:?}");
		let plaintext = res.unwrap();
		assert_eq!(plaintext, TEST_DATA);
	}

	#[test]
	fn encrypt_decrypt_with_static_context() {
		let lst = get_ikm_lst();
		let key_ctx = get_static_key_ctx();
		let data_ctx = DataContext::from(TEST_DATA_CTX);
		let cb = CipherBox::new(&lst);

		// Encrypt
		let res = cb.encrypt(&key_ctx, TEST_DATA, &data_ctx);
		assert!(res.is_ok(), "res: {res:?}");
		let ciphertext = res.unwrap();
		assert!(ciphertext.starts_with("AQAAAA:"));
		assert_eq!(ciphertext.len(), 98);

		// Decrypt
		let res = cb.decrypt(&key_ctx, &ciphertext, &data_ctx);
		assert!(res.is_ok(), "res: {res:?}");
		let plaintext = res.unwrap();
		assert_eq!(plaintext, TEST_DATA);
	}

	#[test]
	fn encrypt_decrypt_with_context() {
		let lst = get_ikm_lst();
		let key_ctx = KeyContext::from(TEST_KEY_CTX);
		let data_ctx = DataContext::from(TEST_DATA_CTX);
		let cb = CipherBox::new(&lst);

		// Encrypt
		let res = cb.encrypt(&key_ctx, TEST_DATA, &data_ctx);
		assert!(res.is_ok(), "res: {res:?}");
		let ciphertext = res.unwrap();
		assert!(ciphertext.starts_with("AQAAAA:"));
		assert_eq!(ciphertext.len(), 110);

		// Decrypt
		let res = cb.decrypt(&key_ctx, &ciphertext, &data_ctx);
		assert!(res.is_ok(), "res: {res:?}");
		let plaintext = res.unwrap();
		assert_eq!(plaintext, TEST_DATA);
	}

	#[test]
	fn decrypt_invalid_ciphertext() {
		let tests = &[
			("", "empty data"),
			("AQAATA:W-nzcGkPU6eWj_JjjqLpQk6WSe_CIUPF:we_HR8yD3XnQ9aaJlZFvqPitnDlQHexw4QPaYaOTzpHSWNW86QQrLRRZOg:NgAAAAAAAAA", "unknown ikm id"),
			("AQAAAA:MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0:we_HR8yD3XnQ9aaJlZFvqPitnDlQHexw4QPaYaOTzpHSWNW86QQrLRRZOg:NgAAAAAAAAA", "invalid nonce"),
			("AQAAAA:W-nzcGkPU6eWj_JjjqLpQk6WSe_CIUPF:8e_HR8yD3XnQ9aaJlZFvqPitnDlQHexw4QPaYaOTzpHSWNW86QQrLRRZOg:NgAAAAAAAAA", "invalid ciphertext"),
			("AQAAAA:W-nzcGkPU6eWj_JjjqLpQk6WSe_CIUPF:we_HR8yD3XnQ9aaJlZFvqPitnDlQHexw4QPaYaOTzpHSWNW86QQrLRRZOg:NaAAAAAAAAA", "invalid time period"),
			("AQAAAA:W-nzcGkPU6eWj_JjjqLpQk6WSe_CIUPF:we_HR8yD3XnQ9aaJlZFvqPitnDlQHexw4QPaYaOTzpHSWNW86QQrLRRZOg:", "empty time period"),
			("AQAAAA:W-nzcGkPU6eWj_JjjqLpQk6WSe_CIUPF:we_HR8yD3XnQ9aaJlZFvqPitnDlQHexw4QPaYaOTzpHSWNW86QQrLRRZOg", "missing time period"),
		];

		let lst = get_ikm_lst();
		let key_ctx = KeyContext::from(TEST_KEY_CTX);
		let data_ctx = DataContext::from(TEST_DATA_CTX);
		let cb = CipherBox::new(&lst);

		// Test if the reference ciphertext used for the tests is actually valid
		let res = cb.decrypt(&key_ctx, TEST_CIPHERTEXT, &data_ctx);
		assert!(res.is_ok(), "invalid reference ciphertext");

		// Test if altered versions of the reference ciphertext are refused
		for (ciphertext, error_str) in tests {
			let res = cb.decrypt(&key_ctx, ciphertext, &data_ctx);
			assert!(res.is_err(), "failed error detection: {error_str}");
		}
	}

	#[test]
	fn invalid_context() {
		let lst = get_ikm_lst();
		let key_ctx = KeyContext::from(TEST_KEY_CTX);
		let data_ctx = DataContext::from(TEST_DATA_CTX);
		let cb = CipherBox::new(&lst);

		let res = cb.decrypt(&key_ctx, TEST_CIPHERTEXT, &data_ctx);
		assert!(res.is_ok(), "invalid reference ciphertext");

		let invalid_key_ctx = KeyContext::from(["invalid", "key", "context"]);
		let res = cb.decrypt(&invalid_key_ctx, TEST_CIPHERTEXT, &data_ctx);
		assert!(res.is_err(), "failed error detection: invalid key context");

		let invalid_data_ctx = DataContext::from(["invalid", "data", "context"]);
		let res = cb.decrypt(&key_ctx, TEST_CIPHERTEXT, &invalid_data_ctx);
		assert!(res.is_err(), "failed error detection: invalid key context");
	}
}
