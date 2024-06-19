use crate::canonicalization::{canonicalize, join_canonicalized_str};
use crate::context::{DataContext, KeyContext};
use crate::error::Result;
use crate::kdf::derive_key;
use crate::{storage, IkmId, InputKeyMaterialList};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Coffio<'a> {
	ikm_list: &'a InputKeyMaterialList,
}

impl<'a> Coffio<'a> {
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
		data_context: &DataContext,
		data: impl AsRef<[u8]>,
	) -> Result<String> {
		self.process_encrypt_at(key_context, data_context, data, SystemTime::now())
	}

	#[cfg(feature = "encrypt-at")]
	pub fn encrypt_at(
		&self,
		key_context: &KeyContext,
		data_context: &DataContext,
		data: impl AsRef<[u8]>,
		encryption_time: SystemTime,
	) -> Result<String> {
		self.process_encrypt_at(key_context, data_context, data, encryption_time)
	}

	fn process_encrypt_at(
		&self,
		key_context: &KeyContext,
		data_context: &DataContext,
		data: impl AsRef<[u8]>,
		encryption_time: SystemTime,
	) -> Result<String> {
		let tp = if key_context.is_periodic() {
			let ts = encryption_time.duration_since(UNIX_EPOCH)?.as_secs();
			key_context.get_time_period(ts)
		} else {
			None
		};
		let ikm = self.ikm_list.get_latest_ikm(encryption_time)?;
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
		data_context: &DataContext,
		stored_data: &str,
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

	const TEST_CIPHERTEXT: &str = "enc-v1:AQAAAA:qpVDbGvu0wl2tQgfF5jngCWCoCq5d9gj:eTkOSKz9YyvJE8PyT1lAFn4hyeK_0l6tWU4yyHA-7WRCJ9G-HWNpqoKBxg:NgAAAAAAAAA";
	const TEST_DATA: &[u8] = b"Lorem ipsum dolor sit amet.";
	const TEST_KEY_CTX: &[&str] = &["db_name", "table_name", "column_name"];
	const TEST_DATA_CTX: &[&str] = &["018db876-3d9d-79af-9460-55d17da991d8"];

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

	#[cfg(feature = "chacha")]
	fn get_ikm_lst_chacha20poly1305_blake3() -> InputKeyMaterialList {
		InputKeyMaterialList::import(
			"ikml-v1:AQAAAA:AQAAAAEAAAC_vYEw1ujVG5i-CtoPYSzik_6xaAq59odjPm5ij01-e6zz4mUAAAAALJGBiwAAAAAA",
		)
		.unwrap()
	}

	#[cfg(feature = "aes")]
	fn get_ikm_lst_aes128gcm_sha256() -> InputKeyMaterialList {
		InputKeyMaterialList::import(
			"ikml-v1:AQAAAA:AQAAAAIAAAA2lXqTSduZ22J0LiwEhmENjB6pLo0GVKvAQYocJcAAp1f8_2UAAAAAuzDPeAAAAAAA",
		)
		.unwrap()
	}

	#[test]
	#[cfg(feature = "chacha")]
	fn encrypt_decrypt_no_context_chacha20poly1305_blake3() {
		let lst = get_ikm_lst_chacha20poly1305_blake3();
		let key_ctx = get_static_empty_key_ctx();
		let data_ctx = DataContext::from([]);
		let cb = Coffio::new(&lst);

		// Encrypt
		let res = cb.encrypt(&key_ctx, &data_ctx, TEST_DATA);
		assert!(res.is_ok(), "res: {res:?}");
		let ciphertext = res.unwrap();
		assert!(ciphertext.starts_with("enc-v1:AQAAAA:"));
		assert_eq!(ciphertext.len(), 105);

		// Decrypt
		let res = cb.decrypt(&key_ctx, &data_ctx, &ciphertext);
		assert!(res.is_ok(), "res: {res:?}");
		let plaintext = res.unwrap();
		assert_eq!(plaintext, TEST_DATA);
	}

	#[test]
	#[cfg(feature = "aes")]
	fn encrypt_decrypt_no_context_aes128gcm_sha256() {
		let lst = get_ikm_lst_aes128gcm_sha256();
		let key_ctx = get_static_empty_key_ctx();
		let data_ctx = DataContext::from([]);
		let cb = Coffio::new(&lst);

		// Encrypt
		let res = cb.encrypt(&key_ctx, &data_ctx, TEST_DATA);
		assert!(res.is_ok(), "res: {res:?}");
		let ciphertext = res.unwrap();
		assert!(ciphertext.starts_with("enc-v1:AQAAAA:"));
		assert_eq!(ciphertext.len(), 89);

		// Decrypt
		let res = cb.decrypt(&key_ctx, &data_ctx, &ciphertext);
		assert!(res.is_ok(), "res: {res:?}");
		let plaintext = res.unwrap();
		assert_eq!(plaintext, TEST_DATA);
	}

	#[test]
	#[cfg(feature = "chacha")]
	fn encrypt_decrypt_with_static_context_chacha20poly1305_blake3() {
		let lst = get_ikm_lst_chacha20poly1305_blake3();
		let key_ctx = get_static_key_ctx();
		let data_ctx = DataContext::from(TEST_DATA_CTX);
		let cb = Coffio::new(&lst);

		// Encrypt
		let res = cb.encrypt(&key_ctx, &data_ctx, TEST_DATA);
		assert!(res.is_ok(), "res: {res:?}");
		let ciphertext = res.unwrap();
		assert!(ciphertext.starts_with("enc-v1:AQAAAA:"));
		assert_eq!(ciphertext.len(), 105);

		// Decrypt
		let res = cb.decrypt(&key_ctx, &data_ctx, &ciphertext);
		assert!(res.is_ok(), "res: {res:?}");
		let plaintext = res.unwrap();
		assert_eq!(plaintext, TEST_DATA);
	}

	#[test]
	#[cfg(feature = "aes")]
	fn encrypt_decrypt_with_static_context_aes128gcm_sha256() {
		let lst = get_ikm_lst_aes128gcm_sha256();
		let key_ctx = get_static_key_ctx();
		let data_ctx = DataContext::from(TEST_DATA_CTX);
		let cb = Coffio::new(&lst);

		// Encrypt
		let res = cb.encrypt(&key_ctx, &data_ctx, TEST_DATA);
		assert!(res.is_ok(), "res: {res:?}");
		let ciphertext = res.unwrap();
		assert!(ciphertext.starts_with("enc-v1:AQAAAA:"));
		assert_eq!(ciphertext.len(), 89);

		// Decrypt
		let res = cb.decrypt(&key_ctx, &data_ctx, &ciphertext);
		assert!(res.is_ok(), "res: {res:?}");
		let plaintext = res.unwrap();
		assert_eq!(plaintext, TEST_DATA);
	}

	#[test]
	#[cfg(feature = "chacha")]
	fn encrypt_decrypt_with_context_chacha20poly1305_blake3() {
		let lst = get_ikm_lst_chacha20poly1305_blake3();
		let key_ctx = KeyContext::from(TEST_KEY_CTX);
		let data_ctx = DataContext::from(TEST_DATA_CTX);
		let cb = Coffio::new(&lst);

		// Encrypt
		let res = cb.encrypt(&key_ctx, &data_ctx, TEST_DATA);
		assert!(res.is_ok(), "res: {res:?}");
		let ciphertext = res.unwrap();
		assert!(ciphertext.starts_with("enc-v1:AQAAAA:"));
		assert_eq!(ciphertext.len(), 117);

		// Decrypt
		let res = cb.decrypt(&key_ctx, &data_ctx, &ciphertext);
		assert!(res.is_ok(), "res: {res:?}");
		let plaintext = res.unwrap();
		assert_eq!(plaintext, TEST_DATA);
	}

	#[test]
	#[cfg(feature = "aes")]
	fn encrypt_decrypt_with_context_aes128gcm_sha256() {
		let lst = get_ikm_lst_aes128gcm_sha256();
		let key_ctx = KeyContext::from(TEST_KEY_CTX);
		let data_ctx = DataContext::from(TEST_DATA_CTX);
		let cb = Coffio::new(&lst);

		// Encrypt
		let res = cb.encrypt(&key_ctx, &data_ctx, TEST_DATA);
		assert!(res.is_ok(), "res: {res:?}");
		let ciphertext = res.unwrap();
		assert!(ciphertext.starts_with("enc-v1:AQAAAA:"));
		assert_eq!(ciphertext.len(), 101);

		// Decrypt
		let res = cb.decrypt(&key_ctx, &data_ctx, &ciphertext);
		assert!(res.is_ok(), "res: {res:?}");
		let plaintext = res.unwrap();
		assert_eq!(plaintext, TEST_DATA);
	}

	#[test]
	#[cfg(feature = "chacha")]
	fn decrypt_invalid_ciphertext() {
		let tests = &[
			("", "empty data 1"),
			("env-v1:", "empty data 2"),
			("enc-v1:AQAATA:qpVDbGvu0wl2tQgfF5jngCWCoCq5d9gj:eTkOSKz9YyvJE8PyT1lAFn4hyeK_0l6tWU4yyHA-7WRCJ9G-HWNpqoKBxg:NgAAAAAAAAA", "unknown ikm id"),
			("enc-v1:AQAAAA:8pVDbGvu0wl2tQgfF5jngCWCoCq5d9gj:eTkOSKz9YyvJE8PyT1lAFn4hyeK_0l6tWU4yyHA-7WRCJ9G-HWNpqoKBxg:NgAAAAAAAAA", "invalid nonce"),
			("enc-v1:AQAAAA:qpVDbGvu0wl2tQgfF5jngCWCoCq5d9gj:8TkOSKz9YyvJE8PyT1lAFn4hyeK_0l6tWU4yyHA-7WRCJ9G-HWNpqoKBxg:NgAAAAAAAAA", "invalid ciphertext"),
			("enc-v1:AQAAAA:qpVDbGvu0wl2tQgfF5jngCWCoCq5d9gj:eTkOSKz9YyvJE8PyT1lAFn4hyeK_0l6tWU4yyHA-7WRCJ9G-HWNpqoKBxg:NaAAAAAAAAA", "invalid time period"),
			("enc-v1:AQAAAA:qpVDbGvu0wl2tQgfF5jngCWCoCq5d9gj:eTkOSKz9YyvJE8PyT1lAFn4hyeK_0l6tWU4yyHA-7WRCJ9G-HWNpqoKBxg:", "empty time period"),
			("enc-v1:AQAAAA:qpVDbGvu0wl2tQgfF5jngCWCoCq5d9gj:eTkOSKz9YyvJE8PyT1lAFn4hyeK_0l6tWU4yyHA-7WRCJ9G-HWNpqoKBxg", "missing time period"),
		];

		let lst = get_ikm_lst_chacha20poly1305_blake3();
		let key_ctx = KeyContext::from(TEST_KEY_CTX);
		let data_ctx = DataContext::from(TEST_DATA_CTX);
		let cb = Coffio::new(&lst);

		// Test if the reference ciphertext used for the tests is actually valid
		let res = cb.decrypt(&key_ctx, &data_ctx, TEST_CIPHERTEXT);
		assert!(res.is_ok(), "invalid reference ciphertext");

		// Test if altered versions of the reference ciphertext are refused
		for (ciphertext, error_str) in tests {
			let res = cb.decrypt(&key_ctx, &data_ctx, ciphertext);
			assert!(res.is_err(), "failed error detection: {error_str}");
		}
	}

	#[test]
	#[cfg(feature = "chacha")]
	fn invalid_context() {
		let lst = get_ikm_lst_chacha20poly1305_blake3();
		let key_ctx = KeyContext::from(TEST_KEY_CTX);
		let data_ctx = DataContext::from(TEST_DATA_CTX);
		let cb = Coffio::new(&lst);

		let res = cb.decrypt(&key_ctx, &data_ctx, TEST_CIPHERTEXT);
		assert!(res.is_ok(), "invalid reference ciphertext");

		let invalid_key_ctx = KeyContext::from(["invalid", "key", "context"]);
		let res = cb.decrypt(&invalid_key_ctx, &data_ctx, TEST_CIPHERTEXT);
		assert!(res.is_err(), "failed error detection: invalid key context");

		let invalid_data_ctx = DataContext::from(["invalid", "data", "context"]);
		let res = cb.decrypt(&key_ctx, &invalid_data_ctx, TEST_CIPHERTEXT);
		assert!(res.is_err(), "failed error detection: invalid key context");
	}
}
