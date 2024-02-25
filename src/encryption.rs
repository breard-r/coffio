use crate::canonicalization::{canonicalize, join_canonicalized_str};
use crate::error::Result;
use crate::kdf::derive_key;
use crate::{storage, InputKeyMaterialList};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

pub(crate) type DecryptionFunction = dyn Fn(&[u8], &EncryptedData, &str) -> Result<Vec<u8>>;
pub(crate) type EncryptionFunction = dyn Fn(&[u8], &[u8], &str) -> Result<EncryptedData>;

pub(crate) struct EncryptedData {
	pub(crate) nonce: Vec<u8>,
	pub(crate) ciphertext: Vec<u8>,
}

#[inline]
fn generate_aad(key_context: &[&str], data_context: &[impl AsRef<[u8]>]) -> String {
	let key_context_canon = canonicalize(key_context);
	let data_context_canon = canonicalize(data_context);
	join_canonicalized_str(&key_context_canon, &data_context_canon)
}

pub fn encrypt(
	ikml: &InputKeyMaterialList,
	key_context: &[&str],
	data: impl AsRef<[u8]>,
	data_context: &[impl AsRef<[u8]>],
) -> Result<String> {
	let ikm = ikml.get_latest_ikm()?;
	let key = derive_key(ikm, key_context);
	let aad = generate_aad(key_context, data_context);
	let encryption_function = ikm.scheme.get_encryption();
	let encrypted_data = encryption_function(&key, data.as_ref(), &aad)?;
	Ok(storage::encode(ikm.id, &encrypted_data))
}

pub(crate) fn xchacha20poly1305_encrypt(
	key: &[u8],
	data: &[u8],
	aad: &str,
) -> Result<EncryptedData> {
	// Adapt the key
	let key = Key::from_slice(key);

	// Generate a nonce
	let mut nonce: [u8; 24] = [0; 24];
	getrandom::getrandom(&mut nonce)?;
	let nonce = XNonce::from_slice(&nonce);

	// Prepare the payload
	let payload = Payload {
		msg: data,
		aad: aad.as_bytes(),
	};

	// Encrypt the payload
	let cipher = XChaCha20Poly1305::new(key);
	let ciphertext = cipher.encrypt(nonce, payload)?;

	// Return the result
	Ok(EncryptedData {
		nonce: nonce.to_vec(),
		ciphertext,
	})
}

pub fn decrypt(
	ikml: &InputKeyMaterialList,
	key_context: &[&str],
	stored_data: &str,
	data_context: &[impl AsRef<[u8]>],
) -> Result<Vec<u8>> {
	let (ikm_id, encrypted_data) = storage::decode(stored_data)?;
	let ikm = ikml.get_ikm_by_id(ikm_id)?;
	let key = derive_key(ikm, key_context);
	let aad = generate_aad(key_context, data_context);
	let decryption_function = ikm.scheme.get_decryption();
	decryption_function(&key, &encrypted_data, &aad)
}

pub(crate) fn xchacha20poly1305_decrypt(
	key: &[u8],
	encrypted_data: &EncryptedData,
	aad: &str,
) -> Result<Vec<u8>> {
	let key = Key::from_slice(key);
	let nonce = XNonce::from_slice(&encrypted_data.nonce);
	let payload = Payload {
		msg: &encrypted_data.ciphertext,
		aad: aad.as_bytes(),
	};
	let cipher = XChaCha20Poly1305::new(key);
	Ok(cipher.decrypt(nonce, payload)?)
}

#[cfg(test)]
mod tests {
	use super::*;

	const TEST_DATA: &[u8] = b"Lorem ipsum dolor sit amet.";
	const TEST_KEY_CTX: &[&str] = &["db_name", "table_name", "column_name"];
	const TEST_DATA_CTX: &[&str] = &["018db876-3d9d-79af-9460-55d17da991d8"];
	const EMPTY_DATA_CTX: &[[u8; 0]] = &[];

	fn get_ikm_lst() -> InputKeyMaterialList {
		InputKeyMaterialList::import(
			"AQAAAAEAAAABAAAANGFtbdYEN0s7dzCfMm7dYeQWD64GdmuKsYSiKwppAhmkz81lAAAAACQDr2cAAAAAAA",
		)
		.unwrap()
	}

	#[test]
	fn encrypt_decrypt_no_context() {
		// Encrypt
		let lst = get_ikm_lst();
		let res = encrypt(&lst, &[], TEST_DATA, EMPTY_DATA_CTX);
		assert!(res.is_ok());
		let ciphertext = res.unwrap();
		assert!(ciphertext.starts_with("AQAAAA:"));
		assert_eq!(ciphertext.len(), 98);

		// Decrypt
		let res = decrypt(&lst, &[], &ciphertext, EMPTY_DATA_CTX);
		assert!(res.is_ok());
		let plaintext = res.unwrap();
		assert_eq!(plaintext, TEST_DATA);
	}

	#[test]
	fn encrypt_decrypt_with_context() {
		// Encrypt
		let lst = get_ikm_lst();
		let res = encrypt(&lst, TEST_KEY_CTX, TEST_DATA, TEST_DATA_CTX);
		assert!(res.is_ok());
		let ciphertext = res.unwrap();
		assert!(ciphertext.starts_with("AQAAAA:"));
		assert_eq!(ciphertext.len(), 98);

		// Decrypt
		let res = decrypt(&lst, TEST_KEY_CTX, &ciphertext, TEST_DATA_CTX);
		assert!(res.is_ok());
		let plaintext = res.unwrap();
		assert_eq!(plaintext, TEST_DATA);
	}
}
