use crate::encrypted_data::EncryptedData;
use crate::error::{Error, Result};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Key, Nonce};

// 96 bits (12 bytes)
const NONCE_SIZE: usize = 12;

pub(crate) fn aes128gcm_gen_nonce() -> Result<Vec<u8>> {
	let mut nonce: [u8; NONCE_SIZE] = [0; NONCE_SIZE];
	getrandom::getrandom(&mut nonce)?;
	Ok(nonce.to_vec())
}

pub(crate) fn aes128gcm_encrypt(
	key: &[u8],
	nonce: &[u8],
	data: &[u8],
	aad: &str,
) -> Result<EncryptedData> {
	// Adapt the key and nonce
	let key = Key::<Aes128Gcm>::from_slice(key);
	let nonce = Nonce::from_slice(&nonce[0..NONCE_SIZE]);

	// Prepare the payload
	let payload = Payload {
		msg: data,
		aad: aad.as_bytes(),
	};

	// Encrypt the payload
	let cipher = Aes128Gcm::new(key);
	let ciphertext = cipher.encrypt(nonce, payload)?;

	// Return the result
	Ok(EncryptedData {
		nonce: nonce.to_vec(),
		ciphertext,
	})
}

pub(crate) fn aes128gcm_decrypt(
	key: &[u8],
	encrypted_data: &EncryptedData,
	aad: &str,
) -> Result<Vec<u8>> {
	// Adapt the key and nonce
	let key = Key::<Aes128Gcm>::from_slice(key);
	if encrypted_data.nonce.len() != NONCE_SIZE {
		return Err(Error::InvalidNonceSize(
			NONCE_SIZE,
			encrypted_data.nonce.len(),
		));
	}
	let nonce = Nonce::from_slice(&encrypted_data.nonce[0..NONCE_SIZE]);

	// Prepare the payload
	let payload = Payload {
		msg: &encrypted_data.ciphertext,
		aad: aad.as_bytes(),
	};

	// Decrypt the payload and return
	let cipher = Aes128Gcm::new(key);
	Ok(cipher.decrypt(nonce, payload)?)
}
