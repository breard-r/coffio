use crate::encrypted_data::EncryptedData;
use crate::error::{Error, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

// X-variant: the nonce's size is 192 bits (24 bytes)
const NONCE_SIZE: usize = 24;

pub(crate) fn xchacha20poly1305_gen_nonce() -> Result<Vec<u8>> {
	let mut nonce: [u8; NONCE_SIZE] = [0; NONCE_SIZE];
	getrandom::getrandom(&mut nonce)?;
	Ok(nonce.to_vec())
}

pub(crate) fn xchacha20poly1305_encrypt(
	key: &[u8],
	nonce: &[u8],
	data: &[u8],
	aad: &str,
) -> Result<EncryptedData> {
	// Adapt the key and nonce
	let key = Key::from_slice(key);
	let nonce = XNonce::from_slice(nonce);

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

pub(crate) fn xchacha20poly1305_decrypt(
	key: &[u8],
	encrypted_data: &EncryptedData,
	aad: &str,
) -> Result<Vec<u8>> {
	// Adapt the key and nonce
	let key = Key::from_slice(key);
	if encrypted_data.nonce.len() != NONCE_SIZE {
		return Err(Error::InvalidNonceSize(
			NONCE_SIZE,
			encrypted_data.nonce.len(),
		));
	}
	let nonce = XNonce::from_slice(&encrypted_data.nonce);

	// Prepare the payload
	let payload = Payload {
		msg: &encrypted_data.ciphertext,
		aad: aad.as_bytes(),
	};

	// Decrypt the payload and return
	let cipher = XChaCha20Poly1305::new(key);
	Ok(cipher.decrypt(nonce, payload)?)
}
