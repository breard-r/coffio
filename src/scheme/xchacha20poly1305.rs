use crate::encryption::EncryptedData;
use crate::error::Result;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

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
