#[derive(Debug)]
pub(crate) struct EncryptedData {
	pub(crate) nonce: Vec<u8>,
	pub(crate) ciphertext: Vec<u8>,
}
