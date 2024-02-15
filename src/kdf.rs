pub(crate) fn blake3_derive(context: &[u8], ikm: &[u8]) -> Vec<u8> {
	// TODO: remove this hack as soon as `blake3::derive_key` accepts bytes
	use std::fmt::Write;
	let context: String = context.iter().fold(String::new(), |mut output, b| {
		let _ = write!(output, "{b:02x}");
		output
	});
	blake3::derive_key(&context, ikm).to_vec()
}
