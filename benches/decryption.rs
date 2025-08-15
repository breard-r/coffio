mod data;

use coffio::{Coffio, DataContext, InputKeyMaterialList, KeyContext};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use data::{
	DATA_CTX, Data, ENCRYPTED_INPUTS, IKML_AES128GCM_SHA256, IKML_XCHACHA20POLY1305_BLAKE3,
	KEY_CTX, MEASUREMENT_TIME,
};
use std::time::Duration;

macro_rules! alg_group {
	($group: ident, $name: expr, $inputs: ident, $ikml: ident) => {
		for (input_name, input) in $inputs.iter() {}
	};
}

fn decrypt_coffio(ikml: &str, input: &str) {
	let ikm = InputKeyMaterialList::import(ikml).unwrap();
	let key_ctx = KeyContext::from(KEY_CTX);
	let data_ctx = DataContext::from(DATA_CTX);
	let cb = Coffio::new(&ikm);
	if let Err(e) = cb.decrypt(&key_ctx, &data_ctx, input) {
		assert!(false, "{e}");
	}
}

pub fn decryption_benchmark(c: &mut Criterion) {
	for (name, input_aes, input_xchacha) in ENCRYPTED_INPUTS {
		let mut group = c.benchmark_group(format!("Decryption {name}"));
		group.measurement_time(Duration::from_secs(MEASUREMENT_TIME));

		let data = Data {
			ikml: IKML_AES128GCM_SHA256,
			input: input_aes,
		};
		group.bench_with_input(
			BenchmarkId::new("Aes128GcmWithSha256", name),
			&data,
			|b, i| b.iter(|| decrypt_coffio(i.ikml, i.input)),
		);

		let data = Data {
			ikml: IKML_XCHACHA20POLY1305_BLAKE3,
			input: input_xchacha,
		};
		group.bench_with_input(
			BenchmarkId::new("XChaCha20Poly1305WithBlake3", name),
			&data,
			|b, i| b.iter(|| decrypt_coffio(i.ikml, i.input)),
		);
	}
}

criterion_group!(benches, decryption_benchmark);
criterion_main!(benches);
