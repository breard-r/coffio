mod data;

use coffio::{CipherBox, DataContext, InputKeyMaterialList, KeyContext};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use data::{
	Data, DATA_CTX, IKML_XCHACHA20POLY1305_BLAKE3, KEY_CTX, MEASUREMENT_TIME,
	XCHACHA20POLY1305_BLAKE3_INPUTS,
};
use std::time::Duration;

fn decrypt_coffio(ikml: &str, input: &str) {
	let ikm = InputKeyMaterialList::import(ikml).unwrap();
	let key_ctx = KeyContext::from(KEY_CTX);
	let data_ctx = DataContext::from(DATA_CTX);
	let cb = CipherBox::new(&ikm);
	if let Err(e) = cb.decrypt(&key_ctx, input, &data_ctx) {
		assert!(false, "{e}");
	}
}

pub fn decryption_benchmark(c: &mut Criterion) {
	let mut group = c.benchmark_group("Decryption");
	group.measurement_time(Duration::from_secs(MEASUREMENT_TIME));
	for (input_name, input) in XCHACHA20POLY1305_BLAKE3_INPUTS.iter() {
		let data = Data {
			ikml: IKML_XCHACHA20POLY1305_BLAKE3,
			input,
		};
		group.bench_with_input(
			BenchmarkId::new("XChaCha20Poly1305WithBlake3", input_name),
			&data,
			|b, i| b.iter(|| decrypt_coffio(i.ikml, i.input)),
		);
	}
}

criterion_group!(benches, decryption_benchmark);
criterion_main!(benches);
