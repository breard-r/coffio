mod data;

use coffio::{Coffio, DataContext, InputKeyMaterialList, KeyContext};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use data::{
	Data, AES128GCM_SHA256_INPUTS, DATA_CTX, IKML_AES128GCM_SHA256, IKML_XCHACHA20POLY1305_BLAKE3,
	KEY_CTX, MEASUREMENT_TIME, XCHACHA20POLY1305_BLAKE3_INPUTS,
};
use std::time::Duration;

macro_rules! alg_group {
	($group: ident, $name: expr, $inputs: ident, $ikml: ident) => {
		for (input_name, input) in $inputs.iter() {
			let data = Data { ikml: $ikml, input };
			$group.bench_with_input(BenchmarkId::new($name, input_name), &data, |b, i| {
				b.iter(|| decrypt_coffio(i.ikml, i.input))
			});
		}
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
	let mut group = c.benchmark_group("Decryption");
	group.measurement_time(Duration::from_secs(MEASUREMENT_TIME));
	alg_group!(
		group,
		"Aes128GcmWithSha256",
		AES128GCM_SHA256_INPUTS,
		IKML_AES128GCM_SHA256
	);
	alg_group!(
		group,
		"XChaCha20Poly1305WithBlake3",
		XCHACHA20POLY1305_BLAKE3_INPUTS,
		IKML_XCHACHA20POLY1305_BLAKE3
	);
}

criterion_group!(benches, decryption_benchmark);
criterion_main!(benches);
