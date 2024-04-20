mod data;

use coffio::{Coffio, DataContext, InputKeyMaterialList, KeyContext};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use data::{Data, DATA_CTX, IKMLS, KEY_CTX, MEASUREMENT_TIME, PLAIN_INPUTS};
use std::time::Duration;

fn encrypt_coffio(ikml: &str, input: &str) {
	let ikm = InputKeyMaterialList::import(ikml).unwrap();
	let key_ctx = KeyContext::from(KEY_CTX);
	let data_ctx = DataContext::from(DATA_CTX);
	let cb = Coffio::new(&ikm);
	if let Err(e) = cb.encrypt(&key_ctx, &data_ctx, input) {
		assert!(false, "{e}");
	}
}

pub fn encryption_benchmark(c: &mut Criterion) {
	let mut group = c.benchmark_group("Encryption");
	group.measurement_time(Duration::from_secs(MEASUREMENT_TIME));
	for (alg_name, ikml) in IKMLS.iter() {
		for (input_name, input) in PLAIN_INPUTS.iter() {
			let data = Data { ikml, input };
			group.bench_with_input(BenchmarkId::new(*alg_name, input_name), &data, |b, i| {
				b.iter(|| encrypt_coffio(i.ikml, i.input))
			});
		}
	}
}

criterion_group!(benches, encryption_benchmark);
criterion_main!(benches);
