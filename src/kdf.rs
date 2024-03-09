use crate::canonicalization::canonicalize;
use crate::ikm::InputKeyMaterial;
use std::num::NonZeroU64;

pub(crate) type KdfFunction = dyn Fn(&str, &[u8]) -> Vec<u8>;

pub struct KeyContext {
	ctx: Vec<String>,
	periodicity: Option<u64>,
}

impl KeyContext {
	pub fn set_static(&mut self) {
		self.periodicity = None;
	}

	pub fn set_periodicity(&mut self, periodicity: NonZeroU64) {
		self.periodicity = Some(periodicity.get());
	}

	pub(crate) fn get_ctx_elems(&self, time_period: Option<u64>) -> Vec<Vec<u8>> {
		let mut ret: Vec<Vec<u8>> = self.ctx.iter().map(|s| s.as_bytes().to_vec()).collect();
		if let Some(tp) = time_period {
			ret.push(tp.to_le_bytes().to_vec());
		}
		ret
	}

	pub(crate) fn get_time_period(&self, timestamp: u64) -> Option<u64> {
		self.periodicity.map(|p| timestamp / p)
	}

	pub(crate) fn is_periodic(&self) -> bool {
		self.periodicity.is_some()
	}
}

impl<const N: usize> From<[&str; N]> for KeyContext {
	fn from(ctx: [&str; N]) -> Self {
		Self {
			ctx: ctx.iter().map(|s| s.to_string()).collect(),
			periodicity: Some(crate::DEFAULT_KEY_CTX_PERIODICITY),
		}
	}
}

pub(crate) fn derive_key(
	ikm: &InputKeyMaterial,
	ctx: &KeyContext,
	time_period: Option<u64>,
) -> Vec<u8> {
	let elems = ctx.get_ctx_elems(time_period);
	let key_context = canonicalize(&elems);
	let kdf = ikm.scheme.get_kdf();
	kdf(&key_context, &ikm.content)
}

#[cfg(test)]
mod tests {
	use crate::ikm::InputKeyMaterial;
	use crate::KeyContext;
	use std::num::NonZeroU64;

	const TEST_RAW_IKM: &[u8] = &[
		0x0a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x7b, 0x85, 0x27, 0xef, 0xf2, 0xbd, 0x58,
		0x9f, 0x6e, 0xb1, 0x7b, 0x71, 0xc3, 0x1e, 0xf6, 0xfd, 0x7f, 0x90, 0xdb, 0xc6, 0x43, 0xea,
		0xe9, 0x9c, 0xa3, 0xb5, 0xee, 0xcc, 0xb6, 0xb6, 0x28, 0x6a, 0xbd, 0xe4, 0xd0, 0x65, 0x00,
		0x00, 0x00, 0x00, 0x3d, 0x82, 0x6f, 0x8b, 0x00, 0x00, 0x00, 0x00, 0x00,
	];

	#[test]
	fn derive_key_no_tp() {
		let ikm = InputKeyMaterial::from_bytes(TEST_RAW_IKM).unwrap();
		let ctx = KeyContext::from(["some", "context"]);
		assert_eq!(
			super::derive_key(&ikm, &ctx, None),
			vec![
				0xc1, 0xd2, 0xf0, 0xa7, 0x4d, 0xc5, 0x32, 0x6e, 0x89, 0x86, 0x85, 0xae, 0x3f, 0xdf,
				0x16, 0x0b, 0xec, 0xe6, 0x63, 0x46, 0x41, 0x8a, 0x28, 0x2b, 0x04, 0xa1, 0x23, 0x20,
				0x36, 0xe3, 0x2f, 0x0a
			]
		);
	}

	#[test]
	fn derive_key_tp_0() {
		let ikm = InputKeyMaterial::from_bytes(TEST_RAW_IKM).unwrap();
		let ctx = KeyContext::from(["some", "context"]);
		assert_eq!(
			super::derive_key(&ikm, &ctx, Some(0)),
			vec![
				0xdc, 0x6c, 0x4b, 0xed, 0xef, 0x31, 0x2a, 0x83, 0x40, 0xc0, 0xee, 0xf4, 0xd7, 0xe5,
				0xec, 0x2e, 0xcf, 0xda, 0x64, 0x0a, 0xb8, 0xb6, 0x89, 0xe4, 0x3c, 0x6e, 0xc2, 0x53,
				0x0e, 0xaa, 0x38, 0x12
			]
		);
	}

	#[test]
	fn derive_key_tp_42() {
		let ikm = InputKeyMaterial::from_bytes(TEST_RAW_IKM).unwrap();
		let ctx = KeyContext::from(["some", "context"]);
		assert_eq!(
			super::derive_key(&ikm, &ctx, Some(42)),
			vec![
				0xc7, 0xfb, 0x96, 0x6a, 0x15, 0xde, 0x5f, 0xfc, 0x66, 0xa6, 0xac, 0xda, 0x6b, 0x8e,
				0xa3, 0x66, 0xd8, 0x70, 0x5b, 0x2f, 0xf9, 0x7f, 0xfb, 0x47, 0xb1, 0xa9, 0x93, 0xfc,
				0xf5, 0x0b, 0x6d, 0x3c
			]
		);
	}

	#[test]
	fn get_time_period() {
		let test_vec = &[
			// (periodicity, timestamp, reference value)
			(1, 0, 0),
			(1, 1, 1),
			(1, 2, 2),
			(1, 35015, 35015),
			(16_777_216, 0, 0),
			(16_777_216, 16_777_215, 0),
			(16_777_216, 16_777_216, 1),
			(16_777_216, 1_709_994_382, 101),
		];
		let mut ctx = KeyContext::from([]);
		for (p, ts, ref_val) in test_vec {
			let p = NonZeroU64::new(*p).unwrap();
			ctx.set_periodicity(p);
			let tp = ctx.get_time_period(*ts);
			assert_eq!(tp, Some(*ref_val));
		}
	}
}
