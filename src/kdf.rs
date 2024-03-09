use crate::canonicalization::canonicalize;
use crate::ikm::InputKeyMaterial;

pub(crate) type KdfFunction = dyn Fn(&str, &[u8]) -> Vec<u8>;

pub struct KeyContext {
	ctx: Vec<String>,
	periodicity: Option<u64>,
}

impl KeyContext {
	pub fn set_static(&mut self) {
		self.periodicity = None;
	}

	pub fn set_periodicity(&mut self, periodicity: u64) {
		self.periodicity = Some(periodicity);
	}

	pub(crate) fn get_value(&self, time_period: Option<u64>) -> Vec<Vec<u8>> {
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
	let key_context = canonicalize(&ctx.get_value(time_period));
	let kdf = ikm.scheme.get_kdf();
	kdf(&key_context, &ikm.content)
}

#[cfg(test)]
mod tests {
	use crate::ikm::InputKeyMaterial;
	use crate::KeyContext;

	#[test]
	fn derive_key() {
		let ikm_raw = [
			0x0a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x7b, 0x85, 0x27, 0xef, 0xf2, 0xbd,
			0x58, 0x9f, 0x6e, 0xb1, 0x7b, 0x71, 0xc3, 0x1e, 0xf6, 0xfd, 0x7f, 0x90, 0xdb, 0xc6,
			0x43, 0xea, 0xe9, 0x9c, 0xa3, 0xb5, 0xee, 0xcc, 0xb6, 0xb6, 0x28, 0x6a, 0xbd, 0xe4,
			0xd0, 0x65, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x82, 0x6f, 0x8b, 0x00, 0x00, 0x00, 0x00,
			0x00,
		];
		let ikm = InputKeyMaterial::from_bytes(&ikm_raw).unwrap();

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
}
