use std::num::NonZeroU64;

macro_rules! data_ctx_from_iter {
	($self: ident, $ctx: ident) => {
		$self {
			ctx: $ctx.iter().map(|s| s.to_string()).collect(),
		}
	};
}

pub struct DataContext {
	ctx: Vec<String>,
}

impl DataContext {
	pub(crate) fn get_ctx_elems(&self) -> &[String] {
		self.ctx.as_ref()
	}
}

impl<const N: usize> From<[&str; N]> for DataContext {
	fn from(ctx: [&str; N]) -> Self {
		data_ctx_from_iter!(Self, ctx)
	}
}

impl<const N: usize> From<&[&str; N]> for DataContext {
	fn from(ctx: &[&str; N]) -> Self {
		data_ctx_from_iter!(Self, ctx)
	}
}

impl From<&[&str]> for DataContext {
	fn from(ctx: &[&str]) -> Self {
		data_ctx_from_iter!(Self, ctx)
	}
}

macro_rules! key_ctx_from_iter {
	($self: ident, $ctx: ident) => {
		$self {
			ctx: $ctx.iter().map(|s| s.to_string()).collect(),
			periodicity: Some(crate::DEFAULT_KEY_CTX_PERIODICITY),
		}
	};
}

pub struct KeyContext {
	pub(crate) ctx: Vec<String>,
	pub(crate) periodicity: Option<u64>,
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
		key_ctx_from_iter!(Self, ctx)
	}
}

impl<const N: usize> From<&[&str; N]> for KeyContext {
	fn from(ctx: &[&str; N]) -> Self {
		key_ctx_from_iter!(Self, ctx)
	}
}

impl From<&[&str]> for KeyContext {
	fn from(ctx: &[&str]) -> Self {
		key_ctx_from_iter!(Self, ctx)
	}
}
