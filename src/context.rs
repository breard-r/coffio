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

/// The context in which a key is used.
///
/// A good practice is to use a different encryption keys for each kind of data you wish to
/// encrypt. For instance, when encrypting fields in a database, you might want to use a different
/// key for each table, or maybe for each column. It is your responsibility to define the
/// granularity. Considering the key are automatically derived from the [InputKeyMaterial][crate::InputKeyMaterial] (IKM),
/// you should go for a high granularity.
///
/// In order to achieve this, coffio uses the concept of [KeyContext]. The main component of this
/// struct is an array of strings which represents the context in which a key is derived, which
/// means that an IKM will derive different keys if this context is different. Therefore, in order
/// to derive a different key for each column of your database, you should use a key context
/// composed of at least 3 elements: the database name, the table name and the column name.
///
/// ```
/// use coffio::KeyContext;
///
/// let my_key_ctx: KeyContext = [
///     "db name",
///     "table name",
///     "column name",
/// ].into();
/// ```
///
/// As shown in the above example, it is highly recommended to use a separated array elements and
/// let coffio concatenate them in a safe way. Not doing so may result in canonicalization issues
/// and therefore the use of the same context (and encryption key) for different use cases.
///
/// Another element of context can be the date and time of the encryption. To achieve this, coffio allows to set a key periodicity. In this concept, the time is divided in periods of a defined length and a different encryption key will be generated for each of those periods. Therefore, the lower is the period, the more frequently the encryption key will change.
///
/// The default period is set to the value of [DEFAULT_KEY_CTX_PERIODICITY][crate::DEFAULT_KEY_CTX_PERIODICITY].
///
/// In order to be able to derive the correct decryption key, the key period is stored along with the encrypted data. An attacker having access to the encrypted data would therefore be able to know the time period when the data has been encrypted.
pub struct KeyContext {
	pub(crate) ctx: Vec<String>,
	pub(crate) periodicity: Option<u64>,
}

impl KeyContext {
	/// Removes the key periodicity. Derived keys will not depend on the time when the encryption
	/// occurred. In this mode, the time period is not stored along with the encrypted data.
	///
	/// ```
	/// use coffio::KeyContext;
	///
	/// let mut my_key_ctx: KeyContext = [
	///     "db name",
	///     "table name",
	///     "column name",
	/// ].into();
	/// my_key_ctx.set_static();
	/// ```
	pub fn set_static(&mut self) {
		self.periodicity = None;
	}

	/// Set a custom key periodicity. The value is specified in seconds.
	///
	/// ```
	/// use coffio::KeyContext;
	/// use std::num::NonZeroU64;
	///
	/// let mut my_key_ctx: KeyContext = [
	///     "db name",
	///     "table name",
	///     "column name",
	/// ].into();
	/// if let Some(period) = NonZeroU64::new(31_556_925) {
	///     my_key_ctx.set_periodicity(period);
	/// }
	/// ```
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
