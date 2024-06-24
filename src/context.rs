use std::num::NonZeroU64;

macro_rules! data_ctx_from_iter {
	($self: ident, $ctx: ident) => {
		$self {
			ctx: $ctx.iter().map(|s| s.to_string()).collect(),
		}
	};
}

/// The context in which some data is encrypted.
///
/// The main purpose of encrypting data before storing it in the database is to preserve data
/// confidentiality even if an attacker gains access to the database. In order to check whether or
/// not the encryption is efficient, we must therefore consider the database as compromised. A
/// typical scenario is to have an application that encrypts data given by the user before storing
/// it and decrypts it before displaying it back to the user. In this scenario, an user should
/// access its own data only.
///
/// In such a scenario, if the application does not include adequate protections, an attacker
/// having access to the database and having a legitimate user account can trick the application
/// into decrypting and displaying the data of other users. This can be done in several ways. A
/// first way of doing it, is by copying and pasting the victim's encrypted data, at cell level,
/// into the attacker's own data cell. A second way of doing it is for the attacker to edit the
/// list of users having access to the victim's data by adding himself. There may be others way to
/// edit the database in such a way that the application is tricked into thinking the attacker's
/// user account has a legitimate access to the victim's data. This is one of the many forms of the
/// [confused deputy problem](https://en.wikipedia.org/wiki/Confused_deputy_problem).
///
/// In order to solve this vulnerability, a solution is to use additional authenticated data (AAD)
/// which is a feature commonly provided by modern authenticated encryption schemes. Such a feature
/// allows, on encryption, to provide some data that will be used during the computation of the
/// encrypted data's checksum. The exact same AAD must be given upon decryption, otherwise the
/// checksum will be invalid and the decryption process will not take place, resulting in an error.
/// To use this feature to solve the confused deputy problem, you must therefore use the
/// appropriate data in the AAD, which Coffio presents you under the name of DataContext.
///
/// <div class="warning">
/// The ADD, and therefore the DataContext, cannot replace the secret encryption key. If the
/// encrypted data and the encryption key has leaked, an attacker can use a modified version of a
/// cryptographic library to decrypt the data even without having access to the AAD.
/// </div>
///
/// The choice of the data that should be set as DataContext is crucial and depends on how your
/// application works. Please carefully study how your application may be abused before deciding
/// which data will be used. This step may require professional advice from your cryptographer. The
/// most common data used in the DataContext are the encrypted data's row ID as well as the access
/// list.
///
/// <div class="warning">
/// If some data used in the DataContext changes, you have to decrypt the encrypted data before
/// changing it and then re-encrypt it. Failing to do so will result in an error when trying to
/// decrypt the data.
/// </div>
///
/// <div class="warning">
/// The concatenation of the different data parts used in the DataContext may lead to weaknesses if
/// done in a naive way. Coffio does concatenate the different parts in a safe way, which is why
/// you should always give as an array of individual parts instead of a single element.
/// </div>
///
/// # Examples
///
/// ```
/// use coffio::DataContext;
///
/// let my_data_ctx: DataContext = [
///     "0a13e260-6d77-4748-ac53-fd7961a513a1", // row's ID
///     "2b84ecf4-5697-40df-a4cd-627fdccfd09d", // owner's ID
/// ].into();
/// ```
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
/// granularity. Considering the key are automatically derived from the
/// [InputKeyMaterial][crate::InputKeyMaterial] (IKM), you should go for a high granularity.
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
/// Another element of context can be the date and time of the encryption. To achieve this, coffio
/// allows to set a key periodicity. In this concept, the time is divided in periods of a defined
/// length and a different encryption key will be generated for each of those periods. Therefore,
/// the lower is the period, the more frequently the encryption key will change.
///
/// The default period is set to the value of
/// [DEFAULT_KEY_CTX_PERIODICITY][crate::DEFAULT_KEY_CTX_PERIODICITY].
///
/// In order to be able to derive the correct decryption key, the key period is stored along with
/// the encrypted data. An attacker having access to the encrypted data would therefore be able to
/// know the time period when the data has been encrypted.
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
