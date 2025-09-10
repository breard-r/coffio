use crate::InputKeyMaterial;
use crate::KeyContext;
use crate::error::{Error, Result};
use std::time::{SystemTime, UNIX_EPOCH};

/// Define the action that will be taken when attempting to decrypt data.
#[derive(Clone, Copy)]
pub enum DecryptionPolicyAction {
	/// Allow decryption.
	Allow,
	/// Deny decryption and emit an error.
	Deny,
	/// Allow decryption and emit a warning.
	Warn,
}

/// Set actions that will be taken when attempting to decrypt data that has previously been
/// encrypted using a now expired or revoked IKM.
#[derive(Clone, Copy)]
pub struct DecryptionPolicy {
	early_enc: DecryptionPolicyAction,
	expired_enc: DecryptionPolicyAction,
	expired_now: DecryptionPolicyAction,
	future_enc: DecryptionPolicyAction,
	revoked: DecryptionPolicyAction,
}

impl DecryptionPolicy {
	/// Enforce the policy on a given IKM.
	pub fn check(
		&self,
		ikm: &InputKeyMaterial,
		key_ctx: &KeyContext,
		time_period: Option<u64>,
	) -> Result<()> {
		process_check(self, ikm, key_ctx, time_period, SystemTime::now())
	}

	/// Set the action for an IKM which has been used before its validity period.
	/// Default value is deny.
	///
	/// Warning: This policy will only work for periodic keys and the check is limited to periods
	/// which are fully outside of the IKM allowed time frame.
	pub fn set_early_enc(&mut self, action: DecryptionPolicyAction) -> &mut Self {
		self.early_enc = action;
		self
	}

	/// Set the action for an IKM which was expired when the encryption took place.
	/// Default value is deny.
	///
	/// Warning: This policy will only work for periodic keys and the check is limited to periods
	/// which are fully outside of the IKM allowed time frame.
	pub fn set_expired_enc(&mut self, action: DecryptionPolicyAction) -> &mut Self {
		self.expired_enc = action;
		self
	}

	/// Set the action for a now expired IKM.
	/// Default value is warn.
	pub fn set_expired_now(&mut self, action: DecryptionPolicyAction) -> &mut Self {
		self.expired_now = action;
		self
	}

	/// Set the action for data previously encrypted using a time period located in the future.
	/// Default value is deny.
	///
	/// Warning: This policy will only work for periodic keys and the check is limited to periods
	/// which are fully outside of the IKM allowed time frame.
	pub fn set_future_enc(&mut self, action: DecryptionPolicyAction) -> &mut Self {
		self.future_enc = action;
		self
	}

	/// Set the action for a revoked IKM.
	/// Default value is warn.
	pub fn set_revoked(&mut self, action: DecryptionPolicyAction) -> &mut Self {
		self.revoked = action;
		self
	}
}

impl Default for DecryptionPolicy {
	fn default() -> Self {
		Self {
			early_enc: DecryptionPolicyAction::Deny,
			expired_enc: DecryptionPolicyAction::Deny,
			expired_now: DecryptionPolicyAction::Warn,
			future_enc: DecryptionPolicyAction::Deny,
			revoked: DecryptionPolicyAction::Warn,
		}
	}
}

macro_rules! policy_match {
	($m: expr, $err: expr) => {
		match $m {
			DecryptionPolicyAction::Allow => {}
			DecryptionPolicyAction::Deny => {
				return Err($err);
			}
			DecryptionPolicyAction::Warn => {
				log::warn!("{}", $err);
			}
		}
	};
}

fn process_check(
	policy: &DecryptionPolicy,
	ikm: &InputKeyMaterial,
	key_ctx: &KeyContext,
	time_period: Option<u64>,
	curr_time: SystemTime,
) -> Result<()> {
	// Check for a revoked IKM
	if ikm.is_revoked() {
		policy_match!(policy.revoked, Error::PolicyDecryptionRevoked);
	}

	// Check for a now expired IKM
	if curr_time > ikm.get_not_after() {
		policy_match!(policy.expired_now, Error::PolicyDecryptionExpiredNow);
	}

	// Checks depending on the encryption time period.
	if let Some(tp) = time_period {
		// Check for an expired IKM at encryption
		let max_ts = ikm.get_not_after().duration_since(UNIX_EPOCH)?.as_secs();
		if let Some(max_tp) = key_ctx.get_time_period(max_ts)
			&& tp > max_tp
		{
			policy_match!(policy.expired_enc, Error::PolicyDecryptionExpiredEnc);
		}

		// Check for an encryption before the IKM validity
		let min_ts = ikm.get_not_before().duration_since(UNIX_EPOCH)?.as_secs();
		if let Some(min_tp) = key_ctx.get_time_period(min_ts)
			&& tp < min_tp
		{
			policy_match!(policy.early_enc, Error::PolicyDecryptionEarly);
		}

		// Check for an encryption in the future
		let curr_ts = curr_time.duration_since(UNIX_EPOCH)?.as_secs();
		if let Some(max_tp) = key_ctx.get_time_period(curr_ts)
			&& tp > max_tp
		{
			policy_match!(policy.future_enc, Error::PolicyDecryptionFuture);
		}
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{InputKeyMaterial, Scheme};
	use std::num::NonZeroU64;
	use std::time::Duration;

	fn get_ikm() -> InputKeyMaterial {
		#[cfg(feature = "chacha")]
		let scheme = Scheme::XChaCha20Poly1305WithBlake3;
		#[cfg(not(feature = "chacha"))]
		let scheme = Scheme::Aes128GcmWithSha256;

		InputKeyMaterial {
			id: 42,
			scheme,
			content: Vec::new(),
			not_before: UNIX_EPOCH + Duration::from_secs(1_680_321_720),
			not_after: UNIX_EPOCH + Duration::from_secs(1_696_132_920),
			is_revoked: false,
		}
	}

	fn get_ctx() -> KeyContext {
		let mut ctx: KeyContext = ["test"].into();
		ctx.set_periodicity(NonZeroU64::new(7_776_000).unwrap());
		ctx
	}

	#[test]
	fn ikm_ok() {
		let policy = DecryptionPolicy::default();
		let ikm = get_ikm();
		let ctx = get_ctx();
		let now = UNIX_EPOCH + Duration::from_secs(1_686_377_340);
		let res = process_check(&policy, &ikm, &ctx, None, now);
		assert!(res.is_ok(), "failed without time period: {res:?}");
		let res = process_check(&policy, &ikm, &ctx, Some(216), now);
		assert!(res.is_ok(), "failed with time period: {res:?}");
		let now = UNIX_EPOCH + Duration::from_secs(1_696_132_020);
		let res = process_check(&policy, &ikm, &ctx, Some(218), now);
		assert!(res.is_ok(), "failed with time period: {res:?}");
	}

	#[test]
	fn ikm_revoked() {
		let mut policy = DecryptionPolicy::default();
		policy.set_revoked(DecryptionPolicyAction::Deny);
		let mut ikm = get_ikm();
		ikm.is_revoked = true;
		let ctx = get_ctx();
		let now = UNIX_EPOCH + Duration::from_secs(1_686_377_340);
		let res = process_check(&policy, &ikm, &ctx, None, now);
		assert_eq!(
			res,
			Err(Error::PolicyDecryptionRevoked),
			"failed with time period: {res:?}"
		);
		let res = process_check(&policy, &ikm, &ctx, Some(216), now);
		assert_eq!(
			res,
			Err(Error::PolicyDecryptionRevoked),
			"failed with time period: {res:?}"
		);
	}

	#[test]
	fn ikm_expired_now() {
		let mut policy = DecryptionPolicy::default();
		policy.set_expired_now(DecryptionPolicyAction::Deny);
		let ikm = get_ikm();
		let ctx = get_ctx();
		let now = UNIX_EPOCH + Duration::from_secs(1_757_525_359);
		let res = process_check(&policy, &ikm, &ctx, None, now);
		assert_eq!(
			res,
			Err(Error::PolicyDecryptionExpiredNow),
			"failed with time period: {res:?}"
		);
		let res = process_check(&policy, &ikm, &ctx, Some(216), now);
		assert_eq!(
			res,
			Err(Error::PolicyDecryptionExpiredNow),
			"failed with time period: {res:?}"
		);
	}

	#[test]
	fn ikm_expired_enc() {
		let policy = DecryptionPolicy::default();
		let ikm = get_ikm();
		let ctx = get_ctx();
		let now = UNIX_EPOCH + Duration::from_secs(1_757_525_359);
		let res = process_check(&policy, &ikm, &ctx, None, now);
		assert!(res.is_ok(), "failed without time period: {res:?}");
		let res = process_check(&policy, &ikm, &ctx, Some(218), now);
		assert!(res.is_ok(), "failed without time period: {res:?}");
		let res = process_check(&policy, &ikm, &ctx, Some(219), now);
		assert_eq!(
			res,
			Err(Error::PolicyDecryptionExpiredEnc),
			"failed with time period: {res:?}"
		);
	}
	#[test]
	fn ikm_early_enc() {
		let policy = DecryptionPolicy::default();
		let ikm = get_ikm();
		let ctx = get_ctx();
		let now = UNIX_EPOCH + Duration::from_secs(1_686_377_340);
		let res = process_check(&policy, &ikm, &ctx, None, now);
		assert!(res.is_ok(), "failed without time period: {res:?}");
		let res = process_check(&policy, &ikm, &ctx, Some(215), now);
		assert_eq!(
			res,
			Err(Error::PolicyDecryptionEarly),
			"failed with time period: {res:?}"
		);
	}

	#[test]
	fn future_enc() {
		// FIXME
		let policy = DecryptionPolicy::default();
		let ikm = get_ikm();
		let ctx = get_ctx();
		let now = UNIX_EPOCH + Duration::from_secs(1_680_321_821);
		let res = process_check(&policy, &ikm, &ctx, None, now);
		assert!(res.is_ok(), "failed without time period: {res:?}");
		let res = process_check(&policy, &ikm, &ctx, Some(217), now);
		assert_eq!(
			res,
			Err(Error::PolicyDecryptionFuture),
			"failed with time period: {res:?}"
		);
	}
}
