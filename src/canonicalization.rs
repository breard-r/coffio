use base64ct::{Base64UrlUnpadded, Encoding};

const CANONICALIZATION_BUFFER_SIZE: usize = 1024;
const CANONICALIZATION_SEPARATOR: &str = ":";

#[inline]
pub(crate) fn join_canonicalized_str(elems: &[String]) -> String {
	elems.join(CANONICALIZATION_SEPARATOR)
}

pub(crate) fn canonicalize(context: &[impl AsRef<[u8]>]) -> String {
	match context.len() {
		0 => String::new(),
		1 => Base64UrlUnpadded::encode_string(context[0].as_ref()),
		_ => {
			let mut ret = String::with_capacity(CANONICALIZATION_BUFFER_SIZE);
			for (i, ctx_elem) in context.iter().enumerate() {
				if i != 0 {
					ret += CANONICALIZATION_SEPARATOR;
				}
				ret += &Base64UrlUnpadded::encode_string(ctx_elem.as_ref());
			}
			ret
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const EMPTY_CTX: &[[u8; 0]] = &[];

	#[test]
	fn canonicalize_empty() {
		let canon = canonicalize(EMPTY_CTX);
		assert_eq!(canon, String::new());
	}

	#[test]
	fn canonicalize_one() {
		let canon = canonicalize(&["test"]);
		assert_eq!(&canon, "dGVzdA");
	}

	#[test]
	fn canonicalize_many() {
		let canon = canonicalize(&["test", "bis", "ter", ""]);
		assert_eq!(&canon, "dGVzdA:Ymlz:dGVy:");
	}

	#[test]
	fn test_join_canonicalized_empty() {
		assert_eq!(join_canonicalized_str(&[]), "");
	}

	#[test]
	fn test_join_canonicalized_one() {
		assert_eq!(
			join_canonicalized_str(&["QWO7RGDt".to_string()]),
			"QWO7RGDt"
		);
	}

	#[test]
	fn test_join_canonicalized_one_empty() {
		assert_eq!(join_canonicalized_str(&[String::new()]), "");
	}

	#[test]
	fn test_join_canonicalized_empty_str() {
		assert_eq!(join_canonicalized_str(&[String::new(), String::new()]), ":");
	}

	#[test]
	fn test_join_canonicalized_with_data() {
		assert_eq!(
			join_canonicalized_str(&["QWO7RGDt:f-JmDPvU".into(), "_Sfx61Fp".into()]),
			"QWO7RGDt:f-JmDPvU:_Sfx61Fp"
		);
	}
}
