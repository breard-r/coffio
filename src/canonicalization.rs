use base64ct::{Base64UrlUnpadded, Encoding};

const CANONICALIZATION_BUFFER_SIZE: usize = 1024;
const CANONICALIZATION_SEPARATOR: &str = ":";

pub(crate) fn canonicalize(key_context: &[&str]) -> String {
	match key_context.len() {
		0 => String::new(),
		1 => key_context[0].to_string(),
		_ => {
			let mut ret = String::with_capacity(CANONICALIZATION_BUFFER_SIZE);
			for (i, ctx_elem) in key_context.iter().enumerate() {
				if i != 0 {
					ret += CANONICALIZATION_SEPARATOR;
				}
				ret += &Base64UrlUnpadded::encode_string(ctx_elem.as_bytes());
			}
			ret
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn canonicalize_empty() {
		let canon = canonicalize(&[]);
		assert_eq!(canon, String::new());
	}

	#[test]
	fn canonicalize_one() {
		let canon = canonicalize(&["test"]);
		assert_eq!(&canon, "test");
	}

	#[test]
	fn canonicalize_many() {
		let canon = canonicalize(&["test", "bis", "ter", ""]);
		assert_eq!(&canon, "dGVzdA:Ymlz:dGVy:");
	}
}
