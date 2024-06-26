pub const MEASUREMENT_TIME: u64 = 30;
pub const KEY_CTX: &[&str] = &["database_name", "table_name", "column_name"];
pub const DATA_CTX: &[&str] = &[
	"b3b21eb1-70d7-4dc6-9a2a-439e17d8491d",
	"8dfa06bc-de19-455a-8e43-2f5d8019442f",
];
// created_at: Sunday 21 February 2021 10:21:42
// expire_at: Thursday 10 February 2180 10:21:42
// is_revoked: false
pub const IKML_AES128GCM_SHA256: &str =
	"ikml-v1:AQAAAA:AQAAAAIAAAAAsPHG8Eyb8uZBAUUyUuxIRdQ5mIO1v1QDBhWOzbCRvzY0MmAAAAAANsk0iwEAAAAA";
// created_at: Sunday 21 February 2021 10:21:42
// expire_at: Thursday 10 February 2180 10:21:42
// is_revoked: false
pub const IKML_XCHACHA20POLY1305_BLAKE3: &str =
	"ikml-v1:AQAAAA:AwAAAAEAAAAMoNIW9gIGkzegUDEsU3N1Rf_Zz0OMuylUSiQjUzLXqzY0MmAAAAAANsk0iwEAAAAA";
pub const IKMLS: &[(&str, &str)] = &[
	("Aes128GcmWithSha256", IKML_AES128GCM_SHA256),
	("XChaCha20Poly1305WithBlake3", IKML_XCHACHA20POLY1305_BLAKE3),
];
pub const PLAIN_INPUTS: &[(&str, &str)] = &[
	("01 - 12 B", include_str!("data/plain_01_xs.txt")),
	("02 - 60 B", include_str!("data/plain_02_s.txt")),
	("03 - 500 B", include_str!("data/plain_03_m.txt")),
	("04 - 3 KB", include_str!("data/plain_04_l.txt")),
	("05 - 1 MB", include_str!("data/plain_05_xl.txt")),
];
pub const ENCRYPTED_INPUTS: &[(&str, &str, &str)] = &[
	(
		"01 - 12 B",
		include_str!("data/aes128gcm-sha256_01_xs.txt"),
		include_str!("data/xchacha20poly1305-blake3_01_xs.txt"),
	),
	(
		"02 - 60 B",
		include_str!("data/aes128gcm-sha256_02_s.txt"),
		include_str!("data/xchacha20poly1305-blake3_02_s.txt"),
	),
	(
		"03 - 500 B",
		include_str!("data/aes128gcm-sha256_03_m.txt"),
		include_str!("data/xchacha20poly1305-blake3_03_m.txt"),
	),
	(
		"04 - 3 KB",
		include_str!("data/aes128gcm-sha256_04_l.txt"),
		include_str!("data/xchacha20poly1305-blake3_04_l.txt"),
	),
	(
		"05 - 1 MB",
		include_str!("data/aes128gcm-sha256_05_xl.txt"),
		include_str!("data/xchacha20poly1305-blake3_05_xl.txt"),
	),
];

pub struct Data<'a> {
	pub ikml: &'a str,
	pub input: &'a str,
}
