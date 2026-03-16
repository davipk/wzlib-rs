// ── Validation limits ────────────────────────────────────────────────
pub const MAX_WZ_STRING_LEN: usize = 1024 * 1024;
pub const MAX_PROPERTY_COUNT: i32 = 500_000;
pub const MAX_DIRECTORY_ENTRIES: i32 = 100_000;
pub const MAX_CONVEX_POINTS: i32 = 100_000;

// ── String encoding masks ───────────────────────────────────────────
pub const WZ_UNICODE_MASK_INIT: u16 = 0xAAAA;
pub const WZ_ASCII_MASK_INIT: u8 = 0xAA;

// ── Extended property type strings ──────────────────────────────────
pub const WZ_TYPE_PROPERTY: &str = "Property";
pub const WZ_TYPE_CANVAS: &str = "Canvas";
pub const WZ_TYPE_VECTOR: &str = "Shape2D#Vector2D";
pub const WZ_TYPE_CONVEX: &str = "Shape2D#Convex2D";
pub const WZ_TYPE_SOUND: &str = "Sound_DX8";
pub const WZ_TYPE_UOL: &str = "UOL";
pub const WZ_TYPE_RAW_DATA: &str = "RawData";
pub const WZ_TYPE_VIDEO: &str = "Canvas#Video";

pub mod binary_reader;
pub mod binary_writer;
pub mod directory;
pub mod error;
pub mod file;
pub mod header;
pub mod image;
pub mod image_writer;
pub mod keys;
pub mod list_file;
pub mod mcv;
pub mod ms_file;
pub mod properties;
pub mod types;

#[cfg(test)]
pub(crate) mod test_utils;
