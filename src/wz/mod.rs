// ── Validation limits ────────────────────────────────────────────────
pub const MAX_WZ_STRING_LEN: usize = 1024 * 1024;
pub const MAX_PROPERTY_COUNT: i32 = 500_000;
pub const MAX_DIRECTORY_ENTRIES: i32 = 100_000;
pub const MAX_CONVEX_POINTS: i32 = 100_000;

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
