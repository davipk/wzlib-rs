pub mod crypto;
pub mod image;
pub mod wz;

#[cfg(feature = "wasm")]
mod wasm_api;

pub use image::encode::{compress_png_data, encode_pixels};
pub use image::{decode_pixels, decompress_png_data};
pub use wz::binary_reader::WzBinaryReader;
pub use wz::binary_writer::WzBinaryWriter;
pub use wz::directory::{WzDirectoryEntry, WzImageEntry};
pub use wz::error::WzError;
pub use wz::file::{
    detect_file_type, parse_hotfix_data_wz, parse_hotfix_data_wz_with_user_key,
    save_hotfix_data_wz, save_hotfix_data_wz_with_user_key, WzFile, WzFileType,
};
pub use wz::header::WzHeader;
pub use wz::image::parse_image as parse_wz_image;
pub use wz::keys::WzKey;
pub use wz::list_file::{
    parse_list_file, parse_list_file_with_iv, parse_list_file_with_iv_and_user_key,
};
pub use wz::ms_file::{
    build_ms_file, decrypt_entry_data, encrypt_entry_data, parse_ms_file, MsEntry, MsParsedFile,
    MsSaveEntry, MsVersion,
};
pub use wz::properties::WzProperty;
pub use wz::types::WzMapleVersion;
pub use wz::types::WzPngFormat;
