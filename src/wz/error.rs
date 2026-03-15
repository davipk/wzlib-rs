//! Error types for WZ parsing.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum WzError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid WZ header: expected 'PKG1', got {0:?}")]
    InvalidHeader(String),

    #[error("Invalid WZ version: {0}")]
    InvalidVersion(String),

    #[error("Unknown directory entry type: {0}")]
    UnknownDirectoryType(u8),

    #[error("Unknown property type: {0}")]
    UnknownPropertyType(String),

    #[error("Decompression failed: {0}")]
    DecompressionFailed(String),

    #[error("Unsupported PNG format: {0}")]
    UnsupportedPngFormat(u32),

    #[error("Invalid image header byte: 0x{0:02X}")]
    InvalidImageHeader(u8),

    #[error("Unexpected end of data")]
    UnexpectedEof,

    #[error("{0}")]
    Custom(String),
}

pub type WzResult<T> = Result<T, WzError>;
