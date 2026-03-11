use std::fmt;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaType {
    Text,
    Image,
    File,
    Other,
}

impl fmt::Display for MediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MediaType::Text => write!(f, "text"),
            MediaType::Image => write!(f, "image"),
            MediaType::File => write!(f, "file"),
            MediaType::Other => write!(f, "other"),
        }
    }
}

impl std::str::FromStr for MediaType {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<MediaType, ()> {
        match s {
            "text" => Ok(MediaType::Text),
            "image" => Ok(MediaType::Image),
            "file" => Ok(MediaType::File),
            "other" => Ok(MediaType::Other),
            _ => Err(()),
        }
    }
}

/// Encrypted entry stored in DB (metadata only, no content).
#[derive(Debug, Clone)]
pub struct Entry {
    pub id: i64,
    pub timestamp: String,
    pub media_type: MediaType,
    pub preview: String,
    pub byte_size: i64,
    pub source_app: Option<String>,
}

/// Full encrypted entry including ciphertext and nonce.
#[derive(Debug, Clone)]
pub struct EncryptedEntry {
    pub id: i64,
    pub timestamp: String,
    pub content: Vec<u8>,
    pub nonce: Vec<u8>,
    pub media_type: MediaType,
    pub preview: String,
    pub byte_size: i64,
    pub source_app: Option<String>,
}

/// Decrypted entry with zeroizing plaintext.
pub struct DecryptedEntry {
    pub id: i64,
    pub timestamp: String,
    pub data: Zeroizing<Vec<u8>>,
    pub media_type: MediaType,
    pub preview: String,
    pub source_app: Option<String>,
}
