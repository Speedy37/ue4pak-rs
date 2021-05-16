/// Raw FArchive tools
pub mod archive;
mod pakbuilder;
mod pakentry;
mod pakfile;
mod pakindex;
mod pakindexv1;
mod pakindexv2;
mod pakinfo;

use std::{fmt, io};

use aes::cipher::generic_array::GenericArray;
use aes::{Aes256, BlockCipher, NewBlockCipher};
use block_modes::block_padding::NoPadding;
use block_modes::{BlockMode, Ecb};
pub use pakbuilder::{AssetWriter, PakFileBuilder};
pub use pakentry::{PakCompressedBlock, PakEntry};
pub use pakfile::PakFile;
pub use pakindex::PakIndex;
pub use pakindexv1::PakIndexV1;
pub use pakindexv2::PakIndexV2;
pub use pakinfo::PakInfo;
use sha1::digest::generic_array::typenum::Unsigned;

type Aes256KeySize = <Aes256 as NewBlockCipher>::KeySize;
type Aes256BlockSize = <Aes256 as BlockCipher>::BlockSize;
type Aes256Key = GenericArray<u8, Aes256KeySize>;
type Aes256Cipher = Ecb<Aes256, NoPadding>;

fn aes256_base64_key(key: &str) -> io::Result<Aes256Key> {
    let key = base64::decode(key).map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
    if key.len() != Aes256KeySize::USIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "invalid base64 key size, found a {} bytes key, expecting a {} bytes key",
                key.len(),
                Aes256KeySize::USIZE
            ),
        ));
    }
    Ok(Aes256Key::from_slice(&key).clone())
}

fn aes256_ecb_cipher(key: &Aes256Key) -> Aes256Cipher {
    Ecb::<Aes256, NoPadding>::new_fix(key, &Default::default())
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum PakVersion {
    Initial,
    NoTimestamps,
    CompressionEncryption,
    IndexEncryption,
    RelativeChunkOffsets,
    DeleteRecords,
    EncryptionKeyGuid,
    /// in 4.22:
    /// - MAX_NUM_COMPRESSION_METHODS was 4 but since 4.23 it is 5
    FNameBasedCompressionMethod422,
    FNameBasedCompressionMethod,
    FrozenIndex,
    PathHashIndex,
    Fnv64BugFix,
}

impl fmt::Display for PakVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}",
            self.raw(),
            if *self == PakVersion::FNameBasedCompressionMethod422 {
                " with 4.22 workaround"
            } else {
                ""
            }
        )
    }
}

impl PakVersion {
    pub fn list() -> &'static [Self] {
        &[
            PakVersion::Initial,
            PakVersion::NoTimestamps,
            PakVersion::CompressionEncryption,
            PakVersion::IndexEncryption,
            PakVersion::RelativeChunkOffsets,
            PakVersion::DeleteRecords,
            PakVersion::EncryptionKeyGuid,
            PakVersion::FNameBasedCompressionMethod422,
            PakVersion::FNameBasedCompressionMethod,
            PakVersion::FrozenIndex,
            PakVersion::PathHashIndex,
            PakVersion::Fnv64BugFix,
        ]
    }

    pub fn raw(self) -> i32 {
        match self {
            PakVersion::Initial => 1,
            PakVersion::NoTimestamps => 2,
            PakVersion::CompressionEncryption => 3,
            PakVersion::IndexEncryption => 4,
            PakVersion::RelativeChunkOffsets => 5,
            PakVersion::DeleteRecords => 6,
            PakVersion::EncryptionKeyGuid => 7,
            PakVersion::FNameBasedCompressionMethod422 => 8,
            PakVersion::FNameBasedCompressionMethod => 8,
            PakVersion::FrozenIndex => 9,
            PakVersion::PathHashIndex => 10,
            PakVersion::Fnv64BugFix => 11,
        }
    }
}

pub mod constants {

    /// Magic number to use in header
    pub const PAK_FILE_MAGIC: u32 = 0x5A6F12E1;
    /// Size of cached data.
    pub const MAX_CHUNK_DATA_SIZE: usize = 64 * 1024;
    /// Length of a compression format name
    pub const COMPRESSION_METHOD_NAME_LEN: usize = 32;
    /// Number of allowed different methods
    pub const MAX_NUM_COMPRESSION_METHODS: usize = 5; // when we remove patchcompatibilitymode421 we can reduce this to 4

    /// No compression
    pub const COMPRESS_NONE: i32 = 0x00;
    /// Compress with ZLIB - DEPRECATED, USE FNAME
    pub const COMPRESS_ZLIB: i32 = 0x01;
    /// Compress with GZIP - DEPRECATED, USE FNAME
    pub const COMPRESS_GZIP: i32 = 0x02;
    /// Compress with user defined callbacks - DEPRECATED, USE FNAME
    pub const COMPRESS_CUSTOM: i32 = 0x04;
    /// Joint of the previous ones to determine if old flags are being used
    pub const COMPRESS_DEPRECATED_FORMAT_FLAGS_MASK: i32 = 0xF;

    /// No flags specified /
    pub const COMPRESS_NO_FLAGS: i32 = 0x00;
    /// Prefer compression that compresses smaller (ONLY VALID FOR COMPRESSION)
    pub const COMPRESS_BIAS_MEMORY: i32 = 0x10;
    /// Prefer compression that compresses faster (ONLY VALID FOR COMPRESSION)
    pub const COMPRESS_BIAS_SPEED: i32 = 0x20;
    /// Is the source buffer padded out (ONLY VALID FOR UNCOMPRESS)
    pub const COMPRESS_SOURCE_IS_PADDED: i32 = 0x80;

    /// Set of flags that are options are still allowed
    pub const COMPRESS_OPTIONS_FLAGS_MASK: i32 = 0xF0;
}
