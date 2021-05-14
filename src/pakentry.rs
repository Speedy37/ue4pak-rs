use crate::{
    archive::{Archivable, Archive, ArchiveLen},
    constant::*,
    PakVersion,
};
use std::io;

pub const FLAG_ENCRYPTED: u8 = 0x01;
pub const FLAG_DELETED: u8 = 0x02;

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct PakEntry {
    /// Offset into pak file where the file is stored.
    pub offset: u64,
    /// Serialized file size.
    pub size: u64,
    /// Uncompressed file size.
    pub uncompressed_size: u64,
    /// Compressed file SHA1 value.
    pub hash: [u8; 20],
    /// Array of compression blocks that describe how to decompress this pak entry.
    pub compression_blocks: Vec<PakCompressedBlock>,
    /// Size of a compressed block in the file.
    pub compression_block_size: u32,
    /// Index into the compression methods in this pakfile.
    pub compression_method_index: u32,
    /// Pak entry flags.
    pub flags: u8,
}

impl PakEntry {
    pub fn is_encrypted(&self) -> bool {
        (self.flags & FLAG_ENCRYPTED) == FLAG_ENCRYPTED
    }

    pub fn is_deleted(&self) -> bool {
        (self.flags & FLAG_DELETED) == FLAG_DELETED
    }

    pub fn ser_de_len(&mut self, version: PakVersion) -> u64 {
        let mut ar = ArchiveLen::new();
        self.ser_de(&mut ar, version).unwrap();
        ar.len()
    }

    pub fn ser_de<A: Archive>(&mut self, ar: &mut A, version: PakVersion) -> io::Result<()> {
        self.offset.ser_de(ar)?;
        self.size.ser_de(ar)?;
        self.uncompressed_size.ser_de(ar)?;
        if version < PakVersion::FNameBasedCompressionMethod422 {
            let mut legacy_compression_method = 0;
            legacy_compression_method.ser_de(ar)?;
            self.compression_method_index = match legacy_compression_method {
                x if x == COMPRESS_NONE => 0,
                x if (x & COMPRESS_ZLIB) > 0 => 1,
                x if (x & COMPRESS_GZIP) > 0 => 2,
                x if (x & COMPRESS_CUSTOM) > 0 => 3,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "unknown legacy compression type",
                    ))
                }
            };
        } else if version == PakVersion::FNameBasedCompressionMethod422 {
            let mut idx = 0u8;
            idx.ser_de(ar)?;
            self.compression_method_index = From::from(idx);
        } else {
            self.compression_method_index.ser_de(ar)?;
        }
        if version <= PakVersion::Initial {
            let mut ticks = 0u64;
            ticks.ser_de(ar)?;
        }

        self.hash.ser_de(ar)?;
        if version >= PakVersion::CompressionEncryption {
            if self.compression_method_index != 0 {
                self.compression_blocks.ser_de(ar)?;
            }
            self.flags.ser_de(ar)?;
            self.compression_block_size.ser_de(ar)?;
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct PakCompressedBlock {
    pub compressed_start: i64,
    pub compressed_end: i64,
}

impl Archivable for PakCompressedBlock {
    fn ser_de<A: Archive>(&mut self, ar: &mut A) -> io::Result<()> {
        self.compressed_start.ser_de(ar)?;
        self.compressed_end.ser_de(ar)?;
        Ok(())
    }
}
