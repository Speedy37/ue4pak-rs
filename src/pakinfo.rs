use std::io;

use crate::{
    archive::{Archivable, Archive},
    constant::*,
    PakVersion,
};

#[derive(Debug, Clone)]
pub struct PakInfo {
    /// Pak file magic value.
    pub magic: u32,
    /// Pak file version.
    pub version: PakVersion,
    /// Offset to pak file index.
    pub index_offset: u64,
    /// Size (in bytes) of pak file index.
    pub index_size: u64,
    /// Index SHA1 value.
    pub hash: [u8; 20],
    /// Flag indicating if the pak index has been encrypted.
    pub encrypted_index: bool,
    /// Flag indicating if the pak index has been frozen
    /// @todo loadtime: we should find a way to unload the index - potentially make two indices, the full one and unloaded one? unclear how, but at least we now have an option to choose per-platform
    pub index_is_frozen: bool,
    /// Encryption key guid. Empty if we should use the embedded key.
    pub encryption_key_guid: [u32; 4],
    /// Compression methods used in this pak file (FNames, saved as FStrings)
    pub compression_methods: Vec<String>,
}

impl Default for PakInfo {
    fn default() -> Self {
        Self {
            magic: PAK_FILE_MAGIC,
            version: PakVersion::Initial,
            index_offset: 0,
            index_size: 0,
            hash: [0; 20],
            encrypted_index: false,
            index_is_frozen: false,
            encryption_key_guid: [0; 4],
            compression_methods: vec![String::new()],
        }
    }
}

impl PakInfo {
    pub fn new(version: PakVersion) -> Self {
        Self {
            version,
            ..Default::default()
        }
    }
}

impl Archivable for PakInfo {
    fn ser_de<A: Archive>(&mut self, ar: &mut A) -> io::Result<()> {
        let version = self.version;
        if version >= PakVersion::EncryptionKeyGuid {
            self.encryption_key_guid.ser_de(ar)?;
        }

        self.encrypted_index.ser_de(ar)?;
        self.magic.ser_de(ar)?;
        if self.magic != PAK_FILE_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("magic {:x} is not {:x}", self.magic, PAK_FILE_MAGIC),
            ));
        }

        let mut version = self.version.raw();
        version.ser_de(ar)?;
        if version != self.version.raw() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("magic {:x} is not {:x}", self.magic, PAK_FILE_MAGIC),
            ));
        }

        self.index_offset.ser_de(ar)?;
        self.index_size.ser_de(ar)?;
        self.hash.ser_de(ar)?;

        if ar.is_loading() {
            if self.version < PakVersion::IndexEncryption {
                self.encrypted_index = false;
            }

            if self.version < PakVersion::EncryptionKeyGuid {
                self.encryption_key_guid = Default::default(); // [0, 0, 0, 0]
            }
        }

        if self.version >= PakVersion::FrozenIndex {
            self.index_is_frozen.ser_de(ar)?;
        }

        if self.version < PakVersion::FNameBasedCompressionMethod422 {
            self.compression_methods.push("Zlib".to_string());
            self.compression_methods.push("Gzip".to_string());
            self.compression_methods.push("Oodle".to_string());
        } else {
            const LEN: usize = COMPRESSION_METHOD_NAME_LEN * MAX_NUM_COMPRESSION_METHODS;
            let mut buffer = &mut [0u8; LEN][..];
            if self.version == PakVersion::FNameBasedCompressionMethod422 {
                buffer = &mut buffer[..LEN - COMPRESSION_METHOD_NAME_LEN];
            }

            if ar.is_loading() {
                buffer.ser_de(ar)?;
                let mut i = 0;
                while i < buffer.len() {
                    let pos = i;
                    i += COMPRESSION_METHOD_NAME_LEN;
                    let cstr = &buffer[pos..i];
                    let compression_method = std::str::from_utf8(cstr)
                        .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?
                        .trim_end_matches('\0')
                        .to_string();
                    self.compression_methods.push(compression_method);
                }
            } else {
                for (i, compression_method) in self.compression_methods[1..].iter().enumerate() {
                    compression_method.as_bytes();
                    let pos = i * COMPRESSION_METHOD_NAME_LEN;
                    buffer[pos..].copy_from_slice(compression_method.as_bytes());
                }
                buffer.ser_de(ar)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::archive::{ArchiveReader, ArchiveWriter};

    fn read(version: PakVersion, ro: &[u8]) -> PakInfo {
        let mut pakinfo = PakInfo::new(version);
        let cursor = Cursor::new(ro.to_vec());
        let mut ar = ArchiveReader(cursor);
        pakinfo.ser_de(&mut ar).expect("deserialize to work");
        pakinfo
    }

    fn write(mut pakinfo: PakInfo, len: usize) -> Vec<u8> {
        let mut wo = vec![0u8; len];
        let cursor = Cursor::new(&mut wo[..]);
        let mut ar = ArchiveWriter(cursor);
        pakinfo.ser_de(&mut ar).expect("serialize to work");
        wo
    }

    #[test]
    fn v7() {
        let ro = include_bytes!("../tests/v7.pakinfo");
        let mut pakinfo = read(PakVersion::EncryptionKeyGuid, ro);
        assert_eq!(pakinfo.ser_de_len(), ro.len() as u64);
        assert_eq!(pakinfo.version, PakVersion::EncryptionKeyGuid);
        assert_eq!(write(pakinfo, ro.len()), ro);
    }
}
