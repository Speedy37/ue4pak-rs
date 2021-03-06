use core::slice;
use std::io::{self, Write};

use aes::cipher::generic_array::GenericArray;
use block_modes::BlockMode;
use sha1::digest::generic_array::typenum::Unsigned;

use crate::archive::{Archivable, Archive, ArchiveLenSha1};
use crate::pakentry::FLAG_DELETED;
use crate::pakindex::PakIndex;
use crate::pakindexv1::PakIndexV1;
use crate::pakindexv2::PakIndexV2;
use crate::{aes256_base64_key, aes256_ecb_cipher, Aes256BlockSize};
use crate::{Aes256Cipher, Aes256Key, PakEntry, PakFile, PakInfo, PakVersion};

/// Aligns to the nearest higher multiple of `alignment`
fn align_arbitrary(v: u64, alignment: u64) -> u64 {
    match alignment {
        0 => v,
        _ => ((v + alignment - 1) / alignment) * alignment,
    }
}

pub struct Cipher {
    cipher: Aes256Cipher,
    buf: GenericArray<u8, Aes256BlockSize>,
    pending: usize,
}

impl Cipher {
    pub fn new(cipher: Aes256Cipher) -> Self {
        Self { cipher, buf: Default::default(), pending: 0 }
    }
}

pub struct AssetWriter<'a, A: Archive> {
    cipher: Option<Cipher>,
    builder: &'a mut PakFileBuilder,
    ar: ArchiveLenSha1<A>,
    name: String,
    entry: PakEntry,
    import: bool,
}

impl<'a, A: Archive> AssetWriter<'a, A> {
    pub fn size(&self) -> u64 {
        self.builder.pos - self.entry.offset
    }

    pub fn get_mut(&mut self) -> &mut A {
        self.ar.get_mut()
    }

    pub fn finalize(mut self) -> io::Result<&'a mut PakEntry> {
        if let Some(cipher) = &mut self.cipher {
            if cipher.pending > 0 {
                let zeros = GenericArray::<u8, Aes256BlockSize>::default();
                let n = cipher.buf.len() - cipher.pending;
                cipher.buf[cipher.pending..].copy_from_slice(&zeros[..n]);
                cipher.cipher.encrypt_blocks(slice::from_mut(&mut cipher.buf));
                self.ar.write_all(&cipher.buf)?;
                self.builder.pos += Aes256BlockSize::U64;
                self.entry.uncompressed_size += Aes256BlockSize::U64;
                cipher.pending = 0;
            }
        }

        self.flush()?;
        let (size, hash) = self.ar.len_sha1();
        if self.import {
            if self.entry.size != size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "imported entry size doesn't match written size",
                ));
            }
            if self.entry.hash != hash {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "imported entry hash doesn't match written hash",
                ));
            }
        } else {
            self.entry.hash = hash;
            self.entry.size = size;
        }
        let entry = self.builder.index.add(self.name, self.entry);
        Ok(entry)
    }
}

impl<'a, A: Archive> io::Write for AssetWriter<'a, A> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_all(buf)?;
        Ok(buf.len())
    }

    fn write_all(&mut self, mut buf: &[u8]) -> io::Result<()> {
        if let Some(cipher) = &mut self.cipher {
            while !buf.is_empty() {
                let n = (cipher.buf.len() - cipher.pending).min(buf.len());
                cipher.buf[cipher.pending..].copy_from_slice(&buf[..n]);
                cipher.pending += n;
                if cipher.pending == Aes256BlockSize::USIZE {
                    cipher.cipher.encrypt_blocks(slice::from_mut(&mut cipher.buf));
                    self.ar.write_all(&cipher.buf)?;
                    self.builder.pos += Aes256BlockSize::U64;
                    self.entry.uncompressed_size += Aes256BlockSize::U64;
                }
                buf = &buf[n..];
            }
            //cipher.en
        } else {
            self.ar.write_all(buf)?;
            let len = buf.len() as u64;
            self.builder.pos += len;
            self.entry.uncompressed_size += len;
        }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct PakFileBuilder {
    pos: u64,
    info: PakInfo,
    index: PakIndexV1,
    key: Option<Aes256Key>,
}

impl PakFileBuilder {
    pub fn new(version: PakVersion) -> Self {
        Self { pos: 0, info: PakInfo::new(version), index: PakIndexV1::default(), key: None }
    }

    pub fn encrypted(&mut self, key: &str) -> io::Result<()> {
        self.key = Some(aes256_base64_key(key)?);
        Ok(())
    }

    /// Write the index and info blocks
    pub fn finalize<A: Archive>(mut self, ar: &mut A) -> io::Result<PakFile> {
        let version = self.info.version;
        self.info.index_offset = self.pos;

        let mut sha1_ar = ArchiveLenSha1::new(&mut *ar);
        if self.info.index_is_frozen {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "frozen index is not supported and is deprecated since UE4.26",
            ));
        } else {
            self.index.ser_de(&mut sha1_ar, version)?;
        }

        let (len, hash) = sha1_ar.len_sha1();
        self.info.index_size = len;
        self.info.index_hash = hash;
        self.info.ser_de(ar)?;

        let pak = PakFile {
            info: self.info,
            index: if version >= PakVersion::PathHashIndex {
                let mut v2 = PakIndexV2::default();
                for (name, entry) in self.index.take_entries() {
                    v2.add(name, entry, version)?;
                }
                PakIndex::V2(v2)
            } else {
                PakIndex::V1(self.index)
            },
            key: self.key,
        };
        Ok(pak)
    }

    /// Write padding bytes to ensure next write is aligned to `alignement`.
    pub fn pad<A: Archive>(&mut self, ar: A, alignment: u64) -> io::Result<()> {
        let pos = align_arbitrary(self.pos, alignment);
        self.seek(ar, pos)
    }

    /// Write padding bytes up to `pos`
    pub fn seek<A: Archive>(&mut self, mut ar: A, pos: u64) -> io::Result<()> {
        while self.pos < pos {
            // fill hole with zeros
            const ZEROS: &[u8; 4096] = &[0u8; 4096];
            let size = (pos - self.pos).min(4096);
            ar.write_all(&ZEROS[0..size as usize])?;
            self.pos += size;
        }
        if self.pos != pos {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "requested seek position {} is invalid, current position is {}",
                    pos, self.pos
                ),
            ))
        } else {
            Ok(())
        }
    }

    fn cipher(&self) -> Option<Cipher> {
        self.key.as_ref().map(|key| Cipher::new(aes256_ecb_cipher(key)))
    }

    pub fn import<A: Archive>(
        &mut self,
        ar: A,
        name: String,
        mut entry: PakEntry,
    ) -> AssetWriter<'_, A> {
        entry.offset = self.pos;
        let ar = ArchiveLenSha1::new(ar);
        let cipher = self.cipher();
        AssetWriter { builder: self, ar, name, entry, import: true, cipher }
    }

    pub fn add<A: Archive>(&mut self, ar: A, name: String) -> AssetWriter<'_, A> {
        let entry = PakEntry { offset: self.pos, ..PakEntry::default() };
        let ar = ArchiveLenSha1::new(ar);
        let cipher = self.cipher();
        AssetWriter { builder: self, ar, name, entry, import: false, cipher }
    }

    pub fn deleted(&mut self, name: &str) -> io::Result<&mut PakEntry> {
        let entry = PakEntry { offset: self.pos, flags: FLAG_DELETED, ..PakEntry::default() };
        let entry = self.index.add(name.to_string(), entry);
        Ok(entry)
    }
}
