use std::io;

use sha1::{Digest, Sha1};

use crate::{
    archive::{Archivable, Archive},
    pakentry::FLAG_DELETED,
    pakindex::PakIndex,
    PakEntry, PakFile, PakInfo, PakVersion,
};

struct Sha1Writer<W> {
    ar: W,
    bytes: u64,
    sha1: Sha1,
}

impl<W> Sha1Writer<W> {
    fn new(ar: W) -> Self {
        Self {
            ar,
            bytes: 0,
            sha1: Sha1::new(),
        }
    }

    pub fn get_mut(&mut self) -> &mut W {
        &mut self.ar
    }

    fn sha1(self) -> [u8; 20] {
        self.sha1.finalize().into()
    }
}

impl<A: Archive> Archive for Sha1Writer<A> {
    fn is_loading(&self) -> bool {
        self.ar.is_loading()
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.ar.write_all(buf)?;
        self.sha1.update(buf);
        self.bytes += buf.len() as u64;
        Ok(())
    }

    fn read_exact(&mut self, _buf: &mut [u8]) -> io::Result<()> {
        unreachable!("read is not allowed while computing sha1")
    }
}

impl<W: io::Write> io::Write for Sha1Writer<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.ar.write(buf)?;
        self.sha1.update(&buf[0..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.ar.flush()
    }
}

/// Aligns to the nearest higher multiple of `alignment`
fn align_arbitrary(v: u64, alignment: u64) -> u64 {
    match alignment {
        0 => v,
        _ => ((v + alignment - 1) / alignment) * alignment,
    }
}

pub struct AssetWriter<'a, A: Archive> {
    builder: &'a mut PakFileBuilder,
    ar: Sha1Writer<A>,
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
        let size = self.size();
        let hash = self.ar.sha1();
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

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.ar.write_all(buf)?;
        let len = buf.len() as u64;
        self.builder.pos += len;
        self.entry.uncompressed_size += len;
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct PakFileBuilder {
    pos: u64,
    info: PakInfo,
    index: PakIndex,
}

impl PakFileBuilder {
    pub fn new(version: PakVersion) -> Self {
        Self {
            pos: 0,
            info: PakInfo::new(version),
            index: PakIndex::default(),
        }
    }

    /// Write the index and info blocks
    pub fn finalize<A: Archive>(mut self, ar: &mut A) -> io::Result<PakFile> {
        self.info.index_offset = self.pos;

        let mut sha1_ar = Sha1Writer::new(&mut *ar);
        if self.info.index_is_frozen {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "frozen index is not supported and is deprecated since UE4.26",
            ));
        } else {
            self.index.ser_de(&mut sha1_ar, self.info.version)?;
        }

        self.info.index_size = sha1_ar.bytes;
        self.info.hash = sha1_ar.sha1();
        self.info.ser_de(ar)?;

        let pak = PakFile {
            info: self.info,
            index: self.index,
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

    pub fn import<'a, A: Archive>(
        &'a mut self,
        ar: A,
        name: String,
        mut entry: PakEntry,
    ) -> AssetWriter<'a, A> {
        entry.offset = self.pos;
        AssetWriter {
            builder: self,
            ar: Sha1Writer::new(ar),
            name,
            entry,
            import: true,
        }
    }

    pub fn add<'a, A: Archive>(&'a mut self, ar: A, name: String) -> AssetWriter<'a, A> {
        let mut entry = PakEntry::default();
        entry.offset = self.pos;
        AssetWriter {
            builder: self,
            ar: Sha1Writer::new(ar),
            name,
            entry,
            import: false,
        }
    }

    pub fn deleted(&mut self, name: &str) -> io::Result<&mut PakEntry> {
        let mut entry = PakEntry::default();
        entry.offset = self.pos;
        entry.size = 0;
        entry.uncompressed_size = 0;
        entry.flags |= FLAG_DELETED;

        let entry = self.index.add(name.to_string(), entry);
        Ok(entry)
    }
}
