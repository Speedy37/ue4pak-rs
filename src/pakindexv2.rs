use std::collections::HashMap;
use std::convert::TryFrom;
use std::{collections::BTreeMap, io};
use std::{fmt, mem};

use crate::archive::{ArchivableWith, ArchiveReader, ArchiveWriter};
use crate::pakentry::FLAG_ENCRYPTED;
use crate::PakCompressedBlock;
use crate::{
    archive::{Archivable, Archive},
    PakEntry, PakVersion,
};

const AES_BLOCK_SIZE: u64 = 16;

fn legacy_fnv64(s: &str, seed: u64) -> u64 {
    const OFFSET: u64 = 0x00000100000001b3;
    const PRIME: u64 = 0xcbf29ce484222325;
    let mut h = OFFSET.wrapping_add(seed);
    for &byte in s.as_bytes() {
        h ^= byte as u64;
        h = h.wrapping_mul(PRIME);
    }
    h
}
fn fnv64(s: &str, seed: u64) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x00000100000001b3;
    let mut h = OFFSET.wrapping_add(seed);
    for &byte in s.as_bytes() {
        h ^= byte as u64;
        h = h.wrapping_mul(PRIME);
    }
    h
}

/// FPakEntryPair archivable
#[derive(Debug, Default)]
struct PakIndexEntry {
    name: String,
    entry: PakEntry,
}
impl ArchivableWith<PakVersion> for PakIndexEntry {
    fn ser_de_with<A: Archive>(&mut self, ar: &mut A, version: PakVersion) -> io::Result<()> {
        self.name.ser_de(ar)?;
        self.entry.ser_de_with(ar, version)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PakEntryLocation {
    Deleted,
    Offset(usize),
    Index(usize),
}

#[derive(Default, Clone, Copy)]
pub struct RawPakEntryLocation {
    index: i32,
}

impl std::fmt::Debug for RawPakEntryLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.get().fmt(f)
    }
}

impl RawPakEntryLocation {
    fn from_offset(offset: usize) -> Self {
        Self { index: offset as i32 }
    }

    fn from_index(index: usize) -> Self {
        Self { index: -(index as i32) - 1 }
    }

    fn get(self) -> PakEntryLocation {
        const MAX: i32 = i32::MAX - 1;
        const MIN: i32 = -MAX - 1;

        match self.index {
            x @ MIN..=-1 => PakEntryLocation::Index((-(x + 1)) as usize),
            x @ 0..=MAX => PakEntryLocation::Offset(x as usize),
            _ => PakEntryLocation::Deleted,
        }
    }
}

impl Archivable for RawPakEntryLocation {
    fn ser_de<A: Archive>(&mut self, ar: &mut A) -> io::Result<()> {
        self.index.ser_de(ar)
    }
}

fn align(size: u64, alignment: u64) -> u64 {
    (size + alignment - 1) & !(alignment - 1)
}

#[derive(Debug, Default)]
pub struct PakIndexV2 {
    /// Mount point
    pub mount_point: String,
    /// The number of file entries in the pak file
    num_entries: u32,
    /// Info on all files stored in pak
    files: Vec<PakEntry>,
    /// The seed passed to the hash function for hashing filenames in this pak.
    /// Differs per pack so that the same filename in different paks has different hashes
    pub path_hash_seed: u64,

    /// FPakEntries that have been serialized into a compacted format in an array of bytes.
    encoded_pak_entries: Vec<u8>,
    decoded_pak_entries: HashMap<usize, PakEntry>,

    pub has_path_hash_index: bool,
    path_hash_index_offset: i64,
    path_hash_index_size: i64,
    pub path_hash_index_hash: [u8; 20],
    /// Index data that provides a map from the hash of a Filename to an FPakEntryLocation
    path_hash_index: BTreeMap<u64, RawPakEntryLocation>,
    pruned_directory_index: BTreeMap<String, BTreeMap<String, RawPakEntryLocation>>,

    pub has_full_directory_index: bool,
    full_directory_index_offset: i64,
    full_directory_index_size: i64,
    pub full_directory_index_hash: [u8; 20],
    /// Pak Index organized as a map of directories to support searches by path.
    full_directory_index: BTreeMap<String, BTreeMap<String, RawPakEntryLocation>>,
}
impl fmt::Display for PakIndexV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "MountPoint: '{}'", self.mount_point)?;
        writeln!(f, "NumEntries: {}", self.num_entries)?;
        writeln!(f, "PathHashSeed: {}", self.path_hash_seed)?;
        writeln!(f, "EncodedPakEntries: {}", self.encoded_pak_entries.len())?;
        writeln!(f, "FilesNum: {}", self.files.len())?;
        writeln!(f, "bReaderHasPathHashIndex: {}", self.has_path_hash_index)?;
        if self.has_path_hash_index {
            writeln!(f, "PathHashIndexOffset: {}", self.path_hash_index_offset)?;
            writeln!(f, "PathHashIndexSize: {}", self.path_hash_index_size)?;
            writeln!(f, "PathHashIndexHash: {:X?}", self.path_hash_index_hash)?;
            writeln!(f, "PathHashIndex: {}", self.path_hash_index.len())?;
            writeln!(f, "PrunedDirectoryIndex: {}", self.pruned_directory_index.len())?;
        }
        writeln!(f, "bReaderHasFullDirectoryIndex: {}", self.has_full_directory_index)?;
        if self.has_full_directory_index {
            writeln!(f, "FullDirectoryIndexOffset: {}", self.full_directory_index_offset)?;
            writeln!(f, "FullDirectoryIndexSize: {}", self.full_directory_index_size)?;
            writeln!(f, "FullDirectoryIndexHash: {:X?}", self.full_directory_index_hash)?;
            writeln!(f, "DirectoryIndex: {}", self.full_directory_index.len())?;
        }
        Ok(())
    }
}
impl PakIndexV2 {
    pub fn clear(&mut self) {
        *self = Self {
            mount_point: mem::take(&mut self.mount_point),
            path_hash_seed: self.path_hash_seed,
            has_path_hash_index: self.has_path_hash_index,
            has_full_directory_index: self.has_full_directory_index,
            ..Self::default()
        };
    }

    pub fn add(
        &mut self,
        name: String,
        entry: PakEntry,
        version: PakVersion,
    ) -> io::Result<PakEntryLocation> {
        let offset = self.encoded_pak_entries.len();
        let mut location = RawPakEntryLocation::from_offset(offset);
        let cursor = io::Cursor::new(&mut self.encoded_pak_entries);
        let mut ar = ArchiveWriter(cursor);
        if Self::encode_entry(&mut ar, &entry, version)? {
            self.decoded_pak_entries.insert(offset, entry);
        } else {
            location = RawPakEntryLocation::from_index(self.files.len());
            self.files.push(entry);
        };

        if self.has_path_hash_index {
            let lname = name.to_lowercase();
            let hash = if version >= PakVersion::Fnv64BugFix {
                fnv64(&lname, self.path_hash_seed)
            } else {
                legacy_fnv64(&lname, self.path_hash_seed)
            };
            if let Some(other) = self.path_hash_index.insert(hash, location) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "fnv64 hash collision for {:?} at {:?} against {:?}",
                        lname,
                        location.get(),
                        other.get()
                    ),
                ));
            }
        }

        if self.has_full_directory_index {
            match name.rsplit_once('/') {
                Some((dir, name)) => {
                    self.full_directory_index
                        .entry(dir.to_owned())
                        .or_default()
                        .insert(name.to_owned(), location);
                }
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("asset {:?} is not inside a directory", name),
                    ));
                }
            }
        }
        Ok(location.get())
    }

    pub fn hashed_entries(&self) -> impl Iterator<Item = (u64, &PakEntry)> + '_ {
        self.path_hash_index.iter().flat_map(move |(hash, location)| match location.get() {
            PakEntryLocation::Deleted => None,
            PakEntryLocation::Offset(i) => {
                Some((*hash, self.decoded_pak_entries.get(&i).expect("a valid offset")))
            }
            PakEntryLocation::Index(i) => Some((*hash, &self.files[i])),
        })
    }

    pub fn entries(&self) -> impl Iterator<Item = &PakEntry> {
        self.path_hash_index.values().flat_map(move |location| match location.get() {
            PakEntryLocation::Deleted => None,
            PakEntryLocation::Offset(i) => {
                Some(self.decoded_pak_entries.get(&i).expect("a valid offset"))
            }
            PakEntryLocation::Index(i) => Some(&self.files[i]),
        })
    }

    pub fn pruned_entries(&self) -> impl Iterator<Item = (&str, &str, PakEntryLocation)> {
        self.pruned_directory_index.iter().flat_map(|(dir_name, entries)| {
            entries.iter().map(move |(entry_name, location)| {
                (dir_name.as_str(), entry_name.as_str(), location.get())
            })
        })
    }

    pub fn full_entries(&self) -> impl Iterator<Item = (&str, &str, PakEntryLocation)> {
        self.full_directory_index.iter().flat_map(|(dir_name, entries)| {
            entries.iter().map(move |(entry_name, location)| {
                (dir_name.as_str(), entry_name.as_str(), location.get())
            })
        })
    }

    pub fn ser<A: Archive>(&mut self, ar: &mut A, version: PakVersion) -> io::Result<()> {
        self.ser_de(ar, version, |_ar, _offset, _size, _hash, _ctx| {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PakIndexV2::ser only supports writing mode",
            ))
        })
    }

    pub fn de<A: Archive + io::Seek>(&mut self, ar: &mut A, version: PakVersion) -> io::Result<()> {
        self.ser_de(ar, version, |ar, offset, _size, _hash, _ctx| {
            ar.seek(io::SeekFrom::Start(offset)).map(|_| ())?;
            Ok(())
        })
    }

    pub fn ser_de<A, F>(&mut self, ar: &mut A, version: PakVersion, mut seek: F) -> io::Result<()>
    where
        A: Archive,
        F: FnMut(&mut A, u64, u64, [u8; 20], &'static str) -> io::Result<()>,
    {
        self.mount_point.ser_de(ar)?;
        self.num_entries.ser_de(ar)?;
        self.path_hash_seed.ser_de(ar)?;
        self.has_path_hash_index.ser_de(ar)?;
        if self.has_path_hash_index {
            self.path_hash_index_offset.ser_de(ar)?;
            self.path_hash_index_size.ser_de(ar)?;
            self.path_hash_index_hash.ser_de(ar)?;
        }

        self.has_full_directory_index.ser_de(ar)?;
        if self.has_full_directory_index {
            self.full_directory_index_offset.ser_de(ar)?;
            self.full_directory_index_size.ser_de(ar)?;
            self.full_directory_index_hash.ser_de(ar)?;
        }

        let mut len = u32::try_from(self.encoded_pak_entries.len())
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        len.ser_de(ar)?;
        if ar.is_reader() {
            self.encoded_pak_entries.clear();
            self.encoded_pak_entries.resize(len as usize, 0);
            ar.read_exact(self.encoded_pak_entries.as_mut_slice())?;
        } else {
            ar.write_all(self.encoded_pak_entries.as_slice())?;
        }

        self.files.ser_de_with(ar, version)?;

        if self.has_path_hash_index && self.path_hash_index_offset != -1 {
            if self.path_hash_index_offset < 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("corrupted PathHashIndexOffset: {}", self.path_hash_index_offset),
                ));
            }
            if ar.is_reader() {
                seek(
                    ar,
                    self.path_hash_index_offset as u64,
                    self.path_hash_index_size as u64,
                    self.path_hash_index_hash,
                    "PathHashIndex",
                )?;
            }
            self.path_hash_index.ser_de(ar)?;
            self.pruned_directory_index.ser_de(ar)?;
        }

        if self.has_full_directory_index && self.full_directory_index_offset != 0 {
            if self.full_directory_index_offset < 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "corrupted FullDirectoryIndexOffset: {}",
                        self.full_directory_index_offset
                    ),
                ));
            }
            if ar.is_reader() {
                seek(
                    ar,
                    self.full_directory_index_offset as u64,
                    self.full_directory_index_size as u64,
                    self.full_directory_index_hash,
                    "FullDirectoryIndex",
                )?;
            }
            self.full_directory_index.ser_de(ar)?;
        }

        if self.has_path_hash_index && ar.is_reader() {
            self.decoded_pak_entries = self
                .path_hash_index
                .values()
                .filter_map(|location| match location.get() {
                    PakEntryLocation::Offset(offset) => {
                        if offset > self.encoded_pak_entries.len() {
                            return Some(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "pak entry location offset {} out of bounds: [0, {}]",
                                    offset,
                                    self.encoded_pak_entries.len(),
                                ),
                            )));
                        }
                        let cursor = io::Cursor::new(&self.encoded_pak_entries[offset..]);
                        let mut ar = ArchiveReader(cursor);
                        Some(Self::decode_entry(&mut ar, version).map(|entry| (offset, entry)))
                    }
                    _ => None,
                })
                .collect::<Result<_, _>>()?;
        }
        Ok(())
    }

    fn can_encode_entry(entry: &PakEntry, version: PakVersion) -> bool {
        let alignment = if entry.is_encrypted() { AES_BLOCK_SIZE } else { 1 };
        let header_size = entry.ser_len_with(version);

        if entry.compression_method_index >= (1 << 6) {
            return false;
        }
        if entry.compression_blocks.len() >= (1 << 16) {
            return false;
        }
        if entry.compression_method_index != 0 {
            if u64::from(entry.compression_block_size) != entry.uncompressed_size
                && ((entry.compression_block_size >> 11) > 0x3f)
            {
                return false;
            }
            if entry.compression_blocks.len() > 0
                && (header_size != entry.compression_blocks[0].compressed_start)
            {
                return false;
            }
            if entry.compression_blocks.len() == 1 {
                let aligned_block_size = align(
                    entry.compression_blocks[0].compressed_end
                        - entry.compression_blocks[0].compressed_start,
                    alignment,
                );
                if header_size + entry.size
                    != entry.compression_blocks[0].compressed_start + aligned_block_size
                {
                    return false;
                }
            }
            if entry.compression_blocks.len() > 1 {
                let mut prev_size = entry.compression_blocks[0].compressed_end
                    - entry.compression_blocks[0].compressed_start;
                for compression_block in entry.compression_blocks[1..].iter() {
                    prev_size = align(prev_size, alignment);
                    if compression_block.compressed_start
                        != compression_block.compressed_start + prev_size
                    {
                        return false;
                    }
                    prev_size =
                        compression_block.compressed_end - compression_block.compressed_start;
                }
            }
        }

        true
    }

    fn encode_entry<A: Archive>(
        ar: &mut A,
        entry: &PakEntry,
        version: PakVersion,
    ) -> io::Result<bool> {
        if !Self::can_encode_entry(entry, version) {
            return Ok(false);
        }

        let offset_u32 = u32::try_from(entry.offset).ok();
        let size_u32 = u32::try_from(entry.size).ok();
        let uncompressed_size_u32 = u32::try_from(entry.uncompressed_size).ok();
        let flags = (u32::from(offset_u32.is_some()) * (1 << 31))
            | (u32::from(uncompressed_size_u32.is_some()) * (1 << 30))
            | (u32::from(size_u32.is_some()) * 1 << 29)
            | (entry.compression_method_index << 23)
            | (u32::from(entry.is_encrypted()) * (1 << 22))
            | ((entry.compression_blocks.len() as u32) << 6)
            | (entry.compression_block_size >> 11);

        flags.ser(ar)?;
        match offset_u32 {
            Some(v) => v.ser(ar)?,
            None => entry.offset.ser(ar)?,
        }
        match uncompressed_size_u32 {
            Some(v) => v.ser(ar)?,
            None => entry.uncompressed_size.ser(ar)?,
        }
        if entry.compression_method_index != 0 {
            match size_u32 {
                Some(v) => v.ser(ar)?,
                None => entry.size.ser(ar)?,
            }
            if entry.compression_blocks.len() > 1
                || (entry.compression_blocks.len() == 1 && entry.is_encrypted())
            {
                for compression_block in &entry.compression_blocks {
                    let block_size =
                        compression_block.compressed_end - compression_block.compressed_start;
                    block_size.ser(ar)?;
                }
            }
        }

        Ok(true)
    }

    fn decode_entry<A: Archive>(ar: &mut A, version: PakVersion) -> io::Result<PakEntry> {
        let mut entry = PakEntry::default();
        let value = u32::de(ar)?;
        entry.compression_method_index = (value >> 23) & 0x3f;

        let is_offset_u32 = (value & (1 << 31)) != 0;
        if is_offset_u32 {
            entry.offset = u64::from(u32::de(ar)?);
        } else {
            entry.offset = u64::de(ar)?;
        }

        let is_uncompressed_size_u32 = (value & (1 << 30)) != 0;
        if is_uncompressed_size_u32 {
            entry.uncompressed_size = u64::from(u32::de(ar)?);
        } else {
            entry.uncompressed_size = u64::de(ar)?;
        }

        if entry.compression_method_index != 0 {
            let is_size_u32 = (value & (1 << 29)) != 0;
            if is_size_u32 {
                entry.size = u64::from(u32::de(ar)?);
            } else {
                entry.size = u64::de(ar)?;
            }
        } else {
            entry.size = entry.uncompressed_size;
        }

        if (value & (1 << 22)) != 0 {
            entry.flags |= FLAG_ENCRYPTED;
        }

        let compression_blocks_len = ((value >> 6) & 0xffff) as usize;
        if compression_blocks_len > 0 {
            entry.compression_block_size = if entry.uncompressed_size < 65536 {
                entry.uncompressed_size as u32
            } else {
                (value & 0x3f) << 11
            };
        }

        entry.compression_blocks.clear();
        if compression_blocks_len == 1 && !entry.is_encrypted() {
            let compressed_start = entry.ser_de_len_with(version);
            entry.compression_blocks.push(PakCompressedBlock {
                compressed_start: compressed_start,
                compressed_end: (compressed_start + entry.size),
            });
        } else if compression_blocks_len > 0 {
            let alignment = if entry.is_encrypted() { AES_BLOCK_SIZE } else { 1 };
            let mut compressed_start = entry.ser_de_len_with(version);
            for _ in 0..compression_blocks_len {
                let block_size = u64::from(u32::de(ar)?);
                let compressed_end = compressed_start + block_size;
                entry
                    .compression_blocks
                    .push(PakCompressedBlock { compressed_start, compressed_end });
                compressed_start += align(block_size, alignment);
            }
        }

        Ok(entry)
    }
}
