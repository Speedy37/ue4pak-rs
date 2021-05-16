use std::fmt;
use std::{collections::HashMap, io};

use crate::archive::ArchivableWith;
use crate::{
    archive::{Archivable, Archive},
    PakEntry, PakVersion,
};

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

/// FPakFile index
#[derive(Debug, Default)]
pub struct PakIndexV1 {
    pub mount_point: String,
    map: HashMap<String, usize>,
    files: Vec<PakIndexEntry>,
}
impl fmt::Display for PakIndexV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "MountPoint: '{}'", self.mount_point)?;
        writeln!(f, "NumEntries: {}", self.files.len())?;
        Ok(())
    }
}

impl PakIndexV1 {
    pub fn find(&self, name: &str) -> Option<&PakEntry> {
        self.map.get(name).map(|&idx| &self.files[idx].entry)
    }

    pub fn named_entries(&self) -> impl Iterator<Item = (&str, &PakEntry)> {
        self.files.iter().map(|entry| (entry.name.as_str(), &entry.entry))
    }

    pub fn entries(&self) -> impl Iterator<Item = &PakEntry> {
        self.files.iter().map(|entry| &entry.entry)
    }

    pub(crate) fn take_entries(self) -> impl Iterator<Item = (String, PakEntry)> {
        self.files.into_iter().map(|n| (n.name, n.entry))
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.files.clear();
    }

    pub fn add(&mut self, name: String, entry: PakEntry) -> &mut PakEntry {
        let idx = self.files.len();
        self.map.insert(name.clone(), idx);
        self.files.push(PakIndexEntry { name, entry });
        &mut self.files[idx].entry
    }

    pub fn ser_de<A: Archive>(&mut self, ar: &mut A, version: PakVersion) -> io::Result<()> {
        self.mount_point.ser_de(ar)?;
        self.files.ser_de_with(ar, version)?;
        self.map =
            self.files.iter().enumerate().map(|(idx, entry)| (entry.name.clone(), idx)).collect();
        Ok(())
    }
}
