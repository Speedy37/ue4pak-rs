use std::{collections::HashMap, convert::TryFrom, io};

use log::trace;

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
impl PakIndexEntry {
    fn ser_de<A: Archive>(&mut self, ar: &mut A, version: PakVersion) -> io::Result<()> {
        self.name.ser_de(ar)?;
        self.entry.ser_de(ar, version)?;
        Ok(())
    }
}

/// FPakFile index
#[derive(Debug, Default)]
pub struct PakIndex {
    mount_point: String,
    map: HashMap<String, usize>,
    files: Vec<PakIndexEntry>,
}

impl PakIndex {
    pub fn find(&self, name: &str) -> Option<&PakEntry> {
        self.map.get(name).map(|&idx| &self.files[idx].entry)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &PakEntry)> {
        self.files.iter().map(|entry| (entry.name.as_str(), &entry.entry))
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
        trace!("mount_point: '{}'", self.mount_point);
        let mut len = u32::try_from(self.files.len())
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        len.ser_de(ar)?;
        trace!("num files: {}", len);
        self.files.resize_with(len as usize, Default::default);
        for item in &mut self.files {
            item.ser_de(ar, version)?;
        }
        self.map =
            self.files.iter().enumerate().map(|(idx, entry)| (entry.name.clone(), idx)).collect();
        Ok(())
    }
}
