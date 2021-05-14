use std::{convert::TryFrom, io};

use log::{debug, trace};

use crate::{
    archive::{Archivable, Archive},
    pakindex::PakIndex,
    PakInfo, PakVersion,
};

#[derive(Debug, Default)]
pub struct PakFile {
    pub(crate) info: PakInfo,
    pub(crate) index: PakIndex,
}

impl PakFile {
    pub fn new<A: Archive + io::Seek>(ar: &mut A) -> io::Result<Self> {
        let info = Self::de_pakinfo(ar)?;
        let mut this = Self { info, index: PakIndex::default() };
        this.load_index(ar)?;
        Ok(this)
    }

    pub fn info(&self) -> &PakInfo {
        &self.info
    }

    pub fn index(&self) -> &PakIndex {
        &self.index
    }

    fn load_index<A: Archive + io::Seek>(&mut self, ar: &mut A) -> io::Result<()> {
        trace!(
            "trying to decode PakIndex at {:x} (size: {})",
            self.info.index_offset,
            self.info.index_size,
        );
        ar.seek(io::SeekFrom::Start(self.info.index_offset))?;

        if self.info.version >= PakVersion::FrozenIndex && self.info.index_is_frozen {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "PakFile was frozen, this is not supported and UE4.26 also dropped the support",
            ));
        } else if self.info.encrypted_index {
            let index_size = usize::try_from(self.info.index_size)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
            let mut buffer = vec![0u8; index_size];
            buffer.ser_de(ar)?;
            todo!()
        } else {
            self.index.ser_de(ar, self.info.version)?;
        }
        Ok(())
    }

    fn de_pakinfo<A: Archive + io::Seek>(ar: &mut A) -> io::Result<PakInfo> {
        let ar_len = ar.seek(io::SeekFrom::End(0))?;

        for &version in PakVersion::list().iter().rev() {
            let mut info = PakInfo::new(version);
            let info_len = info.ser_de_len();
            if info_len < ar_len {
                trace!(
                    "trying to decode PakInfo version {:?} at {:x} (size: {})",
                    info.version,
                    ar_len - info_len,
                    info_len
                );
                ar.seek(io::SeekFrom::Start(ar_len - info_len))?;
                match info.ser_de(ar) {
                    Err(err) if err.kind() == io::ErrorKind::InvalidInput => {
                        // try older version
                    }
                    Err(err) => return Err(err),
                    Ok(()) => {
                        debug!("found PakInfo version {}", info.version);
                        ar.seek(io::SeekFrom::Start(0))?;
                        return Ok(info);
                    }
                }
            }
        }

        Err(io::Error::new(io::ErrorKind::InvalidData, "no compatible version found"))
    }
}
