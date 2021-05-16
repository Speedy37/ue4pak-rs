use std::{convert::TryFrom, io};

use log::{debug, trace};

use crate::archive::{Archivable, Archive};
use crate::pakindex::PakIndex;
use crate::pakindexv1::PakIndexV1;
use crate::pakindexv2::PakIndexV2;
use crate::{PakInfo, PakVersion};

#[derive(Debug)]
pub struct PakFile {
    pub(crate) info: PakInfo,
    pub(crate) index: PakIndex,
}

impl PakFile {
    pub fn new(version: PakVersion) -> Self {
        Self { info: PakInfo::new(version), index: PakIndex::new(version) }
    }

    pub fn autodetect<A: Archive + io::Seek>(ar: &mut A) -> io::Result<Self> {
        Self::with_versions(ar, PakVersion::list().iter().rev().copied())
    }

    pub fn with_versions<A: Archive + io::Seek>(
        ar: &mut A,
        versions: impl Iterator<Item = PakVersion>,
    ) -> io::Result<Self> {
        let info = Self::de_pakinfo_versions(ar, versions)?;
        let index = Self::load_index(&info, ar)?;
        Ok(Self { info, index })
    }

    pub fn info(&self) -> &PakInfo {
        &self.info
    }

    pub fn index(&self) -> &PakIndex {
        &self.index
    }

    fn load_index<A: Archive + io::Seek>(info: &PakInfo, ar: &mut A) -> io::Result<PakIndex> {
        trace!("trying to decode PakIndex at {:x} (size: {})", info.index_offset, info.index_size,);
        ar.seek(io::SeekFrom::Start(info.index_offset))?;

        if info.version >= PakVersion::FrozenIndex && info.index_is_frozen {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "PakFile was frozen, this is not supported and UE4.26 also dropped the support",
            ));
        } else if info.encrypted_index {
            let index_size = usize::try_from(info.index_size)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
            let mut buffer = vec![0u8; index_size];
            buffer.ser_de(ar)?;
            todo!()
        } else if info.version >= PakVersion::PathHashIndex {
            let mut pak_index = PakIndexV2::default();
            pak_index.de(ar, info.version)?;
            Ok(PakIndex::V2(pak_index))
        } else {
            let mut pak_index = PakIndexV1::default();
            pak_index.ser_de(ar, info.version)?;
            Ok(PakIndex::V1(pak_index))
        }
    }

    fn de_pakinfo_versions<A: Archive + io::Seek>(
        ar: &mut A,
        versions: impl Iterator<Item = PakVersion>,
    ) -> io::Result<PakInfo> {
        let ar_len = ar.seek(io::SeekFrom::End(0))?;

        for version in versions {
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
