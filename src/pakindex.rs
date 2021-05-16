use std::io;

use crate::archive::Archive;
use crate::pakindexv1::PakIndexV1;
use crate::pakindexv2::PakIndexV2;
use crate::PakVersion;

#[derive(Debug)]
pub enum PakIndex {
    V1(PakIndexV1),
    V2(PakIndexV2),
}

impl PakIndex {
    pub fn new(version: PakVersion) -> Self {
        if version >= PakVersion::PathHashIndex {
            PakIndex::V2(PakIndexV2::default())
        } else {
            PakIndex::V1(PakIndexV1::default())
        }
    }

    pub fn ser<A: Archive>(&mut self, ar: &mut A, version: PakVersion) -> io::Result<()> {
        match self {
            PakIndex::V1(v1) => v1.ser_de(ar, version),
            PakIndex::V2(v2) => v2.ser(ar, version),
        }
    }
}
