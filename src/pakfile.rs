use std::{convert::TryFrom, io};

use aes::cipher::generic_array::GenericArray;
use aes::{Aes256, BlockCipher, NewBlockCipher};
use block_modes::block_padding::NoPadding;
use block_modes::{BlockMode, Ecb};
use log::{debug, trace};
use sha1::digest::generic_array::typenum::Unsigned;

use crate::archive::{Archivable, Archive, ArchiveLenSha1, ArchiveReader};
use crate::pakindex::PakIndex;
use crate::pakindexv1::PakIndexV1;
use crate::pakindexv2::PakIndexV2;
use crate::{PakInfo, PakVersion};

type Aes256KeySize = <Aes256 as NewBlockCipher>::KeySize;
type Aes256BlockSize = <Aes256 as BlockCipher>::BlockSize;
type Aes256Key = GenericArray<u8, Aes256KeySize>;

#[derive(Debug)]
pub struct PakFile {
    pub(crate) info: PakInfo,
    pub(crate) index: PakIndex,
}

impl PakFile {
    pub fn load_any<A: Archive + io::Seek>(ar: &mut A) -> io::Result<Self> {
        Self::load_versions(ar, "", PakVersion::list().iter().rev().copied())
    }

    pub fn load_any_with_key<A: Archive + io::Seek>(ar: &mut A, key: &str) -> io::Result<Self> {
        Self::load_versions(ar, key, PakVersion::list().iter().rev().copied())
    }

    pub fn load_version<A: Archive + io::Seek>(
        ar: &mut A,
        version: PakVersion,
    ) -> io::Result<Self> {
        Self::load_versions(ar, "", [version].iter().copied())
    }

    pub fn load_versions<A: Archive + io::Seek>(
        ar: &mut A,
        key: &str,
        versions: impl Iterator<Item = PakVersion>,
    ) -> io::Result<Self> {
        let info = Self::de_pakinfo_versions(ar, versions)?;
        let index = Self::load_index(&info, ar, key)?;
        Ok(Self { info, index })
    }

    pub fn info(&self) -> &PakInfo {
        &self.info
    }

    pub fn index(&self) -> &PakIndex {
        &self.index
    }

    fn decrypt_index(
        ar: &mut impl Archive,
        size: u64,
        key: &Aes256Key,
    ) -> io::Result<ArchiveReader<io::Cursor<Vec<u8>>>> {
        let index_size =
            usize::try_from(size).map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        let mut block = vec![0u8; index_size];
        ar.read_exact(&mut block)?;
        let cipher = Ecb::<Aes256, NoPadding>::new_fix(key, &Default::default());
        cipher.decrypt(&mut block).map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        Ok(ArchiveReader(io::Cursor::new(block)))
    }

    fn load_index<A: Archive + io::Seek>(
        info: &PakInfo,
        ar: &mut A,
        key: &str,
    ) -> io::Result<PakIndex> {
        trace!("trying to decode PakIndex at {:x} (size: {})", info.index_offset, info.index_size,);
        ar.seek(io::SeekFrom::Start(info.index_offset))?;

        if info.version >= PakVersion::FrozenIndex && info.index_is_frozen {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "PakFile was frozen, this is not supported and UE4.26 also dropped the support",
            ));
        }
        if info.encrypted_index {
            let key =
                base64::decode(key).map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
            if key.len() != Aes256KeySize::USIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "invalid base64 key size, found a {} bytes key, expecting a {} bytes key",
                        key.len(),
                        Aes256KeySize::USIZE
                    ),
                ));
            }
            let key = Aes256Key::from_slice(&key);
            let mut decrypted_ar = Self::decrypt_index(ar, info.index_size, &key)?;
            Self::_load_index(
                info,
                &mut decrypted_ar,
                move |decrypted_ar, offset, size| {
                    ar.seek(io::SeekFrom::Start(offset))?;
                    *decrypted_ar = Self::decrypt_index(ar, size, &key)?;
                    Ok(())
                },
                |sha1_ar, size| {
                    if sha1_ar.len() < size {
                        let pad_size = size - sha1_ar.len();
                        if pad_size < Aes256BlockSize::U64 {
                            // read at most one block size
                            let mut b = [0u8; Aes256BlockSize::USIZE];
                            sha1_ar.read_exact(&mut b[0..pad_size as usize])?;
                        }
                    }
                    Ok(())
                },
            )
        } else {
            Self::_load_index(
                info,
                ar,
                |ar, offset, _size| ar.seek(io::SeekFrom::Start(offset)).map(|_| ()),
                |_, _| Ok(()),
            )
        }
    }

    fn _load_index<A, F, P>(
        info: &PakInfo,
        ar: &mut A,
        mut seek: F,
        mut pad: P,
    ) -> io::Result<PakIndex>
    where
        A: Archive,
        F: FnMut(&mut A, u64, u64) -> io::Result<()>,
        P: FnMut(&mut ArchiveLenSha1<&mut A>, u64) -> io::Result<()>,
    {
        let mut sha1_ar = ArchiveLenSha1::new(ar);
        let (mut next_size, mut next_hash) = (info.index_size, info.index_hash);
        let mut next_ctx = "PakIndex";

        let pak_index = if info.version >= PakVersion::PathHashIndex {
            let mut pak_index = PakIndexV2::default();
            pak_index.ser_de(&mut sha1_ar, info.version, |sha1_ar, offset, size, hash, ctx| {
                pad(sha1_ar, next_size)?;
                let (ar_len, ar_hash) = sha1_ar.len_sha1();
                if next_size != ar_len || ar_hash != next_hash {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Corrupt {} ({} != {} or {:X?} != {:X?})",
                            next_ctx, ar_len, next_size, ar_hash, next_hash
                        ),
                    ));
                }
                next_size = size;
                next_hash = hash;
                next_ctx = ctx;
                seek(sha1_ar.get_mut(), offset, size)?;
                Ok(())
            })?;
            PakIndex::V2(pak_index)
        } else {
            let mut pak_index = PakIndexV1::default();
            pak_index.ser_de(&mut sha1_ar, info.version)?;
            PakIndex::V1(pak_index)
        };
        pad(&mut sha1_ar, next_size)?;
        let (ar_len, ar_hash) = sha1_ar.len_sha1();
        if next_size != ar_len || ar_hash != next_hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Corrupt {} ({} != {} or {:X?} != {:X?})",
                    next_ctx, ar_len, next_size, ar_hash, next_hash
                ),
            ));
        }

        Ok(pak_index)
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
