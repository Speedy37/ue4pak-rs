use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::{io, mem};

use sha1::{Digest, Sha1};

/// An archive reader or writer trait

/// There is a single trait in order to simplify `Archivable` impls.
pub trait Archive {
    /// `true` if this is an archive reader
    fn is_reader(&self) -> bool;

    /// Write all requested bytes in `buf` or return an error
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()>;

    /// Read exactly the requested bytes into `buf` or return an error
    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()>;
}

impl<A: Archive + ?Sized> Archive for &mut A {
    #[inline]
    fn is_reader(&self) -> bool {
        (**self).is_reader()
    }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        (**self).write_all(buf)
    }

    #[inline]
    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        (**self).read_exact(buf)
    }
}

/// A read archive wrapper for `io::Read`
pub struct ArchiveReader<F>(pub F);

/// A write archive wrapper for `io::Write`
pub struct ArchiveWriter<F>(pub F);

/// A write archive wrapper that count written bytes
pub struct ArchiveLen {
    len: u64,
}

impl ArchiveLen {
    pub const fn new() -> Self {
        Self { len: 0 }
    }

    pub const fn len(&self) -> u64 {
        self.len
    }
}

impl Archive for ArchiveLen {
    fn is_reader(&self) -> bool {
        false
    }

    fn read_exact(&mut self, _buf: &mut [u8]) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "read only"))
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.len += buf.len() as u64;
        Ok(())
    }
}

impl<F: io::Read> Archive for io::BufReader<F> {
    fn is_reader(&self) -> bool {
        true
    }

    fn write_all(&mut self, _buf: &[u8]) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "read only"))
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        io::Read::read_exact(self, buf)
    }
}

impl<F: io::Write> Archive for io::BufWriter<F> {
    fn is_reader(&self) -> bool {
        false
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        io::Write::write_all(self, buf)
    }

    fn read_exact(&mut self, _buf: &mut [u8]) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "write only"))
    }
}

impl<F: io::Seek> io::Seek for ArchiveReader<F> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.0.seek(pos)
    }
}

impl<F: io::Read> io::Read for ArchiveReader<F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<F: io::Read> Archive for ArchiveReader<F> {
    fn is_reader(&self) -> bool {
        true
    }

    fn write_all(&mut self, _buf: &[u8]) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "read only"))
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        io::Read::read_exact(&mut self.0, buf)
    }
}

impl<F: io::Seek> io::Seek for ArchiveWriter<F> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.0.seek(pos)
    }
}

impl<F: io::Write> io::Write for ArchiveWriter<F> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<F: io::Write> Archive for ArchiveWriter<F> {
    fn is_reader(&self) -> bool {
        false
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        io::Write::write_all(&mut self.0, buf)
    }

    fn read_exact(&mut self, _buf: &mut [u8]) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "write only"))
    }
}

pub(crate) struct ArchiveLenSha1<A> {
    ar: A,
    bytes: u64,
    sha1: Sha1,
}

impl<A> ArchiveLenSha1<A> {
    pub fn new(ar: A) -> Self {
        Self { ar, bytes: 0, sha1: Sha1::new() }
    }

    pub fn get_mut(&mut self) -> &mut A {
        &mut self.ar
    }

    pub fn len_sha1(&mut self) -> (u64, [u8; 20]) {
        (std::mem::take(&mut self.bytes), std::mem::take(&mut self.sha1).finalize().into())
    }

    pub const fn len(&self) -> u64 {
        self.bytes
    }
}

impl<A: Archive> Archive for ArchiveLenSha1<A> {
    fn is_reader(&self) -> bool {
        self.ar.is_reader()
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.ar.write_all(buf)?;
        self.sha1.update(buf);
        self.bytes += buf.len() as u64;
        Ok(())
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.ar.read_exact(buf)?;
        self.sha1.update(&*buf);
        self.bytes += buf.len() as u64;
        Ok(())
    }
}

impl<W: io::Write> io::Write for ArchiveLenSha1<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.ar.write(buf)?;
        self.sha1.update(&buf[0..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.ar.flush()
    }
}

/// A data structure that can be archived (encoded/decoded)
pub trait Archivable: 'static {
    fn ser_de<A: Archive>(&mut self, ar: &mut A) -> io::Result<()>;

    fn ser_de_len(&mut self) -> u64 {
        let mut ar = ArchiveLen::new();
        self.ser_de(&mut ar).unwrap();
        ar.len()
    }

    fn ser<A: Archive>(&self, ar: &mut A) -> io::Result<()>
    where
        Self: Clone,
    {
        self.clone().ser_de(ar)
    }

    fn ser_len(&self) -> u64
    where
        Self: Clone,
    {
        let mut ar = ArchiveLen::new();
        self.ser(&mut ar).unwrap();
        ar.len()
    }

    fn de<A: Archive>(ar: &mut A) -> io::Result<Self>
    where
        Self: Default,
    {
        let mut v = Self::default();
        v.ser_de(ar)?;
        Ok(v)
    }
}

pub trait ArchivableWith<E> {
    fn ser_de_with<A: Archive>(&mut self, ar: &mut A, extra: E) -> io::Result<()>;

    fn ser_de_len_with(&mut self, extra: E) -> u64 {
        let mut ar = ArchiveLen::new();
        self.ser_de_with(&mut ar, extra).unwrap();
        ar.len()
    }

    fn ser_with<A: Archive>(&self, ar: &mut A, extra: E) -> io::Result<()>
    where
        Self: Clone,
    {
        self.clone().ser_de_with(ar, extra)
    }

    fn ser_len_with(&self, extra: E) -> u64
    where
        Self: Clone,
    {
        let mut ar = ArchiveLen::new();
        self.ser_with(&mut ar, extra).unwrap();
        ar.len()
    }

    fn de_with<A: Archive>(ar: &mut A, extra: E) -> io::Result<Self>
    where
        Self: Default,
    {
        let mut v = Self::default();
        v.ser_de_with(ar, extra)?;
        Ok(v)
    }
}

impl Archivable for [u8] {
    fn ser_de<A: Archive>(&mut self, ar: &mut A) -> io::Result<()> {
        if ar.is_reader() {
            ar.read_exact(self)
        } else {
            ar.write_all(self)
        }
    }
}

impl Archivable for [u32] {
    fn ser_de<A: Archive>(&mut self, ar: &mut A) -> io::Result<()> {
        for item in self {
            item.ser_de(ar)?;
        }
        Ok(())
    }
}

impl<T: Archivable + Default> Archivable for Vec<T> {
    fn ser_de<A: Archive>(&mut self, ar: &mut A) -> io::Result<()> {
        let mut len =
            u32::try_from(self.len()).map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        len.ser_de(ar)?;
        if ar.is_reader() {
            self.clear();
            self.resize_with(len as usize, Default::default);
        }
        for item in self {
            item.ser_de(ar)?;
        }
        Ok(())
    }
}
impl<E: Copy, T: ArchivableWith<E> + Default> ArchivableWith<E> for Vec<T> {
    fn ser_de_with<A: Archive>(&mut self, ar: &mut A, extra: E) -> io::Result<()> {
        let mut len =
            u32::try_from(self.len()).map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        len.ser_de(ar)?;
        if ar.is_reader() {
            self.clear();
            self.resize_with(len as usize, Default::default);
        }
        for item in self {
            item.ser_de_with(ar, extra)?;
        }
        Ok(())
    }
}

impl<K: Archivable + Default + Clone + Ord, V: Archivable + Default> Archivable for BTreeMap<K, V> {
    fn ser_de<A: Archive>(&mut self, ar: &mut A) -> io::Result<()> {
        let mut len =
            u32::try_from(self.len()).map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        len.ser_de(ar)?;
        if ar.is_reader() {
            self.clear();
            for _ in 0..len {
                let mut key = K::default();
                key.ser_de(ar)?;
                let mut value = V::default();
                value.ser_de(ar)?;
                self.insert(key, value);
            }
        } else {
            for (key, value) in self {
                key.clone().ser_de(ar)?;
                value.ser_de(ar)?
            }
        }
        Ok(())
    }
}

macro_rules! doit {
    ($($x:ident),+) => {$(
        impl Archivable for $x {
            fn ser_de<A: Archive>(&mut self, ar: &mut A) -> io::Result<()> {
                if ar.is_reader() {
                    let mut bytes: [u8; mem::size_of::<Self>()] = Default::default();
                    bytes.ser_de(ar)?;
                    *self = Self::from_le_bytes(bytes);
                    Ok(())
                } else {
                    self.to_le_bytes().ser_de(ar)
                }
            }
        }
    )+};
}
doit!(u8, u16, u32, u64, i8, i16, i32, i64, usize);

impl Archivable for bool {
    fn ser_de<A: Archive>(&mut self, ar: &mut A) -> io::Result<()> {
        if ar.is_reader() {
            let mut v = 0u32;
            v.ser_de(ar)?;
            *self = v != 0;
            Ok(())
        } else {
            (*self as u32).ser_de(ar)
        }
    }
}

impl Archivable for String {
    fn ser_de<A: Archive>(&mut self, ar: &mut A) -> io::Result<()> {
        let mut len =
            u32::try_from(self.len()).map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        len.ser_de(ar)?;
        let tmp = mem::take(self);
        let mut buffer = tmp.into_bytes();
        if ar.is_reader() {
            buffer.resize(len as usize, 0);
            ar.read_exact(&mut buffer)?;
            match buffer.pop() {
                Some(0) => (),
                _ => {
                    return Err(io::Error::new(io::ErrorKind::Other, "strings are null terminated"))
                }
            }
            *self = String::from_utf8(buffer)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        } else {
            buffer.push(0u8);
            ar.write_all(&buffer)?;
            buffer.pop();
            *self = String::from_utf8(buffer)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        }
        Ok(())
    }
}
