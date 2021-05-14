use std::convert::TryFrom;
use std::{io, mem};

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

/// A data structure that can be archived (encoded/decoded)
pub trait Archivable {
    fn ser_de<A: Archive>(&mut self, ar: &mut A) -> io::Result<()>;

    fn ser_de_len(&mut self) -> u64 {
        let mut ar = ArchiveLen::new();
        self.ser_de(&mut ar).unwrap();
        ar.len()
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
        self.resize_with(len as usize, Default::default);
        for item in self {
            item.ser_de(ar)?;
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
            let mut v = 0u8;
            v.ser_de(ar)?;
            *self = v != 0;
            Ok(())
        } else {
            (*self as u8).ser_de(ar)
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
