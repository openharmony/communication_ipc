// Copyright (C) 2024 Huawei Device Co., Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::borrow::Borrow;
use std::fs::File;
use std::mem;
use std::ops::Deref;
use std::os::fd::{FromRawFd, IntoRawFd};
use std::pin::Pin;

use cxx::UniquePtr;

use super::error::ParcelSetError;
use super::wrapper::{
    AsParcel, AsParcelMut, MessageOption, MessageParcel, NewMessageOption, NewMessageParcel,
    Parcel, ReadBuffer, ReadInterfaceToken, ReadRemoteObject, ReadString16, ReadString16Vector,
    WriteBuffer, WriteInterfaceToken, WriteRemoteObject, WriteString16, WriteString16Vector,
};
use super::{Deserialize, Serialize};
use crate::parcel::wrapper::IRemoteObjectWrapper;
use crate::remote::RemoteObj;
use crate::{IpcResult, IpcStatusCode};
const STRING_16_SIZE: usize = 12;

pub(crate) enum ParcelMem {
    Unique(UniquePtr<MessageParcel>),
    Borrow(*mut MessageParcel),
    Null,
}

/// Ipc MsgParcel
pub struct MsgParcel {
    pub(crate) inner: ParcelMem,
}

unsafe impl Send for MsgParcel {}
unsafe impl Send for MsgOption {}

impl MsgParcel {
    /// Creates a new, empty MsgParcel.
    ///
    /// # Panics
    /// Panics if allocate failed.
    ///
    /// # Examples
    /// ```rust
    /// use ipc::parcel::MsgParcel;
    ///
    /// let msg = MsgParcel::new();
    /// ```
    pub fn new() -> Self {
        let ptr = NewMessageParcel();
        assert!(!ptr.is_null(), "memory allocation of MessageParcel failed");
        Self {
            inner: ParcelMem::Unique(ptr),
        }
    }

    /// create MsgParcel from raw ptr
    pub fn from_ptr(ptr: *mut MessageParcel) -> Self {
        Self {
            inner: ParcelMem::Borrow(ptr),
        }
    }

    /// into raw ptr
    pub fn into_raw(self) -> *mut MessageParcel {
        match self.inner {
            ParcelMem::Unique(p) => p.into_raw(),
            ParcelMem::Borrow(p) => p,
            ParcelMem::Null => unreachable!(),
        }
    }

    /// Writes a [`Serialize`] value into this MsgParcel.
    ///
    /// [Serialize]: crate::parcel::Serialize
    ///
    /// # Example
    /// ``` rust
    /// use ipc::parcel::{MsgParcel, Serialize};
    /// use ipc::IpcResult;
    /// struct Foo {
    ///     a: i32,
    /// }
    ///
    /// impl Serialize for Foo {
    ///     fn serialize(&self, parcel: &mut MsgParcel) -> IpcResult<()> {
    ///         parcel.write(&self.a)
    ///     }
    /// }
    ///
    /// let mut msg = MsgParcel::new();
    /// msg.write(&Foo { a: 1 }).unwrap();
    /// assert_eq!(1, msg.read::<i32>().unwrap());
    /// ```
    pub fn write<T: Serialize + ?Sized>(&mut self, value: &T) -> IpcResult<()> {
        value.serialize(self)
    }

    /// Reads a [`Deserialize`] value out of this MsgParcel.
    ///
    /// [Deserialize]: crate::parcel::Deserialize
    ///
    /// # Example
    /// ```rust
    /// use ipc::parcel::{Deserialize, MsgParcel, Serialize};
    /// use ipc::IpcResult;
    ///
    /// struct Foo {
    ///     a: i32,
    /// }
    /// impl Serialize for Foo {
    ///     fn serialize(&self, parcel: &mut MsgParcel) -> IpcResult<()> {
    ///         parcel.write(&self.a)
    ///     }
    /// }
    /// impl Deserialize for Foo {
    ///     fn deserialize(parcel: &mut MsgParcel) -> IpcResult<Self> {
    ///         Ok(Foo { a: parcel.read()? })
    ///     }
    /// }
    /// let mut msg = MsgParcel::new();
    /// msg.write(&Foo { a: 1 }).unwrap();
    /// let foo = msg.read::<Foo>().unwrap();
    /// assert_eq!(foo.a, 1);
    /// ```
    pub fn read<T: Deserialize>(&mut self) -> IpcResult<T> {
        T::deserialize(self)
    }

    /// Writes a interface token into this MsgParcel.
    ///
    /// # Example
    /// ```rust
    /// use ipc::parcel::MsgParcel;
    ///
    /// let mut msg = MsgParcel::new();
    /// msg.write_interface_token("OHOS.Download.RequestServiceInterface");
    /// ```
    pub fn write_interface_token(&mut self, name: &str) -> IpcResult<()> {
        self.write_process(name, WriteInterfaceToken)
    }

    /// Reads a interface token from this MsgParcel.
    ///
    /// # Example
    /// ```rust
    /// use ipc::parcel::MsgParcel;
    ///
    /// let mut msg = MsgParcel::new();
    /// msg.write_interface_token("OHOS.Download.RequestServiceInterface");
    /// assert_eq!(
    ///     "OHOS.Download.RequestServiceInterface",
    ///     msg.read_interface_token().unwrap().as_str(),
    /// );
    /// ```
    pub fn read_interface_token(&mut self) -> IpcResult<String> {
        fn read_process(parcel: Pin<&mut MessageParcel>) -> IpcResult<String> {
            Ok(ReadInterfaceToken(parcel))
        }

        self.read_process(read_process)
    }

    /// Writes a raw fd from a given file into this MsgParcel.
    ///
    /// ```no_run
    /// use std::fs::File;
    /// use std::io::{Read, Seek, Write};
    ///
    /// use ipc::parcel::MsgParcel;
    ///
    /// let mut msg = MsgParcel::new();
    /// let mut file = std::fs::OpenOptions::new()
    ///     .read(true)
    ///     .write(true)
    ///     .truncate(true)
    ///     .open("foo")
    ///     .unwrap();
    /// file.write_all(b"hello world").unwrap();
    /// msg.write_file(file).unwrap();
    ///
    /// let mut f = msg.read_file().unwrap();
    /// let mut buf = String::new();
    /// f.rewind().unwrap();
    /// f.read_to_string(&mut buf).unwrap();
    /// assert_eq!("hello world", buf);
    /// ```
    pub fn write_file(&mut self, file: File) -> IpcResult<()> {
        let fd = file.into_raw_fd();
        match self.as_msg_parcel_mut().WriteFileDescriptor(fd) {
            true => Ok(()),
            false => Err(IpcStatusCode::Failed),
        }
    }

    /// Reads a file out of this MsgParcel, that created from the fd written
    /// before.
    ///
    /// # Examples
    /// ```no_run
    /// use std::fs::File;
    /// use std::io::{Read, Seek, Write};
    ///
    /// use ipc::parcel::MsgParcel;
    /// let mut msg = MsgParcel::new();
    /// let mut file = std::fs::OpenOptions::new()
    ///     .read(true)
    ///     .write(true)
    ///     .truncate(true)
    ///     .open("foo")
    ///     .unwrap();
    /// file.write_all(b"hello world").unwrap();
    /// msg.write_file(file).unwrap();
    ///
    /// let mut f = msg.read_file().unwrap();
    /// let mut buf = String::new();
    /// f.rewind().unwrap();
    /// f.read_to_string(&mut buf).unwrap();
    /// assert_eq!("hello world", buf);
    /// ```
    pub fn read_file(&mut self) -> IpcResult<File> {
        let fd = self.as_msg_parcel_mut().ReadFileDescriptor();
        unsafe { Ok(File::from_raw_fd(fd)) }
    }

    /// Writes a data region (buffer) to this parcel
    ///
    /// # Example
    /// ```rust
    /// use crate::parcel::MsgParcel;
    ///
    /// let msg = MsgParcel::new();
    /// let data = vec![];
    /// msg.write_buffer(data.as_bytes);
    /// ```
    pub fn write_buffer(&mut self, buffer: &[u8]) -> IpcResult<()> {
        match WriteBuffer(self.as_msg_parcel_mut(), buffer) {
            true => Ok(()),
            false => Err(IpcStatusCode::Failed),
        }
    }

    /// Reads a block of data (buffer data) from this parcel
    ///
    /// # Example
    /// ```rust
    /// use crate::parcel::MsgParcel;
    ///
    /// let msg = MsgParcel::new();
    /// let data = msg.read_buffer().unwrap();
    /// ```
    pub fn read_buffer(&mut self, len: usize) -> IpcResult<Vec<u8>> {
        let pad_size = Self::get_pad_size(len);
        let mut vec = Vec::with_capacity(len + pad_size);
        match ReadBuffer(self.as_msg_parcel_mut(), len + pad_size, &mut vec) {
            true => Ok({
                unsafe { vec.set_len(len) };
                vec
            }),
            false => Err(IpcStatusCode::Failed),
        }
    }

    pub fn write_string16(&mut self, s: &str) -> IpcResult<()> {
        match WriteString16(self.as_parcel_mut(), s) {
            true => Ok(()),
            false => Err(IpcStatusCode::Failed),
        }
    }

    pub fn read_string16(&mut self) -> IpcResult<String> {
        Ok(ReadString16(self.as_parcel_mut()))
    }

    pub fn write_string16_vec(&mut self, s: &[String]) -> IpcResult<()> {
        match WriteString16Vector(self.as_parcel_mut(), s) {
            true => Ok(()),
            false => Err(IpcStatusCode::Failed),
        }
    }

    pub fn read_string16_vec(&mut self) -> IpcResult<Vec<String>> {
        let mut v = vec![];
        match ReadString16Vector(self.as_parcel_mut(), &mut v) {
            true => Ok(v),
            false => Err(IpcStatusCode::Failed),
        }
    }

    /// Writes a RemoteObj into this MsgParcel.
    ///
    /// # Example
    /// ```rust
    /// use ipc::parcel::MsgParcel;
    /// use ipc::remote::{RemoteObj, RemoteStub};
    ///
    /// struct TestRemoteStub;
    /// impl RemoteStub for TestRemoteStub {
    ///     fn on_remote_request(&self, code: u32, data: &mut MsgParcel, reply: &mut MsgParcel) -> i32 {
    ///         reply.write("nihao");
    ///         println!("hello");
    ///         0
    ///     }
    /// }
    ///
    /// let mut msg = MsgParcel::new();
    /// msg.write_remote(RemoteObj::from_stub(TestRemoteStub).unwrap())
    ///     .unwrap();
    /// ```
    pub fn write_remote(&mut self, remote: RemoteObj) -> IpcResult<()> {
        self.write_process(remote.inner, WriteRemoteObject)
    }

    /// Reads a RemoteObj from this MsgParcel.
    ///
    /// # Example
    /// ```rust
    /// use ipc::parcel::MsgParcel;
    /// use ipc::remote::{RemoteObj, RemoteStub};
    ///
    /// struct TestRemoteStub;
    /// impl RemoteStub for TestRemoteStub {
    ///     fn on_remote_request(&self, code: u32, data: &mut MsgParcel, reply: &mut MsgParcel) -> i32 {
    ///         reply.write("nihao");
    ///         println!("hello");
    ///         0
    ///     }
    /// }
    ///
    /// let mut msg = MsgParcel::new();
    /// msg.write_remote(RemoteObj::from_stub(TestRemoteStub).unwrap())
    ///     .unwrap();
    /// let remote = msg.read_remote().unwrap();
    /// ```
    pub fn read_remote(&mut self) -> IpcResult<RemoteObj> {
        fn read_remote_process(
            parcel: Pin<&mut MessageParcel>,
        ) -> IpcResult<UniquePtr<IRemoteObjectWrapper>> {
            let remote = ReadRemoteObject(parcel);
            if remote.is_null() {
                Err(IpcStatusCode::Failed)
            } else {
                Ok(remote)
            }
        }

        self.read_process(read_remote_process)
            .map(|remote| unsafe { RemoteObj::new_unchecked(remote) })
    }

    /// Returns the size that this MsgParcel has written in bytes.
    ///
    /// # Example
    /// ```rust
    /// use ipc::parcel::MsgParcel;
    ///
    /// let mut msg = MsgParcel::new();
    /// msg.write(&1i32);
    /// assert_eq!(msg.size(), 4);
    /// ```
    pub fn size(&self) -> usize {
        self.as_parcel().GetDataSize()
    }

    /// Returns the remaining writable size in bytes before reallocating.
    ///
    /// # Example
    /// ```rust
    /// use ipc::parcel::MsgParcel;
    ///
    /// let mut msg = MsgParcel::new();
    /// assert_eq!(0, msg.writable());
    /// msg.write(&1i32);
    /// assert_eq!(60, msg.writable());
    /// ```
    pub fn writable(&self) -> usize {
        self.as_parcel().GetWritableBytes()
    }

    /// Returns the remaining readable size in bytes.
    ///
    /// # Example
    /// ```rust
    /// use ipc::parcel::MsgParcel;
    ///
    /// let mut msg = MsgParcel::new();
    /// msg.write(&1i32);
    /// assert_eq!(4, msg.readable() as u32);
    /// ```
    pub fn readable(&self) -> usize {
        self.as_parcel().GetReadableBytes()
    }

    /// Returns the offset size in bytes.
    ///
    /// # Example
    /// ```rust
    /// use ipc::parcel::MsgParcel;
    /// let msg = MsgParcel::new();
    /// ```
    pub fn offset(&self) -> usize {
        self.as_parcel().GetOffsetsSize()
    }

    /// Returns the total bytes the MsgParcel can hold without reallocating.
    ///
    /// # Example
    /// ```rust
    /// use ipc::parcel::MsgParcel;
    ///
    /// let mut msg = MsgParcel::new();
    /// assert_eq!(0, msg.capacity());
    /// msg.write(&1i32);
    /// assert_eq!(64, msg.capacity());
    /// ```
    pub fn capacity(&self) -> usize {
        self.as_parcel().GetDataCapacity()
    }

    /// Returns the maximum capacity MsgParcel can allocate.
    ///
    /// # Example
    /// ```rust
    /// use ipc::parcel::MsgParcel;
    ///
    /// let msg = MsgParcel::new();
    /// assert_eq!(204800, msg.max_capacity());
    /// ```
    pub fn max_capacity(&self) -> usize {
        self.as_parcel().GetMaxCapacity()
    }

    /// Returns the write_position of the MsgPacel in bytes.
    ///
    /// # Example
    /// ```rust
    /// use ipc::parcel::MsgParcel;
    ///
    /// let mut msg = MsgParcel::new();
    /// assert_eq!(0, msg.write_position());
    /// msg.write(&1i32).unwrap();
    /// assert_eq!(4, msg.write_position());
    /// ```
    pub fn write_position(&mut self) -> usize {
        self.as_parcel_mut().GetWritePosition()
    }

    /// Returns the read_position of the MsgParcel in bytes.
    ///
    /// # Example
    /// ```rust
    /// use ipc::parcel::MsgParcel;
    ///
    /// let mut msg = MsgParcel::new();
    /// assert_eq!(0, msg.read_position());
    /// msg.write(&1i32).unwrap();
    /// assert_eq!(0, msg.read_position());
    /// msg.read::<i32>().unwrap();
    /// assert_eq!(4, msg.read_position());
    /// ```
    pub fn read_position(&mut self) -> usize {
        self.as_parcel_mut().GetReadPosition()
    }

    /// Changes the size of the MsgParcel.
    ///
    /// # Errors
    /// If new data size > capacity, set will fail.
    ///
    /// # Example
    /// ```rust
    /// use ipc::parcel::MsgParcel;
    ///
    /// let mut msg = MsgParcel::new();
    /// msg.write(&1i32);
    /// assert_eq!(4, msg.size());
    /// msg.set_size(0);
    /// assert_eq!(0, msg.size());
    /// ```
    pub fn set_size(&mut self, size: usize) -> Result<(), ParcelSetError> {
        if self.as_parcel_mut().SetDataSize(size) {
            Ok(())
        } else {
            Err(ParcelSetError)
        }
    }

    /// Changes the capacity of the MsgParcel.
    ///
    /// # Errors
    /// If data size > new capacity bytes, set will fail.
    ///
    /// # Example
    /// ```rust
    /// use ipc::parcel::MsgParcel;
    ///
    /// let msg = MsgParcel::new();
    /// msg.set_capacity(64).unwrap();
    /// assert_eq!(64, msg.capacity());
    /// ```
    pub fn set_capacity(&mut self, size: usize) -> Result<(), ParcelSetError> {
        if self.as_parcel_mut().SetDataCapacity(size) {
            Ok(())
        } else {
            Err(ParcelSetError)
        }
    }

    /// Changes the capacity of the MsgParcel.
    ///
    /// # Errors
    /// If new max capacity reach the limit, set will fail.
    ///
    /// # Example
    /// ```rust
    /// use ipc::parcel::MsgParcel;
    ///
    /// let mut msg = MsgParcel::new();
    /// msg.set_max_capacity(64).unwrap();
    /// ```
    pub fn set_max_capacity(&mut self, size: usize) -> Result<(), ParcelSetError> {
        if self.as_parcel_mut().SetMaxCapacity(size) {
            Ok(())
        } else {
            Err(ParcelSetError)
        }
    }

    /// Changes the read position of the MsgParcel.
    ///
    /// # Errors
    /// If new position > data size, set will fail.
    ///
    /// # Example
    /// ```rust
    /// use ipc::parcel::MsgParcel;
    ///
    /// let mut msg = MsgParcel::new();
    /// msg.write(&1i32).unwrap();
    /// msg.write(&2i32).unwrap();
    /// msg.set_read_position(4).unwrap();
    /// assert_eq!(2, msg.read().unwrap());
    /// ```
    pub fn set_read_position(&mut self, size: usize) -> Result<(), ParcelSetError> {
        if self.as_parcel_mut().RewindRead(size) {
            Ok(())
        } else {
            Err(ParcelSetError)
        }
    }

    /// Changes the write position of the MsgParcel.
    ///
    /// # Errors
    /// if new position > data size, set will fail
    ///
    /// # Example
    /// ```rust
    /// use ipc::parcel::MsgParcel;
    ///
    /// let mut msg = MsgParcel::new();
    /// msg.write(&1i32).unwrap();
    /// msg.write(&2i32).unwrap();
    /// msg.set_write_position(0);
    /// msg.write(&2i32).unwrap();
    /// assert_eq(2, msg.read().unwrap());
    /// ```
    pub fn set_write_position(&mut self, size: usize) -> Result<(), ParcelSetError> {
        if self.as_parcel_mut().RewindWrite(size) {
            Ok(())
        } else {
            Err(ParcelSetError)
        }
    }

    /// Skip read data in bytes of the MsgParcel
    ///
    /// # Errors
    /// if skip size > readable data the the read position will be the capacity.
    ///
    /// # Examples
    /// ```rust
    /// use ipc::parcel::MsgParcel;
    ///
    /// let mut msg = MsgParcel::new();
    /// msg.write(&1i32).unwrap();
    /// msg.write(&2i32).unwrap();
    /// msg.skip_read(4);
    /// assert_eq!(2, msg.read().unwrap());
    /// ```
    pub fn skip_read(&mut self, size: usize) {
        self.as_parcel_mut().SkipBytes(size)
    }

    fn as_msg_parcel_mut(&mut self) -> Pin<&mut MessageParcel> {
        match &mut self.inner {
            ParcelMem::Unique(p) => p.pin_mut(),
            ParcelMem::Borrow(p) => unsafe { Pin::new_unchecked(&mut **p) },
            _ => unreachable!(),
        }
    }

    fn as_parcel(&self) -> &Parcel {
        match &self.inner {
            ParcelMem::Unique(p) => unsafe {
                let parcel = AsParcel(p.as_ref().unwrap());
                &*parcel
            },
            ParcelMem::Borrow(p) => unsafe {
                let parcel = AsParcel(&**p);
                &*parcel
            },
            _ => unreachable!(),
        }
    }

    pub(crate) fn as_parcel_mut(&mut self) -> Pin<&mut Parcel> {
        match &mut self.inner {
            ParcelMem::Unique(p) => unsafe {
                let parcel = AsParcelMut(p.pin_mut());
                Pin::new_unchecked(&mut *parcel)
            },
            ParcelMem::Borrow(p) => unsafe {
                let parcel = AsParcelMut(Pin::new_unchecked(&mut **p));
                Pin::new_unchecked(&mut *parcel)
            },
            _ => unreachable!(),
        }
    }

    pub(crate) fn write_process<T>(
        &mut self,
        value: T,
        f: fn(parcel: Pin<&mut MessageParcel>, value: T) -> bool,
    ) -> IpcResult<()> {
        match mem::replace(&mut self.inner, ParcelMem::Null) {
            ParcelMem::Unique(mut p) => {
                let res = f(p.pin_mut(), value);
                self.inner = ParcelMem::Unique(p);
                match res {
                    true => Ok(()),
                    false => Err(IpcStatusCode::Failed),
                }
            }
            ParcelMem::Borrow(p) => {
                let w = unsafe { Pin::new_unchecked(&mut *p) };
                let res = f(w, value);
                self.inner = ParcelMem::Borrow(p);
                match res {
                    true => Ok(()),
                    false => Err(IpcStatusCode::Failed),
                }
            }
            ParcelMem::Null => IpcResult::Err(IpcStatusCode::Failed),
        }
    }

    pub(crate) fn read_process<T>(
        &mut self,
        f: fn(parcel: Pin<&mut MessageParcel>) -> IpcResult<T>,
    ) -> IpcResult<T> {
        match mem::replace(&mut self.inner, ParcelMem::Null) {
            ParcelMem::Unique(mut p) => {
                let res = f(p.pin_mut());
                self.inner = ParcelMem::Unique(p);
                res
            }
            ParcelMem::Borrow(p) => {
                let w = unsafe { Pin::new_unchecked(&mut *p) };
                let res = f(w);
                self.inner = ParcelMem::Borrow(p);
                res
            }
            ParcelMem::Null => IpcResult::Err(IpcStatusCode::Failed),
        }
    }

    pub fn pin_mut(&mut self) -> Option<Pin<&mut MessageParcel>> {
        match &mut self.inner {
            ParcelMem::Unique(p) => Some(p.pin_mut()),
            _ => None,
        }
    }

    fn get_pad_size(size: usize) -> usize {
        const SIZE_OFFSET: usize = 3;
        ((size + SIZE_OFFSET) & (!SIZE_OFFSET)) - size
    }
}

/// Ipc MsgOption used when send request, including some settings.
pub struct MsgOption {
    pub(crate) inner: UniquePtr<MessageOption>,
}

impl MsgOption {
    const TF_SYNC: i32 = 0x00;
    const TF_ASYNC: i32 = 0x01;

    /// Creates a new, empty MsgOption.

    /// # Panics
    /// Panics if allocate failed.
    ///
    /// # Examples
    /// ```rust
    /// use ipc::parcel::MsgOption;
    ///
    /// let msg = MsgOption::new();
    /// ```
    pub fn new() -> Self {
        let ptr = NewMessageOption();
        assert!(!ptr.is_null(), "memory allocation of MessageOption failed");

        Self {
            inner: NewMessageOption(),
        }
    }

    /// Set send to be async.
    pub fn set_async(&mut self) {
        self.inner.pin_mut().SetFlags(Self::TF_ASYNC);
    }

    /// Sets send to be sync.
    pub fn set_sync(&mut self) {
        self.inner.pin_mut().SetFlags(Self::TF_SYNC);
    }

    /// Return true if has set to async.
    pub fn is_async(&self) -> bool {
        self.inner.GetFlags() == Self::TF_ASYNC
    }
}

impl Default for MsgParcel {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for MsgOption {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test {
    use std::mem;

    use super::MsgParcel;

    /// UT test cases for `GetDataSize`
    ///
    /// # Brief
    /// 1. Creates a MsgParcel
    /// 2. Writes a value to the MsgParcel and then check its data size.
    #[test]
    fn parcel_size() {
        let mut msg = MsgParcel::new();
        let mut size = 0;

        msg.write(&1i8).unwrap();
        size += mem::size_of::<i32>();
        assert_eq!(size, msg.size());

        msg.write(&1i16).unwrap();
        size += mem::size_of::<i32>();
        assert_eq!(size, msg.size());

        msg.write(&1i32).unwrap();
        size += mem::size_of::<i32>();
        assert_eq!(size, msg.size());

        msg.write(&1i64).unwrap();
        size += mem::size_of::<i64>();
        assert_eq!(size, msg.size());

        msg.write(&1u8).unwrap();
        size += mem::size_of::<u32>();
        assert_eq!(size, msg.size());

        msg.write(&1u16).unwrap();
        size += mem::size_of::<u32>();
        assert_eq!(size, msg.size());

        msg.write(&1u32).unwrap();
        size += mem::size_of::<u32>();
        assert_eq!(size, msg.size());

        msg.write(&1u64).unwrap();
        size += mem::size_of::<u64>();
        assert_eq!(size, msg.size());

        msg.write(&true).unwrap();
        size += mem::size_of::<i32>();
        assert_eq!(size, msg.size());
    }

    /// UT test cases for read_to_end
    ///
    /// # Brief
    /// 1. Creates a new MsgParcel.
    /// 3. Write a bool and read it out.
    /// 2. write a vector into this MsgParcel, and read_to_end check the
    ///    correctness.
    #[test]
    fn read_to_end() {
        let mut msg = MsgParcel::new();
        msg.write(&true).unwrap();
        msg.read::<bool>().unwrap();

        msg.write(&vec![1, 2, 3]).unwrap();
        assert_eq!(
            vec![3, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0],
            msg.read_buffer(msg.readable()).unwrap()
        );
    }
}
