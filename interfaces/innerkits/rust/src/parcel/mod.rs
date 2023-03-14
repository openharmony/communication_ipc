/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

pub mod parcelable;
pub mod types;

pub use types::on_string16_writer;
pub use types::vec_u16_to_string;
pub use types::vec_to_string;
pub use parcelable::allocate_vec_with_buffer;

use crate::{ipc_binding, IpcResult, IpcStatusCode};
use crate::ipc_binding::{CParcel};
use std::marker::PhantomData;
use std::mem::{ManuallyDrop,MaybeUninit};
use std::ops::{Drop};
use std::ptr::{NonNull};
use std::slice;
use crate::AsRawPtr;
use crate::parcel::parcelable::{Serialize, Deserialize};

/// This trait implements the common function for MsgParcel
/// and BorrowedMsgParcel
pub trait IMsgParcel: AsRawPtr<CParcel> {
    /// Get current data size in parcel
    fn get_data_size(&self) -> u32 {
        unsafe {
            ipc_binding::CParcelGetDataSize(self.as_raw())
        }
    }

    /// Set current data size in parcel
    fn set_data_size(&mut self, new_size: u32) -> bool {
        unsafe {
            ipc_binding::CParcelSetDataSize(self.as_mut_raw(), new_size)
        }
    }

    /// Get current data capacity in parcel
    fn get_data_capacity(&self) -> u32 {
        unsafe {
            ipc_binding::CParcelGetDataCapacity(self.as_raw())
        }
    }

    /// Set current data capacity in parcel
    fn set_data_capacity(&mut self, new_size: u32) -> bool {
        unsafe {
            ipc_binding::CParcelSetDataCapacity(self.as_mut_raw(), new_size)
        }
    }

    /// Get maximum capacity in parcel
    fn get_max_capacity(&self) -> u32 {
        unsafe {
            ipc_binding::CParcelGetMaxCapacity(self.as_raw())
        }
    }

    /// Set maximum capacity in parcel
    fn set_max_capacity(&mut self, new_size: u32) -> bool {
        unsafe {
            ipc_binding::CParcelSetMaxCapacity(self.as_mut_raw(), new_size)
        }
    }

    /// Get current writalbe bytes in parcel
    fn get_writable_bytes(&self) -> u32 {
        unsafe {
            ipc_binding::CParcelGetWritableBytes(self.as_raw())
        }
    }

    /// Get current readable bytes in parcel
    fn get_readable_bytes(&self) -> u32 {
        unsafe {
            ipc_binding::CParcelGetReadableBytes(self.as_raw())
        }
    }

    /// Get current read position of parcel
    fn get_read_position(&self) -> u32 {
        unsafe {
            ipc_binding::CParcelGetReadPosition(self.as_raw())
        }
    }

    /// Get current write position of parcel
    fn get_write_position(&self) -> u32 {
        unsafe {
            ipc_binding::CParcelGetWritePosition(self.as_raw())
        }
    }

    /// Rewind the read position to a new position of parcel
    fn rewind_read(&mut self, new_pos: u32) -> bool {
        unsafe {
            ipc_binding::CParcelRewindRead(self.as_mut_raw(), new_pos)
        }
    }

    /// Rewind the write position to a new position of parcel
    fn rewind_write(&mut self, new_pos: u32) -> bool {
        unsafe {
            ipc_binding::CParcelRewindWrite(self.as_mut_raw(), new_pos)
        }
    }

    /// Write a bytes stream into parcel
    fn write_buffer(&mut self, data: &[u8]) -> bool {
        // SAFETY:
        unsafe {
            ipc_binding::CParcelWriteBuffer(self.as_mut_raw(),
                data.as_ptr(), data.len() as u32)
        }
    }

    /// Read a sized bytes stream from parcel
    fn read_buffer(&self, len: u32) -> IpcResult<Vec<u8>> {
        let mut buffer: Vec<MaybeUninit<u8>> = Vec::with_capacity(len as usize);
        // SAFETY: this is safe because the vector contains MaybeUninit elements which can be uninitialized
        unsafe{
            buffer.set_len(len as usize);
        }

        let ok_status = unsafe {
            ipc_binding::CParcelReadBuffer(
                self.as_raw(),
                buffer.as_mut_ptr() as *mut u8,
                len
            )
        };
        // SAFETY: MaybeUninit has been initialized, this should be safe
        // since MaybeUninit should have same layout as inner type
        unsafe fn transmute_vec(v: Vec<std::mem::MaybeUninit<u8>>) -> Vec<u8> {
            std::mem::transmute(v)
        }
        let buffer = unsafe { transmute_vec(buffer) };
        if ok_status { Ok(buffer) } else { Err(IpcStatusCode::Failed) }
    }

    /// Write a large bytes stream into parcel
    fn write_raw_data(&mut self, data: &[u8]) -> bool {
        // SAFETY:
        unsafe {
            ipc_binding::CParcelWriteRawData(self.as_mut_raw(),
                data.as_ptr(), data.len() as u32)
        }
    }

    /// Read a big bytes stream from parcel
    fn read_raw_data(&self, len: u32) -> IpcResult<RawData> {
        let raw_data_ptr = unsafe {
            ipc_binding::CParcelReadRawData(self.as_raw(), len)
        };
        if raw_data_ptr.is_null() {
            Err(IpcStatusCode::Failed)
        } else {
            Ok(RawData::new(raw_data_ptr, len))
         }
    }

    /// contain file descriptors
    fn has_fd(&self) -> bool {
        unsafe {
            ipc_binding::CParcelContainFileDescriptors(self.as_raw())
        }
    }

    /// clear file descriptor
    fn clear_fd(&mut self) {
        unsafe {
            ipc_binding::CParcelClearFileDescriptor(self.as_mut_raw());
        }
    }

    /// get raw data size
    fn get_raw_data_size(&self) -> usize {
        unsafe {
            ipc_binding::CParcelGetRawDataSize(self.as_raw())
        }
    }

    /// get raw data capacity
    fn get_raw_data_capacity(&self) -> usize {
        unsafe {
            ipc_binding::CParcelGetRawDataCapacity(self.as_raw())
        }
    }

    /// set clear fd flag
    fn set_clear_fd_flag(&mut self) {
        unsafe {
            ipc_binding::CParcelSetClearFdFlag(self.as_mut_raw());
        }
    }

    /// append a MsgParcel
    fn append(&mut self, data: &mut MsgParcel) -> bool {
        let data_parcel = data.as_mut_raw();
        unsafe {
            ipc_binding::CParcelAppend(self.as_mut_raw(), data_parcel)
        }
    }
}

/// Rust RawData type which just for fetch data from C++ MssageParcel::ReadRawData()
#[repr(C)]
pub struct RawData{
    raw_ptr: *const u8,
    len: u32,
}

impl RawData{
    /// Create RawData object
    pub fn new(raw_ptr: *const u8, len: u32) -> Self {
        RawData {
            raw_ptr,
            len,
        }
    }

    /// The caller should ensure that the u8 slice can be
    /// correctly converted to other rust types
    pub fn read(&self, start: u32, len: u32) -> IpcResult<&[u8]> {
        if len == 0 || len > self.len || start >= self.len || (start + len) > self.len {
            return Err(IpcStatusCode::Failed);
        }

        let data_ptr = unsafe {
            // SAFETY: raw_ptr is valid in [0..len], the memory is matained by C++ Parcel.
            self.raw_ptr.add(start as usize)
        };
        if !data_ptr.is_null() {
            // SAFETY:
            // 1. data is valid for reads for `len * mem::size_of::<u8>() `
            // 2. The entire memory range of this slice be contained within a single allocated object (From Cpp)
            // 3. data_ptr point to len consecutive properly initialized values of `u8`
            // 4. The total size `len * mem::size_of::<u8>()` of the slice is no larger than `isize::MAX`
            unsafe {
                Ok(slice::from_raw_parts::<u8>(data_ptr, len as usize))
            }
        } else {
            Err(IpcStatusCode::Failed)
        }
    }
}


/// Container for a message (data and object references) that can be sent
/// through Binder.
///
/// This type represents a parcel that is owned by Rust code.
#[repr(transparent)]
pub struct MsgParcel {
    ptr: NonNull<CParcel>,
}

unsafe impl Send for MsgParcel {}

impl IMsgParcel for MsgParcel {}

impl MsgParcel {
    /// Create a MsgParcel object
    pub fn new() -> Option<Self> {
        let cparcel: *mut CParcel = unsafe {
            ipc_binding::CParcelObtain()
        };

        NonNull::new(cparcel).map(|x| MsgParcel{ptr: x})
    }

    /// # Safety
    pub unsafe fn from_raw(ptr: *mut CParcel) -> Option<MsgParcel> {
        NonNull::new(ptr).map(|ptr| Self { ptr })
    }

    /// Get a raw CParcel pointer and MsgParcel dropped its ownership
    pub fn into_raw(self) -> *mut CParcel {
        let ptr = self.ptr.as_ptr();
        let _ = ManuallyDrop::new(self);
        ptr
    }

    /// Get a borrowed view into the contents of this `MsgParcel`.
    pub fn borrowed(&mut self) -> BorrowedMsgParcel<'_> {
        // SAFETY: The raw pointer is a valid pointer
        BorrowedMsgParcel {
            ptr: self.ptr,
            _mark: PhantomData,
        }
    }

    /// Get an immutable borrowed view into the contents of this `MsgParcel`.
    pub fn borrowed_ref(&self) -> &BorrowedMsgParcel<'_> {
        // Safety: MsgParcel and BorrowedParcel are both represented in the same
        // way as a NonNull<CParcel> due to their use of repr(transparent),
        // so casting references as done here is valid.
        unsafe {
            &*(self as *const MsgParcel as *const BorrowedMsgParcel<'_>)
        }
    }
}

/// # Safety
///
/// The `MsgParcel` constructors guarantee that a `MsgParcel` object will always
/// contain a valid pointer to an `CParcel`.
unsafe impl AsRawPtr<CParcel> for MsgParcel {
    fn as_raw(&self) -> *const CParcel {
        self.ptr.as_ptr()
    }

    fn as_mut_raw(&mut self) -> *mut CParcel {
        self.ptr.as_ptr()
    }
}

impl Drop for MsgParcel {
    fn drop(&mut self) {
        unsafe {
            ipc_binding::CParcelDecStrongRef(self.as_mut_raw())
        }
    }
}

/// Container for a message (data and object references) that can be sent
/// through Binder.
///
/// This object is a borrowed variant of [`MsgParcel`]
#[repr(transparent)]
pub struct BorrowedMsgParcel<'a> {
    ptr: NonNull<CParcel>,
    _mark: PhantomData<&'a mut MsgParcel>,
}

impl<'a> IMsgParcel for BorrowedMsgParcel<'a> {}

impl<'a> BorrowedMsgParcel<'a> {

    /// # Safety
    ///
    /// `*mut CParcel` must be a valid pointer
    pub unsafe fn from_raw(ptr: *mut CParcel) -> Option<BorrowedMsgParcel<'a>> {
        Some(Self {
            ptr: NonNull::new(ptr)?,
            _mark: PhantomData,
        })
    }

    /// Get a sub-reference to this reference to the parcel.
    pub fn reborrow(&mut self) -> BorrowedMsgParcel<'_> {
        BorrowedMsgParcel {
            ptr: self.ptr,
            _mark: PhantomData,
        }
    }
}

/// # Safety
///
/// The `BorrowedMsgParcel` constructors guarantee that a `BorrowedMsgParcel` object
/// will always contain a valid pointer to an `CParcel`.
unsafe impl<'a> AsRawPtr<CParcel> for BorrowedMsgParcel<'a> {
    fn as_raw(&self) -> *const CParcel {
        self.ptr.as_ptr()
    }

    fn as_mut_raw(&mut self) -> *mut CParcel {
        self.ptr.as_ptr()
    }
}

impl MsgParcel {
    /// Read a data object which implements the Deserialize trait from MsgParcel
    pub fn read<D: Deserialize>(&self) -> IpcResult<D> {
        self.borrowed_ref().read()
    }

    /// Write a data object which implements the Serialize trait to MsgParcel
    pub fn write<S: Serialize + ?Sized>(&mut self, parcelable: &S) -> IpcResult<()> {
        self.borrowed().write(parcelable)
    }
}

impl<'a> BorrowedMsgParcel<'a> {
    /// Read a data object which implements the Deserialize trait from BorrowedMsgParcel
    pub fn read<D: Deserialize>(&self) -> IpcResult<D> {
        D::deserialize(self)
    }

    /// Write a data object which implements the Serialize trait to BorrowedMsgParcel
    pub fn write<S: Serialize + ?Sized>(&mut self, parcelable: &S) -> IpcResult<()> {
        parcelable.serialize(self)
    }
}