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

use crate::{IpcResult, IpcStatusCode, status_result, BorrowedMsgParcel, ipc_binding, AsRawPtr};
use std::mem::MaybeUninit;
use std::ffi::{c_void, c_ulong};
use std::ptr;

/// Implement `Serialize` trait to serialize a custom MsgParcel.
///
/// # Example:
///
/// ```ignore
/// struct Year(i64);
///
/// impl Serialize for Year {
///     fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> IpcResult<()> {
///         parcel::write(self.0);
///     }
/// }
/// ```
pub trait Serialize {
    /// Serialize Self to BorrowedMsgParcel
    fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> IpcResult<()>;
}

/// Implement `Deserialize` trait to deserialize a custom MsgParcel.
///
/// # Example:
///
/// ```ignore
/// struct Year(i64);
///
/// impl Deserialize for Year {
///     fn deserialize(parcel: &mut BorrowedMsgParcel<'_>) -> IpcResult<Self> {
///         let i = parcel::read::<i64>(parcel);
///         Ok(Year(i))
///     }
/// }
/// ```
pub trait Deserialize: Sized {
    /// Deserialize an instance from the given [`Parcel`].
    fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> IpcResult<Self>;
}

pub const NULL_FLAG : i32 = 0;
pub const NON_NULL_FLAG : i32 = 1;

/// Define trait function for Option<T> which T must implements the trait Serialize.
pub trait SerOption: Serialize {
    /// Serialize the Option<T>
    fn ser_option(this: Option<&Self>, parcel: &mut BorrowedMsgParcel<'_>) -> IpcResult<(), > {
        if let Some(inner) = this {
            parcel.write(&NON_NULL_FLAG)?;
            parcel.write(inner)
        } else {
            parcel.write(&NULL_FLAG)
        }
    }
}

/// Define trait function for Option<T> which T must implements the trait Deserialize.
pub trait DeOption: Deserialize {
    /// Deserialize the Option<T>
    fn de_option(parcel: &BorrowedMsgParcel<'_>) -> IpcResult<Option<Self>> {
        let null: i32 = parcel.read()?;
        if null == NULL_FLAG {
            Ok(None)
        } else {
            parcel.read().map(Some)
        }
    }
}

/// Callback to allocate a vector for parcel array read functions.
///
/// # Safety
///
/// The opaque data pointer passed to the array read function must be a mutable
/// pointer to an `Option<Vec<MaybeUninit<T>>>`.
pub unsafe extern "C" fn allocate_vec_with_buffer<T>(
    value: *mut c_void,
    buffer: *mut *mut T,
    len: i32
) -> bool {
    let res = allocate_vec::<T>(value, len);
    // `buffer` will be assigned a mutable pointer to the allocated vector data
    // if this function returns true.
    let vec = &mut *(value as *mut Option<Vec<MaybeUninit<T>>>);
    if let Some(new_vec) = vec {
        *buffer = new_vec.as_mut_ptr() as *mut T;
    }
    res
}

/// Callback to allocate a vector for parcel array read functions.
///
/// # Safety
///
/// The opaque data pointer passed to the array read function must be a mutable
/// pointer to an `Option<Vec<MaybeUninit<T>>>`.
unsafe extern "C" fn allocate_vec<T>(
    value: *mut c_void,
    len: i32,
) -> bool {
    if len < 0 {
        return true;
    }
    allocate_vec_maybeuninit::<T>(value, len as u32);
    true
}

/// Helper trait for types that can be serialized as arrays.
/// Defaults to calling Serialize::serialize() manually for every element,
/// but can be overridden for custom implementations like `writeByteArray`.
// Until specialization is stabilized in Rust, we need this to be a separate
// trait because it's the only way to have a default implementation for a method.
// We want the default implementation for most types, but an override for
// a few special ones like `readByteArray` for `u8`.
pub trait SerArray: Serialize + Sized {
    /// Default array serialize implement.
    fn ser_array(slice: &[Self], parcel: &mut BorrowedMsgParcel<'_>) -> IpcResult<()> {
        let ret = unsafe {
            // SAFETY: Safe FFI, slice will always be a safe pointer to pass.
            ipc_binding::CParcelWriteParcelableArray(
                parcel.as_mut_raw(),
                slice.as_ptr() as *const c_void,
                slice.len().try_into().unwrap(),
                ser_element::<Self>,
            )
        };
        status_result::<()>(ret as i32, ())
    }
}

/// Callback to serialize an element of a generic parcelable array.
///
/// Safety: We are relying on c interface to not overrun our slice. As long
/// as it doesn't provide an index larger than the length of the original
/// slice in serialize_array, this operation is safe. The index provided
/// is zero-based.
#[allow(dead_code)]
pub(crate) unsafe extern "C" fn ser_element<T: Serialize>(
    parcel: *mut ipc_binding::CParcel,
    array: *const c_void,
    index: c_ulong,
) -> bool {
    // c_ulong and usize are the same, but we need the explicitly sized version
    // so the function signature matches what bindgen generates.
    let index = index as usize;

    let slice: &[T] = std::slice::from_raw_parts(array.cast(), index+1);

    let mut parcel = match BorrowedMsgParcel::from_raw(parcel) {
        None => return false,
        Some(p) => p,
    };
    slice[index].serialize(&mut parcel).is_ok()
}

/// Helper trait for types that can be deserialized as arrays.
/// Defaults to calling Deserialize::deserialize() manually for every element,
/// but can be overridden for custom implementations like `readByteArray`.
pub trait DeArray: Deserialize {
    /// Deserialize an array of type from the given parcel.
    fn de_array(parcel: &BorrowedMsgParcel<'_>) -> IpcResult<Option<Vec<Self>>> {
        let mut vec: Option<Vec<MaybeUninit<Self>>> = None;
        let ok_status = unsafe {
            // SAFETY: Safe FFI, vec is the correct opaque type expected by
            // allocate_vec and de_element.
            ipc_binding::CParcelReadParcelableArray(
                parcel.as_raw(),
                &mut vec as *mut _ as *mut c_void,
                allocate_vec::<Self>,
                de_element::<Self>,
            )
        };

        if ok_status{
            let vec: Option<Vec<Self>> = unsafe {
                // SAFETY: We are assuming that the C-API correctly initialized every
                // element of the vector by now, so we know that all the
                // MaybeUninits are now properly initialized. We can transmute from
                // Vec<MaybeUninit<T>> to Vec<T> because MaybeUninit<T> has the same
                // alignment and size as T, so the pointer to the vector allocation
                // will be compatible.
                std::mem::transmute(vec)
            };
            Ok(vec)
        } else {
            Err(IpcStatusCode::Failed)
        }
    }
}

/// Callback to deserialize a parcelable element.
///
/// The opaque array data pointer must be a mutable pointer to an
/// `Option<Vec<MaybeUninit<T>>>` with at least enough elements for `index` to be valid
/// (zero-based).
#[allow(dead_code)]
unsafe extern "C" fn de_element<T: Deserialize>(
    parcel: *const ipc_binding::CParcel,
    array: *mut c_void,
    index: c_ulong,
) -> bool {
    // c_ulong and usize are the same, but we need the explicitly sized version
    // so the function signature matches what bindgen generates.
    let index = index as usize;

    let vec = &mut *(array as *mut Option<Vec<MaybeUninit<T>>>);
    let vec = match vec {
        Some(v) => v,
        None => return false,
    };
    let parcel = match BorrowedMsgParcel::from_raw(parcel as *mut _) {
        None => return false,
        Some(p) => p,
    };
    let element = match parcel.read() {
        Ok(e) => e,
        Err(_) => return false,
    };
    ptr::write(vec[index].as_mut_ptr(), element);
    true
}

/// Safety: All elements in the vector must be properly initialized.
pub unsafe fn vec_assume_init<T>(vec: Vec<MaybeUninit<T>>) -> Vec<T> {
    // We can convert from Vec<MaybeUninit<T>> to Vec<T> because MaybeUninit<T>
    // has the same alignment and size as T, so the pointer to the vector
    // allocation will be compatible.
    let mut vec = std::mem::ManuallyDrop::new(vec);
    Vec::from_raw_parts(
        vec.as_mut_ptr().cast(),
        vec.len(),
        vec.capacity(),
    )
}

pub(crate) unsafe fn allocate_vec_maybeuninit<T>(
    value: *mut c_void,
    len: u32,
) {
    let vec = &mut *(value as *mut Option<Vec<MaybeUninit<T>>>);
    let mut new_vec: Vec<MaybeUninit<T>> = Vec::with_capacity(len as usize);

    // SAFETY: this is safe because the vector contains MaybeUninit elements which can be uninitialized
    new_vec.set_len(len as usize);
    ptr::write(vec, Some(new_vec));
}