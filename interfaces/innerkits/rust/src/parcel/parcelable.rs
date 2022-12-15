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

use crate::{Result, BorrowedMsgParcel};
use std::mem::MaybeUninit;
use std::ffi::c_void;
use std::ptr;

// Internal use 
pub(crate) trait Parcelable {
    fn marshalling(&self, parcel: &mut BorrowedMsgParcel<'_>) -> Result<()>;
    fn unmarshalling(parcel: &BorrowedMsgParcel<'_>) -> Result<()>;
}

/// Implement `Serialize` trait to serialize a custom MsgParcel.
/// 
/// # Example:
/// 
/// ```ignore
/// struct Year(i64);
///
/// impl Serialize for Year {
///     fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
///         parcel::write(self.0);
///     }
/// }
/// ```
pub trait Serialize {
    fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> Result<()>;
}

/// Implement `Deserialize` trait to deserialize a custom MsgParcel.
/// 
/// # Example:
/// 
/// ```ignore
/// struct Year(i64);
///
/// impl Deserialize for Year {
///     fn deserialize(parcel: &mut BorrowedMsgParcel<'_>) -> Result<Self> {
///         let i = parcel::read::<i64>(parcel);
///         Ok(Year(i))
///     }
/// }
/// ```
pub trait Deserialize: Sized {
    /// Deserialize an instance from the given [`Parcel`].
    fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> Result<Self>;
}

pub const NULL_FLAG : i32 = 0;
pub const NON_NULL_FLAG : i32 = 1;
 
// DOC TODO
pub trait SerOption: Serialize {

    fn ser_option(this: Option<&Self>, parcel: &mut BorrowedMsgParcel<'_>) -> Result<(), > {
        if let Some(inner) = this {
            parcel.write(&NON_NULL_FLAG)?;
            parcel.write(inner)
        } else {
            parcel.write(&NULL_FLAG)
        }
    }
}

// DOC TODO
pub trait DeSerOption: Deserialize {

    fn de_option(parcel: &BorrowedMsgParcel<'_>) -> Result<Option<Self>> {
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
    println!("allocate_vec_with_buffer, len: {}", len);
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
    let vec = &mut *(value as *mut Option<Vec<MaybeUninit<T>>>);
    if len < 0 {
        *vec = None;
        return true;
    }
    let mut new_vec: Vec<MaybeUninit<T>> = Vec::with_capacity(len as usize);

    // SAFETY: this is safe because the vector contains MaybeUninit elements which can be uninitialized
    new_vec.set_len(len as usize);
    ptr::write(vec, Some(new_vec));
    true
}

// DOC TODO
pub trait SerArray: Serialize + Sized {
    fn ser_array(slice: &[Self], parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> ;
}

// DOC TODO
pub trait DeArray: Deserialize {
    fn de_array(parcel: &BorrowedMsgParcel<'_>) -> Result<Option<Vec<Self>>>;
}