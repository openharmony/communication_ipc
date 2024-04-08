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

//! IPC process

use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::ptr;

use crate::skeleton::ffi::IsHandlingTransaction;

/// Determine whether the current thread is currently executing an incoming
/// transaction.
#[inline]
pub fn is_handling_transaction() -> bool {
    // SAFETY:
    // Ensure proper usage within the context of the IPC binding system and its
    // intended behavior.
    IsHandlingTransaction()
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
    len: i32,
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
unsafe extern "C" fn allocate_vec<T>(value: *mut c_void, len: i32) -> bool {
    if len < 0 {
        return false;
    }
    allocate_vec_maybeuninit::<T>(value, len as u32);
    true
}

/// # Safety
///
/// Ensure that the value pointer is not null
pub(crate) unsafe fn allocate_vec_maybeuninit<T>(value: *mut c_void, len: u32) {
    let vec = &mut *(value as *mut Option<Vec<MaybeUninit<T>>>);
    let mut new_vec: Vec<MaybeUninit<T>> = Vec::with_capacity(len as usize);

    // SAFETY: this is safe because the vector contains MaybeUninit elements which
    // can be uninitialized
    new_vec.set_len(len as usize);
    ptr::write(vec, Some(new_vec));
}
