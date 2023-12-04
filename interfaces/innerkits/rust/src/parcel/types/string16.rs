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

use super::*;
use crate::{ipc_binding, BorrowedMsgParcel, IpcResult, IpcStatusCode, status_result, AsRawPtr};
use std::convert::TryInto;
use std::mem::MaybeUninit;
use std::ffi::{CString};
use hilog_rust::{error, hilog, HiLogLabel, LogType};

const LOG_LABEL: HiLogLabel = HiLogLabel {
    log_type: LogType::LogCore,
    domain: 0xd001510,
    tag: "RustString16"
};

/// String16 packed a String type which transfered with C++ std::u16string.
pub struct String16(String);

impl String16 {
    /// Create a String16 object with rust String
    pub fn new(value: &str) -> Self {
        Self(String::from(value))
    }

    /// Get packed String of String16
    pub fn get_string(&self) -> String {
        String::from(&self.0)
    }
}

impl Serialize for String16 {
    fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> IpcResult<()> {
        let string = &self.0;
        // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
        let ret = unsafe {
            ipc_binding::CParcelWriteString16(
                parcel.as_mut_raw(),
                string.as_ptr() as *const c_char,
                string.as_bytes().len().try_into().unwrap()
            )};
        status_result::<()>(ret as i32, ())
    }
}

impl Deserialize for String16 {
    fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> IpcResult<Self> {
        let mut vec: Option<Vec<u8>> = None;
        // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
        let ok_status = unsafe {
            ipc_binding::CParcelReadString16(
                parcel.as_raw(),
                &mut vec as *mut _ as *mut c_void,
                allocate_vec_with_buffer::<u8>
            )
        };

        if ok_status {
            let result = vec.map(|s| {
                match String::from_utf8(s) {
                    Ok(val) => val,
                    Err(_) => String::from("")
                }
            });
            if let Some(val) = result {
                Ok(Self(val))
            } else {
                error!(LOG_LABEL, "convert native string16 to String fail");
                Err(IpcStatusCode::Failed)
            }
        } else {
            error!(LOG_LABEL, "read string16 from native fail");
            Err(IpcStatusCode::Failed)
        }
    }
}

impl SerArray for String16 {
    fn ser_array(slice: &[Self], parcel: &mut BorrowedMsgParcel<'_>) -> IpcResult<()> {
        // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
        let ret = unsafe {
            ipc_binding::CParcelWriteString16Array(
                parcel.as_mut_raw(),
                slice.as_ptr() as *const c_void,
                slice.len().try_into().unwrap(),
                on_string16_writer,
            )
        };
        status_result::<()>(ret as i32, ())
    }
}

impl DeArray for String16 {
    fn de_array(parcel: &BorrowedMsgParcel<'_>) -> IpcResult<Option<Vec<Self>>> {
        let mut vec: Option<Vec<MaybeUninit<Self>>> = None;
        // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
        // `allocate_vec<T>` expects the opaque pointer to
        // be of type `*mut Option<Vec<MaybeUninit<T>>>`, so `&mut vec` is
        // correct for it.
        let ok_status = unsafe {
            ipc_binding::CParcelReadString16Array(
                parcel.as_raw(),
                &mut vec as *mut _ as *mut c_void,
                on_string16_reader,
            )
        };
        if ok_status {
            // SAFETY: all the MaybeUninits are now properly initialized.
            let vec: Option<Vec<Self>> = unsafe {
                vec.map(|vec| vec_assume_init(vec))
            };
            Ok(vec)
        } else {
            error!(LOG_LABEL, "read string16 from native fail");
            Err(IpcStatusCode::Failed)
        }
    }
}
/// Callback to serialize a String16 array to c++ std::vector<std::u16string>.
///
/// # Safety:
///
/// We are relying on c interface to not overrun our slice. As long
/// as it doesn't provide an index larger than the length of the original
/// slice in ser_array, this operation is safe. The index provided
/// is zero-based.
#[allow(dead_code)]
pub unsafe extern "C" fn on_string16_writer(
    array: *const c_void, // C++ vector pointer
    value: *mut c_void, // Rust slice pointer
    len: u32,
) -> bool {
    if len == 0 {
        return false;
    }
    let len = len as usize;
    let slice: &[String16] = std::slice::from_raw_parts(value.cast(), len);

    for item in slice.iter().take(len) {
        // SAFETY:
        let ret = unsafe {
            ipc_binding::CParcelWritU16stringElement(
                array,
                item.0.as_ptr() as *const c_char,
                item.0.as_bytes().len().try_into().unwrap())
        };
        if !ret {
            return false;
        }
    }
    true
}

/// Callback to deserialize a String element in Vector<String16>.
///
/// # Safety:
///
/// The opaque array data pointer must be a mutable pointer to an
/// `Option<Vec<MaybeUninit<T>>>` with at least enough elements for `index` to be valid
/// (zero-based).
#[allow(dead_code)]
unsafe extern "C" fn on_string16_reader(
    data: *const c_void, // C++ vector pointer
    value: *mut c_void, // Rust vector pointer
    len: u32, // C++ vector length
) -> bool {
    // SAFETY:
    // Allocate Vec<String16> capacity, data_len will set correctly by vec.push().
    unsafe { allocate_vec_maybeuninit::<String16>(value, 0) };
    let vec = &mut *(value as *mut Option<Vec<MaybeUninit<String16>>>);
    for index in 0..len {
        let mut vec_u16: Option<Vec<u16>> = None;
        // SAFETY: The length of the index will not exceed the range,
        // as the traversal range is the pointer length of the data passed from the C++side
        let ok_status = unsafe {
            ipc_binding::CParcelReadString16Element(
                index,
                data,
                &mut vec_u16 as *mut _ as *mut c_void,
                allocate_vec_with_buffer::<u16>
            )
        };
        if ok_status {
            if let Ok(string) = vec_u16_to_string(vec_u16) {
                if let Some(new_vec) = vec {
                    new_vec.push(MaybeUninit::new(String16::new(string.as_str())));
                } else {
                    error!(LOG_LABEL, "on_string_reader allocate vec failed");
                    return false;
                }
            } else {
                error!(LOG_LABEL, "on_string_reader vec_to_string failed");
                return false;
            }
        } else {
            return false;
        }
    }
    true
}