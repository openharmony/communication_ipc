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
        let ok_status = unsafe {
            // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
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

/// Callback to serialize a String16 array to c++ std::vector<std::u16string>.
///
/// Safety: We are relying on c interface to not overrun our slice. As long
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
