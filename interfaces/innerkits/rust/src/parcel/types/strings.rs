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
use crate::{
    ipc_binding, BorrowedMsgParcel, Result, result_status,
    AsRawPtr
};
use std::ptr;
use std::convert::TryInto;
use std::ffi::{c_char, c_void};

impl SerOption for str {
    fn ser_option(this: Option<&Self>, parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
        // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
        match this {
            None => {
                let ret = unsafe {
                    ipc_binding::CParcelWriteString(parcel.as_mut_raw(), ptr::null(), -1)
                };
                result_status::<()>(ret, ())
            },
            Some(s) => {
                let ret = unsafe {
                    ipc_binding::CParcelWriteString(
                        parcel.as_mut_raw(), 
                        s.as_ptr() as *const c_char,
                        s.as_bytes().len().try_into().unwrap()  
                    )};
                result_status::<()>(ret, ())
            },
        }
    }
}

impl Serialize for str {
    fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
        Some(self).serialize(parcel)
    }
}

impl Serialize for String {
    fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
        Some(self.as_str()).serialize(parcel)
    }
}

impl SerOption for String {
    fn ser_option(this: Option<&Self>, parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
        SerOption::ser_option(this.map(String::as_str), parcel)
    }
}

impl Deserialize for Option<String> {
    fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> Result<Self> {
        let mut vec: Option<Vec<u8>> = None;
        let ok_status = unsafe {
            // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
            ipc_binding::CParcelReadString(
                parcel.as_raw(), 
                &mut vec as *mut _ as *mut c_void,
                allocate_vec_with_buffer::<u8>
            )
        };

        if ok_status {
            vec.map(|s| {
                // The vector includes a null-terminator and 
                // we don't want the string to be null-terminated for Rust.
                String::from_utf8(s).or(Err(-1))
            })
            .transpose()
        }else{
            Err(-1)
        }
    }
}

impl Deserialize for String {
    fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> Result<Self> {
        Deserialize::deserialize(parcel)
            .transpose()
            .unwrap_or(Err(-1))
    }
}
