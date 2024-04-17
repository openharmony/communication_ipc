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

#![cfg(gn_test)]
mod c_mem;
mod interactive;
mod parcel_remote;
mod skeleton;
use std::ffi::{c_char, CString};
use std::ptr;

#[repr(C)]
struct TokenInfoParams {
    dcaps_num: i32,
    perms_num: i32,
    acls_num: i32,
    dcaps: *const *const c_char,
    perms: *const c_char,
    acls: *const *const c_char,
    process_name: *const c_char,
    apl_str: *const c_char,
}

extern "C" {
    fn GetAccessTokenId(token_info: *mut TokenInfoParams) -> u64;
    fn SetSelfTokenID(token_id: u64) -> i32;
}

pub fn init_access_token() {
    let perms_str = CString::new("ohos.permission.DISTRIBUTED_DATASYNC").unwrap();
    let name = CString::new("listen_test").unwrap();
    let apl = CString::new("system_core").unwrap();
    let mut param = TokenInfoParams {
        dcaps_num: 0,
        perms_num: 0,
        acls_num: 0,
        dcaps: ptr::null(),
        perms: perms_str.as_ptr(),
        acls: ptr::null(),
        process_name: name.as_ptr(),
        apl_str: apl.as_ptr(),
    };

    unsafe {
        let token_id = GetAccessTokenId(&mut param as *mut TokenInfoParams);
        SetSelfTokenID(token_id);
    }
}
