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

#![allow(missing_docs, unused)]
use std::ffi::{c_char, c_uchar};
use std::io::{Read, Seek, SeekFrom, Write};

use ipc::parcel::{Deserialize, MsgOption, MsgParcel, Serialize};
use ipc::remote::{RemoteObj, RemoteStub};
use ipc::{IpcResult, Skeleton};

const TEST_SYSTEM_ABILITY_ID: i32 = 1011;

fn init() {
    #[cfg(gn_test)]
    super::init_access_token();
}

struct TestRemoteStub;

impl RemoteStub for TestRemoteStub {
    fn on_remote_request(&self, code: u32, data: &mut MsgParcel, reply: &mut MsgParcel) -> i32 {
        reply.write("TestRemoteStub");
        0
    }
}

/// UT test case for "contest object"
///
/// # brief
/// 1. Get SAMGR context object
/// 2. Add a system ability by send request
/// 3. Check this system ability by send request
/// 4. Remove this system ability by send request
#[test]
fn context() {
    init();
    let context = Skeleton::get_context_object().unwrap();
    let mut data = MsgParcel::new();
    let mut option = MsgOption::new();
    data.write_interface_token("ohos.samgr.accessToken");
    data.write(&TEST_SYSTEM_ABILITY_ID);
    data.write_remote(RemoteObj::from_stub(TestRemoteStub).unwrap())
        .unwrap();
    data.write(&false);
    data.write(&0);
    data.write("");
    data.write("");

    let mut reply = context.send_request(3, &mut data).unwrap();
    let value = reply.read::<i32>().unwrap();

    assert_eq!(value, 0);

    data.write_interface_token("ohos.samgr.accessToken");
    data.write(&TEST_SYSTEM_ABILITY_ID);
    let mut reply = context.send_request(2, &mut data).unwrap();
    let remote = reply.read_remote().unwrap();
    let mut reply = remote.send_request(0, &mut data).unwrap();
    let s = reply.read::<String>().unwrap();
    assert_eq!("TestRemoteStub", s);

    data.write_interface_token("ohos.samgr.accessToken");
    data.write(&TEST_SYSTEM_ABILITY_ID);
    let mut reply = context.send_request(4, &mut data).unwrap();
    let value = reply.read::<i32>().unwrap();
    assert_eq!(value, 0);
}

#[test]
fn skeleton() {
    unsafe {
        assert_eq!(
            Skeleton::calling_device_id(),
            (*GetCallingDeviceID()).to_string()
        );
        assert_eq!(Skeleton::calling_full_token_id(), GetCallingFullTokenID());
        assert_eq!(Skeleton::calling_pid(), GetCallingPid());
        assert_eq!(Skeleton::calling_real_pid(), GetCallingRealPid());
        assert_eq!(Skeleton::calling_token_id(), GetCallingTokenID());
        assert_eq!(Skeleton::calling_uid(), GetCallingUid());
        assert_eq!(Skeleton::first_full_token_id(), GetFirstFullTokenID());
        assert_eq!(Skeleton::first_token_id(), GetFirstTokenID());
        assert_eq!(Skeleton::self_token_id(), SelfTokenID());
        assert_eq!(Skeleton::is_local_calling(), IsLocalCalling());
        assert_eq!(Skeleton::local_device_id(), (*LocalDeviceID()).to_string());
        assert_eq!(
            Skeleton::reset_calling_identity(),
            (*ResetCallingIdentity()).to_string()
        );
    }
}

#[repr(C)]
struct CStringWrapper {
    c_str: *mut c_uchar,
    len: usize,
}

#[allow(clippy::inherent_to_string)]
impl CStringWrapper {
    fn to_string(&self) -> String {
        let bytes = unsafe { std::slice::from_raw_parts(self.c_str, self.len) };
        unsafe { String::from_utf8_unchecked(bytes.to_vec()) }
    }
}

#[link(name = "ipc_rust_test_c")]
extern "C" {
    fn GetCallingDeviceID() -> *mut CStringWrapper;
    fn GetCallingFullTokenID() -> u64;
    fn GetCallingPid() -> u64;
    fn GetCallingRealPid() -> u64;
    fn GetCallingTokenID() -> u32;
    fn GetCallingUid() -> u64;
    fn GetFirstFullTokenID() -> u64;
    fn GetFirstTokenID() -> u32;
    fn SelfTokenID() -> u64;
    fn IsLocalCalling() -> bool;
    fn LocalDeviceID() -> *mut CStringWrapper;
    fn ResetCallingIdentity() -> *mut CStringWrapper;
}
