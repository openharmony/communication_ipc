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
use std::ffi::{c_char, CString};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Once;

use hilog_rust::{hilog, info};
use ipc::parcel::{Deserialize, MsgOption, MsgParcel, Serialize};
use ipc::remote::{RemoteObj, RemoteStub};
use ipc::{IpcResult, Skeleton};

const TEST_SYSTEM_ABILITY_ID: i32 = 1191;

const LOG_LABEL: hilog_rust::HiLogLabel = hilog_rust::HiLogLabel {
    log_type: hilog_rust::LogType::LogCore,
    domain: 0xD001C50,
    tag: "RequestService",
};

fn init() {
    #[cfg(gn_test)]
    super::init_access_token();

    static ONCE: Once = Once::new();

    ONCE.call_once(|| {
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
    });
}

fn test_service() -> RemoteObj {
    let context = Skeleton::get_context_object().unwrap();
    let mut data = MsgParcel::new();
    let mut option = MsgOption::new();
    data.write_interface_token("ohos.samgr.accessToken");
    data.write(&TEST_SYSTEM_ABILITY_ID);
    let mut reply = context.send_request(2, &mut data).unwrap();
    reply.read_remote().unwrap()
}

fn unload_service() {
    let context = Skeleton::get_context_object().unwrap();
    let mut data = MsgParcel::new();
    let mut option = MsgOption::new();
    data.write_interface_token("ohos.samgr.accessToken");
    data.write(&TEST_SYSTEM_ABILITY_ID);
    let mut reply = context.send_request(21, &mut data).unwrap();
}

struct TestRemoteStub;

impl RemoteStub for TestRemoteStub {
    fn on_remote_request(&self, code: u32, data: &mut MsgParcel, reply: &mut MsgParcel) -> i32 {
        reply.write("TestRemoteStub");
        0
    }
}

#[test]
fn death_recipient() {}
