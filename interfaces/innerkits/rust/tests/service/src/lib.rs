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

extern crate ipc_rust;

// Import types
// use std::convert::{TryFrom, TryInto};
use ipc_rust::{
    IRemoteBroker, IRemoteObj, RemoteStub,
    RemoteObj, define_remote_object, FIRST_CALL_TRANSACTION
};
use ipc_rust::{MsgParcel, BorrowedMsgParcel};

pub const IPC_TEST_SERVICE_ID: i32 = 1118;

pub enum ITestCode {
    CodeEchoStr = FIRST_CALL_TRANSACTION,
    CodeRequestConcurrent,
}

impl ITestCode {
    fn to_u32(self) -> u32 {
        self as u32
    }
}

pub trait ITest: IRemoteBroker {
    fn echo_str(&self, value: &str) -> String;
    fn request_concurent(&self, is_async: bool) -> bool;
}

fn on_remote_request(stub: &dyn ITest, code: u32, data: &BorrowedMsgParcel,
    reply: &mut BorrowedMsgParcel) -> i32 {
    println!("on_remote_reuqest in Rust TestStub, code: {}", code);
    match code {
        1 => {
            let value: String = data.read().expect("should have a string");
            let value = stub.echo_str(&value);
            reply.write(&value);
            0
        }
        2 => {
            stub.request_concurent(true);
            0
        }
        _ => -1
    }
}

define_remote_object!(
    ITest["ohos.ipc.test"] {
        stub: TestStub(on_remote_request),
        proxy: TestProxy,
    }
);

// Make RemoteStub<TestStub> object can call ITest function directly.
impl ITest for RemoteStub<TestStub> {
    fn echo_str(&self, value: &str) -> String {
        // self will be convert to TestStub automatic because RemoteStub<TestStub>
        // implement the Deref trait
        self.0.echo_str(value)
    }

    fn request_concurent(&self, is_async: bool) -> bool {
        self.0.request_concurent(is_async)
    }
}

impl ITest for TestProxy {
    fn echo_str(&self, value: &str) -> String {
        let mut data = MsgParcel::new().expect("MsgParcel should success");
        data.write(value);
        let reply =
            self.remote.send_request(ITestCode::CodeEchoStr as u32, &data, false);
        match reply {
            Ok(reply) => {
                let echo_value: String = reply.read().expect("need reply value");
                echo_value
            }
            Err(error) => {
                String::from("Error")
            }
        }
    }

    fn request_concurent(&self, is_async: bool) -> bool {
        let mut data = MsgParcel::new().expect("MsgParcel should success");
        let reply =
            self.remote.send_request(ITestCode::CodeRequestConcurrent as u32, &data, is_async);
        match reply {
            Ok(_) => true,
            Err(_) => false
        }
    }
}