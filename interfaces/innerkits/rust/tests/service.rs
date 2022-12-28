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
use ipc_rust::{IRemoteBroker, RemoteStub, define_remote_object};
use ipc_rust::{MsgParcel, BorrowedMsgParcel};

pub trait ITest: IRemoteBroker {
    fn hello(&self, greeting: &str) -> String;
}

fn on_remote_request(stub: &dyn ITest, code: u32, _data: &BorrowedMsgParcel, _reply: &mut BorrowedMsgParcel) -> i32 {
    match code {
        1 => {
            println!("TestStub hello: {}", stub.hello("hello"));
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
    fn hello(&self, greeting: &str) -> String {
        // self will be convert to TestStub automatic because RemoteStub<TestStub>
        // implement the Deref trait
        self.0.hello(greeting)
    }
}

impl ITest for TestProxy {
    fn hello(&self, _greeting: &str) -> String {
        let data = MsgParcel::new().expect("MsgParcel should success");
        let reply =
            self.remote.send_request(1, &data, false);
        match reply {
            Ok(reply) => {
                println!("send hello ipc request success");
            }
            Err(error) => {
                println!("send hello ipc request fail: {}", error);
            }
        };
        String::from("hello")
    }
}