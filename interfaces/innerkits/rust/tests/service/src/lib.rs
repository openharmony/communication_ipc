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
    IRemoteBroker, IRemoteObj, RemoteStub, Result,
    RemoteObj, define_remote_object, FIRST_CALL_TRANSACTION
};
use ipc_rust::{
    MsgParcel, BorrowedMsgParcel, FileDesc, InterfaceToken,
};

pub const IPC_TEST_SERVICE_ID: i32 = 1118;

pub enum ITestCode {
    CodeEchoStr = FIRST_CALL_TRANSACTION,
    CodeRequestConcurrent = 2,
    CodePassFd = 3,
    CodeInterfaceToekn = 4,
    CodeCallingInfo = 5,
}

pub trait ITest: IRemoteBroker {
    fn echo_str(&self, value: &str) -> String;
    fn request_concurent(&self, is_async: bool) -> bool;
    fn pass_file(&self, fd: FileDesc) -> String;
    fn echo_interface_token(&self, token: &InterfaceToken) -> Result<InterfaceToken>;
    fn echo_calling_info(&self) -> Result<(u64, u64, u64, u64)>;
}

fn on_remote_request(stub: &dyn ITest, code: u32, data: &BorrowedMsgParcel,
    reply: &mut BorrowedMsgParcel) -> Result<()> {
    println!("on_remote_reuqest in Rust TestStub, code: {}", code);
    match code {
        1 => {
            let value: String = data.read().expect("should have a string");
            let value = stub.echo_str(&value);
            reply.write(&value);
            Ok(())
        }
        2 => {
            stub.request_concurent(true);
            Ok(())
        }
        3 => {
            let fd: FileDesc = data.read().expect("should have a fd");
            let value = stub.pass_file(fd);
            reply.write(&value);
            Ok(())
        }
        4 => {
            let token: InterfaceToken = data.read().expect("should have a interface token");
            let value = stub.echo_interface_token(&token).expect("service deal echo token failed");
            reply.write(&value).expect("write echo token result failed");
            Ok(())
        }
        5 => {
            let (token_id, first_token_id, pid, uid) = stub.echo_calling_info()?;
            reply.write(&token_id).expect("write token id failed");
            reply.write(&first_token_id).expect("write first token id failed");
            reply.write(&pid).expect("write pid failed");
            reply.write(&uid).expect("write uid failed");
            Ok(())
        }
        _ => Err(-1)
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

    fn pass_file(&self, fd: FileDesc) -> String {
        self.0.pass_file(fd)
    }

    fn echo_interface_token(&self, token: &InterfaceToken) -> Result<InterfaceToken> {
        self.0.echo_interface_token(token)
    }

    fn echo_calling_info(&self) -> Result<(u64, u64, u64, u64)> {
        self.0.echo_calling_info()
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
            Err(_) => {
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

    fn pass_file(&self, fd: FileDesc) -> String {
        let mut data = MsgParcel::new().expect("MsgParcel should success");
        data.write(&fd).expect("write fd should success");
        let reply =
            self.remote.send_request(ITestCode::CodePassFd as u32, &data, false);
        match reply {
            Ok(reply) => {
                let echo_value: String = reply.read().expect("need reply value");
                echo_value
            }
            Err(_) => {
                String::from("Error")
            }
        }
    }

    fn echo_interface_token(&self, token: &InterfaceToken) -> Result<InterfaceToken> {
        let mut data = MsgParcel::new().expect("MsgParcel should success");
        data.write(token).expect("write token should success");
        let reply = self.remote.send_request(ITestCode::CodeInterfaceToekn as u32,
            &data, false)?;
        let echo_value: InterfaceToken = reply.read().expect("need reply token");
        Ok(echo_value)
    }

    fn echo_calling_info(&self) -> Result<(u64, u64, u64, u64)> {
        let mut data = MsgParcel::new().expect("MsgParcel should success");
        let reply = self.remote.send_request(ITestCode::CodeCallingInfo as u32,
            &data, false)?;
        let token_id: u64 = reply.read().expect("need reply calling token id");
        let first_token_id: u64 = reply.read().expect("need reply first calling token id");
        let pid: u64 = reply.read().expect("need reply calling pid");
        let uid: u64 = reply.read().expect("need reply calling uid");
        Ok((token_id, first_token_id, pid, uid))
    }
}