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

//! This create implement the IPC proxy and stub for "test.ipc.ITestService"

extern crate ipc_rust;

mod access_token;

use ipc_rust::{
    IRemoteBroker, IRemoteObj, RemoteStub, IpcResult, IpcStatusCode,
    RemoteObj, define_remote_object, FIRST_CALL_TRANSACTION,
};
use ipc_rust::{
    MsgParcel, BorrowedMsgParcel, FileDesc, InterfaceToken, String16,
};
use std::convert::{TryFrom, TryInto};
pub use access_token::init_access_token;

/// Reverse a i32 value, for example reverse 2019 to 9102
pub fn reverse(mut value: i32) -> i32 {
    let mut result = 0;
    let decimal = 10;

    while value != 0 {
        result = result * decimal + value % decimal;
        value /= decimal;
    }
    result
}

/// SA ID for "test.ipc.ITestService"
pub const IPC_TEST_SERVICE_ID: i32 = 1118;

/// Function code of ITestService
pub enum ITestCode {
    /// Sync transaction code
    CodeSyncTransaction = FIRST_CALL_TRANSACTION,
    /// Async transaction code
    CodeAsyncTransaction,
    /// Ping transaction code
    CodePingService,
    /// Get FooService IPC object transaction code
    CodeGetFooService,
    /// Transaction file descriptor code
    CodeTransactFd,
    /// Transaction string code
    CodeTransactString,
    /// Transaction Interface token code
    CodeInterfaceToekn,
    /// Transaction calling infomation code
    CodeCallingInfo,
    /// Transaction device id code
    CodeGetDeviceId,
}

impl TryFrom<u32> for ITestCode {
    type Error = IpcStatusCode;
    fn try_from(code: u32) -> IpcResult<Self> {
        match code {
            _ if code == ITestCode::CodeSyncTransaction as u32 => Ok(ITestCode::CodeSyncTransaction),
            _ if code == ITestCode::CodeAsyncTransaction as u32 => Ok(ITestCode::CodeAsyncTransaction),
            _ if code == ITestCode::CodePingService as u32 => Ok(ITestCode::CodePingService),
            _ if code == ITestCode::CodeGetFooService as u32 => Ok(ITestCode::CodeGetFooService),
            _ if code == ITestCode::CodeTransactFd as u32 => Ok(ITestCode::CodeTransactFd),
            _ if code == ITestCode::CodeTransactString as u32 => Ok(ITestCode::CodeTransactString),
            _ if code == ITestCode::CodeInterfaceToekn as u32 => Ok(ITestCode::CodeInterfaceToekn),
            _ if code == ITestCode::CodeCallingInfo as u32 => Ok(ITestCode::CodeCallingInfo),
            _ if code == ITestCode::CodeGetDeviceId as u32 => Ok(ITestCode::CodeGetDeviceId),
            _ => Err(IpcStatusCode::Failed),
        }
    }
}

/// Function between proxy and stub of ITestService
pub trait ITest: IRemoteBroker {
    /// Test sync transaction
    fn test_sync_transaction(&self, value: i32, delay_time: i32) -> IpcResult<i32>;
    /// Test async transaction
    fn test_async_transaction(&self, value: i32, delay_time: i32) -> IpcResult<()>;
    /// Test ping service transaction
    fn test_ping_service(&self, service_name: &String16) -> IpcResult<()>;
    /// Test file descriptor transaction
    fn test_transact_fd(&self) -> IpcResult<FileDesc>;
    /// Test string transaction
    fn test_transact_string(&self, value: &str) -> IpcResult<i32>;
    /// Test get foo service IPC object transaction
    fn test_get_foo_service(&self) -> IpcResult<RemoteObj>;
    /// Test interface token transaction
    fn echo_interface_token(&self, token: &InterfaceToken) -> IpcResult<InterfaceToken>;
    /// Test calling infomation transaction
    fn echo_calling_info(&self) -> IpcResult<(u64, u64, u64, u64)>;
    /// Test get device id
    fn test_get_device_id(&self) -> IpcResult<(String, String)>;
}

fn on_itest_remote_request(stub: &dyn ITest, code: u32, data: &BorrowedMsgParcel,
    reply: &mut BorrowedMsgParcel) -> IpcResult<()> {
    match code.try_into()? {
        ITestCode::CodeSyncTransaction => {
            let value: i32 = data.read().expect("should a value");
            let delay_time: i32 = data.read().expect("should a delay time");
            let ret = stub.test_sync_transaction(value, delay_time)?;
            reply.write(&ret)?;
            Ok(())
        }
        ITestCode::CodeAsyncTransaction => {
            let value: i32 = data.read().expect("should a value");
            let delay_time: i32 = data.read().expect("should a delay time");
            stub.test_async_transaction(value, delay_time)?;
            Ok(())
        }
        ITestCode::CodePingService => {
            let service_name: String16 = data.read().expect("should a service name");
            stub.test_ping_service(&service_name)?;
            Ok(())
        }
        ITestCode::CodeGetFooService => {
            let service = stub.test_get_foo_service()?;
            reply.write(&service)?;
            Ok(())
        }
        ITestCode::CodeTransactFd => {
            let fd = stub.test_transact_fd()?;
            reply.write(&fd).expect("should write fd success");
            Ok(())
        }
        ITestCode::CodeTransactString => {
            let value: String = data.read()?;
            let len = stub.test_transact_string(&value)?;
            reply.write(&len)?;
            Ok(())
        }
        ITestCode::CodeInterfaceToekn => {
            let token: InterfaceToken = data.read().expect("should have a interface token");
            let value = stub.echo_interface_token(&token).expect("service deal echo token failed");
            reply.write(&value).expect("write echo token result failed");
            Ok(())
        }
        ITestCode::CodeCallingInfo => {
            let (token_id, first_token_id, pid, uid) = stub.echo_calling_info()?;
            reply.write(&token_id).expect("write token id failed");
            reply.write(&first_token_id).expect("write first token id failed");
            reply.write(&pid).expect("write pid failed");
            reply.write(&uid).expect("write uid failed");
            Ok(())
        }
        ITestCode::CodeGetDeviceId => {
            let (local_device_id, calling_device_id) = stub.test_get_device_id()?;
            reply.write(&local_device_id).expect("write local device id failed");
            reply.write(&calling_device_id).expect("write calling device id failed");
            Ok(())
        }
    }
}

define_remote_object!(
    ITest["test.ipc.ITestService"] {
        stub: TestStub(on_itest_remote_request),
        proxy: TestProxy,
    }
);

// Make RemoteStub<TestStub> object can call ITest function directly.
impl ITest for RemoteStub<TestStub> {
    fn test_sync_transaction(&self, value: i32, delay_time: i32) -> IpcResult<i32> {
        self.0.test_sync_transaction(value, delay_time)
    }

    fn test_async_transaction(&self, value: i32, delay_time: i32) -> IpcResult<()> {
        self.0.test_async_transaction(value, delay_time)
    }

    fn test_ping_service(&self, service_name: &String16) -> IpcResult<()> {
        self.0.test_ping_service(service_name)
    }

    fn test_transact_fd(&self) -> IpcResult<FileDesc> {
        self.0.test_transact_fd()
    }

    fn test_transact_string(&self, value: &str) -> IpcResult<i32> {
        self.0.test_transact_string(value)
    }

    fn test_get_foo_service(&self) -> IpcResult<RemoteObj> {
        self.0.test_get_foo_service()
    }

    fn echo_interface_token(&self, token: &InterfaceToken) -> IpcResult<InterfaceToken> {
        self.0.echo_interface_token(token)
    }

    fn echo_calling_info(&self) -> IpcResult<(u64, u64, u64, u64)> {
        self.0.echo_calling_info()
    }

    fn test_get_device_id(&self) -> IpcResult<(String, String)> {
        self.0.test_get_device_id()
    }
}

impl ITest for TestProxy {
    fn test_sync_transaction(&self, value: i32, delay_time: i32) -> IpcResult<i32> {
        let mut data = MsgParcel::new().expect("MsgParcel should success");
        data.write(&value)?;
        data.write(&delay_time)?;
        let reply = self.remote.send_request(ITestCode::CodeSyncTransaction as u32,
            &data, false)?;
        let ret: i32 = reply.read().expect("need reply i32");
        Ok(ret)
    }

    fn test_async_transaction(&self, value: i32, delay_time: i32) -> IpcResult<()> {
        let mut data = MsgParcel::new().expect("MsgParcel should success");
        data.write(&value)?;
        data.write(&delay_time)?;
        let _reply = self.remote.send_request(ITestCode::CodeAsyncTransaction as u32,
            &data, true)?;
        Ok(())
    }

    fn test_ping_service(&self, service_name: &String16) -> IpcResult<()> {
        let mut data = MsgParcel::new().expect("MsgParcel should success");
        data.write(service_name)?;
        let _reply = self.remote.send_request(ITestCode::CodePingService as u32,
            &data, false)?;
        Ok(())
    }

    fn test_transact_fd(&self) -> IpcResult<FileDesc> {
        let data = MsgParcel::new().expect("MsgParcel should success");
        let reply = self.remote.send_request(ITestCode::CodeTransactFd as u32,
            &data, false)?;
        let fd: FileDesc = reply.read()?;
        Ok(fd)
    }

    fn test_transact_string(&self, value: &str) -> IpcResult<i32> {
        let mut data = MsgParcel::new().expect("MsgParcel should success");
        data.write(value).expect("should write string success");
        let reply = self.remote.send_request(ITestCode::CodeTransactString as u32,
            &data, false)?;
        let len: i32 = reply.read()?;
        Ok(len)
    }

    fn test_get_foo_service(&self) -> IpcResult<RemoteObj> {
        let data = MsgParcel::new().expect("MsgParcel should success");
        let reply = self.remote.send_request(ITestCode::CodeGetFooService as u32,
            &data, false)?;
        let service: RemoteObj = reply.read()?;
        Ok(service)
    }

    fn echo_interface_token(&self, token: &InterfaceToken) -> IpcResult<InterfaceToken> {
        let mut data = MsgParcel::new().expect("MsgParcel should success");
        data.write(token).expect("write token should success");
        let reply = self.remote.send_request(ITestCode::CodeInterfaceToekn as u32,
            &data, false)?;
        let echo_value: InterfaceToken = reply.read().expect("need reply token");
        Ok(echo_value)
    }

    fn echo_calling_info(&self) -> IpcResult<(u64, u64, u64, u64)> {
        let data = MsgParcel::new().expect("MsgParcel should success");
        let reply = self.remote.send_request(ITestCode::CodeCallingInfo as u32,
            &data, false)?;
        let token_id: u64 = reply.read().expect("need reply calling token id");
        let first_token_id: u64 = reply.read().expect("need reply first calling token id");
        let pid: u64 = reply.read().expect("need reply calling pid");
        let uid: u64 = reply.read().expect("need reply calling uid");
        Ok((token_id, first_token_id, pid, uid))
    }

    fn test_get_device_id(&self) -> IpcResult<(String, String)> {
        let data = MsgParcel::new().expect("MsgParcel should success");
        let reply = self.remote.send_request(ITestCode::CodeGetDeviceId as u32,
            &data, false)?;
        let local_device_id: String = reply.read().expect("need reply calling local device id");
        let calling_device_id: String = reply.read().expect("need reply first calling device id");
        Ok((local_device_id, calling_device_id))
    }
}

/// Interface trait for FooService
pub trait IFoo: IRemoteBroker {
}

fn on_foo_remote_request(_stub: &dyn IFoo, _code: u32, _data: &BorrowedMsgParcel,
    _reply: &mut BorrowedMsgParcel) -> IpcResult<()> {
    Ok(())
}

impl IFoo for RemoteStub<FooStub> {
}

impl IFoo for FooProxy {
}

define_remote_object!(
    IFoo["ohos.ipc.test.foo"] {
        stub: FooStub(on_foo_remote_request),
        proxy: FooProxy,
    }
);