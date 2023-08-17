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

//! IPC test server

extern crate ipc_rust;
extern crate test_ipc_service;

use ipc_rust::{
    IRemoteBroker, join_work_thread, FileDesc, InterfaceToken, IpcResult,
    add_service, get_calling_token_id, get_first_token_id, get_calling_pid,
    get_calling_uid, String16, RemoteObj, IRemoteStub, get_local_device_id,
    get_calling_device_id, IpcStatusCode,
};
use test_ipc_service::{
    ITest, TestStub, IPC_TEST_SERVICE_ID, IPC_TEST_STATUS_SUCCESS,
    reverse, IFoo, FooStub, init_access_token, IPC_TEST_STATUS_FAILED,
};
use std::io::Write;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::{thread, time};

/// FooService type
pub struct FooService;

impl IFoo for FooService {
}

impl IRemoteBroker for FooService {
}

/// test.ipc.ITestService type
pub struct TestService;

impl ITest for TestService {
    fn test_sync_transaction(&self, value: i32, delay_time: i32) -> IpcResult<i32> {
        if delay_time > 0 {
            thread::sleep(time::Duration::from_millis(delay_time as u64));
        }
        Ok(reverse(value))
    }

    fn test_async_transaction(&self, _value: i32, delay_time: i32) -> IpcResult<()> {
        if delay_time > 0 {
            thread::sleep(time::Duration::from_millis(delay_time as u64));
        }
        Ok(())
    }

    fn test_ping_service(&self, service_name: &String16) -> IpcResult<()> {
        let name = service_name.get_string();
        println!("test_ping_service recv service name: {}", name);
        if name == TestStub::get_descriptor() {
            Ok(())
        } else {
            Err(IpcStatusCode::Failed)
        }
    }

    fn test_transact_fd(&self) -> IpcResult<FileDesc> {
        let path = "/data/test.txt";
        let mut value = OpenOptions::new().read(true)
                                          .write(true)
                                          .create(true)
                                          .open(path).expect("create /data/test.txt failed");
        let file_content = "Sever write!\n";
        write!(value, "{}", file_content).expect("write file success");
        Ok(FileDesc::new(value))
    }

    fn test_transact_string(&self, value: &str) -> IpcResult<i32> {
        Ok(value.len() as i32)
    }

    fn test_get_foo_service(&self) -> IpcResult<RemoteObj> {
        let service = FooStub::new_remote_stub(FooService).expect("create FooService success");
        Ok(service.as_object().expect("get a RemoteObj success"))
    }

    fn echo_interface_token(&self, token: &InterfaceToken) -> IpcResult<InterfaceToken> {
        Ok(InterfaceToken::new(&token.get_token()))
    }

    fn echo_calling_info(&self) -> IpcResult<(u64, u64, u64, u64)> {
        let token_id = get_calling_token_id();
        let first_token_id = get_first_token_id();
        let pid = get_calling_pid();
        let uid = get_calling_uid();
        Ok((token_id, first_token_id, pid, uid))
    }

    fn test_get_device_id(&self) -> IpcResult<(String, String)> {
        let local_device_id = get_local_device_id();
        let calling_device_id = get_calling_device_id();

        if let (Ok(local_id), Ok(calling_id)) = (local_device_id, calling_device_id) {
            Ok((local_id, calling_id))
        } else {
            Err(IpcStatusCode::Failed)
        }
    }
}

impl IRemoteBroker for TestService {
    /// Dump implementation of service rewrite ipc
    fn dump(&self, _file: &FileDesc, _args: &mut Vec<String16>) -> i32 {
        let fd = _file.as_raw_fd();
        if fd < 0 {
            println!("fd is invalid: {}", fd);
            return IPC_TEST_STATUS_FAILED;
        }

        for arg in _args.as_slice() {
            println!("{}", arg.get_string().as_str());
            _file.as_ref().write_all(arg.get_string().as_str().as_bytes()).expect("write failed");
        }
        IPC_TEST_STATUS_SUCCESS
    }
}

fn main() {
    init_access_token();
    // create stub
    let service = TestStub::new_remote_stub(TestService).expect("create TestService success");
    add_service(&service.as_object().expect("get ITest service failed"),
        IPC_TEST_SERVICE_ID).expect("add server to samgr failed"); 
    println!("join to ipc work thread");
    join_work_thread();
}