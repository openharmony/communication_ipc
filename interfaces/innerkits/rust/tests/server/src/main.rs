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
extern crate test_ipc_service;

use ipc_rust::{
    IRemoteBroker, join_work_thread, FileDesc, InterfaceToken, Result,
    add_service, init_access_token, get_calling_token_id, get_first_token_id,
    get_calling_pid, get_calling_uid,
};
use test_ipc_service::{ITest, TestStub, IPC_TEST_SERVICE_ID};
use std::io::{Read, Seek, SeekFrom};
use std::fs::File;

pub struct TestService;

impl ITest for TestService {
    fn echo_str(&self, value: &str) -> String {
        println!("TestService echo_str: {}", value);
        String::from(value)
    }

    fn request_concurent(&self, is_async: bool) -> bool {
        println!("TestService request_concurent: {}", is_async);
        true
    }

    fn pass_file(&self, fd: FileDesc) -> String {
        let mut info = String::new();
        let mut file = File::from(fd);
        file.seek(SeekFrom::Start(0));
        file.read_to_string(&mut info).expect("The string cannot be read");
        println!("file content: {}", info);
        info
    }

    fn echo_interface_token(&self, token: &InterfaceToken) -> Result<InterfaceToken> {
        Ok(InterfaceToken::new(&token.get_token()))
    }

    fn echo_calling_info(&self) -> Result<(u64, u64, u64, u64)> {
        let token_id = get_calling_token_id();
        let first_token_id = get_first_token_id();
        let pid = get_calling_pid();
        let uid = get_calling_uid();
        println!("{}, {}, {}, {}", token_id, first_token_id, pid, uid);
        Ok((token_id, first_token_id, pid, uid))
    }
}

impl IRemoteBroker for TestService {}

fn main() {
    init_access_token();
    // create stub
    let service = TestStub::new_remote_stub(TestService).expect("create TestService success");
    add_service(&service.as_object().expect("get ITest service failed"),
        IPC_TEST_SERVICE_ID); 
    println!("join to ipc work thread");
    join_work_thread();   
}