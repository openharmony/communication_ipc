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
    IRemoteBroker, join_work_thread,
    add_service, init_access_token
};
use test_ipc_service::{ITest, TestStub, IPC_TEST_SERVICE_ID};

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
}

impl IRemoteBroker for TestService {}

fn main() {
    init_access_token();
    // create stub
    let service = TestStub::new_remote_stub(TestService).expect("create TestService success");
    add_service(&service.as_object().unwrap(), IPC_TEST_SERVICE_ID); 
    println!("join to ipc work thread");
    join_work_thread();   
}