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

use std::thread;
use std::time::Duration;
use ipc_rust::{
    FromRemoteObj, DeathRecipient, IRemoteObj,
    get_service, init_access_token
};
use test_ipc_service::{ITest, IPC_TEST_SERVICE_ID};

#[test]
fn test_add_access_token() {
    init_access_token();
}

#[test]
fn test_ipc_request() {
    let object = get_service(IPC_TEST_SERVICE_ID);
    let remote = <dyn ITest as FromRemoteObj>::from(object);
    let remote = match remote {
        Ok(x) => x,
        Err(error) => {
            println!("convert RemoteObj to TestProxy failed: {}", error);
            panic!();
        }
    };
    assert_eq!(remote.echo_str("hello"), "hello");
}

#[test]
fn test_request_concurrent() {
    let object = get_service(IPC_TEST_SERVICE_ID);
    let remote = <dyn ITest as FromRemoteObj>::from(object);
    let remote = match remote {
        Ok(x) => x,
        Err(error) => {
            println!("convert RemoteObj to TestProxy failed: {}", error);
            panic!();
        }
    };
    for i in 1..=5 {
        assert_eq!(remote.request_concurent(false), true);
        assert_eq!(remote.request_concurent(true), true);
    }
}

#[test]
fn test_death_recipient_001() {
    let object = get_service(IPC_TEST_SERVICE_ID);
    let mut death_recipient = DeathRecipient::new(|| {
            println!("recv death recipient in rust");
        }).expect("new death recipient failed");
    assert_eq!(object.add_death_recipient(&mut death_recipient), true);
    assert_eq!(object.add_death_recipient(&mut death_recipient), true);
    assert_eq!(object.remove_death_recipient(&mut death_recipient), true);
    assert_eq!(object.remove_death_recipient(&mut death_recipient), true);
}

#[test]
fn test_death_recipient_002() {
    let object = get_service(IPC_TEST_SERVICE_ID);
    let mut death_recipient = DeathRecipient::new(|| {
        println!("recv death recipient in rust");
    }).expect("new death recipient failed");
    assert_eq!(object.add_death_recipient(&mut death_recipient), true);
    println!("please kill remote ITest service");
    thread::sleep(Duration::from_secs(10));
}