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
use std::io::Write;
use ipc_rust::{
    FromRemoteObj, DeathRecipient, IRemoteObj, FileDesc, RemoteObjRef,
    MsgParcel, String16, InterfaceToken, get_service, init_access_token,
    get_first_token_id, get_self_token_id, get_calling_pid, get_calling_uid,
    IMsgParcel,
};
use test_ipc_service::{ITest, IPC_TEST_SERVICE_ID};
use std::fs::OpenOptions;

fn get_test_service() -> RemoteObjRef<dyn ITest>
{
    let object = get_service(IPC_TEST_SERVICE_ID).expect("get itest service failed");
    let remote = <dyn ITest as FromRemoteObj>::from(object);
    let remote = match remote {
        Ok(x) => x,
        Err(error) => {
            println!("convert RemoteObj to TestProxy failed: {}", error);
            panic!();
        }
    };
    return remote;
}

#[test]
fn test_add_access_token() {
    init_access_token();
}

#[test]
fn test_ipc_request() {
    let remote = get_test_service();
    assert_eq!(remote.echo_str("hello"), "hello");
}

#[test]
fn test_request_concurrent() {
    let remote = get_test_service();
    for _i in 1..=5 {
        assert!(remote.request_concurent(false));
        assert!(remote.request_concurent(true));
    }
}

#[test]
fn test_death_recipient_001() {
    let object = get_service(IPC_TEST_SERVICE_ID).expect("get itest service failed");
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
    let object = get_service(IPC_TEST_SERVICE_ID).expect("get itest service failed");
    let mut death_recipient = DeathRecipient::new(|| {
        println!("recv death recipient in rust");
    }).expect("new death recipient failed");
    assert_eq!(object.add_death_recipient(&mut death_recipient), true);
    println!("please kill remote ITest service");
    thread::sleep(Duration::from_secs(10));
}

#[test]
fn test_parcel_interface_token() {
    let remote = get_test_service();
    let token = InterfaceToken::new("Hello, Rust");
    let echo_token = remote.echo_interface_token(&token).expect("echo normal interface token failed");
    assert_eq!(token.get_token(), echo_token.get_token());

    let token = InterfaceToken::new("");
    let echo_token = remote.echo_interface_token(&token).expect("echo empty interface token failed");
    assert_eq!(token.get_token(), echo_token.get_token());
}

#[test]
fn test_parcel_string() {
    let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
    parcel.write("Hello").expect("write str failed");
    parcel.write("").expect("write empty str failed");
    parcel.write(&String::from("Hello")).expect("write String failed");
    parcel.write(&String::from("")).expect("write empty String failed");

    let hello_str: String = parcel.read().expect("read str failed");
    assert_eq!(hello_str, "Hello");
    let empty_str: String = parcel.read().expect("read empty str failed");
    assert_eq!(empty_str, "");
    let hello_str: String = parcel.read().expect("read String failed");
    assert_eq!(hello_str, String::from("Hello"));
    let empty_str: String = parcel.read().expect("read empty String failed");
    assert_eq!(empty_str, String::from(""));
}

#[test]
fn test_parcel_string16() {
    let hello_str = String16::new("Hello");
    let empty_str = String16::new("");
    let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
    parcel.write(&hello_str).expect("write String16 failed");
    parcel.write("").expect("write empty String16 failed");

    let read_hello_str: String16 = parcel.read().expect("read String16 failed");
    assert_eq!(hello_str.get_string(), read_hello_str.get_string());
    let read_empty_str: String16 = parcel.read().expect("read empty String16 failed");
    assert_eq!(empty_str.get_string(), read_empty_str.get_string());
}

#[test]
fn test_parcel_basic_data_type() {
    let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
    parcel.write(&false).expect("write false failed");
    parcel.write(&true).expect("write true failed");
    parcel.write(&1_u8).expect("write u8 failed");
    parcel.write(&2_i8).expect("write i8 failed");
    parcel.write(&3_u16).expect("write u16 failed");
    parcel.write(&4_i16).expect("write i16 failed");
    parcel.write(&5_u32).expect("write u32 failed");
    parcel.write(&6_i32).expect("write i32 failed");
    parcel.write(&7_u64).expect("write u64 failed");
    parcel.write(&8_i64).expect("write i64 failed");
    parcel.write(&1.1_f32).expect("write f32 failed");
    parcel.write(&2.2_f64).expect("write f64 failed");

    let value: bool = parcel.read().expect("read false failed");
    assert_eq!(value, false);
    let value: bool = parcel.read().expect("read true failed");
    assert_eq!(value, true);
    let value: u8 = parcel.read().expect("read u8 failed");
    assert_eq!(value, 1_u8);
    let value: i8 = parcel.read().expect("read i8 failed");
    assert_eq!(value, 2_i8);
    let value: u16 = parcel.read().expect("read u16 failed");
    assert_eq!(value, 3_u16);
    let value: i16 = parcel.read().expect("read i16 failed");
    assert_eq!(value, 4_i16);
    let value: u32 = parcel.read().expect("read u32 failed");
    assert_eq!(value, 5_u32);
    let value: i32 = parcel.read().expect("read i32 failed");
    assert_eq!(value, 6_i32);
    let value: u64 = parcel.read().expect("read u64 failed");
    assert_eq!(value, 7_u64);
    let value: i64 = parcel.read().expect("read i64 failed");
    assert_eq!(value, 8_i64);
    let value: f32 = parcel.read().expect("read f32 failed");
    assert!((value - 1.1_f32).abs() < 0.00001);
    let value: f64 = parcel.read().expect("read f64 failed");
    assert!((value - 2.2_f64).abs() < 0.00001);
}

#[test]
fn test_parcel_info() {
    let mut parcel = MsgParcel::new().expect("create MsgParcel failed");

    let max_capacity = parcel.get_max_capacity();
    assert!(max_capacity > 0);
    assert!(parcel.set_max_capacity(max_capacity + 1));
    assert_eq!(parcel.get_max_capacity(), max_capacity + 1);

    assert_eq!(parcel.get_data_size(), 0);
    assert_eq!(parcel.get_data_capacity(), 0);
    assert_eq!(parcel.get_writable_bytes(), 0);
    assert_eq!(parcel.get_readable_bytes(), 0);
    assert_eq!(parcel.get_read_position(), 0);
    assert_eq!(parcel.get_write_position(), 0);

    parcel.write("Hello").expect("write hello failed");
    let data_size = parcel.get_data_size();
    assert!(data_size > 0);
    assert!(parcel.get_data_capacity() > 0);
    assert!(parcel.get_writable_bytes() > 0);
    assert!(parcel.get_readable_bytes() > 0);
    assert_eq!(parcel.get_read_position(), 0);
    assert!(parcel.get_write_position() > 0);

    let _: String = parcel.read().expect("read String failed");
    assert_eq!(parcel.get_readable_bytes(), 0);
    assert!(parcel.get_read_position() > 0);

    assert!(parcel.set_data_size(data_size - 1));
    assert!(parcel.set_data_capacity(data_size + 1));

    assert!(parcel.rewind_read(0));
    assert!(parcel.rewind_write(0));
    assert_eq!(parcel.get_data_size(), 0);
    assert!(parcel.get_data_capacity() > 0);
    assert!(parcel.get_writable_bytes() > 0);
    assert_eq!(parcel.get_readable_bytes(), 0);
    assert_eq!(parcel.get_read_position(), 0);
    assert_eq!(parcel.get_write_position(), 0);
}

#[test]
fn test_calling_info() {
    let remote = get_test_service();
    let (token_id, first_token_id, pid, uid) =
        remote.echo_calling_info().expect("echo calling info failed");
    assert_eq!(token_id, get_self_token_id());
    assert_eq!(first_token_id, get_first_token_id());
    assert_eq!(pid, get_calling_pid());
    assert_eq!(uid, get_calling_uid());
}

#[test]
fn test_parcel_fd() {
    let remote = get_test_service();

    let path = "/data/test_fd";
    let mut value = OpenOptions::new().read(true)
                                      .write(true)
                                      .create(true)
                                      .open(path).expect("create data failed");
    let file_content = "Rust IPC Pass FD";
    write!(value, "{}", file_content);
    assert_eq!(remote.pass_file(FileDesc::new(value)), file_content);
}