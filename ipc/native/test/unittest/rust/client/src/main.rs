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
use std::io::{Read, SeekFrom, Seek};
use ipc_rust::{
    FromRemoteObj, DeathRecipient, IRemoteObj, FileDesc, RemoteObjRef,
    MsgParcel, String16, InterfaceToken, get_service, get_first_token_id,
    get_self_token_id, get_calling_pid, get_calling_uid, IMsgParcel, Result,
    RawData,
};

use ipc_rust::{Serialize, Deserialize, BorrowedMsgParcel, Ashmem};
use test_ipc_service::{ITest, TestProxy, IPC_TEST_SERVICE_ID, IFoo, init_access_token};
use std::fs::File;

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
    remote
}

#[test]
fn test_add_access_token() {
    init_access_token();
}

#[test]
fn test_death_recipient_001() {
    let object = get_service(IPC_TEST_SERVICE_ID).expect("get itest service failed");
    let mut death_recipient = DeathRecipient::new(|| {
            println!("recv death recipient in rust");
        }).expect("new death recipient failed");
    assert!(object.add_death_recipient(&mut death_recipient));
    assert!(object.add_death_recipient(&mut death_recipient));
    assert!(object.remove_death_recipient(&mut death_recipient));
    assert!(object.remove_death_recipient(&mut death_recipient));
}

#[test]
fn test_death_recipient_002() {
    let object = get_service(IPC_TEST_SERVICE_ID).expect("get itest service failed");
    let mut death_recipient = DeathRecipient::new(|| {
        println!("recv death recipient in rust");
    }).expect("new death recipient failed");
    assert!(object.add_death_recipient(&mut death_recipient));
    println!("please kill remote ITest service");
    thread::sleep(Duration::from_secs(10));
}

#[test]
fn test_parcel_interface_token() {
    let remote = get_test_service();
    let token = InterfaceToken::new("Hello, Rust");
    let echo_token = remote.echo_interface_token(&token).expect(
        "echo normal interface token failed");
    assert_eq!(token.get_token(), echo_token.get_token());

    let token = InterfaceToken::new("");
    let echo_token = remote.echo_interface_token(&token).expect(
        "echo empty interface token failed");
    assert_eq!(token.get_token(), echo_token.get_token());
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
fn test_sync_request() {
    let remote = get_test_service();
    let value = remote.test_sync_transaction(2019, 0).expect(
        "sync ipc request failed");
    assert_eq!(value, 9102);
}

#[test]
fn test_async_request() {
    let remote = get_test_service();
    remote.test_async_transaction(2019, 0).expect("async ipc request failed");
}

#[test]
fn test_ping_service() {
    let remote = get_test_service();
    let descriptor = String16::new(TestProxy::get_descriptor());
    remote.test_ping_service(&descriptor).expect("ping TestService failed");
}

#[test]
fn test_fd() {
    let remote = get_test_service();
    let fd: FileDesc = remote.test_transact_fd().expect("get server fd failed");
    let mut info = String::new();
    let mut file = File::from(fd);
    file.seek(SeekFrom::Start(0)).expect("seek failed");
    file.read_to_string(&mut info).expect("read string from fd failed");
    println!("file content: {}", info);
    assert_eq!(info, "Sever write!\n");
}

#[test]
fn test_loop_request() {
    let remote = get_test_service();
    // start loop test, test times is 1000
    let mut value = String::new();
    let append = "0123456789abcdefghijklmnopqrstuvwxyz~!@#$%^&*()_+{}?/[]<>-='|~";
    for _i in 1..=1000 {
        value.push_str(append);
        let len = remote.test_transact_string(&value).expect("transact string failed");
        assert_eq!(value.len() as i32, len);
    }
}

#[test]
fn test_remote_obj() {
    let remote = get_test_service();
    let remote = remote.test_get_foo_service().expect("get FooService proxy failed");
    <dyn IFoo as FromRemoteObj>::from(remote).expect(
        "convert foo service should success");
}

#[cfg(test)]
mod parcel_type_test {
    use super::*;

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
        assert!(!value);
        let value: bool = parcel.read().expect("read true failed");
        assert!(value);
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
    fn test_parcel_string() {
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write("Hello").expect("write Hello str failed");
        parcel.write("").expect("write empty str failed");
        parcel.write(&String::from("Hello")).expect("write Hello String failed");
        parcel.write(&String::from("")).expect("write empty String failed");

        let hello_str: String = parcel.read().expect("read Hello str failed");
        assert_eq!(hello_str, "Hello");
        let empty_str: String = parcel.read().expect("read empty str failed");
        assert_eq!(empty_str, "");
        let hello_str: String = parcel.read().expect("read Hello String failed");
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
    fn test_parcel_bool_array() {
        let arr = [false, true, false];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write bool array failed");
        let res: [bool; 3] = parcel.read().expect("read bool array failed");
        assert_eq!(&res, &arr);

        let slice = &arr[..];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(slice).expect("write bool slice failed");
        let res: Vec<bool> = parcel.read().expect("read bool slice failed");
        assert_eq!(res, slice);

        let vec = vec![false, true, false];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&vec).expect("write bool vector failed");
        let res: Vec<bool> = parcel.read().expect("read bool vector failed");
        assert_eq!(&res, &vec);
    }

    #[test]
    fn test_parcel_i8u8_array() {
        let arr = [1i8, 2i8, 3i8];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write i8 array failed");
        let res: [i8; 3] = parcel.read().expect("read i8 array failed");
        assert_eq!(&res, &arr);

        let slice = &arr[..];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(slice).expect("write i8 slice failed");
        let res: Vec<i8> = parcel.read().expect("read i8 slice failed");
        assert_eq!(res, slice);

        let arr = [1u8, 2u8, 3u8];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write u8 array failed");
        let res: [u8; 3] = parcel.read().expect("read u8 array failed");
        assert_eq!(&res, &arr);

        let slice = &arr[..];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(slice).expect("write u8 slice failed");
        let res: Vec<u8> = parcel.read().expect("read u8 slice failed");
        assert_eq!(res, slice);

        let arr = vec![1i8, 2i8, 3i8];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write i8 vector failed");
        let res: Vec<i8> = parcel.read().expect("read i8 vector failed");
        assert_eq!(&res, &arr);

        let arr = vec![1u8, 2u8, 3u8];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write u8 vector failed");
        let res: Vec<u8> = parcel.read().expect("read u8 vector failed");
        assert_eq!(&res, &arr);
    }

    #[test]
    fn test_parcel_i16u16_array() {
        let arr = [1i16, 2i16, 3i16];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write i16 array failed");
        let res: [i16; 3] = parcel.read().expect("read i16 array failed");
        assert_eq!(&res, &arr);

        let slice = &arr[..];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(slice).expect("write i16 slice failed");
        let res: Vec<i16> = parcel.read().expect("read i16 slice failed");
        assert_eq!(res, slice);

        let arr = [1u16, 2u16, 3u16, 4u16];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write u16 array failed");
        let res: [u16; 4] = parcel.read().expect("read u16 array failed");
        assert_eq!(&res, &arr);

        let slice = &arr[..];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(slice).expect("write u16 slice failed");
        let res: Vec<u16> = parcel.read().expect("read u16 slice failed");
        assert_eq!(res, slice);

        let arr = vec![1i16, 2i16, 3i16];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write i16 vector failed");
        let res: Vec<i16> = parcel.read().expect("read i16 vector failed");
        assert_eq!(&res, &arr);

        let arr = vec![1u16, 2u16, 3u16];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write u16 vector failed");
        let res: Vec<u16> = parcel.read().expect("read u16 vector failed");
        assert_eq!(&res, &arr);
    }

    #[test]
    fn test_parcel_i32u32_array() {
        let arr = [1i32, 2i32, 3i32];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write i32 array failed");
        let res: [i32; 3] = parcel.read().expect("read i32 array failed");
        assert_eq!(&res, &arr);

        let slice = &arr[..];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(slice).expect("write i32 slice failed");
        let res: Vec<i32> = parcel.read().expect("read i32 slice failed");
        assert_eq!(res, slice);

        let arr = [1u32, 2u32, 3u32, 4u32];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write u32 array failed");
        let res: [u32; 4] = parcel.read().expect("read u32 array failed");
        assert_eq!(&res, &arr);

        let slice = &arr[..];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(slice).expect("write u32 slice failed");
        let res: Vec<u32> = parcel.read().expect("read u32 slice failed");
        assert_eq!(res, slice);

        let arr = vec![1i32, 2i32, 3i32];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write i32 vector failed");
        let res: Vec<i32> = parcel.read().expect("read i32 vector failed");
        assert_eq!(&res, &arr);

        let arr = vec![1u32, 2u32, 3u32];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write u32 vector failed");
        let res: Vec<u32> = parcel.read().expect("read u32 vector failed");
        assert_eq!(&res, &arr);
    }

    #[test]
    fn test_parcel_i64u64_array() {
        let arr = [1i64, 2i64, 3i64];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write i64 array failed");
        let res: [i64; 3] = parcel.read().expect("read i64 array failed");
        assert_eq!(&res, &arr);

        let slice = &arr[..];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(slice).expect("write i64 slice failed");
        let res: Vec<i64> = parcel.read().expect("read i64 slice failed");
        assert_eq!(res, slice);

        let arr = [1u64, 2u64, 3u64, 4u64];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write u64 array failed");
        let res: [u64; 4] = parcel.read().expect("read u64 array failed");
        assert_eq!(&res, &arr);

        let slice = &arr[..];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(slice).expect("write u64 slice failed");
        let res: Vec<u64> = parcel.read().expect("read u64 slice failed");
        assert_eq!(res, slice);

        let arr = vec![1i64, 2i64, 3i64];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write i64 vector failed");
        let res: Vec<i64> = parcel.read().expect("read i64 vector failed");
        assert_eq!(&res, &arr);

        let arr = vec![1u64, 2u64, 3u64];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write u64 vector failed");
        let res: Vec<u64> = parcel.read().expect("read u64 vector failed");
        assert_eq!(&res, &arr);
    }

    #[test]
    fn test_parcel_float_array() {
        let arr = [1.0f32, 2.0f32, 3.0f32];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write float array failed");
        let res: [f32; 3] = parcel.read().expect("read float array failed");
        assert_eq!(&res, &arr);

        let slice = &arr[..];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(slice).expect("write float slice failed");
        let res: Vec<f32> = parcel.read().expect("read float slice failed");
        assert_eq!(res, slice);

        let arr = vec![1.0f32, 2.0f32, 3.0f32];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write Vec<f32> failed");
        let res: Vec<f32> = parcel.read().expect("read Vec<f32> failed");
        assert_eq!(&res, &arr);
    }

    #[test]
    fn test_parcel_double_array() {
        let arr = [1.0f64, 2.0f64, 3.0f64];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write double array failed");
        let res: [f64; 3] = parcel.read().expect("read double array failed");
        assert_eq!(&res, &arr);

        let slice = &arr[..];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(slice).expect("write double slice failed");
        let res: Vec<f64> = parcel.read().expect("read double slice failed");
        assert_eq!(res, slice);

        let arr = vec![1.0f64, 2.0f64, 3.0f64];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write Vec<f64> failed");
        let res: Vec<f64> = parcel.read().expect("read Vec<f64> failed");
        assert_eq!(&res, &arr);
    }

    #[test]
    fn test_parcel_string_array() {
        let arr = [String::from("A"), String::from("B")];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write String array failed");
        let res: Vec<String> = parcel.read().expect("read String array failed");
        assert_eq!(&res[..], &arr[..]);

        let slice = &arr[..];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(slice).expect("write String slice failed");
        let res: Vec<String> = parcel.read().expect("read String slice failed");
        assert_eq!(res, slice);

        let arr = vec![String::from("A"), String::from("B")];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write Vec<String> failed");
        let res: Vec<String> = parcel.read().expect("read Vec<String> failed");
        assert_eq!(&res, &arr);
    }

    #[test]
    fn test_parcel_empty_string_array() {
        let arr: [&str; 0] = [];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write empty String array failed");
        let res: Vec<String> = parcel.read().expect("read String array failed");
        assert_eq!(&res[..], &arr[..]);
    }

    #[test]
    fn test_parcel_str_array() {
        let arr = ["A", "B"];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write String array failed");
        let res: Vec<String> = parcel.read().expect("read String array failed");
        assert_eq!(&res[..], &arr[..]);

        let slice = &arr[..];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(slice).expect("write String slice failed");
        let res: Vec<String> = parcel.read().expect("read String slice failed");
        assert_eq!(res, slice);

        let arr = vec!["A", "B"];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&arr).expect("write Vec<String> failed");
        let res: Vec<String> = parcel.read().expect("read Vec<String> failed");
        assert_eq!(&res, &arr);
    }

    #[test]
    fn test_parcel_option_type() {
        let s = Some("hello".to_string());
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&s).expect("write Some(String) failed");
        let res: Option<String> = parcel.read().expect("read Some(String) failed");
        assert_eq!(res, s);

        let s = Some("hello");
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&s).expect("write Some(str) failed");
        let res: Option<String> = parcel.read().expect("read Some(String) failed");
        assert_eq!(res.as_deref(), s);

        let s = Some(42u8);
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&s).expect("write Some(u8) failed");
        let res: Option<u8> = parcel.read().expect("read Some(u8) failed");
        assert_eq!(res, s);

        let s = Some(42i16);
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&s).expect("write Some(i16) failed");
        let res: Option<i16> = parcel.read().expect("read Some(i16) failed");
        assert_eq!(res, s);

        let s = Some(42.0f32);
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&s).expect("write Some(float) failed");
        let res: Option<f32> = parcel.read().expect("read Some(float) failed");
        assert_eq!(res, s);

        let s = Some(true);
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&s).expect("write Some(bool) failed");
        let res: Option<bool> = parcel.read().expect("read Some(bool) failed");
        assert_eq!(res, s);

        let s: Option<String> = None;
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&s).expect("write None failed");
        let res: Option<String> = parcel.read().expect("read None failed");
        assert_eq!(res, s);
    }

    #[test]
    fn test_parcel_box_type() {
        let s = Box::new("hello".to_string());
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&s).expect("write Box<String> failed");
        let res: Box<String> = parcel.read().expect("read Box<String> failed");
        assert_eq!(res, s);
    }

    #[test]
    fn test_parcel_buffer() {
        let u8_slice = [1u8;100];
        let u8_slice = &u8_slice[..];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        let res = parcel.write_buffer(u8_slice);
        assert!(res);
        let u8_vec: Vec<u8> = parcel.read_buffer(100).expect("read buffer failed");
        assert_eq!(u8_vec, u8_slice);
    }

    #[test]
    fn test_parcel_buffer_other() {
        let u8_slice = [1u8;100];
        let u8_slice = &u8_slice[..];
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        let res = parcel.write_buffer(u8_slice);
        assert!(res);
        let u8_vec = parcel.read_buffer(0).expect("read zero length buffer failed");
        assert_eq!(u8_vec.len() as i32, 0);
    }

    #[test]
    fn test_parcel_ref() {
        let s = "hello".to_string();
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&&s).expect("write String reference failed");
        let res: String = parcel.read().expect("read String reference failed");
        assert_eq!(res, s);
    }

    #[test]
    fn test_parcel_custome_type() {
        #[derive(Debug, PartialEq, Eq)]
        struct Year(i64);

        impl Serialize for Year {
            fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
                parcel.write(&self.0)
            }
        }

        impl Deserialize for Year {
            fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> Result<Self> {
                let ret = parcel.read::<i64>();
                match ret {
                    Ok(year) => Ok(Year(year)),
                    Err(_) => Err(-1),
                }
            }
        }

        let year = Year(2023);
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        parcel.write(&year).expect("write Year failed");
        let res: Year = parcel.read().expect("read Year failed");
        assert_eq!(&res, &year);
    }

    #[test]
    fn test_parcel_raw_data() {
        let mut data: Vec<u8> = Vec::new();
        let small_len = 32 * 1024; // 32KB
        let large_len = small_len * 2; // 64KB

        for _i in 0..small_len {
            data.push(1);
        }
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        assert!(parcel.write_raw_data(&data[..]));
        let res: RawData = parcel.read_raw_data(small_len).expect(
            "read samll len raw data failed");
        for i in 0..small_len {
            let value = res.read(i, 1).expect("read value from small len raw data failed");
            assert_eq!(value[0], data[i as usize]);
        }

        for _i in 0..small_len {
            data.push(2);
        }
        let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
        assert!(parcel.write_raw_data(&data[..]));
        let res: RawData = parcel.read_raw_data(large_len).expect(
            "read large len raw data failed");
        for i in 0..large_len {
            let value = res.read(i, 1).expect("read value from large len raw data failed");
            assert_eq!(value[0], data[i as usize]);
        }
    }

    #[test]
    fn test_ashmem_read_and_write(){
        let ashmemName = "AshmemIpc";
        let rawData1k = 1024;
        let ashmemString = "HelloWorld2023";

        for _i in 1..=30000 {
            let ashmem = Ashmem::new(&ashmemName, rawData1k).expect("create ashmem failed");
            assert_eq!(ashmem.map_read_write(), true);
            assert_eq!(ashmem.write(&ashmemString.as_bytes(), 0), true);

            let mut parcel = MsgParcel::new().expect("create MsgParcel failed");
            parcel.write(&ashmem).expect("write MsgParcel failed");
            assert_eq!(parcel.rewind_read(0), true);

            let ashmem2: Ashmem = parcel.read().expect("read MsgParcel failed");
            assert_eq!(ashmem2.map_readonly(), true);

            let res: Result<RawData> = ashmem2.read(ashmemString.len() as i32, 0);
            let ptr = res.unwrap();
            let read_string = ptr.read(0, ashmemString.len() as u32);
            let res = std::str::from_utf8(read_string.unwrap()).unwrap();
            assert_eq!(&ashmemString, &res);

            ashmem.unmap();
            ashmem.close();
            ashmem2.unmap();
            ashmem2.close();
        }
    }
}