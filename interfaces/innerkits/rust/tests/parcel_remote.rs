// Copyright (C) 2024 Huawei Device Co., Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(missing_docs, unused)]
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Once;

use ipc::parcel::{Deserialize, MsgOption, MsgParcel, Serialize};
use ipc::remote::{RemoteObj, RemoteStub};
use ipc::{IpcResult, Skeleton};
use samgr::manage::SystemAbilityManager;

const TEST_SYSTEM_ABILITY_ID: i32 = 1012;
const TEST_FLOAT: f32 = 7.02;
const TEST_DOUBLE: f64 = 7.03;

const TEST_LEN: usize = 10;

struct TestRemoteStub;

impl RemoteStub for TestRemoteStub {
    fn on_remote_request(&self, code: u32, data: &mut MsgParcel, reply: &mut MsgParcel) -> i32 {
        match code {
            0 => {
                parcel_remote_primitive(data, reply);
                parcel_remote_vec(data, reply);
            }
            _ => unreachable!(),
        }
        0
    }
}

fn init() {
    #[cfg(gn_test)]
    super::init_access_token();

    static ONCE: Once = Once::new();

    ONCE.call_once(|| {
        SystemAbilityManager::add_systemability(TEST_SYSTEM_ABILITY_ID, TestRemoteStub);
    });
}

fn parcel_remote_primitive(data: &mut MsgParcel, reply: &mut MsgParcel) {
    reply
        .write_interface_token(data.read_interface_token().unwrap().as_str())
        .unwrap();
    let w = data.read_buffer(TEST_LEN).unwrap();
    reply.write_buffer(&w);

    reply.write_file(data.read_file().unwrap());

    reply.write(&data.read::<bool>().unwrap());
    reply.write(&data.read::<bool>().unwrap());
    reply.write(&data.read::<i8>().unwrap());
    reply.write(&data.read::<i8>().unwrap());
    reply.write(&data.read::<i16>().unwrap());
    reply.write(&data.read::<i16>().unwrap());
    reply.write(&data.read::<i32>().unwrap());
    reply.write(&data.read::<i32>().unwrap());
    reply.write(&data.read::<i64>().unwrap());
    reply.write(&data.read::<i64>().unwrap());

    reply.write(&data.read::<u8>().unwrap());
    reply.write(&data.read::<u8>().unwrap());
    reply.write(&data.read::<u16>().unwrap());
    reply.write(&data.read::<u16>().unwrap());
    reply.write(&data.read::<u32>().unwrap());
    reply.write(&data.read::<u32>().unwrap());
    reply.write(&data.read::<u64>().unwrap());
    reply.write(&data.read::<u64>().unwrap());

    reply.write(&data.read::<usize>().unwrap());
    reply.write(&data.read::<usize>().unwrap());
}

fn parcel_remote_vec(data: &mut MsgParcel, reply: &mut MsgParcel) {
    reply.write(&data.read::<Vec<bool>>().unwrap());
    reply.write(&data.read::<Vec<i8>>().unwrap());
    reply.write(&data.read::<Vec<i16>>().unwrap());
    reply.write(&data.read::<Vec<i32>>().unwrap());
    reply.write(&data.read::<Vec<i64>>().unwrap());

    reply.write(&data.read::<Vec<i8>>().unwrap());
    reply.write(&data.read::<Vec<i16>>().unwrap());
    reply.write(&data.read::<Vec<i32>>().unwrap());
    reply.write(&data.read::<Vec<i64>>().unwrap());

    reply.write(&data.read::<Vec<u8>>().unwrap());
    reply.write(&data.read::<Vec<u16>>().unwrap());
    reply.write(&data.read::<Vec<u32>>().unwrap());
    reply.write(&data.read::<Vec<u64>>().unwrap());

    reply.write(&data.read::<Vec<u8>>().unwrap());
    reply.write(&data.read::<Vec<u16>>().unwrap());
    reply.write(&data.read::<Vec<u32>>().unwrap());
    reply.write(&data.read::<Vec<u64>>().unwrap());

    reply.write(&data.read::<Vec<f32>>().unwrap());
    reply.write(&data.read::<Vec<f64>>().unwrap());

    reply.write(&data.read::<String>().unwrap());
    reply.write(&data.read::<String>().unwrap());
    reply.write(&data.read::<Vec<String>>().unwrap());
    reply.write_string16(&data.read_string16().unwrap());
    reply.write_string16_vec(&data.read_string16_vec().unwrap());
}

fn read_and_write(msg: &mut MsgParcel) {
    msg.write_interface_token("hello ipc").unwrap();
    msg.write_buffer(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open("ipc_rust_test_temp1")
        .unwrap();
    file.write_all("hello ipc".as_bytes());
    msg.write_file(file);

    msg.write(&true).unwrap();
    msg.write(&false).unwrap();
    msg.write(&i8::MAX).unwrap();
    msg.write(&i8::MIN).unwrap();
    msg.write(&i16::MAX).unwrap();
    msg.write(&i16::MIN).unwrap();
    msg.write(&i32::MAX).unwrap();
    msg.write(&i32::MIN).unwrap();
    msg.write(&i64::MAX).unwrap();
    msg.write(&i64::MIN).unwrap();
    msg.write(&u8::MAX).unwrap();
    msg.write(&u8::MIN).unwrap();

    msg.write(&u16::MAX).unwrap();
    msg.write(&u16::MIN).unwrap();
    msg.write(&u32::MAX).unwrap();
    msg.write(&u32::MIN).unwrap();
    msg.write(&u64::MAX).unwrap();
    msg.write(&u64::MIN).unwrap();
    msg.write(&usize::MAX).unwrap();
    msg.write(&usize::MIN).unwrap();
}

fn read_and_write_vec(msg: &mut MsgParcel) {
    msg.write(&vec![true; 3]).unwrap();
    msg.write(&vec![i8::MIN; 3]).unwrap();
    msg.write(&vec![i16::MIN; 3]).unwrap();
    msg.write(&vec![i32::MIN; 3]).unwrap();
    msg.write(&vec![i64::MIN; 3]).unwrap();

    msg.write(&vec![i8::MAX; 3]).unwrap();
    msg.write(&vec![i16::MAX; 3]).unwrap();
    msg.write(&vec![i32::MAX; 3]).unwrap();
    msg.write(&vec![i64::MAX; 3]).unwrap();

    msg.write(&vec![u8::MIN; 3]).unwrap();
    msg.write(&vec![u16::MIN; 3]).unwrap();
    msg.write(&vec![u32::MIN; 3]).unwrap();
    msg.write(&vec![u64::MIN; 3]).unwrap();

    msg.write(&vec![u8::MAX; 3]).unwrap();
    msg.write(&vec![u16::MAX; 3]).unwrap();
    msg.write(&vec![u32::MAX; 3]).unwrap();
    msg.write(&vec![u64::MAX; 3]).unwrap();

    msg.write(&vec![TEST_FLOAT; 3]).unwrap();
    msg.write(&vec![TEST_DOUBLE; 3]).unwrap();

    msg.write("hello ipc").unwrap();
    let s = String::from("hello ipc");
    msg.write(&s).unwrap();
}

#[test]
fn parcel_read_and_write() {
    init();

    let test_service = SystemAbilityManager::get_system_ability(TEST_SYSTEM_ABILITY_ID).unwrap();
    let mut msg = MsgParcel::new();

    read_and_write(&mut msg);
    read_and_write_vec(&mut msg);

    let s = String::from("ipc hello");
    let v = vec![s.clone(), s.clone(), s.clone()];
    msg.write(&v).unwrap();

    msg.write_string16(&s);
    msg.write_string16_vec(&v);

    let mut reply = test_service.send_request(0, &mut msg).unwrap();

    assert_eq!(reply.read_interface_token().unwrap(), "hello ipc");

    assert_eq!(
        reply.read_buffer(TEST_LEN).unwrap(),
        vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    );

    let mut file = reply.read_file().unwrap();
    file.rewind();
    let mut res = vec![];
    file.read_to_end(&mut res);
    let s = String::from_utf8(res).unwrap();
    assert_eq!(s, "hello ipc");

}

fn assert_read_and_write(reply: &mut MsgParcel) {
    assert!(reply.read::<bool>().unwrap());
    assert!(!reply.read::<bool>().unwrap());
    assert_eq!(i8::MAX, reply.read().unwrap());
    assert_eq!(i8::MIN, reply.read().unwrap());

    assert_eq!(i16::MAX, reply.read().unwrap());
    assert_eq!(i16::MIN, reply.read().unwrap());
    assert_eq!(i32::MAX, reply.read().unwrap());
    assert_eq!(i32::MIN, reply.read().unwrap());
    assert_eq!(i64::MAX, reply.read().unwrap());
    assert_eq!(i64::MIN, reply.read().unwrap());
    assert_eq!(u8::MAX, reply.read().unwrap());
    assert_eq!(u8::MIN, reply.read().unwrap());

    assert_eq!(u16::MAX, reply.read().unwrap());
    assert_eq!(u16::MIN, reply.read().unwrap());
    assert_eq!(u32::MAX, reply.read().unwrap());
    assert_eq!(u32::MIN, reply.read().unwrap());
    assert_eq!(u64::MAX, reply.read().unwrap());
    assert_eq!(u64::MIN, reply.read().unwrap());
    assert_eq!(usize::MAX, reply.read().unwrap());
    assert_eq!(usize::MIN, reply.read().unwrap());
}

fn assert_read_and_write_vec(reply: &mut MsgParcel) {
    assert_eq!(reply.read::<Vec<bool>>().unwrap(), vec![true; 3]);
    assert_eq!(reply.read::<Vec<i8>>().unwrap(), vec![i8::MIN; 3]);
    assert_eq!(reply.read::<Vec<i16>>().unwrap(), vec![i16::MIN; 3]);
    assert_eq!(reply.read::<Vec<i32>>().unwrap(), vec![i32::MIN; 3]);
    assert_eq!(reply.read::<Vec<i64>>().unwrap(), vec![i64::MIN; 3]);

    assert_eq!(reply.read::<Vec<i8>>().unwrap(), vec![i8::MAX; 3]);
    assert_eq!(reply.read::<Vec<i16>>().unwrap(), vec![i16::MAX; 3]);
    assert_eq!(reply.read::<Vec<i32>>().unwrap(), vec![i32::MAX; 3]);
    assert_eq!(reply.read::<Vec<i64>>().unwrap(), vec![i64::MAX; 3]);

    assert_eq!(reply.read::<Vec<u8>>().unwrap(), vec![u8::MIN; 3]);
    assert_eq!(reply.read::<Vec<u16>>().unwrap(), vec![u16::MIN; 3]);
    assert_eq!(reply.read::<Vec<u32>>().unwrap(), vec![u32::MIN; 3]);
    assert_eq!(reply.read::<Vec<u64>>().unwrap(), vec![u64::MIN; 3]);

    assert_eq!(reply.read::<Vec<u8>>().unwrap(), vec![u8::MAX; 3]);
    assert_eq!(reply.read::<Vec<u16>>().unwrap(), vec![u16::MAX; 3]);
    assert_eq!(reply.read::<Vec<u32>>().unwrap(), vec![u32::MAX; 3]);
    assert_eq!(reply.read::<Vec<u64>>().unwrap(), vec![u64::MAX; 3]);

    assert_eq!(reply.read::<Vec<f32>>().unwrap(), vec![TEST_FLOAT; 3]);
    assert_eq!(reply.read::<Vec<f64>>().unwrap(), vec![TEST_DOUBLE; 3]);
}
