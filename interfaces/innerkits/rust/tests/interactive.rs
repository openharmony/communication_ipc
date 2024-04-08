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

use ipc::cxx_share::MessageParcel;
use ipc::parcel::MsgParcel;

const TEST_FLOAT: f32 = 7.02;
const TEST_DOUBLE: f64 = 7.03;

fn check_parcel(msg: &mut MsgParcel) {
    assert_eq!(msg.read_interface_token().unwrap(), "TEST");
    assert_eq!(msg.read_buffer("TEST".len()).unwrap(), "TEST".as_bytes());
    assert!(msg.read::<bool>().unwrap());
    assert_eq!(msg.read::<u8>().unwrap(), u8::MAX);
    assert_eq!(msg.read::<u16>().unwrap(), u16::MAX);
    assert_eq!(msg.read::<u32>().unwrap(), u32::MAX);
    assert_eq!(msg.read::<u64>().unwrap(), u64::MAX);

    assert_eq!(msg.read::<i8>().unwrap(), i8::MAX);
    assert_eq!(msg.read::<i16>().unwrap(), i16::MAX);
    assert_eq!(msg.read::<i32>().unwrap(), i32::MAX);
    assert_eq!(msg.read::<i64>().unwrap(), i64::MAX);

    assert_eq!(msg.read::<i8>().unwrap(), i8::MIN);
    assert_eq!(msg.read::<i16>().unwrap(), i16::MIN);
    assert_eq!(msg.read::<i32>().unwrap(), i32::MIN);
    assert_eq!(msg.read::<i64>().unwrap(), i64::MIN);

    assert_eq!(msg.read::<f32>().unwrap(), 7.02);
    assert_eq!(msg.read::<f64>().unwrap(), 7.03);

    assert_eq!(msg.read::<Vec<bool>>().unwrap(), vec![true; 3]);

    assert_eq!(msg.read::<Vec<u8>>().unwrap(), vec![u8::MAX; 3]);
    assert_eq!(msg.read::<Vec<u16>>().unwrap(), vec![u16::MAX; 3]);
    assert_eq!(msg.read::<Vec<u32>>().unwrap(), vec![u32::MAX; 3]);
    assert_eq!(msg.read::<Vec<u64>>().unwrap(), vec![u64::MAX; 3]);

    assert_eq!(msg.read::<Vec<i8>>().unwrap(), vec![i8::MAX; 3]);
    assert_eq!(msg.read::<Vec<i16>>().unwrap(), vec![i16::MAX; 3]);
    assert_eq!(msg.read::<Vec<i32>>().unwrap(), vec![i32::MAX; 3]);
    assert_eq!(msg.read::<Vec<i64>>().unwrap(), vec![i64::MAX; 3]);

    assert_eq!(msg.read::<Vec<i8>>().unwrap(), vec![i8::MIN; 3]);
    assert_eq!(msg.read::<Vec<i16>>().unwrap(), vec![i16::MIN; 3]);
    assert_eq!(msg.read::<Vec<i32>>().unwrap(), vec![i32::MIN; 3]);
    assert_eq!(msg.read::<Vec<i64>>().unwrap(), vec![i64::MIN; 3]);

    assert_eq!(msg.read::<Vec<f32>>().unwrap(), vec![TEST_FLOAT; 3]);
    assert_eq!(msg.read::<Vec<f64>>().unwrap(), vec![TEST_DOUBLE; 3]);
    
    assert_eq!(
        msg.read::<Vec<String>>().unwrap(),
        vec![String::from("TEST"); 3]
    );

    assert_eq!(
        msg.read_string16_vec().unwrap(),
        vec![String::from("TEST"); 3]
    );
}

#[test]
fn interactive_msg_parcel_read() {
    let mut msg = unsafe { MsgParcel::from_ptr(GetTestMessageParcel()) };
    check_parcel(&mut msg);
}

#[test]
fn interactive_msg_parcel_write() {
    let mut msg = MsgParcel::new();
    msg.write_interface_token("TEST").unwrap();

    let data = String::from("TEST");
    msg.write_buffer(data.as_bytes()).unwrap();

    msg.write(&true).unwrap();
    msg.write(&u8::MAX).unwrap();
    msg.write(&u16::MAX).unwrap();
    msg.write(&u32::MAX).unwrap();
    msg.write(&u64::MAX).unwrap();

    msg.write(&i8::MAX).unwrap();
    msg.write(&i16::MAX).unwrap();
    msg.write(&i32::MAX).unwrap();
    msg.write(&i64::MAX).unwrap();

    msg.write(&i8::MIN).unwrap();
    msg.write(&i16::MIN).unwrap();
    msg.write(&i32::MIN).unwrap();
    msg.write(&i64::MIN).unwrap();

    msg.write(&7.02f32).unwrap();
    msg.write(&7.03f64).unwrap();

    msg.write(&vec![true; 3]).unwrap();
    msg.write(&vec![u8::MAX; 3]).unwrap();
    msg.write(&vec![u16::MAX; 3]).unwrap();
    msg.write(&vec![u32::MAX; 3]).unwrap();
    msg.write(&vec![u64::MAX; 3]).unwrap();

    msg.write(&vec![i8::MAX; 3]).unwrap();
    msg.write(&vec![i16::MAX; 3]).unwrap();
    msg.write(&vec![i32::MAX; 3]).unwrap();
    msg.write(&vec![i64::MAX; 3]).unwrap();

    msg.write(&vec![i8::MIN; 3]).unwrap();
    msg.write(&vec![i16::MIN; 3]).unwrap();
    msg.write(&vec![i32::MIN; 3]).unwrap();
    msg.write(&vec![i64::MIN; 3]).unwrap();

    msg.write(&vec![TEST_FLOAT; 3]).unwrap();
    msg.write(&vec![TEST_DOUBLE; 3]).unwrap();
    
    msg.write(&vec![String::from("TEST"); 3]).unwrap();

    msg.write_string16_vec(&[
        String::from("TEST"),
        String::from("TEST"),
        String::from("TEST"),
    ])
    .unwrap();

    let mut reply = unsafe { MsgParcel::from_ptr(ReadAndWrite(msg.into_raw())) };
    check_parcel(&mut reply);
}

#[link(name = "ipc_rust_test_c")]
extern "C" {
    fn GetTestMessageParcel() -> *mut MessageParcel;
    fn ReadAndWrite(parcel: *mut MessageParcel) -> *mut MessageParcel;
}
