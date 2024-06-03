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

#![allow(unused)]

use std::mem::size_of;
use std::pin::Pin;

use cxx::CxxVector;
pub use ffi::*;

use super::msg::MsgParcel;
use super::{Deserialize, Serialize};
use crate::{IpcResult, IpcStatusCode};

#[cxx::bridge(namespace = "OHOS::IpcRust")]
mod ffi {

    unsafe extern "C++" {
        include!("parcel_wrapper.h");
        include!("message_option.h");
        type IRemoteObjectWrapper = crate::remote::wrapper::IRemoteObjectWrapper;

        #[namespace = "OHOS"]
        type MessageParcel;
        #[namespace = "OHOS"]
        type MessageOption;
        #[namespace = "OHOS"]
        type Parcel;

        fn NewMessageParcel() -> UniquePtr<MessageParcel>;
        fn NewMessageOption() -> UniquePtr<MessageOption>;

        fn ReadFileDescriptor(self: Pin<&mut MessageParcel>) -> i32;
        fn WriteFileDescriptor(self: Pin<&mut MessageParcel>, fd: i32) -> bool;

        unsafe fn AsParcel(MsgParcel: &MessageParcel) -> *const Parcel;
        unsafe fn AsParcelMut(msgParcel: Pin<&mut MessageParcel>) -> *mut Parcel;

        fn WriteInterfaceToken(msgParcel: Pin<&mut MessageParcel>, name: &str) -> bool;
        fn ReadInterfaceToken(msgParcel: Pin<&mut MessageParcel>) -> String;

        fn WriteBuffer(msgParcel: Pin<&mut MessageParcel>, buffer: &[u8]) -> bool;

        fn ReadBuffer(msgParcel: Pin<&mut MessageParcel>, len: usize, buffer: &mut Vec<u8>)
            -> bool;

        fn WriteRemoteObject(
            msgParcel: Pin<&mut MessageParcel>,
            value: UniquePtr<IRemoteObjectWrapper>,
        ) -> bool;

        fn ReadRemoteObject(msgParcel: Pin<&mut MessageParcel>) -> UniquePtr<IRemoteObjectWrapper>;

        fn ReadString(parcel: Pin<&mut Parcel>, val: &mut String) -> bool;
        fn WriteString(parcel: Pin<&mut Parcel>, val: &str) -> bool;

        fn ReadString16(parcel: Pin<&mut Parcel>) -> String;
        fn WriteString16(parcel: Pin<&mut Parcel>, val: &str) -> bool;

        fn WriteBool(self: Pin<&mut Parcel>, mut value: bool) -> bool;
        fn WriteInt8(self: Pin<&mut Parcel>, mut value: i8) -> bool;
        fn WriteInt16(self: Pin<&mut Parcel>, mut value: i16) -> bool;
        fn WriteInt32(self: Pin<&mut Parcel>, mut value: i32) -> bool;
        fn WriteInt64(self: Pin<&mut Parcel>, mut value: i64) -> bool;

        fn WriteUint8(self: Pin<&mut Parcel>, mut value: u8) -> bool;
        fn WriteUint16(self: Pin<&mut Parcel>, mut value: u16) -> bool;
        fn WriteUint32(self: Pin<&mut Parcel>, mut value: u32) -> bool;
        fn WriteUint64(self: Pin<&mut Parcel>, mut value: u64) -> bool;

        fn WriteFloat(self: Pin<&mut Parcel>, mut value: f32) -> bool;
        fn WriteDouble(self: Pin<&mut Parcel>, mut value: f64) -> bool;
        fn WritePointer(self: Pin<&mut Parcel>, mut value: usize) -> bool;

        fn ReadBool(self: Pin<&mut Parcel>, v: &mut bool) -> bool;
        fn ReadInt8(self: Pin<&mut Parcel>, v: &mut i8) -> bool;
        fn ReadInt16(self: Pin<&mut Parcel>, v: &mut i16) -> bool;
        fn ReadInt32(self: Pin<&mut Parcel>, v: &mut i32) -> bool;
        fn ReadInt64(self: Pin<&mut Parcel>, v: &mut i64) -> bool;
        fn ReadUint8(self: Pin<&mut Parcel>, v: &mut u8) -> bool;
        fn ReadUint16(self: Pin<&mut Parcel>, v: &mut u16) -> bool;
        fn ReadUint32(self: Pin<&mut Parcel>, v: &mut u32) -> bool;
        fn ReadUint64(self: Pin<&mut Parcel>, v: &mut u64) -> bool;
        fn ReadFloat(self: Pin<&mut Parcel>, v: &mut f32) -> bool;
        fn ReadDouble(self: Pin<&mut Parcel>, v: &mut f64) -> bool;
        fn ReadPointer(self: Pin<&mut Parcel>) -> usize;

        fn GetDataSize(self: &Parcel) -> usize;
        fn GetWritableBytes(self: &Parcel) -> usize;
        fn GetReadableBytes(self: &Parcel) -> usize;
        fn GetOffsetsSize(self: &Parcel) -> usize;
        fn GetDataCapacity(self: &Parcel) -> usize;
        fn GetMaxCapacity(self: &Parcel) -> usize;

        fn SetDataCapacity(self: Pin<&mut Parcel>, size: usize) -> bool;
        fn SetDataSize(self: Pin<&mut Parcel>, size: usize) -> bool;
        fn SetMaxCapacity(self: Pin<&mut Parcel>, size: usize) -> bool;

        fn GetReadPosition(self: Pin<&mut Parcel>) -> usize;
        fn GetWritePosition(self: Pin<&mut Parcel>) -> usize;

        fn SkipBytes(self: Pin<&mut Parcel>, size: usize);
        fn RewindRead(self: Pin<&mut Parcel>, size: usize) -> bool;
        fn RewindWrite(self: Pin<&mut Parcel>, size: usize) -> bool;

        fn ReadUint8Unaligned(self: Pin<&mut Parcel>, val: &mut u8) -> bool;

        fn SetFlags(self: Pin<&mut MessageOption>, flag: i32);
        fn GetFlags(self: &MessageOption) -> i32;

        fn WriteBoolVector(parcel: Pin<&mut Parcel>, val: &[bool]) -> bool;
        fn WriteInt8Vector(parcel: Pin<&mut Parcel>, val: &[i8]) -> bool;
        fn WriteInt16Vector(parcel: Pin<&mut Parcel>, val: &[i16]) -> bool;
        fn WriteInt32Vector(parcel: Pin<&mut Parcel>, val: &[i32]) -> bool;
        fn WriteInt64Vector(parcel: Pin<&mut Parcel>, val: &[i64]) -> bool;
        fn WriteUInt8Vector(parcel: Pin<&mut Parcel>, val: &[u8]) -> bool;
        fn WriteUInt16Vector(parcel: Pin<&mut Parcel>, val: &[u16]) -> bool;
        fn WriteUInt32Vector(parcel: Pin<&mut Parcel>, val: &[u32]) -> bool;
        fn WriteUInt64Vector(parcel: Pin<&mut Parcel>, val: &[u64]) -> bool;
        fn WriteFloatVector(parcel: Pin<&mut Parcel>, val: &[f32]) -> bool;
        fn WriteDoubleVector(parcel: Pin<&mut Parcel>, val: &[f64]) -> bool;
        fn WriteStringVector(parcel: Pin<&mut Parcel>, val: &[String]) -> bool;
        fn WriteString16Vector(parcel: Pin<&mut Parcel>, val: &[String]) -> bool;

        fn ReadBoolVector(parcel: Pin<&mut Parcel>, v: &mut Vec<bool>) -> bool;
        fn ReadInt8Vector(parcel: Pin<&mut Parcel>, v: &mut Vec<i8>) -> bool;
        fn ReadInt16Vector(parcel: Pin<&mut Parcel>, v: &mut Vec<i16>) -> bool;
        fn ReadInt32Vector(parcel: Pin<&mut Parcel>, v: &mut Vec<i32>) -> bool;
        fn ReadInt64Vector(parcel: Pin<&mut Parcel>, v: &mut Vec<i64>) -> bool;
        fn ReadUInt8Vector(parcel: Pin<&mut Parcel>, v: &mut Vec<u8>) -> bool;
        fn ReadUInt16Vector(parcel: Pin<&mut Parcel>, v: &mut Vec<u16>) -> bool;
        fn ReadUInt32Vector(parcel: Pin<&mut Parcel>, v: &mut Vec<u32>) -> bool;
        fn ReadUInt64Vector(parcel: Pin<&mut Parcel>, v: &mut Vec<u64>) -> bool;
        fn ReadFloatVector(parcel: Pin<&mut Parcel>, v: &mut Vec<f32>) -> bool;
        fn ReadDoubleVector(parcel: Pin<&mut Parcel>, v: &mut Vec<f64>) -> bool;
        fn ReadStringVector(parcel: Pin<&mut Parcel>, v: &mut Vec<String>) -> bool;
        fn ReadString16Vector(parcel: Pin<&mut Parcel>, v: &mut Vec<String>) -> bool;
    }
}

pub(crate) fn get_pad_size(size: usize) -> usize {
    const SIZE_OFFSET: usize = 3;
    (((size + SIZE_OFFSET) & (!SIZE_OFFSET)) - size)
}

trait Process: Sized {
    fn write_process(&self, parcel: Pin<&mut Parcel>) -> bool;

    fn read_process(parcel: Pin<&mut Parcel>) -> IpcResult<Self>;

    fn write_process_vec(val: &[Self], parcel: Pin<&mut Parcel>) -> bool;

    fn read_process_vec(parcel: Pin<&mut Parcel>) -> IpcResult<Vec<Self>>;
}

impl Process for bool {
    fn write_process(&self, parcel: Pin<&mut Parcel>) -> bool {
        parcel.WriteBool(*self)
    }

    fn read_process(parcel: Pin<&mut Parcel>) -> IpcResult<Self> {
        let mut v = Self::default();
        match parcel.ReadBool(&mut v) {
            true => Ok(v),
            false => Err(IpcStatusCode::Failed),
        }
    }

    fn write_process_vec(val: &[Self], parcel: Pin<&mut Parcel>) -> bool {
        WriteBoolVector(parcel, val)
    }

    fn read_process_vec(parcel: Pin<&mut Parcel>) -> IpcResult<Vec<Self>> {
        let mut v = vec![];
        match ReadBoolVector(parcel, &mut v) {
            true => Ok(v),
            false => Err(IpcStatusCode::Failed),
        }
    }
}

impl Process for i8 {
    fn write_process(&self, parcel: Pin<&mut Parcel>) -> bool {
        parcel.WriteInt8(*self)
    }

    fn read_process(parcel: Pin<&mut Parcel>) -> IpcResult<Self> {
        let mut v = Self::default();
        match parcel.ReadInt8(&mut v) {
            true => Ok(v),
            false => Err(IpcStatusCode::Failed),
        }
    }

    fn write_process_vec(val: &[Self], parcel: Pin<&mut Parcel>) -> bool {
        WriteInt8Vector(parcel, val)
    }

    fn read_process_vec(parcel: Pin<&mut Parcel>) -> IpcResult<Vec<Self>> {
        let mut v = vec![];
        match ReadInt8Vector(parcel, &mut v) {
            true => Ok(v),
            false => Err(IpcStatusCode::Failed),
        }
    }
}

impl Process for i16 {
    fn write_process(&self, parcel: Pin<&mut Parcel>) -> bool {
        parcel.WriteInt16(*self)
    }

    fn read_process(parcel: Pin<&mut Parcel>) -> IpcResult<Self> {
        let mut v = Self::default();
        match parcel.ReadInt16(&mut v) {
            true => Ok(v),
            false => Err(IpcStatusCode::Failed),
        }
    }
    fn write_process_vec(val: &[Self], parcel: Pin<&mut Parcel>) -> bool {
        WriteInt16Vector(parcel, val)
    }

    fn read_process_vec(parcel: Pin<&mut Parcel>) -> IpcResult<Vec<Self>> {
        let mut v = vec![];
        match ReadInt16Vector(parcel, &mut v) {
            true => Ok(v),
            false => Err(IpcStatusCode::Failed),
        }
    }
}

impl Process for i32 {
    fn write_process(&self, parcel: Pin<&mut Parcel>) -> bool {
        parcel.WriteInt32(*self)
    }

    fn read_process(parcel: Pin<&mut Parcel>) -> IpcResult<Self> {
        let mut v = Self::default();
        match parcel.ReadInt32(&mut v) {
            true => Ok(v),
            false => Err(IpcStatusCode::Failed),
        }
    }

    fn write_process_vec(val: &[Self], parcel: Pin<&mut Parcel>) -> bool {
        WriteInt32Vector(parcel, val)
    }

    fn read_process_vec(parcel: Pin<&mut Parcel>) -> IpcResult<Vec<Self>> {
        let mut v = vec![];
        match ReadInt32Vector(parcel, &mut v) {
            true => Ok(v),
            false => Err(IpcStatusCode::Failed),
        }
    }
}

impl Process for i64 {
    fn write_process(&self, parcel: Pin<&mut Parcel>) -> bool {
        parcel.WriteInt64(*self)
    }
    fn read_process(parcel: Pin<&mut Parcel>) -> IpcResult<Self> {
        let mut v = Self::default();
        match parcel.ReadInt64(&mut v) {
            true => Ok(v),
            false => Err(IpcStatusCode::Failed),
        }
    }

    fn write_process_vec(val: &[Self], parcel: Pin<&mut Parcel>) -> bool {
        WriteInt64Vector(parcel, val)
    }

    fn read_process_vec(parcel: Pin<&mut Parcel>) -> IpcResult<Vec<Self>> {
        let mut v = vec![];
        match ReadInt64Vector(parcel, &mut v) {
            true => Ok(v),
            false => Err(IpcStatusCode::Failed),
        }
    }
}

impl Process for u8 {
    fn write_process(&self, parcel: Pin<&mut Parcel>) -> bool {
        parcel.WriteUint8(*self)
    }

    fn read_process(parcel: Pin<&mut Parcel>) -> IpcResult<Self> {
        let mut v = Self::default();
        match parcel.ReadUint8(&mut v) {
            true => Ok(v),
            false => Err(IpcStatusCode::Failed),
        }
    }

    fn write_process_vec(val: &[Self], parcel: Pin<&mut Parcel>) -> bool {
        WriteUInt8Vector(parcel, val)
    }

    fn read_process_vec(parcel: Pin<&mut Parcel>) -> IpcResult<Vec<Self>> {
        let mut v = vec![];
        match ReadUInt8Vector(parcel, &mut v) {
            true => Ok(v),
            false => Err(IpcStatusCode::Failed),
        }
    }
}

impl Process for u16 {
    fn write_process(&self, parcel: Pin<&mut Parcel>) -> bool {
        parcel.WriteUint16(*self)
    }
    fn read_process(parcel: Pin<&mut Parcel>) -> IpcResult<Self> {
        let mut v = Self::default();
        match parcel.ReadUint16(&mut v) {
            true => Ok(v),
            false => Err(IpcStatusCode::Failed),
        }
    }

    fn write_process_vec(val: &[Self], parcel: Pin<&mut Parcel>) -> bool {
        WriteUInt16Vector(parcel, val)
    }

    fn read_process_vec(parcel: Pin<&mut Parcel>) -> IpcResult<Vec<Self>> {
        let mut v = vec![];
        match ReadUInt16Vector(parcel, &mut v) {
            true => Ok(v),
            false => Err(IpcStatusCode::Failed),
        }
    }
}

impl Process for u32 {
    fn write_process(&self, parcel: Pin<&mut Parcel>) -> bool {
        parcel.WriteUint32(*self)
    }

    fn read_process(parcel: Pin<&mut Parcel>) -> IpcResult<Self> {
        let mut v = Self::default();
        match parcel.ReadUint32(&mut v) {
            true => Ok(v),
            false => Err(IpcStatusCode::Failed),
        }
    }

    fn write_process_vec(val: &[Self], parcel: Pin<&mut Parcel>) -> bool {
        WriteUInt32Vector(parcel, val)
    }

    fn read_process_vec(parcel: Pin<&mut Parcel>) -> IpcResult<Vec<Self>> {
        let mut v = vec![];
        match ReadUInt32Vector(parcel, &mut v) {
            true => Ok(v),
            false => Err(IpcStatusCode::Failed),
        }
    }
}

impl Process for u64 {
    fn write_process(&self, parcel: Pin<&mut Parcel>) -> bool {
        parcel.WriteUint64(*self)
    }
    fn read_process(parcel: Pin<&mut Parcel>) -> IpcResult<Self> {
        let mut v = Self::default();
        match parcel.ReadUint64(&mut v) {
            true => Ok(v),
            false => Err(IpcStatusCode::Failed),
        }
    }
    fn write_process_vec(val: &[Self], parcel: Pin<&mut Parcel>) -> bool {
        WriteUInt64Vector(parcel, val)
    }

    fn read_process_vec(parcel: Pin<&mut Parcel>) -> IpcResult<Vec<Self>> {
        let mut v = vec![];
        match ReadUInt64Vector(parcel, &mut v) {
            true => Ok(v),
            false => Err(IpcStatusCode::Failed),
        }
    }
}
#[cfg(target_pointer_width = "64")]
impl Process for usize {
    fn write_process(&self, parcel: Pin<&mut Parcel>) -> bool {
        parcel.WriteUint64(*self as u64)
    }
    fn read_process(parcel: Pin<&mut Parcel>) -> IpcResult<Self> {
        let mut v: u64 = u64::default();
        match parcel.ReadUint64(&mut v) {
            true => Ok(v as usize),
            false => Err(IpcStatusCode::Failed),
        }
    }
    fn write_process_vec(val: &[Self], parcel: Pin<&mut Parcel>) -> bool {
        let v: Vec<u64> = val.iter().map(|i| *i as u64).collect();
        WriteUInt64Vector(parcel, &v[..])
    }

    fn read_process_vec(parcel: Pin<&mut Parcel>) -> IpcResult<Vec<Self>> {
        let mut v = vec![];
        match ReadUInt64Vector(parcel, &mut v) {
            true => Ok(v.into_iter().map(|i| i as usize).collect()),
            false => Err(IpcStatusCode::Failed),
        }
    }
}

#[cfg(target_pointer_width = "32")]
impl Process for usize {
    fn write_process(&self, parcel: Pin<&mut Parcel>) -> bool {
        parcel.WriteUint32(*self as u32)
    }
    fn read_process(parcel: Pin<&mut Parcel>) -> IpcResult<Self> {
        let mut v: u32 = u32::default();
        match parcel.ReadUint32(&mut v) {
            true => Ok(v as usize),
            false => Err(IpcStatusCode::Failed),
        }
    }
    fn write_process_vec(val: &[Self], parcel: Pin<&mut Parcel>) -> bool {
        let v: Vec<u32> = val.iter().map(|i| *i as u32).collect();
        WriteUInt32Vector(parcel, &v[..])
    }

    fn read_process_vec(parcel: Pin<&mut Parcel>) -> IpcResult<Vec<Self>> {
        let mut v = vec![];
        match ReadUInt32Vector(parcel, &mut v) {
            true => Ok(v.into_iter().map(|i| i as usize).collect()),
            false => Err(IpcStatusCode::Failed),
        }
    }
}

impl Process for f32 {
    fn write_process(&self, parcel: Pin<&mut Parcel>) -> bool {
        parcel.WriteFloat(*self)
    }
    fn read_process(parcel: Pin<&mut Parcel>) -> IpcResult<Self> {
        let mut v = Self::default();
        match parcel.ReadFloat(&mut v) {
            true => Ok(v),
            false => Err(IpcStatusCode::Failed),
        }
    }

    fn write_process_vec(val: &[Self], parcel: Pin<&mut Parcel>) -> bool {
        WriteFloatVector(parcel, val)
    }

    fn read_process_vec(parcel: Pin<&mut Parcel>) -> IpcResult<Vec<Self>> {
        let mut v = vec![];
        match ReadFloatVector(parcel, &mut v) {
            true => Ok(v),
            false => Err(IpcStatusCode::Failed),
        }
    }
}

impl Process for f64 {
    fn write_process(&self, parcel: Pin<&mut Parcel>) -> bool {
        parcel.WriteDouble(*self)
    }
    fn read_process(parcel: Pin<&mut Parcel>) -> IpcResult<Self> {
        let mut v = Self::default();
        match parcel.ReadDouble(&mut v) {
            true => Ok(v),
            false => Err(IpcStatusCode::Failed),
        }
    }

    fn write_process_vec(val: &[Self], parcel: Pin<&mut Parcel>) -> bool {
        WriteDoubleVector(parcel, val)
    }

    fn read_process_vec(parcel: Pin<&mut Parcel>) -> IpcResult<Vec<Self>> {
        let mut v = vec![];
        match ReadDoubleVector(parcel, &mut v) {
            true => Ok(v),
            false => Err(IpcStatusCode::Failed),
        }
    }
}

impl Process for String {
    fn write_process(&self, parcel: Pin<&mut Parcel>) -> bool {
        WriteString(parcel, self.as_str())
    }
    fn read_process(parcel: Pin<&mut Parcel>) -> IpcResult<Self> {
        let mut s = String::new();
        match ReadString(parcel, &mut s) {
            true => Ok(s),
            false => Err(IpcStatusCode::Failed),
        }
    }

    fn write_process_vec(val: &[Self], parcel: Pin<&mut Parcel>) -> bool {
        WriteStringVector(parcel, val)
    }

    fn read_process_vec(parcel: Pin<&mut Parcel>) -> IpcResult<Vec<Self>> {
        let mut v = vec![];
        match ReadStringVector(parcel, &mut v) {
            true => Ok(v),
            false => Err(IpcStatusCode::Failed),
        }
    }
}

impl<T: Process> Serialize for T {
    fn serialize(&self, parcel: &mut MsgParcel) -> IpcResult<()> {
        fn write<T: Process>(parcel: Pin<&mut MessageParcel>, value: &T) -> bool {
            unsafe {
                let parcel = AsParcelMut(parcel);
                value.write_process(Pin::new_unchecked(&mut *parcel))
            }
        }
        parcel.write_process(self, write)
    }
}

impl<T: Process> Deserialize for T {
    fn deserialize(parcel: &mut MsgParcel) -> IpcResult<T> {
        fn read<T: Process>(parcel: Pin<&mut MessageParcel>) -> IpcResult<T> {
            unsafe {
                let parcel = AsParcelMut(parcel);
                Process::read_process(Pin::new_unchecked(&mut *parcel))
            }
        }
        parcel.read_process(read)
    }
}

impl Serialize for str {
    fn serialize(&self, parcel: &mut MsgParcel) -> crate::IpcResult<()> {
        fn write(parcel: Pin<&mut MessageParcel>, value: &str) -> bool {
            unsafe {
                let parcel = AsParcelMut(parcel);
                WriteString(Pin::new_unchecked(&mut *parcel), value)
            }
        }
        parcel.write_process(self, write)
    }
}

impl<T: Process> Serialize for [T] {
    fn serialize(&self, parcel: &mut MsgParcel) -> IpcResult<()> {
        match T::write_process_vec(self, parcel.as_parcel_mut()) {
            true => Ok(()),
            false => Err(IpcStatusCode::Failed),
        }
    }
}

impl<T: Process> Deserialize for Vec<T> {
    fn deserialize(parcel: &mut MsgParcel) -> IpcResult<Self> {
        T::read_process_vec(parcel.as_parcel_mut())
    }
}

impl<T: Process> Serialize for Vec<T> {
    fn serialize(&self, parcel: &mut MsgParcel) -> crate::IpcResult<()> {
        <[T]>::serialize(self, parcel)
    }
}

#[cfg(test)]
mod test {
    use std::fs;
    use std::io::{Read, Seek, Write};

    use crate::parcel::MsgParcel;

    /// UT test cases for `MsgParcel`
    ///
    /// # Brief
    /// 1. Create a MsgParcel
    /// 2. Write a value to the MsgParcel and then read it out, check the
    ///    correctness.
    /// 3. Check other types.
    #[test]
    fn primitive() {
        let mut msg = MsgParcel::new();

        msg.write_interface_token("test");
        assert_eq!(msg.read_interface_token().unwrap(), "test");

        msg.write_buffer("test".as_bytes());
        assert_eq!(msg.read_buffer(msg.readable()).unwrap(), "test".as_bytes());

        msg.write(&true).unwrap();
        assert!(msg.read::<bool>().unwrap());

        msg.write(&false).unwrap();
        assert!(!msg.read::<bool>().unwrap());

        msg.write(&i8::MAX).unwrap();
        assert_eq!(i8::MAX, msg.read().unwrap());
        msg.write(&i8::MIN).unwrap();
        assert_eq!(i8::MIN, msg.read().unwrap());

        msg.write(&i16::MAX).unwrap();
        assert_eq!(i16::MAX, msg.read().unwrap());
        msg.write(&i16::MIN).unwrap();
        assert_eq!(i16::MIN, msg.read().unwrap());

        msg.write(&i32::MAX).unwrap();
        assert_eq!(i32::MAX, msg.read().unwrap());
        msg.write(&i32::MIN).unwrap();
        assert_eq!(i32::MIN, msg.read().unwrap());

        msg.write(&i64::MAX).unwrap();
        assert_eq!(i64::MAX, msg.read().unwrap());
        msg.write(&i64::MIN).unwrap();
        assert_eq!(i64::MIN, msg.read().unwrap());

        msg.write(&u8::MAX).unwrap();
        assert_eq!(u8::MAX, msg.read().unwrap());
        msg.write(&u8::MIN).unwrap();
        assert_eq!(u8::MIN, msg.read().unwrap());

        msg.write(&u16::MAX).unwrap();
        assert_eq!(u16::MAX, msg.read().unwrap());
        msg.write(&u16::MIN).unwrap();
        assert_eq!(u16::MIN, msg.read().unwrap());

        msg.write(&u32::MAX).unwrap();
        assert_eq!(u32::MAX, msg.read().unwrap());
        msg.write(&u32::MIN).unwrap();
        assert_eq!(u32::MIN, msg.read().unwrap());

        msg.write(&u64::MAX).unwrap();
        assert_eq!(u64::MAX, msg.read().unwrap());
        msg.write(&u64::MIN).unwrap();
        assert_eq!(u64::MIN, msg.read().unwrap());

        msg.write(&usize::MAX).unwrap();
        assert_eq!(usize::MAX, msg.read().unwrap());
        msg.write(&usize::MIN).unwrap();
        assert_eq!(usize::MIN, msg.read().unwrap());
    }

    #[test]
    fn string() {
        let mut msg = MsgParcel::new();
        msg.write("hello ipc").unwrap();
        assert_eq!(String::from("hello ipc"), msg.read::<String>().unwrap());

        let s = String::from("hello ipc");
        msg.write(&s).unwrap();
        assert_eq!(String::from("hello ipc"), msg.read::<String>().unwrap());

        let v = vec![1];
        msg.write(&v).unwrap();
        assert_eq!(vec![1], msg.read::<Vec<i32>>().unwrap());

        let s = String::from("ipc hello");
        let v = vec![s.clone(), s.clone(), s.clone(), s];
        msg.write(&v).unwrap();
        assert_eq!(v, msg.read::<Vec<String>>().unwrap());

        msg.write("hello ipc").unwrap();
        let s = String::from("hello ipc");
        msg.write(&s).unwrap();
        let v = vec![1];
        msg.write(&v).unwrap();
        let s = String::from("ipc hello");
        let v = vec![s.clone(), s.clone(), s.clone(), s];
        msg.write(&v).unwrap();
        assert_eq!(String::from("hello ipc"), msg.read::<String>().unwrap());
        assert_eq!(String::from("hello ipc"), msg.read::<String>().unwrap());
        assert_eq!(vec![1], msg.read::<Vec<i32>>().unwrap());
        assert_eq!(v, msg.read::<Vec<String>>().unwrap());
    }

    /// UT test cases for `MsgParcel`
    ///
    /// # Brief
    /// 1. Create a MsgParcel
    /// 2. Write a bunch of value to the MsgParcel and then read them out, check
    ///    the correctness.
    #[test]
    fn primitive_bunch() {
        let mut msg = MsgParcel::new();
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

        assert!(msg.read::<bool>().unwrap());
        assert!(!msg.read::<bool>().unwrap());
        assert_eq!(i8::MAX, msg.read().unwrap());
        assert_eq!(i8::MIN, msg.read().unwrap());

        assert_eq!(i16::MAX, msg.read().unwrap());
        assert_eq!(i16::MIN, msg.read().unwrap());
        assert_eq!(i32::MAX, msg.read().unwrap());
        assert_eq!(i32::MIN, msg.read().unwrap());
        assert_eq!(i64::MAX, msg.read().unwrap());
        assert_eq!(i64::MIN, msg.read().unwrap());
        assert_eq!(u8::MAX, msg.read().unwrap());
        assert_eq!(u8::MIN, msg.read().unwrap());

        assert_eq!(u16::MAX, msg.read().unwrap());
        assert_eq!(u16::MIN, msg.read().unwrap());
        assert_eq!(u32::MAX, msg.read().unwrap());
        assert_eq!(u32::MIN, msg.read().unwrap());
        assert_eq!(u64::MAX, msg.read().unwrap());
        assert_eq!(u64::MIN, msg.read().unwrap());
        assert_eq!(usize::MAX, msg.read().unwrap());
        assert_eq!(usize::MIN, msg.read().unwrap());
    }

    /// UT test cases for `MsgParcel`
    ///
    /// # Brief
    /// 1. Create a MsgParcel
    /// 2. Write interface to the MsgParcel and then read them out, check the
    ///    correctness.
    #[test]
    fn interface() {
        let mut msg = MsgParcel::new();
        msg.write_interface_token("test token").unwrap();
        assert_eq!("test token", msg.read_interface_token().unwrap());
    }

    /// UT test cases for `MsgParcel`
    ///
    /// # Brief
    /// 1. Create a MsgParcel
    /// 2. Write a file descriptor to the MsgParcel and then read them out,
    ///    check the correctness.
    #[test]
    fn file_descriptor() {
        let mut msg = MsgParcel::new();

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open("ipc_rust_test_temp0")
            .unwrap();
        file.write_all(b"hello world").unwrap();
        file.sync_all().unwrap();

        msg.write_file(file).unwrap();
        let mut f = msg.read_file().unwrap();
        let mut buf = String::new();
        f.rewind().unwrap();
        f.read_to_string(&mut buf).unwrap();
        fs::remove_file("ipc_rust_test_temp0").unwrap();
        assert_eq!("hello world", buf);
    }

    /// UT test cases for `MsgParcel`
    ///
    /// # Brief
    /// 1. Create a MsgParcel
    /// 2. Write a i32 value to the MsgParcel in different position and then
    ///    read them out, check the correctness.
    #[test]
    fn position() {
        let mut msg = MsgParcel::new();
        assert_eq!(0, msg.write_position());
        assert_eq!(0, msg.read_position());

        msg.set_write_position(4).unwrap_err();
        msg.set_read_position(4).unwrap_err();

        msg.write(&1).unwrap();
        msg.write(&2).unwrap();
        assert_eq!(msg.size(), 8);

        msg.set_capacity(4).unwrap_err();
        msg.set_size(msg.capacity() + 1).unwrap_err();

        msg.set_read_position(4).unwrap();
        assert_eq!(2, msg.read().unwrap());

        msg.set_write_position(0).unwrap();
        msg.write(&2).unwrap();

        assert_eq!(4, msg.size());

        msg.set_read_position(0).unwrap();
        assert_eq!(2, msg.read().unwrap());
        msg.write(&1).unwrap();
        msg.write(&2).unwrap();

        assert_eq!(8, msg.readable() as u32);

        msg.skip_read(4);
        assert_eq!(2, msg.read().unwrap());
    }
}
