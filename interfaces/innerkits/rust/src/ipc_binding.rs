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

#![allow(dead_code)]

use std::ffi::{c_char, c_void, c_ulong};

#[repr(C)]
pub struct CRemoteObject {
    _private: [u8; 0],
}

#[repr(C)]
pub struct CDeathRecipient {
    _private: [u8; 0],
}

#[repr(C)]
pub struct CParcel {
    _private: [u8; 0],
}

#[repr(C)]
pub struct CAshmem {
    _private: [u8; 0],
}

// Callback function type for OnRemoteRequest() from native, this
// callback will be called when native recive client IPC request.
pub type OnRemoteRequest = unsafe extern "C" fn (
    user_data: *mut c_void,
    code: u32,
    data: *const CParcel,
    reply: *mut CParcel
) -> i32;

// Callback function type for OnRemoteObjectDestroy() from native,
// this callback will be called when native remote object destroyed.
pub type OnRemoteObjectDestroy = unsafe extern "C" fn (
    user_data: *mut c_void
);

// Callback function type for OnDeathRecipientCb() from native,
// this callback will be called when remote stub is destroyed.
pub type OnDeathRecipientCb = unsafe extern "C" fn (
    callback: *mut c_void
);

// Callback function type for OnDeathRecipientDestroyCb() from native,
// this callback will be called when native CDeathRecipient destroyed.
pub type OnDeathRecipientDestroyCb = unsafe extern "C" fn (
    callback: *mut c_void
);

// Callback function type for OnCParcelBytesAllocator() from native,
// this callback will be called when native parcel need allocate buffer
// for string or bytes buffer by rust.
pub type OnCParcelBytesAllocator<T> = unsafe extern "C" fn (
    value: *mut c_void,
    buffer: *mut *mut T,
    len: i32
) -> bool;

pub type OnCParcelAllocator = unsafe extern "C" fn (
    value: *mut c_void,
    len: i32
) -> bool;

// Callback function type for CParcelReadStringArray() from native.
// Rust side need read string one by one from native according calling
// CParcelReadStringElement().
pub type OnStringArrayRead = unsafe extern "C" fn(
    data: *const c_void, // C++ vector pointer
    value: *mut c_void, // Rust vector pointer
    len: u32 // C++ vector length
) -> bool;

// Callback function type for CParcelWriteStringArray() from native.
// Rust side need write string one by one to native according calling
// CParcelWriteStringElement().
pub type OnStringArrayWrite = unsafe extern "C" fn(
    array: *const c_void, // C++ vector pointer
    value: *mut c_void, // Rust vector pointer
    len: u32, // Rust vector length
) -> bool;

pub type OnCParcelWriteElement = unsafe extern "C" fn (
    value: *mut CParcel,
    arr: *const c_void,
    index: c_ulong,
) -> bool;

pub type OnCParcelReadElement = unsafe extern "C" fn (
    value: *const CParcel,
    arr: *mut c_void,
    index: c_ulong,
) -> bool;

// C interface for IPC core object
extern "C" {
    pub fn CreateRemoteStub(descripor: *const c_char, on_remote_request: OnRemoteRequest,
        on_remote_object_destroy: OnRemoteObjectDestroy,
        user_data: *const c_void) -> *mut CRemoteObject;
    pub fn RemoteObjectIncStrongRef(object: *mut CRemoteObject);
    pub fn RemoteObjectDecStrongRef(object: *mut CRemoteObject);

    pub fn RemoteObjectSendRequest(object: *mut CRemoteObject, code: u32,
        data: *const CParcel, reply: *mut CParcel, is_async: bool) -> i32;
    pub fn RemoteObjectLessThan(object: *const CRemoteObject,
        other: *const CRemoteObject) -> bool;

    pub fn CreateDeathRecipient(onDeathRecipient: OnDeathRecipientCb,
        onDestroy: OnDeathRecipientDestroyCb,
        userData: *const c_void) -> *mut CDeathRecipient;
    pub fn DeathRecipientDecStrongRef(recipient: *mut CDeathRecipient);
    pub fn AddDeathRecipient(object: *mut CRemoteObject,
        recipient: *mut CDeathRecipient) -> bool;
    pub fn RemoveDeathRecipient(object: *mut CRemoteObject,
        recipient: *mut CDeathRecipient) -> bool;

    pub fn IsProxyObject(object: *mut CRemoteObject) -> bool;
    pub fn Dump(object: *mut CRemoteObject, fd: i32, value: *const c_void, len: i32,
            writer: OnStringArrayWrite) -> i32;

    pub fn IsObjectDead(object: *mut CRemoteObject) -> bool;
    pub fn GetInterfaceDescriptor(object: *mut CRemoteObject,
        value: *mut c_void, allocator: OnCParcelBytesAllocator::<u16>) -> bool;
}

// C interface for Parcel
extern "C" {
    pub fn CParcelObtain() -> *mut CParcel;
    pub fn CParcelDecStrongRef(parcel: *mut CParcel);

    pub fn CParcelWriteBool(parcel: *mut CParcel, value: bool) -> bool;
    pub fn CParcelReadBool(parcel: *const CParcel, value: *mut bool) -> bool;
    pub fn CParcelWriteInt8(parcel: *mut CParcel, value: i8) -> bool;
    pub fn CParcelReadInt8(parcel: *const CParcel, value: *mut i8) -> bool;
    pub fn CParcelWriteInt16(parcel: *mut CParcel, value: i16) -> bool;
    pub fn CParcelReadInt16(parcel: *const CParcel, value: *mut i16) -> bool;
    pub fn CParcelWriteInt32(parcel: *mut CParcel, value: i32) -> bool;
    pub fn CParcelReadInt32(parcel: *const CParcel, value: *mut i32) -> bool;
    pub fn CParcelWriteInt64(parcel: *mut CParcel, value: i64) -> bool;
    pub fn CParcelReadInt64(parcel: *const CParcel, value: *mut i64) -> bool;
    pub fn CParcelWriteFloat(parcel: *mut CParcel, value: f32) -> bool;
    pub fn CParcelReadFloat(parcel: *const CParcel, value: *mut f32) -> bool;
    pub fn CParcelWriteDouble(parcel: *mut CParcel, value: f64) -> bool;
    pub fn CParcelReadDouble(parcel: *const CParcel, value: *mut f64) -> bool;
    pub fn CParcelWriteString(parcel: *mut CParcel, value: *const c_char, len: i32) -> bool;
    pub fn CParcelReadString(parcel: *const CParcel, value: *mut c_void,
        allocator: OnCParcelBytesAllocator::<u8>) -> bool;
    pub fn CParcelWriteString16(parcel: *mut CParcel, value: *const c_char, len: i32) -> bool;
    pub fn CParcelReadString16(parcel: *const CParcel, value: *mut c_void,
        allocator: OnCParcelBytesAllocator::<u8>) -> bool;
    pub fn CParcelWriteInterfaceToken(parcel: *mut CParcel,
        token: *const c_char, len: i32) -> bool;
    pub fn CParcelReadInterfaceToken(parcel: *const CParcel, token: *mut c_void,
        allocator: OnCParcelBytesAllocator::<u8>) -> bool;
    pub fn CParcelWriteRemoteObject(parcel: *mut CParcel, object: *mut CRemoteObject) -> bool;
    pub fn CParcelReadRemoteObject(parcel: *const CParcel) -> *mut CRemoteObject;
    pub fn CParcelWriteBuffer(parcel: *mut CParcel, value: *const u8, len: u32) -> bool;
    pub fn CParcelReadBuffer(parcel: *const CParcel, value: *mut u8, len: u32) -> bool;
    pub fn CParcelWriteRawData(parcel: *mut CParcel, value: *const u8, len: u32) -> bool;
    pub fn CParcelReadRawData(parcel: *const CParcel,  len: u32) ->  *mut u8;
    pub fn CParcelWriteFileDescriptor(parcel: *mut CParcel, fd: i32) -> bool;
    pub fn CParcelReadFileDescriptor(parcel: *const CParcel, fd: *mut i32) -> bool;

    pub fn CParcelWriteBoolArray(parcel: *mut CParcel, value: *const bool, len: i32) -> bool;
    pub fn CParcelReadBoolArray(parcel: *const CParcel, value: *mut c_void,
        allocator: OnCParcelBytesAllocator::<bool>) -> bool;
    pub fn CParcelWriteInt8Array(parcel: *mut CParcel, value: *const i8, len: i32) -> bool;
    pub fn CParcelReadInt8Array(parcel: *const CParcel, value: *mut c_void,
        allocator: OnCParcelBytesAllocator::<i8>) -> bool;
    pub fn CParcelWriteInt16Array(parcel: *mut CParcel, value: *const i16, len: i32) -> bool;
    pub fn CParcelReadInt16Array(parcel: *const CParcel, value: *mut c_void,
        allocator: OnCParcelBytesAllocator::<i16>) -> bool;
    pub fn CParcelWriteInt32Array(parcel: *mut CParcel, value: *const i32, len: i32) -> bool;
    pub fn CParcelReadInt32Array(parcel: *const CParcel, value: *mut c_void,
        allocator: OnCParcelBytesAllocator::<i32>) -> bool;
    pub fn CParcelWriteInt64Array(parcel: *mut CParcel, value: *const i64, len: i32) -> bool;
    pub fn CParcelReadInt64Array(parcel: *const CParcel, value: *mut c_void,
        allocator: OnCParcelBytesAllocator::<i64>) -> bool;
    pub fn CParcelWriteFloatArray(parcel: *mut CParcel, value: *const f32, len: i32) -> bool;
    pub fn CParcelReadFloatArray(parcel: *const CParcel, value: *mut c_void,
        allocator: OnCParcelBytesAllocator::<f32>) -> bool;
    pub fn CParcelWriteDoubleArray(parcel: *mut CParcel, value: *const f64, len: i32) -> bool;
    pub fn CParcelReadDoubleArray(parcel: *const CParcel, value: *mut c_void,
        allocator: OnCParcelBytesAllocator::<f64>) -> bool;
    pub fn CParcelWriteStringArray(parcel: *mut CParcel, value: *const c_void, len: i32,
        writer: OnStringArrayWrite) -> bool;
    pub fn CParcelWriteStringElement(data: *const c_void, value: *const c_char,
        len: i32) -> bool;
    pub fn CParcelWritU16stringElement(data: *const c_void, value: *const c_char,
        len: i32) -> bool;
    pub fn CParcelReadStringArray(parcel: *const CParcel, value: *mut c_void,
        reader: OnStringArrayRead) -> bool;
    pub fn CParcelReadStringElement(index: u32, data: *const c_void, value: *mut c_void,
        allocator: OnCParcelBytesAllocator::<u8>) -> bool;
    pub fn CParcelWriteParcelableArray(parcel: *mut CParcel, value: *const c_void, len: i32,
        element_writer: OnCParcelWriteElement) -> bool;
    pub fn CParcelReadParcelableArray(parcel: *const CParcel, value: *mut c_void,
        allocator: OnCParcelAllocator, element_reader: OnCParcelReadElement ) -> bool;

    pub fn CParcelGetDataSize(parcel: *const CParcel) -> u32;
    pub fn CParcelSetDataSize(parcel: *mut CParcel, new_size: u32) -> bool;
    pub fn CParcelGetDataCapacity(parcel: *const CParcel) -> u32;
    pub fn CParcelSetDataCapacity(parcel: *mut CParcel, new_size: u32) -> bool;
    pub fn CParcelGetMaxCapacity(parcel: *const CParcel) -> u32;
    pub fn CParcelSetMaxCapacity(parcel: *mut CParcel, new_size: u32) -> bool;
    pub fn CParcelGetWritableBytes(parcel: *const CParcel) -> u32;
    pub fn CParcelGetReadableBytes(parcel: *const CParcel) -> u32;
    pub fn CParcelGetReadPosition(parcel: *const CParcel) -> u32;
    pub fn CParcelGetWritePosition(parcel: *const CParcel) -> u32;
    pub fn CParcelRewindRead(parcel: *mut CParcel, new_pos: u32) -> bool;
    pub fn CParcelRewindWrite(parcel: *mut CParcel, new_pos: u32) -> bool;
    pub fn CParcelWriteAshmem(parcel: *mut CParcel, ashmem: *mut CAshmem) -> bool;
    pub fn CParcelReadAshmem(parcel: *const CParcel) -> *mut CAshmem;

    pub fn CParcelContainFileDescriptors(parcel: *const CParcel) -> bool;
    pub fn CParcelGetRawDataSize(parcel: *const CParcel) -> usize;
    pub fn CParcelGetRawDataCapacity(parcel: *const CParcel) -> usize;
    pub fn CParcelClearFileDescriptor(parcel: *mut CParcel);
    pub fn CParcelSetClearFdFlag(parcel: *mut CParcel);
    pub fn CParcelAppend(parcel: *mut CParcel, data: *mut CParcel) -> bool;
}

// C interface for Ashmem
extern "C" {
    pub fn CreateCAshmem(name: *const c_char, size: i32) -> *mut CAshmem;
    pub fn CAshmemIncStrongRef(ashmem: *mut CAshmem);
    pub fn CAshmemDecStrongRef(ashmem: *mut CAshmem);

    pub fn CloseCAshmem(ashmem: *mut CAshmem);
    pub fn MapCAshmem(ashmem: *mut CAshmem, mapType: i32) -> bool;
    pub fn MapReadAndWriteCAshmem(ashmem: *mut CAshmem) -> bool;
    pub fn MapReadOnlyCAshmem(ashmem: *mut CAshmem) -> bool;
    pub fn UnmapCAshmem(ashmem: *mut CAshmem);
    pub fn SetCAshmemProtection(ashmem: *mut CAshmem, protectionType: i32) -> bool;
    pub fn GetCAshmemProtection(ashmem: *const CAshmem) -> i32;
    pub fn GetCAshmemSize(ashmem: *const CAshmem) -> i32;
    pub fn WriteToCAshmem(ashmem: *mut CAshmem, data: *const u8,
        size: i32, offset: i32) -> bool;
    pub fn ReadFromCAshmem(ashmem: *const CAshmem, size: i32, offset: i32) -> *const u8;
    pub fn GetCAshmemFd(ashmem: *const CAshmem) -> i32;
}

// C interface for IPC miscellaneous
extern "C" {
    pub fn GetContextManager() -> *mut CRemoteObject;
    pub fn JoinWorkThread();
    pub fn StopWorkThread();
    pub fn GetCallingTokenId() -> u64;
    pub fn GetFirstToekenId() -> u64;
    pub fn GetSelfToekenId() -> u64;
    pub fn GetCallingPid() -> u64;
    pub fn GetCallingUid() -> u64;

    pub fn SetMaxWorkThreadNum(maxThreadNum: i32) -> bool;
    pub fn IsLocalCalling() -> bool;
    pub fn SetCallingIdentity(identity: *const c_char) -> bool;
    pub fn GetLocalDeviceID(value: *mut c_void, allocator: OnCParcelBytesAllocator::<u8>) -> bool;
    pub fn GetCallingDeviceID(value: *mut c_void, allocator: OnCParcelBytesAllocator::<u8>) -> bool;
    pub fn ResetCallingIdentity(value: *mut c_void, allocator: OnCParcelBytesAllocator::<u8>) -> bool;
}