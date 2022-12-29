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

use std::ffi::{c_char, c_void};

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
 
// Callback function type for OnRemoteRequest() from native, this
// callback will be called when native recive client IPC request.
pub type OnRemoteRequest = unsafe extern "C" fn (
    stub: *mut CRemoteObject,
    code: u32,
    data: *const CParcel,
    reply: *mut CParcel
) -> i32;

// Callback function type for OnRemoteObjectDestroy() from native,
// this callback will be called when native remote object destroyed.
pub type OnRemoteObjectDestroy = unsafe extern "C" fn (
    stub: *mut c_void
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
pub type OnCParcelBytesAllocator = unsafe extern "C" fn (
    value: *mut c_void,
    buffer: *mut *mut c_char,
    len: i32
) -> bool;

#[link(name = "ipc_c")]
extern "C" {
    pub fn CreateRemoteStub(descripor: *const c_char, on_remote_request: OnRemoteRequest,
        on_remote_object_destroy: OnRemoteObjectDestroy, user_data: *const c_void) -> *mut CRemoteObject;

    pub fn RemoteObjectIncStrongRef(object: *mut CRemoteObject);
    pub fn RemoteObjectDecStrongRef(object: *mut CRemoteObject);
    pub fn RemoteObjectGetUserData(object: *mut CRemoteObject) -> *const c_void;
    pub fn RemoteObjectSendRequest(object: *mut CRemoteObject, code: u32, data: *const CParcel,
        reply: *mut CParcel, is_async: bool) -> i32;
    // Compare CRemoteObject
    pub fn RemoteObjectLessThan(object: *const CRemoteObject, other:  *const CRemoteObject) -> bool;

    pub fn CreateDeathRecipient(onDeathRecipient: OnDeathRecipientCb, onDestroy: OnDeathRecipientDestroyCb,
        userData: *const c_void) -> *mut CDeathRecipient;
    pub fn DeathRecipientDecStrongRef(recipient: *mut CDeathRecipient);
    pub fn AddDeathRecipient(object: *mut CRemoteObject, recipient: *mut CDeathRecipient) -> bool;
    pub fn RemoveDeathRecipient(object: *mut CRemoteObject, recipient: *mut CDeathRecipient) -> bool;

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
        allocator: OnCParcelBytesAllocator) -> bool;
    pub fn CParcelWriteString16(parcel: *mut CParcel, value: *const c_char, len: i32) -> bool;
    pub fn CParcelReadString16(parcel: *const CParcel, value: *mut c_void,
        allocator: OnCParcelBytesAllocator) -> bool;
    pub fn CParcelWriteInterfaceToken(parcel: *mut CParcel, token: *const c_char, len: i32) -> bool;
    pub fn CParcelReadInterfaceToken(parcel: *const CParcel, token: *mut c_void,
        allocator: OnCParcelBytesAllocator) -> bool;
    pub fn CParcelWriteRemoteObject(parcel: *mut CParcel, object: *mut CRemoteObject) -> bool;
    pub fn CParcelReadRemoteObject(parcel: *const CParcel) -> *mut CRemoteObject;
    pub fn CParcelWriteBuffer(parcel: *mut CParcel, value: *const u8, len: u32) -> bool;
    pub fn CParcelReadBuffer(parcel: *const CParcel, value: *mut u8, len: u32) -> bool;
    pub fn CParcelWriteFileDescriptor(parcel: *mut CParcel, fd: i32) -> bool;
    pub fn CParcelReadFileDescriptor(parcel: *const CParcel, fd: *mut i32) -> bool;
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

    pub fn GetContextManager() -> *mut CRemoteObject;
    pub fn JoinWorkThread();
    pub fn StopWorkThread();
    pub fn GetCallingTokenId() -> u64;
    pub fn GetFirstToekenId() -> u64;
    pub fn GetSelfToekenId() -> u64;
    pub fn GetCallingPid() -> u64;
    pub fn GetCallingUid() -> u64;
}