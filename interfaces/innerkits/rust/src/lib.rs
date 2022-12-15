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

mod ipc_binding;
pub mod errors;
pub mod ipc;
pub mod parcel;
pub mod process;

// Export types of this crate
pub use crate::errors::{Result, result_status};
pub use crate::ipc::{
    IRemoteBroker, IRemoteObj, IRemoteStub, FromRemoteObj, RemoteObjRef,
    remote_obj::RemoteObj, remote_obj::DeathRecipient, remote_stub::RemoteStub,
};
pub use crate::parcel::{MsgParcel, BorrowedMsgParcel,
    parcelable::{Serialize, Deserialize, SerOption, DeSerOption, SerArray, DeArray},
};
pub use crate::parcel::types::{
    interface_token::InterFaceToken,
    string16::String16
};
pub use crate::process::{add_service, get_service, init_access_token, join_work_thread};

/// First request code available for user IPC request(inclusive)
pub const FIRST_CALL_TRANSACTION: isize = 0x00000001;
/// Last request code available for user IPC request(inclusive)
pub const LAST_CALL_TRANSACTION: isize = 0x00ffffff;

/// Trait for transparent Rust wrappers around native raw pointer types.
///
/// # Safety
///
/// The pointer return by this trait's methods should be immediately passed to
/// native and not stored by Rust. The pointer is valid only as long as the
/// underlying native object is alive, so users must be careful to take this into
/// account, as Rust cannot enforce this.
///
/// For this trait to be a correct implementation, `T` must be a valid native
/// type. Since we cannot constrain this via the type system, this trait is
/// marked as unsafe.
pub unsafe trait AsRawPtr<T> {
    /// Return a pointer to the native version of `self`
    fn as_raw(&self) -> *const T;

    /// Return a mutable pointer to the native version of `self`
    fn as_mut_raw(&mut self) -> *mut T;
}