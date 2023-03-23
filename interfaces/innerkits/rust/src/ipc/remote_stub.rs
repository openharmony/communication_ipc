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

use crate::{ipc_binding, IRemoteStub, IRemoteBroker, RemoteObj, BorrowedMsgParcel};
use crate::ipc_binding::{CRemoteObject, CParcel};
use std::ffi::{c_void, CString, c_char};
use std::ops::{Deref};
use hilog_rust::{info, hilog, HiLogLabel, LogType};

const LOG_LABEL: HiLogLabel = HiLogLabel {
    log_type: LogType::LogCore,
    domain: 0xd001510,
    tag: "RustRemoteStub"
};

/// RemoteStub packed the native CRemoteObject and the rust stub object T
/// which must implement IRemoteStub trait.
#[repr(C)]
pub struct RemoteStub<T: IRemoteStub> {
    native: *mut CRemoteObject,
    rust: *mut T,
}

impl<T: IRemoteStub> RemoteStub<T> {
    /// Create a RemoteStub object
    pub fn new(rust: T) -> Option<Self> {
        let rust = Box::into_raw(Box::new(rust));
        let descripor = CString::new(T::get_descriptor()).expect("descripor must be valid!");
        // SAFETY:
        let native = unsafe {
            // set rust object pointer to native, so we can figure out who deal
            // the request during on_remote_request().
            ipc_binding::CreateRemoteStub(descripor.as_ptr(), Self::on_remote_request,
                Self::on_destroy, rust as *mut c_void)
        };
        if native.is_null() {
            None
        } else {
            Some( RemoteStub { native, rust } )
        }
    }
}

impl<T: IRemoteStub> IRemoteBroker for RemoteStub<T> {
    fn as_object(&self) -> Option<RemoteObj> {
        // SAFETY:
        unsafe {
            // add remote object reference count
            ipc_binding::RemoteObjectIncStrongRef(self.native);
            // construct a new RemoteObject from a native pointer
            RemoteObj::from_raw(self.native)
        }
    }
}

unsafe impl<T: IRemoteStub> Send for RemoteStub<T> {}
unsafe impl<T: IRemoteStub> Sync for RemoteStub<T> {}

impl<T: IRemoteStub> Deref for RemoteStub<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: Rust `Box::into_raw` poiter, so is valid
        unsafe {
            &*self.rust
        }
    }
}

impl<T: IRemoteStub> Drop for RemoteStub<T> {
    fn drop(&mut self) {
        unsafe {
            ipc_binding::RemoteObjectDecStrongRef(self.native);
        }
    }
}

/// C call Rust
impl<T: IRemoteStub> RemoteStub<T> {
    unsafe extern "C" fn on_remote_request(user_data: *mut c_void, code: u32,
        data: *const CParcel, reply: *mut CParcel) -> i32 {
        let res = {
            let mut reply = BorrowedMsgParcel::from_raw(reply).unwrap();
            let data = BorrowedMsgParcel::from_raw(data as *mut CParcel).unwrap();
            let rust_object: &T = &*(user_data as *mut T);
            rust_object.on_remote_request(code, &data, &mut reply)
        };
        res
    }

    unsafe extern "C" fn on_destroy(user_data: *mut c_void) {
        info!(LOG_LABEL, "RemoteStub<T> on_destroy in Rust");
        // T will be freed by Box after this function end.
        drop(Box::from_raw(user_data as *mut T));
    }
}