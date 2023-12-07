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

use crate::{
    ipc_binding, IRemoteStub, IRemoteBroker, IpcStatusCode,
    RemoteObj, BorrowedMsgParcel, FileDesc, String16,
};
use crate::ipc_binding::{CRemoteObject, CParcel};
use std::ffi::{c_void, CString, c_char};
use std::ops::{Deref};
use hilog_rust::{info, error, hilog, HiLogLabel, LogType};

const LOG_LABEL: HiLogLabel = HiLogLabel {
    log_type: LogType::LogCore,
    domain: 0xD0057CA,
    tag: "RustRemoteStub"
};

/// RemoteStub packed the native CRemoteObject and the rust stub object T
/// which must implement IRemoteStub trait.
/// Safety Invariant: The native pointer must be a valid pointer and cannot be null.
/// The native is guaranteed by the c interface
/// FFI Safety : Ensure stable memory layout C-ABI compatibility
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
        // SAFETY: The incoming parameters are FFI safety
        // Descripor is converted to a string type compatible with the c interface through CString.
        // on_remote_request and on_destroy callback function has been checked for security,
        // and the parameter type is FFI safety
        let native = unsafe {
            // set rust object pointer to native, so we can figure out who deal
            // the request during on_remote_request().
            ipc_binding::CreateRemoteStub(descripor.as_ptr(), Self::on_remote_request,
                Self::on_destroy, rust as *mut c_void, Self::on_dump)
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
/// # Safety
///
/// RemoteSub thread safety. Multi-thread access and sharing have been considered inside the C-side code
unsafe impl<T: IRemoteStub> Sync for RemoteStub<T> {}

impl<T: IRemoteStub> Deref for RemoteStub<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY:
        // Rust `Box::into_raw` poiter, so is valid
        unsafe {
            &*self.rust
        }
    }
}

impl<T: IRemoteStub> Drop for RemoteStub<T> {
    fn drop(&mut self) {
        // SAFETY:
        // Because self is valid, its internal native pointer is valid.
        unsafe {
            ipc_binding::RemoteObjectDecStrongRef(self.native);
        }
    }
}

/// C call Rust
impl<T: IRemoteStub> RemoteStub<T> {
    /// # Safety
    ///
    /// The parameters passed in should ensure FFI safety
    /// user_data pointer, data pointer and reply pointer on the c side must be guaranteed not to be null
    unsafe extern "C" fn on_remote_request(user_data: *mut c_void, code: u32,
        data: *const CParcel, reply: *mut CParcel) -> i32 {
        let res = {
            // BorrowedMsgParcel calls the correlation function from_raw must return as Some,
            // direct deconstruction will not crash.
            let mut reply = BorrowedMsgParcel::from_raw(reply).unwrap();
            let data = BorrowedMsgParcel::from_raw(data as *mut CParcel).expect("MsgParcel should success");
            let rust_object: &T = &*(user_data as *mut T);
            rust_object.on_remote_request(code, &data, &mut reply)
        };
        res
    }
    /// # Safety
    ///
    /// The parameters passed in should ensure FFI safety
    /// user_data pointer, data pointer and reply pointer on the c side must be guaranteed not to be null
    unsafe extern "C" fn on_dump(user_data: *mut c_void, data: *const CParcel) -> i32 {
        let res = {
            let rust_object: &T = &*(user_data as *mut T);
            // BorrowedMsgParcel calls the correlation functio from_raw must return as Some,
            // direct deconstruction will not crash.
            let data = BorrowedMsgParcel::from_raw(data as *mut CParcel).expect("MsgParcel should success");
            let file: FileDesc = match data.read::<FileDesc>() {
                Ok(file) => file,
                _ => {
                    error!(LOG_LABEL, "read FileDesc failed");
                    return IpcStatusCode::Failed as i32;
                }
            };
            let mut args: Vec<String16> = match data.read::<Vec<String16>>() {
                Ok(args) => args,
                _ => {
                    error!(LOG_LABEL, "read String16 array failed");
                    return IpcStatusCode::Failed as i32;
                }
            };
            rust_object.on_dump(&file, &mut args)
        };
        res
    }
    /// # Safety
    ///
    /// The parameters passed in should ensure FFI safety
    /// user_data pointer, data pointer and reply pointer on the c side must be guaranteed not to be null
    unsafe extern "C" fn on_destroy(user_data: *mut c_void) {
        info!(LOG_LABEL, "RemoteStub<T> on_destroy in Rust");
        // T will be freed by Box after this function end.
        drop(Box::from_raw(user_data as *mut T));
    }
}