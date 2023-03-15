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

//! Implement of RemoteObj type, which represent a C++ IRemoteObject.

use std::ptr;
use crate::{
    ipc_binding, IRemoteObj, DeathRecipient, IpcResult, IpcStatusCode,
    MsgParcel, BorrowedMsgParcel, AsRawPtr, parcel::on_string16_writer,
    parcel::vec_u16_to_string, parse_status_code,
};
use crate::ipc_binding::{CRemoteObject, CDeathRecipient};
use crate::parcel::parcelable::{Serialize, Deserialize, allocate_vec_with_buffer};
use std::ffi::{c_void};
use crate::String16;

pub mod death_recipient;
pub mod cmp;

/// RemoteObject can be used as proxy or stub object.
/// It always contained a native CRemoteObject pointer.
/// # Invariant
///
/// `*mut CRemoteObject` must be valid
pub struct RemoteObj(ptr::NonNull<CRemoteObject>);

impl RemoteObj {
    /// Create an `RemoteObj` wrapper object from a raw `CRemoteObject` pointer.
    /// # Safety
    pub unsafe fn from_raw(obj: *mut CRemoteObject) -> Option<RemoteObj> {
        if obj.is_null() {
            None
        } else {
            Some(RemoteObj(unsafe{ptr::NonNull::new_unchecked(obj)}))
        }
    }

    /// Extract a raw `CRemoteObject` pointer from this wrapper.
    /// # Safety
    pub unsafe fn as_inner(&self) -> *mut CRemoteObject {
        self.0.as_ptr()
    }
}

impl IRemoteObj for RemoteObj {
    fn send_request(&self, code: u32, data: &MsgParcel, is_async: bool) -> IpcResult<MsgParcel> {
        // SAFETY:
        unsafe {
            let mut reply = MsgParcel::new().expect("create reply MsgParcel not success");
            let result = ipc_binding::RemoteObjectSendRequest(self.as_inner(), code, data.as_raw(),
                reply.as_mut_raw(), is_async);
            if result == 0 {
                Ok(reply)
            } else {
                Err(parse_status_code(result))
            }
        }
    }

    // Add death Recipient
    fn add_death_recipient(&self, recipient: &mut DeathRecipient) -> bool {
        // SAFETY:
        unsafe {
            ipc_binding::AddDeathRecipient(self.as_inner(), recipient.as_mut_raw())
        }
    }

    // remove death Recipients
    fn remove_death_recipient(&self, recipient: &mut DeathRecipient) -> bool {
        // SAFETY:
        unsafe {
            ipc_binding::RemoveDeathRecipient(self.as_inner(), recipient.as_mut_raw())
        }
    }

    fn is_proxy(&self) -> bool {
        // SAFETY:
        unsafe {
            ipc_binding::IsProxyObject(self.as_inner())
        }
    }

    fn dump(&self, fd: i32, args: &mut Vec<String16>) -> i32 {
        let slice = &args[..];
        // SAFETY:
        unsafe {
            ipc_binding::Dump(self.as_inner(), fd, slice.as_ptr() as *const c_void,
                slice.len().try_into().unwrap(), on_string16_writer)
        }
    }

    fn is_dead(&self) -> bool {
        // SAFETY:
        unsafe {
            ipc_binding::IsObjectDead(self.as_inner())
        }
    }

    fn interface_descriptor(&self) -> IpcResult<String> {
        let mut vec: Option<Vec<u16>> = None;
        let ok_status = unsafe {
            // SAFETY:
            ipc_binding::GetInterfaceDescriptor(
                self.as_inner(),
                &mut vec as *mut _ as *mut c_void,
                allocate_vec_with_buffer::<u16>
            )
        };
        if ok_status {
            vec_u16_to_string(vec)
        } else {
            Err(IpcStatusCode::Failed)
        }
    }
}

impl Serialize for RemoteObj {
    fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> IpcResult<()> {
        let ret = unsafe {
            ipc_binding::CParcelWriteRemoteObject(parcel.as_mut_raw(), self.as_inner())
        };
        if ret {
            Ok(())
        } else {
            Err(IpcStatusCode::Failed)
        }
    }
}

impl Deserialize for RemoteObj {
    fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> IpcResult<Self> {
        // Safety: `Parcel` always contains a valid pointer to an
        // `AParcel`. We pass a valid, mutable pointer to `val`, a
        // literal of type `$ty`, and `$read_fn` will write the
        let object = unsafe {
            let remote = ipc_binding::CParcelReadRemoteObject(parcel.as_raw());
            Self::from_raw(remote)
        };
        if let Some(x) = object {
            Ok(x)
        } else {
            Err(IpcStatusCode::Failed)
        }
    }
}

/// # Safety
///
/// An `RemoteObj` is an immutable handle to CRemoteObject, which is thread-safe
unsafe impl Send for RemoteObj {}
/// # Safety
///
/// An `RemoteObj` is an immutable handle to CRemoteObject, which is thread-safe
unsafe impl Sync for RemoteObj {}

impl Clone for RemoteObj {
    fn clone(&self) -> Self {
        // SAFETY:
        unsafe {
            ipc_binding::RemoteObjectIncStrongRef(self.as_inner());
        }
        // SAFETY: no `None` here, cause `self` is valid
        Self(self.0)
    }
}

impl Drop for RemoteObj {
    fn drop(&mut self) {
        // SAFETY:
        unsafe {
            ipc_binding::RemoteObjectDecStrongRef(self.as_inner());
        }
    }
}
