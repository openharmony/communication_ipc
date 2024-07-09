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

use std::mem;
use std::sync::Arc;

use cxx::UniquePtr;

use super::wrapper::{
    CloneRemoteObj, DeathRecipientRemoveHandler, FromCIRemoteObject, FromSptrRemote, IRemoteObject,
    IRemoteObjectWrapper, RemoteStubWrapper, SptrIRemoteObject,
};
use super::RemoteStub;
use crate::errors::{IpcResult, IpcStatusCode};
use crate::ipc_async::{IpcAsyncRuntime, Runtime};
use crate::parcel::msg::ParcelMem;
use crate::parcel::{MsgOption, MsgParcel};

/// Remote Object
pub struct RemoteObj {
    pub(crate) inner: UniquePtr<IRemoteObjectWrapper>,
}

impl Clone for RemoteObj {
    fn clone(&self) -> Self {
        Self {
            inner: CloneRemoteObj(self.inner.as_ref().unwrap()),
        }
    }
}

unsafe impl Send for RemoteObj {}
unsafe impl Sync for RemoteObj {}

pub struct RecipientRemoveHandler {
    inner: UniquePtr<DeathRecipientRemoveHandler>,
}

impl RemoteObj {
    /// Creates a Remote Object from C++ IRemoteObejectWrapper.
    pub fn try_new(wrap: UniquePtr<IRemoteObjectWrapper>) -> Option<Self> {
        if wrap.is_null() {
            return None;
        }
        Some(Self { inner: wrap })
    }

    /// Creates a Remote Object from C++ IRemoteObejectWrapper.
    pub unsafe fn new_unchecked(wrap: UniquePtr<IRemoteObjectWrapper>) -> Self {
        Self { inner: wrap }
    }

    pub unsafe fn from_ciremote(remote: *mut IRemoteObject) -> Option<Self> {
        if remote.is_null() {
            return None;
        }

        let inner = FromCIRemoteObject(remote);
        if inner.is_null() {
            return None;
        }

        Some(Self { inner })
    }

    /// Creates a RemoteObj from RemoteStub.
    pub fn from_stub<T: RemoteStub + 'static>(stub: T) -> Option<Self> {
        RemoteStubWrapper::new(stub).into_remote()
    }

    /// Creates a RemoteObj from sptr
    pub fn from_sptr(sptr: UniquePtr<SptrIRemoteObject>) -> Option<Self> {
        Self::try_new(FromSptrRemote(sptr))
    }

    /// Sends a IPC request to remote service
    pub fn send_request(&self, code: u32, data: &mut MsgParcel) -> IpcResult<MsgParcel> {
        let mut reply = MsgParcel::new();
        let mut option = MsgOption::new();
        match mem::replace(&mut data.inner, ParcelMem::Null) {
            ParcelMem::Unique(mut p) => {
                let res = self.inner.SendRequest(
                    code,
                    p.pin_mut(),
                    reply.pin_mut().unwrap(),
                    option.inner.pin_mut(),
                );
                data.inner = ParcelMem::Unique(p);
                if res != 0 {
                    return Err(IpcStatusCode::Failed);
                }
                Ok(reply)
            }
            _ => Err(IpcStatusCode::Failed),
        }
    }

    /// Sends asynchronous IPC requests to remote services, The current
    /// interface will use ylong runtime to start a separate thread to execute
    /// requests
    pub fn async_send_request<F, R>(
        self: &Arc<Self>,
        code: u32,
        mut data: MsgParcel,
        mut option: MsgOption,
        call_back: F,
    ) where
        F: FnOnce(MsgParcel) -> R,
        F: Send + 'static,
        R: Send + 'static,
    {
        let remote = self.clone();
        Runtime::spawn_blocking(move || {
            let reply = remote.send_request(code, &mut data);
            match reply {
                Ok(reply) => {
                    call_back(reply);
                    IpcStatusCode::Ok
                }
                _ => IpcStatusCode::Failed,
            }
        });
    }

    /// Registries a death recipient, and returns a RecipientRemoveHandler, if
    /// the registration is successful.
    pub fn add_death_recipient(&self, f: fn(Box<RemoteObj>)) -> Option<RecipientRemoveHandler> {
        let inner = self.inner.AddDeathRecipient(f);
        inner.is_null().then_some(RecipientRemoveHandler { inner })
    }

    /// Returns true if it is a proxy object.
    pub fn is_proxy(&self) -> bool {
        self.inner.IsProxyObject()
    }

    /// Dumps a service through a String
    pub fn dump(&self, fd: i32, args: &[String]) -> i32 {
        self.inner.Dump(fd, args)
    }

    ///
    pub fn check_legalit(&self) -> bool {
        self.inner.CheckObjectLegality()
    }

    /// Returns true if the object is dead.
    pub fn is_dead(&self) -> bool {
        self.inner.IsObjectDead()
    }

    /// Returns interface descriptor.
    pub fn interface_descriptor(&self) -> IpcResult<String> {
        Ok(self.inner.GetInterfaceDescriptor())
    }

    /// Returns Object descriptor.
    pub fn object_descriptor(&self) -> IpcResult<String> {
        Ok(self.inner.GetObjectDescriptor())
    }
}

impl RecipientRemoveHandler {
    pub fn remove_recipient(self) {
        self.inner.remove();
    }
}
