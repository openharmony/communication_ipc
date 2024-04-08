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

//! cxx wrapper
#![allow(missing_docs)]

use std::fs::File;
use std::os::fd::FromRawFd;
use std::pin::Pin;

use cxx::UniquePtr;
pub use ffi::*;

pub use super::obj::RemoteObj;
use super::stub::RemoteStub;
use crate::parcel::MsgParcel;

#[cxx::bridge(namespace = "OHOS::IpcRust")]
pub mod ffi {

    extern "Rust" {
        type RemoteObj;
        pub type RemoteStubWrapper;

        fn on_remote_request(
            self: &mut RemoteStubWrapper,
            code: u32,
            data: Pin<&mut MessageParcel>,
            reply: Pin<&mut MessageParcel>,
        ) -> i32;

        fn dump(self: &mut RemoteStubWrapper, fd: i32, args: Vec<String>) -> i32;

        fn descriptor(self: &mut RemoteStubWrapper) -> &'static str;

        fn new_remote_obj(wrap: UniquePtr<IRemoteObjectWrapper>) -> Box<RemoteObj>;

    }

    unsafe extern "C++" {
        include!("remote_object_wrapper.h");
        type IRemoteObjectWrapper;

        #[namespace = "OHOS"]
        type IRemoteObject;
        #[namespace = "OHOS"]
        type MessageParcel = crate::parcel::wrapper::MessageParcel;
        #[namespace = "OHOS"]
        type MessageOption = crate::parcel::wrapper::MessageOption;
        type DeathRecipientRemoveHandler;

        #[namespace = "OHOS"]
        type SptrIRemoteObject;

        fn FromSptrRemote(sptr: UniquePtr<SptrIRemoteObject>) -> UniquePtr<IRemoteObjectWrapper>;

        fn FromRemoteStub(stub: Box<RemoteStubWrapper>) -> UniquePtr<IRemoteObjectWrapper>;

        unsafe fn FromCIRemoteObject(remote: *mut IRemoteObject)
            -> UniquePtr<IRemoteObjectWrapper>;

        fn SendRequest(
            self: &IRemoteObjectWrapper,
            code: u32,
            data: Pin<&mut MessageParcel>,
            reply: Pin<&mut MessageParcel>,
            option: Pin<&mut MessageOption>,
        ) -> i32;

        fn GetInterfaceDescriptor(self: &IRemoteObjectWrapper) -> String;
        fn GetObjectDescriptor(self: &IRemoteObjectWrapper) -> String;

        fn IsProxyObject(self: &IRemoteObjectWrapper) -> bool;
        fn IsObjectDead(self: &IRemoteObjectWrapper) -> bool;
        fn CheckObjectLegality(self: &IRemoteObjectWrapper) -> bool;

        fn Dump(self: &IRemoteObjectWrapper, fd: i32, args: &[String]) -> i32;
        fn AddDeathRecipient(
            self: &IRemoteObjectWrapper,
            cb: fn(Box<RemoteObj>),
        ) -> UniquePtr<DeathRecipientRemoveHandler>;

        fn remove(self: &DeathRecipientRemoveHandler);

        fn CloneRemoteObj(remote: &IRemoteObjectWrapper) -> UniquePtr<IRemoteObjectWrapper>;
    }
    impl UniquePtr<IRemoteObjectWrapper> {}
}

fn new_remote_obj(wrap: UniquePtr<ffi::IRemoteObjectWrapper>) -> Box<RemoteObj> {
    Box::new(RemoteObj::try_new(wrap).unwrap())
}

pub struct RemoteStubWrapper {
    inner: Box<dyn RemoteStub>,
}

impl RemoteStubWrapper {
    pub fn new<A: RemoteStub + 'static>(remote: A) -> Self {
        Self {
            inner: Box::new(remote),
        }
    }

    pub fn on_remote_request(
        &mut self,
        code: u32,
        data: Pin<&mut MessageParcel>,
        reply: Pin<&mut MessageParcel>,
    ) -> i32 {
        unsafe {
            let mut data = MsgParcel::from_ptr(data.get_unchecked_mut() as *mut MessageParcel);
            let mut reply = MsgParcel::from_ptr(reply.get_unchecked_mut() as *mut MessageParcel);
            self.inner.on_remote_request(code, &mut data, &mut reply)
        }
    }

    pub fn dump(&mut self, fd: i32, args: Vec<String>) -> i32 {
        let file = unsafe { File::from_raw_fd(fd) };
        self.inner.dump(file, args)
    }

    pub fn descriptor(&self) -> &'static str {
        self.inner.descriptor()
    }

    pub fn into_remote(self) -> Option<RemoteObj> {
        RemoteObj::try_new(FromRemoteStub(Box::new(self)))
    }
}
