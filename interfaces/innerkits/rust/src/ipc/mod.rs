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

pub mod remote_obj;
pub mod remote_stub;
pub mod macros;

use crate::{BorrowedMsgParcel, MsgParcel, IpcResult, DeathRecipient,};
use std::ops::{Deref};
use std::cmp::Ordering;
use crate::String16;

// Export types of this module
pub use crate::RemoteObj;

/// Like C++ IRemoteObject class, define function for both proxy and stub object
pub trait IRemoteObj {
    /// Send a IPC request to remote service
    fn send_request(&self, code: u32, data: &MsgParcel, is_async: bool) -> IpcResult<MsgParcel>;

    /// Add a death recipient
    fn add_death_recipient(&self, recipient: &mut DeathRecipient) -> bool;

    /// Remove a death recipient
    fn remove_death_recipient(&self, recipient: &mut DeathRecipient) -> bool;

    /// Determine whether it is a proxy object
    fn is_proxy(&self) -> bool;

    /// Dump a service through a string
    fn dump(&self, fd: i32, args: &mut Vec<String16>) -> i32;

    /// Judge whether the object is dead
    fn is_dead(&self) -> bool;

    /// get interface descriptor
    fn interface_descriptor(&self) -> IpcResult<String>;
}

/// Like C++ IPCObjectStub class, define function for stub object only, like on_remote_request().
pub trait IRemoteStub: Send + Sync {
    /// Get object descriptor of this stub
    fn get_descriptor() -> &'static str;

    /// Callback for deal IPC request
    fn on_remote_request(&self, code: u32, data: &BorrowedMsgParcel, reply: &mut BorrowedMsgParcel) -> i32;
}

/// Like C++ IRemoteBroker class
pub trait IRemoteBroker: Send + Sync {
    /// Convert self to RemoteObject
    fn as_object(&self) -> Option<RemoteObj> {
        panic!("This is not a RemoteObject.")
    }
}

/// Define function which how to convert a RemoteObj to RemoteObjRef, the later contains a
/// dynamic trait object: IRemoteObject. For example, "dyn ITest" should implements this trait
pub trait FromRemoteObj: IRemoteBroker {
    /// Convert a RemoteObj to RemoteObjeRef
    fn try_from(object: RemoteObj) -> IpcResult<RemoteObjRef<Self>>;
}

/// Strong reference for "dyn IRemoteBroker" object, for example T is "dyn ITest"
pub struct RemoteObjRef<T: FromRemoteObj + ?Sized>(Box<T>);

impl<T: FromRemoteObj + ?Sized> RemoteObjRef<T> {
    /// Create a RemoteObjRef object
    pub fn new(object: Box<T>) -> Self {
        Self(object)
    }
}

impl<T: FromRemoteObj + ?Sized> Deref for RemoteObjRef<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<I: FromRemoteObj + ?Sized> Clone for RemoteObjRef<I> {
    fn clone(&self) -> Self {
        // Clone is a method in the RemoteObjRef structure.
        // T in RemoteObjRef<T>implements the trait FromRemoteObj,
        // so self.0.as_ Object(). unwrap() must be a RemoteObj object that exists
        FromRemoteObj::try_from(self.0.as_object().unwrap()).unwrap()
    }
}

impl<I: FromRemoteObj + ?Sized> Ord for RemoteObjRef<I> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_object().cmp(&other.0.as_object())
    }
}

impl<I: FromRemoteObj + ?Sized> PartialOrd for RemoteObjRef<I> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.as_object().partial_cmp(&other.0.as_object())
    }
}

impl<I: FromRemoteObj + ?Sized> PartialEq for RemoteObjRef<I> {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_object().eq(&other.0.as_object())
    }
}

impl<I: FromRemoteObj + ?Sized> Eq for RemoteObjRef<I> {}
