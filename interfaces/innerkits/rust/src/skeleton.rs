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


use ffi::*;

use crate::remote::RemoteObj;

#[cxx::bridge(namespace = "OHOS::IpcRust")]
pub mod ffi {

    unsafe extern "C++" {
        include!("skeleton_wrapper.h");
        type IRemoteObjectWrapper = crate::remote::wrapper::IRemoteObjectWrapper;

        fn SetMaxWorkThreadNum(maxThreadNum: i32) -> bool;

        fn JoinWorkThread();

        fn StopWorkThread();

        fn GetCallingPid() -> u64;

        fn GetCallingRealPid() -> u64;

        fn GetCallingUid() -> u64;

        fn GetCallingTokenID() -> u32;

        fn GetCallingFullTokenID() -> u64;

        fn GetFirstTokenID() -> u32;

        fn GetFirstFullTokenID() -> u64;

        fn GetSelfTokenID() -> u64;

        fn GetLocalDeviceID() -> String;

        fn GetCallingDeviceID() -> String;

        fn IsLocalCalling() -> bool;

        fn GetContextObject() -> UniquePtr<IRemoteObjectWrapper>;

        fn FlushCommands(object: Pin<&mut IRemoteObjectWrapper>) -> i32;

        fn ResetCallingIdentity() -> String;

        fn SetCallingIdentity(identity: &str) -> bool;

        fn IsHandlingTransaction() -> bool;
    }
}

/// Ipc Skeleton
pub struct Skeleton;

impl Skeleton {
    /// Sets the maximum number of threads.
    pub fn set_max_work_thread_num(max_thread_num: i32) -> bool {
        SetMaxWorkThreadNum(max_thread_num)
    }

    /// Makes current thread join to the IPC/RPC work thread pool.
    pub fn join_work_thread() {
        JoinWorkThread();
    }

    /// Exits current thread from IPC/RPC work thread pool.
    pub fn stop_work_thread() {
        StopWorkThread();
    }

    /// Returns the calling process id of caller.
    pub fn calling_pid() -> u64 {
        GetCallingPid()
    }

    /// Returns the calling process id of caller.
    pub fn calling_real_pid() -> u64 {
        GetCallingRealPid()
    }

    /// Returns the calling user id of caller.
    pub fn calling_uid() -> u64 {
        GetCallingUid()
    }

    /// Returns the calling token ID of caller.
    pub fn calling_token_id() -> u32 {
        GetCallingTokenID()
    }

    /// Returns the calling token ID of caller.
    pub fn calling_full_token_id() -> u64 {
        GetCallingFullTokenID()
    }

    /// Returns the the first token ID.
    pub fn first_token_id() -> u32 {
        GetFirstTokenID()
    }

    /// Returns the the first full token ID.
    pub fn first_full_token_id() -> u64 {
        GetFirstFullTokenID()
    }

    /// Returns the the token ID of the self.
    pub fn self_token_id() -> u64 {
        GetSelfTokenID()
    }

    /// Returns the local device ID.
    pub fn local_device_id() -> String {
        GetLocalDeviceID()
    }

    /// Returns the calling device id.
    pub fn calling_device_id() -> String {
        GetCallingDeviceID()
    }

    /// Returns true if it is a local call.
    pub fn is_local_calling() -> bool {
        IsLocalCalling()
    }

    /// Returns the context object.
    pub fn get_context_object() -> Option<RemoteObj> {
        RemoteObj::try_new(GetContextObject())
    }

    /// Flushes all pending commands.
    pub fn flush_commands(remote: &mut RemoteObj) -> i32 {
        FlushCommands(remote.inner.pin_mut())
    }

    /// Resets calling identity.
    pub fn reset_calling_identity() -> String {
        ResetCallingIdentity()
    }

    /// Sets calling identity.
    pub fn set_calling_identity(identity: &str) -> bool {
        SetCallingIdentity(identity)
    }
}
