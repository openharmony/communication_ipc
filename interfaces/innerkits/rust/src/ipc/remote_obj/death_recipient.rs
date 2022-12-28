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

use super::*;

#[repr(C)]
pub struct DeathRecipient {
    native: *mut CDeathRecipient,
    callback: *mut c_void,
}

impl DeathRecipient {
    pub fn new<F>(callback: F) -> Option<DeathRecipient>
    where
        F: Fn() + Send + Sync + 'static,
    {
        let callback = Box::into_raw(Box::new(callback));
        let native = unsafe {
            // set callback pointer to native, so we can find call which fuction
            // when remote service died.
            ipc_binding::CreateDeathRecipient(Self::on_remote_died::<F>,
                Self::on_destroy::<F>, callback as *mut c_void)
        };
        if native.is_null() {
            None
        } else {
            Some(DeathRecipient {
                native,
                callback: callback as *mut c_void,
            })
        }
    }

    /// Callback when remote service died by native.
    ///
    /// # Safety
    ///
    /// The callback parameter will be kept valid during native
    /// CDeathRecipient object lifetime.
    unsafe extern "C" fn on_remote_died<F>(callback: *mut c_void)
    where
        F: Fn() + Send + Sync + 'static,
    {
        let callback = (callback as *const F).as_ref().unwrap();
        callback();
    }

    /// Callback when native CDeathRecipient destroyed
    ///
    /// # Safety
    ///
    /// The callback parameter will be kept valid during native
    /// CDeathRecipient object lifetime.
    unsafe extern "C" fn on_destroy<F>(callback: *mut c_void)
    where
        F: Fn() + Send + Sync + 'static,
    {
        if !callback.is_null() {
            println!("death recipient on destroy");
            Box::from_raw(callback as *mut F);
        }
    }
}

/// # Safety
///
/// A `DeathRecipient` is always constructed with a valid raw pointer
/// to a `CDeathRecipient`.
unsafe impl AsRawPtr<CDeathRecipient> for DeathRecipient {
    fn as_raw(&self) -> *const CDeathRecipient {
        self.native
    }

    fn as_mut_raw(&mut self) -> *mut CDeathRecipient {
        self.native
    }
}

impl Drop for DeathRecipient {
    fn drop(&mut self) {
        unsafe {
            // Safety: DeathRecipient will always hold a reference for
            // native CDeathRecipient.
            ipc_binding::DeathRecipientDecStrongRef(self.native);
        }
    }
}