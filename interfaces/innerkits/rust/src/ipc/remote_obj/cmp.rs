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
use std::cmp::Ordering;

impl Ord for RemoteObj {
    fn cmp(&self, other: &Self) -> Ordering {
        // SAFETY: RemoteObj always holds a valid `CRemoteObject` pointer
        // (null is also safe to pass to this function, but we should never do that).
        let less_than = unsafe {
            ipc_binding::RemoteObjectLessThan(self.0.as_ptr(), other.0.as_ptr())
        };
        // SAFETY: RemoteObj always holds a valid `CRemoteObject` pointer
        // (null is also safe to pass to this function, but we should never do that).
        let greater_than = unsafe {
            ipc_binding::RemoteObjectLessThan(other.0.as_ptr(), self.0.as_ptr())
        };
        if !less_than && !greater_than {
            Ordering::Equal
        } else if less_than {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    }
}

impl PartialOrd for RemoteObj {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for RemoteObj {
    fn eq(&self, other: &Self) -> bool {
        ptr::eq(self.0.as_ptr(), other.0.as_ptr())
    }
}

impl Eq for RemoteObj {}
