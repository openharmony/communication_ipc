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

impl Serialize for bool {
    fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
        unsafe {
            // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
            let ret = ipc_binding::CParcelWriteBool(parcel.as_mut_raw(), *self);
            result_status::<()>(ret, ())
        }
    }
}

impl Deserialize for bool {
    fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> Result<Self> {
        let mut val = Self::default();
        // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
        let ret = unsafe {
            ipc_binding::CParcelReadBool(parcel.as_raw(), &mut val)
        };

        result_status::<bool>(ret, val)
    }
}