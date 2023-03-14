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

impl<T: SerArray, const N: usize> Serialize for [T; N] {
    fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> IpcResult<()> {
        // forwards to T::serialize_array.
        SerArray::ser_array(self, parcel)
    }
}

impl<T: SerArray, const N: usize> SerOption for [T; N] {
    fn ser_option(this: Option<&Self>, parcel: &mut BorrowedMsgParcel<'_>) -> IpcResult<()> {
        SerOption::ser_option(this.map(|arr| &arr[..]), parcel)
    }
}

impl<T: SerArray, const N: usize> SerArray for [T; N] {}

impl<T: DeArray, const N: usize> Deserialize for [T; N] {
    fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> IpcResult<Self> {
        let vec = DeArray::de_array(parcel)
            .transpose()
            .unwrap_or(Err(IpcStatusCode::Failed))?;
        vec.try_into().or(Err(IpcStatusCode::Failed))
    }
}

impl<T: DeArray, const N: usize> DeOption for [T; N] {
    fn de_option(parcel: &BorrowedMsgParcel<'_>) -> IpcResult<Option<Self>> {
        let vec = DeArray::de_array(parcel)?;
        vec.map(|v| v.try_into().or(Err(IpcStatusCode::Failed))).transpose()
    }
}

impl<T: DeArray, const N: usize> DeArray for [T; N] {}