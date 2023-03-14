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

impl<T: Serialize> Serialize for Box<T> {
    fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> IpcResult<()> {
        Serialize::serialize(&**self, parcel)
    }
}

impl<T: Deserialize> Deserialize for Box<T> {
    fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> IpcResult<Self> {
        Deserialize::deserialize(parcel).map(Box::new)
    }
}

impl<T: SerOption> SerOption for Box<T> {
    fn ser_option(this: Option<&Self>, parcel: &mut BorrowedMsgParcel<'_>) -> IpcResult<()> {
        SerOption::ser_option(this.map(|inner| &**inner), parcel)
    }
}

impl<T: DeOption> DeOption for Box<T> {
    fn de_option(parcel: &BorrowedMsgParcel<'_>) -> IpcResult<Option<Self>> {
        DeOption::de_option(parcel).map(|t| t.map(Box::new))
    }
}