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

impl<T: SerArray> Serialize for Vec<T> {
    fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
        SerArray::ser_array(&self[..], parcel)
    }
}

impl<T: SerArray> SerOption for Vec<T> {
    fn ser_option(this: Option<&Self>, parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
        SerOption::ser_option(this.map(Vec::as_slice), parcel)
    }
}

impl<T: DeArray> Deserialize for Vec<T> {
    fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> Result<Self> {
        DeArray::de_array(parcel)
            .transpose()
            .unwrap_or(Err(-1))
    }
}

impl<T: DeArray> DeOption for Vec<T> {
    fn de_option(parcel: &BorrowedMsgParcel<'_>) -> Result<Option<Self>> {
        DeArray::de_array(parcel)
    }
}