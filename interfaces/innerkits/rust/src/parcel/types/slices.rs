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
use crate::{BorrowedMsgParcel, Result};

impl<T: SerArray> Serialize for [T] {
    fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
        SerArray::ser_array(self, parcel)
    }
}

impl<T: SerArray> SerOption for [T] {
    fn ser_option(this: Option<&Self>, parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
        if let Some(v) = this {
            SerArray::ser_array(v, parcel)
        } else {
            parcel.write(&-1i32)
        }
    }
}