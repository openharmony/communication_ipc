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
use crate::{ipc_binding, BorrowedMsgParcel, Result, result_status, AsRawPtr};

///  i8 && u8
impl Serialize for i8 {
    fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
        // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
        let ret = unsafe {
            ipc_binding::CParcelWriteInt8(parcel.as_mut_raw(), *self)
        };
        result_status::<()>(ret, ())
    }
}

impl Deserialize for i8 {
    fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> Result<Self> {
        let mut val = Self::default();
        // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
        let ret = unsafe {
            ipc_binding::CParcelReadInt8(parcel.as_raw(), &mut val)
        };
        result_status::<i8>(ret, val)
    }
}

// u8 -> i8
impl Serialize for u8 {
    fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
        (*self as i8).serialize(parcel)
    }
}
// i8 -> u8
impl Deserialize for u8 {
    fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> Result<Self> {
        i8::deserialize(parcel).map(|v| v as u8)
    }
}


///  i16 && u16
impl Serialize for i16 {
    fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
        // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
        let ret = unsafe {
            ipc_binding::CParcelWriteInt16(parcel.as_mut_raw(), *self)
        };
        result_status::<()>(ret, ())
    }
}

impl Deserialize for i16 {
    fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> Result<Self> {
        let mut val = Self::default();
        // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
        let ret = unsafe {
            ipc_binding::CParcelReadInt16(parcel.as_raw(), &mut val)
        };
        result_status::<i16>(ret, val)
    }
}

impl Serialize for u16 {
    fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
        (*self as i16).serialize(parcel)
    }
}

impl Deserialize for u16 {
    fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> Result<Self> {
        i16::deserialize(parcel).map(|v| v as u16)
    }
}


/// i32 && u32
impl Serialize for i32 {
    fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
        // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
        let ret = unsafe {
            ipc_binding::CParcelWriteInt32(parcel.as_mut_raw(), *self)
        };
        result_status::<()>(ret, ())
    }
}

impl Deserialize for i32 {
    fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> Result<Self> {
        let mut val = Self::default();
        // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
        let ret = unsafe {
            ipc_binding::CParcelReadInt32(parcel.as_raw(), &mut val)
        };
        result_status::<i32>(ret, val)
    }
}

impl Serialize for u32 {
    fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
        (*self as i32).serialize(parcel)
    }
}

impl Deserialize for u32 {
    fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> Result<Self> {
        i32::deserialize(parcel).map(|v| v as u32)
    }
}

/// i64 && u64
impl Serialize for i64 {
    fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
        // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
        let ret = unsafe {
            ipc_binding::CParcelWriteInt64(parcel.as_mut_raw(), *self)
        };
        result_status::<()>(ret, ())
    }
}

impl Deserialize for i64 {
    fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> Result<Self> {
        let mut val = Self::default();
        // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
        let ret = unsafe {
            ipc_binding::CParcelReadInt64(parcel.as_raw(), &mut val)
        };
        result_status::<i64>(ret, val)
    }
}

impl Serialize for u64 {
    fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
        (*self as i64).serialize(parcel)
    }
}

impl Deserialize for u64 {
    fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> Result<Self> {
        i64::deserialize(parcel).map(|v| v as u64)
    }
}



/// f32
impl Serialize for f32 {
    fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
        // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
        let ret = unsafe {
            ipc_binding::CParcelWriteFloat(parcel.as_mut_raw(), *self)
        };
        result_status::<()>(ret, ())
    }
}

impl Deserialize for f32 {
    fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> Result<Self> {
        let mut val = Self::default();
        // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
        let ret = unsafe {
            ipc_binding::CParcelReadFloat(parcel.as_raw(), &mut val)
        };
        result_status::<f32>(ret, val)
    }
}


/// f64
impl Serialize for f64 {
    fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
        // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
        let ret = unsafe {
            ipc_binding::CParcelWriteDouble(parcel.as_mut_raw(), *self)
        };
        result_status::<()>(ret, ())
    }
}

impl Deserialize for f64 {
    fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> Result<Self> {
        let mut val = Self::default();
        // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
        let ret = unsafe {
            ipc_binding::CParcelReadDouble(parcel.as_raw(), &mut val)
        };
        result_status::<f64>(ret, val)
    }
}
