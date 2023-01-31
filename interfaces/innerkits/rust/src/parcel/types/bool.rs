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
use std::mem::MaybeUninit;

impl_serde_option_for_parcelable!(bool);

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

impl SerArray for bool {
    fn ser_array(slice: &[Self], parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
        let ret = unsafe {
            // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
            // If the slice is > 0 length, `slice.as_ptr()` will be a
            // valid pointer to an array of elements of type `$ty`. If the slice
            // length is 0, `slice.as_ptr()` may be dangling, but this is safe
            // since the pointer is not dereferenced if the length parameter is
            // 0.
            ipc_binding::CParcelWriteBoolArray(
                parcel.as_mut_raw(),
                slice.as_ptr(),
                slice.len().try_into().unwrap(),
            )
        };
        result_status::<()>(ret, ())
    }
}

impl DeArray for bool {
    fn de_array(parcel: &BorrowedMsgParcel<'_>) -> Result<Option<Vec<Self>>> {
        let mut vec: Option<Vec<MaybeUninit<Self>>> = None;
        let ok_status = unsafe {
            // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
            // `allocate_vec<T>` expects the opaque pointer to
            // be of type `*mut Option<Vec<MaybeUninit<T>>>`, so `&mut vec` is
            // correct for it.
            ipc_binding::CParcelReadBoolArray(
                parcel.as_raw(),
                &mut vec as *mut _ as *mut c_void,
                allocate_vec_with_buffer,
            )
        };
        if ok_status{
            let vec: Option<Vec<Self>> = unsafe {
                // SAFETY: We are assuming that the NDK correctly
                // initialized every element of the vector by now, so we
                // know that all the MaybeUninits are now properly
                // initialized.
                vec.map(|vec| vec_assume_init(vec))
            };
            Ok(vec)
        } else {
            Err(-1)
        }
    }
}
