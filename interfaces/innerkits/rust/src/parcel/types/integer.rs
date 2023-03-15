/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
use crate::{ipc_binding, BorrowedMsgParcel, IpcResult, status_result, AsRawPtr};
use std::mem::MaybeUninit;

impl_serde_option_for_parcelable!(i8, u8, i16, u16, i32, u32, i64, u64, f32,f64);

/// Macros expand signed numbers and floating point numbers
#[macro_export]
macro_rules! parcelable_number {
    {
        $(
            impl $trait:ident for $num_ty:ty = $fn:path;
        )*
    } => {
        $(define_impl_serde!{$trait, $num_ty, $fn})*
    };
}

/// # Macro expand example:
///
/// ```ignore
/// impl Serialize for i8 {
///     fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> IpcResult<()> {
///         // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
///         let ret = unsafe {
///             ipc_binding::CParcelWriteInt8(parcel.as_mut_raw(), *self)
///         };
///         status_result::<()>(i32::from(ret), ())
///     }
/// }
///
/// impl Deserialize for i8 {
///     fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> IpcResult<Self> {
///         let mut val = Self::default();
///         // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
///         let ret = unsafe {
///             ipc_binding::CParcelReadInt8(parcel.as_raw(), &mut val)
///         };
///         status_result::<i8>(ret, val)
///     }
/// }
/// ```
#[macro_export]
macro_rules! define_impl_serde {
    {Serialize, $num_ty:ty, $cparcel_write_fn:path} => {
        impl Serialize for $num_ty {
            fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> IpcResult<()> {
                // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`,
                // and any `$num_ty` literal value is safe to pass to `$cparcel_write_fn`.
                let ret = unsafe {
                    $cparcel_write_fn(parcel.as_mut_raw(), *self)
                };
                status_result::<()>(i32::from(ret), ())
            }
        }
    };

    {Deserialize, $num_ty:ty, $cparcel_read_fn:path} => {
        impl Deserialize for $num_ty {
            fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> IpcResult<Self> {
                let mut val = Self::default();
                // SAFETY: `parcel` always contains a valid pointer to a `CParcel`.
                // We pass a valid, mutable pointer to `val`, a literal of type `$num_ty`,
                // and `$cparcel_read_fn` will write the value read into `val` if successful
                let ret = unsafe {
                    $cparcel_read_fn(parcel.as_raw(), &mut val)
                };
                status_result::<$num_ty>(ret as i32, val)
            }
        }
    }
}

parcelable_number! {
    impl Serialize for i8 = ipc_binding::CParcelWriteInt8;
    impl Deserialize for i8 = ipc_binding::CParcelReadInt8;
    impl Serialize for i16 = ipc_binding::CParcelWriteInt16;
    impl Deserialize for i16 = ipc_binding::CParcelReadInt16;
    impl Serialize for i32 = ipc_binding::CParcelWriteInt32;
    impl Deserialize for i32 = ipc_binding::CParcelReadInt32;
    impl Serialize for i64 = ipc_binding::CParcelWriteInt64;
    impl Deserialize for i64 = ipc_binding::CParcelReadInt64;
    impl Serialize for f32 = ipc_binding::CParcelWriteFloat;
    impl Deserialize for f32 = ipc_binding::CParcelReadFloat;
    impl Serialize for f64 = ipc_binding::CParcelWriteDouble;
    impl Deserialize for f64 = ipc_binding::CParcelReadDouble;
}

/// Unsigned number of macro expansion
#[macro_export]
macro_rules! parcelable_for_unsign_number {
    {
        $(
            impl $trait:ident for $unum_ty:ty as $inum_ty:ty;
        )*
    } => {
        $(
            define_impl_serde_for_unsign!{ $trait, $unum_ty, $inum_ty}
        )*
    };
}

/// # Example:
///
/// ```ignore
/// // u8 -> i8
/// impl Serialize for u8 {
///     fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> IpcResult<()> {
///         (*self as i8).serialize(parcel)
///     }
/// }
/// // i8 -> u8
/// impl Deserialize for u8 {
///     fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> IpcResult<Self> {
///         i8::deserialize(parcel).map(|v| v as u8)
///     }
/// }
/// ```
#[macro_export]
macro_rules! define_impl_serde_for_unsign {
    {Serialize, $unum_ty:ty, $inum_ty:ty} => {
        impl Serialize for $unum_ty {
            fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> IpcResult<()> {
                (*self as $inum_ty).serialize(parcel)
            }
        }
    };

    {Deserialize, $unum_ty:ty, $inum_ty:ty} => {
        impl Deserialize for $unum_ty {
            fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> IpcResult<Self> {
                <$inum_ty>::deserialize(parcel).map(|v| v as $unum_ty)
            }
        }
    }
}

parcelable_for_unsign_number! {
    impl Serialize for u8 as i8;
    impl Deserialize for u8 as i8;
    impl Serialize for u16 as i16;
    impl Deserialize for u16 as i16;
    impl Serialize for u32 as i32;
    impl Deserialize for u32 as i32;
    impl Serialize for u64 as i64;
    impl Deserialize for u64 as i64;
}

/// Macros expand signed numbers and floating point arrays
#[macro_export]
macro_rules! parcelable_array {
    {
        $(
            impl $trait:ident for $num_ty:ty = $fn:path;
        )*
    } => {
        $(define_impl_array!{$trait, $num_ty, $fn})*
    };
}

/// # Example:
///
/// ```ignore
/// impl DeArray for i8 {
///     fn de_array(parcel: &BorrowedMsgParcel<'_>) -> IpcResult<Option<Vec<Self>>> {
///         let mut vec: Option<Vec<MaybeUninit<Self>>> = None;
///         let ok_status = unsafe {
///             // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
///             // `allocate_vec<T>` expects the opaque pointer to
///             // be of type `*mut Option<Vec<MaybeUninit<T>>>`, so `&mut vec` is
///             // correct for it.
///             ipc_binding::CParcelReadInt8Array(
///                 parcel.as_raw(),
///                 &mut vec as *mut _ as *mut c_void,
///                 allocate_vec_with_buffer,
///             )
///         };
///         if ok_status {
///             let vec: Option<Vec<Self>> = unsafe {
///                 // SAFETY: We are assuming that the NDK correctly
///                 // initialized every element of the vector by now, so we
///                 // know that all the MaybeUninits are now properly
///                 // initialized.
///                 vec.map(|vec| vec_assume_init(vec))
///             };
///             Ok(vec)
///         } else {
///             Err(IpcStatusCode::Failed)
///         }
///     }
// }
/// ```
#[macro_export]
macro_rules! define_impl_array {
    {SerArray, $num_ty:ty, $cparcel_write_fn:path} => {
        impl SerArray for $num_ty {
            fn ser_array(slice: &[Self], parcel: &mut BorrowedMsgParcel<'_>) -> IpcResult<()> {
                let ret = unsafe {
                    // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
                    // If the slice is > 0 length, `slice.as_ptr()` will be a
                    // valid pointer to an array of elements of type `$ty`. If the slice
                    // length is 0, `slice.as_ptr()` may be dangling, but this is safe
                    // since the pointer is not dereferenced if the length parameter is
                    // 0.
                    $cparcel_write_fn(
                        parcel.as_mut_raw(),
                        slice.as_ptr(),
                        slice.len().try_into().unwrap(),
                    )
                };
                status_result::<()>(ret as i32, ())
            }
        }
    };

    {DeArray, $num_ty:ty, $cparcel_read_fn:path} => {
        impl DeArray for $num_ty {
            fn de_array(parcel: &BorrowedMsgParcel<'_>) -> IpcResult<Option<Vec<Self>>> {
                let mut vec: Option<Vec<MaybeUninit<Self>>> = None;
                let ok_status = unsafe {
                    // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
                    // `allocate_vec<T>` expects the opaque pointer to
                    // be of type `*mut Option<Vec<MaybeUninit<T>>>`, so `&mut vec` is
                    // correct for it.
                    $cparcel_read_fn(
                        parcel.as_raw(),
                        &mut vec as *mut _ as *mut c_void,
                        allocate_vec_with_buffer,
                    )
                };
                if ok_status {
                    let vec: Option<Vec<Self>> = unsafe {
                        // SAFETY: We are assuming that the NDK correctly
                        // initialized every element of the vector by now, so we
                        // know that all the MaybeUninits are now properly
                        // initialized.
                        vec.map(|vec| vec_assume_init(vec))
                    };
                    Ok(vec)
                } else {
                    Err(IpcStatusCode::Failed)
                }
            }
        }
    }
}

parcelable_array! {
    impl SerArray for i8 = ipc_binding::CParcelWriteInt8Array;
    impl DeArray for i8 = ipc_binding::CParcelReadInt8Array;
    impl SerArray for i16 = ipc_binding::CParcelWriteInt16Array;
    impl DeArray for i16 = ipc_binding::CParcelReadInt16Array;
    impl SerArray for i32 = ipc_binding::CParcelWriteInt32Array;
    impl DeArray for i32 = ipc_binding::CParcelReadInt32Array;
    impl SerArray for i64 = ipc_binding::CParcelWriteInt64Array;
    impl DeArray for i64 = ipc_binding::CParcelReadInt64Array;
    impl SerArray for f32 = ipc_binding::CParcelWriteFloatArray;
    impl DeArray for f32 = ipc_binding::CParcelReadFloatArray;
    impl SerArray for f64 = ipc_binding::CParcelWriteDoubleArray;
    impl DeArray for f64 = ipc_binding::CParcelReadDoubleArray;
}

/// Macro Expand Unsigned Count Group
#[macro_export]
macro_rules! parcelable_for_array_unsign_number {
    {
        $(
            impl $trait:ident for $unum_ty:ty as $inum_ty:ty;
        )*
    } => {
        $(
            define_impl_array_for_unsign!{ $trait, $unum_ty, $inum_ty}
        )*
    };
}

/// # Example:
///
/// ```ignore
/// impl SerArray for u8 {
///     fn ser_array(slice: &[Self], parcel: &mut BorrowedMsgParcel<'_>) -> IpcResult<()> {
///         // SAFETY:
///         let slice = unsafe {std::slice::from_raw_parts(slice.as_ptr() as *const i8, slice.len()) };
///         i8::ser_array(slice, parcel)
///     }
/// }
///
/// impl DeArray for u8 {
///     fn de_array(parcel: &BorrowedMsgParcel<'_>) -> IpcResult<Option<Vec<Self>>> {
//         i8::de_array(parcel).map(|v|
///             v.map(|mut v| v.iter_mut().map(|i| *i as u8).collect())
///         )
///     }
/// }
/// ```
#[macro_export]
macro_rules! define_impl_array_for_unsign {
    {SerArray, $unum_ty:ty, $inum_ty:ty} => {
        impl SerArray for $unum_ty {
            fn ser_array(slice: &[Self], parcel: &mut BorrowedMsgParcel<'_>) -> IpcResult<()> {
                // SAFETY:
                let slice = unsafe {std::slice::from_raw_parts(slice.as_ptr() as *const $inum_ty, slice.len()) };
                <$inum_ty>::ser_array(slice, parcel)
            }
        }
    };

    {DeArray, $unum_ty:ty, $inum_ty:ty} => {
        impl DeArray for $unum_ty {
            fn de_array(parcel: &BorrowedMsgParcel<'_>) -> IpcResult<Option<Vec<Self>>> {
                <$inum_ty>::de_array(parcel).map(|v|
                    v.map(|mut v| v.iter_mut().map(|i| *i as $unum_ty).collect())
                )
            }
        }
    }
}

parcelable_for_array_unsign_number! {
    impl SerArray for u8 as i8;
    impl DeArray for u8 as i8;
    impl SerArray for u16 as i16;
    impl DeArray for u16 as i16;
    impl SerArray for u32 as i32;
    impl DeArray for u32 as i32;
    impl SerArray for u64 as i64;
    impl DeArray for u64 as i64;
}
