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

// impl SerArray for i16 {
//     fn ser_array(slice: &[Self], parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
//         let ret = unsafe {
//             // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
//             // If the slice is > 0 length, `slice.as_ptr()` will be a
//             // valid pointer to an array of elements of type `$ty`. If the slice
//             // length is 0, `slice.as_ptr()` may be dangling, but this is safe
//             // since the pointer is not dereferenced if the length parameter is
//             // 0.
//             ipc_binding::CParcelWriteInt16Array(
//                 parcel.as_mut_raw(),
//                 slice.as_ptr(),
//                 slice.len()
//             )
//         };
//         result_status::<()>(ret, ())
//     }
// }

// impl DeArray for i16 {
//     fn de_array(parcel: &BorrowedMsgParcel<'_>) -> Result<Option<Vec<Self>>> {
//         let mut vec: Option<Vec<MaybeUninit<Self>>> = None;
//         let ok_status = unsafe {
//             // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
//             // `allocate_vec<T>` expects the opaque pointer to
//             // be of type `*mut Option<Vec<MaybeUninit<T>>>`, so `&mut vec` is
//             // correct for it.
//             ipc_binding::CParcelReadInt16Array(
//                 parcel.as_raw(),
//                 &mut vec as *mut _ as *mut c_void,
//                 allocate_vec_with_buffer,
//             )
//         };
//         if ok_status{
//             let vec: Option<Vec<Self>> = unsafe {
//                 // SAFETY: We are assuming that the NDK correctly
//                 // initialized every element of the vector by now, so we
//                 // know that all the MaybeUninits are now properly
//                 // initialized.
//                 vec.map(|vec| vec_assume_init(vec))
//             };
//             Ok(vec)
//         }else{
//             Err(-1)
//         }
        
//     }
// }

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

// impl SerArray for u16 {
//     fn ser_array(slice: &[Self], parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
//         let ret = unsafe {
//             // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
//             // If the slice is > 0 length, `slice.as_ptr()` will be a
//             // valid pointer to an array of elements of type `$ty`. If the slice
//             // length is 0, `slice.as_ptr()` may be dangling, but this is safe
//             // since the pointer is not dereferenced if the length parameter is
//             // 0.
//             ipc_binding::CParcelWriteInt16Array(
//                 parcel.as_mut_raw(),
//                 slice.as_ptr() as *const i16,
//                 slice.len()
//             )
//         };
//         result_status::<()>(ret, ())
//     }
// }

// impl DeArray for u16 {
//     fn de_array(parcel: &BorrowedMsgParcel<'_>) -> Result<Option<Vec<Self>>> {
//         let mut vec: Option<Vec<MaybeUninit<Self>>> = None;
//         let ok_status = unsafe {
//             // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
//             // `allocate_vec<T>` expects the opaque pointer to
//             // be of type `*mut Option<Vec<MaybeUninit<T>>>`, so `&mut vec` is
//             // correct for it.
//             ipc_binding::CParcelReadInt16Array(
//                 parcel.as_raw(),
//                 &mut vec as *mut _ as *mut c_void,
//                 allocate_vec_with_buffer,
//             )
//         };
//         if ok_status{
//             let vec: Option<Vec<Self>> = unsafe {
//                 // SAFETY: We are assuming that the NDK correctly
//                 // initialized every element of the vector by now, so we
//                 // know that all the MaybeUninits are now properly
//                 // initialized.
//                 vec.map(|vec| vec_assume_init(vec))
//             };
//             Ok(vec)
//         }else{
//             Err(-1)
//         }
        
//     }
// }

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

// impl SerArray for i32 {
//     fn ser_array(slice: &[Self], parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
//         let ret = unsafe {
//             // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
//             // If the slice is > 0 length, `slice.as_ptr()` will be a
//             // valid pointer to an array of elements of type `$ty`. If the slice
//             // length is 0, `slice.as_ptr()` may be dangling, but this is safe
//             // since the pointer is not dereferenced if the length parameter is
//             // 0.
//             ipc_binding::CParcelWriteInt32Array(
//                 parcel.as_mut_raw(),
//                 slice.as_ptr(),
//                 slice.len()
//             )
//         };
//         result_status::<()>(ret, ())
//     }
// }

// impl DeArray for i32 {
//     fn de_array(parcel: &BorrowedMsgParcel<'_>) -> Result<Option<Vec<Self>>> {
//         let mut vec: Option<Vec<MaybeUninit<Self>>> = None;
//         let ok_status = unsafe {
//             // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
//             // `allocate_vec<T>` expects the opaque pointer to
//             // be of type `*mut Option<Vec<MaybeUninit<T>>>`, so `&mut vec` is
//             // correct for it.
//             ipc_binding::CParcelReadInt32Array(
//                 parcel.as_raw(),
//                 &mut vec as *mut _ as *mut c_void,
//                 allocate_vec_with_buffer,
//             )
//         };
//         if ok_status{
//             let vec: Option<Vec<Self>> = unsafe {
//                 // SAFETY: We are assuming that the NDK correctly
//                 // initialized every element of the vector by now, so we
//                 // know that all the MaybeUninits are now properly
//                 // initialized.
//                 vec.map(|vec| vec_assume_init(vec))
//             };
//             Ok(vec)
//         }else{
//             Err(-1)
//         }
        
//     }
// }

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

// impl SerArray for u32 {
//     fn ser_array(slice: &[Self], parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
//         let ret = unsafe {
//             // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
//             // If the slice is > 0 length, `slice.as_ptr()` will be a
//             // valid pointer to an array of elements of type `$ty`. If the slice
//             // length is 0, `slice.as_ptr()` may be dangling, but this is safe
//             // since the pointer is not dereferenced if the length parameter is
//             // 0.
//             ipc_binding::CParcelWriteInt32Array(
//                 parcel.as_mut_raw(),
//                 slice.as_ptr() as *const i32,
//                 slice.len().try_into().or(Err(-1)?,
//             )
//         };
//         result_status::<()>(ret, ())
//     }
// }

// impl DeArray for u32 {
//     fn de_array(parcel: &BorrowedMsgParcel<'_>) -> Result<Option<Vec<Self>>> {
//         let mut vec: Option<Vec<MaybeUninit<Self>>> = None;
//         let ok_status = unsafe {
//             // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
//             // `allocate_vec<T>` expects the opaque pointer to
//             // be of type `*mut Option<Vec<MaybeUninit<T>>>`, so `&mut vec` is
//             // correct for it.
//             ipc_binding::CParcelReadInt32Array(
//                 parcel.as_raw(),
//                 &mut vec as *mut _ as *mut c_void,
//                 allocate_vec_with_buffer,
//             )
//         };
//         if ok_status{
//             let vec: Option<Vec<Self>> = unsafe {
//                 // SAFETY: We are assuming that the NDK correctly
//                 // initialized every element of the vector by now, so we
//                 // know that all the MaybeUninits are now properly
//                 // initialized.
//                 vec.map(|vec| vec_assume_init(vec))
//             };
//             Ok(vec)
//         }else{
//             Err(-1)
//         }
        
//     }
// }

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

// impl SerArray for i64 {
//     fn ser_array(slice: &[Self], parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
//         let ret = unsafe {
//             // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
//             // If the slice is > 0 length, `slice.as_ptr()` will be a
//             // valid pointer to an array of elements of type `$ty`. If the slice
//             // length is 0, `slice.as_ptr()` may be dangling, but this is safe
//             // since the pointer is not dereferenced if the length parameter is
//             // 0.
//             ipc_binding::CParcelWriteInt64Array(
//                 parcel.as_mut_raw(),
//                 slice.as_ptr() as *const i64,
//                 slice.len()
//             )
//         };
//         result_status::<()>(ret, ())
//     }
// }

// impl DeArray for i64 {
//     fn de_array(parcel: &BorrowedMsgParcel<'_>) -> Result<Option<Vec<Self>>> {
//         let mut vec: Option<Vec<MaybeUninit<Self>>> = None;
//         let ok_status = unsafe {
//             // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
//             // `allocate_vec<T>` expects the opaque pointer to
//             // be of type `*mut Option<Vec<MaybeUninit<T>>>`, so `&mut vec` is
//             // correct for it.
//             ipc_binding::CParcelReadInt64Array(
//                 parcel.as_raw(),
//                 &mut vec as *mut _ as *mut c_void,
//                 allocate_vec_with_buffer,
//             )
//         };
//         if ok_status{
//             let vec: Option<Vec<Self>> = unsafe {
//                 // SAFETY: We are assuming that the NDK correctly
//                 // initialized every element of the vector by now, so we
//                 // know that all the MaybeUninits are now properly
//                 // initialized.
//                 vec.map(|vec| vec_assume_init(vec))
//             };
//             Ok(vec)
//         }else{
//             Err(-1)
//         }
        
//     }
// }

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

// impl SerArray for u64 {
//     fn ser_array(slice: &[Self], parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
//         let ret = unsafe {
//             // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
//             // If the slice is > 0 length, `slice.as_ptr()` will be a
//             // valid pointer to an array of elements of type `$ty`. If the slice
//             // length is 0, `slice.as_ptr()` may be dangling, but this is safe
//             // since the pointer is not dereferenced if the length parameter is
//             // 0.
//             ipc_binding::CParcelWriteInt64Array(
//                 parcel.as_mut_raw(),
//                 slice.as_ptr() as *const i64,
//                 slice.len()
//             )
//         };
//         result_status::<()>(ret, ())
//     }
// }

// impl DeArray for u64 {
//     fn de_array(parcel: &BorrowedMsgParcel<'_>) -> Result<Option<Vec<Self>>> {
//         let mut vec: Option<Vec<MaybeUninit<Self>>> = None;
//         let ok_status = unsafe {
//             // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
//             // `allocate_vec<T>` expects the opaque pointer to
//             // be of type `*mut Option<Vec<MaybeUninit<T>>>`, so `&mut vec` is
//             // correct for it.
//             ipc_binding::CParcelReadInt64Array(
//                 parcel.as_raw(),
//                 &mut vec as *mut _ as *mut c_void,
//                 allocate_vec_with_buffer,
//             )
//         };
//         if ok_status{
//             let vec: Option<Vec<Self>> = unsafe {
//                 // SAFETY: We are assuming that the NDK correctly
//                 // initialized every element of the vector by now, so we
//                 // know that all the MaybeUninits are now properly
//                 // initialized.
//                 vec.map(|vec| vec_assume_init(vec))
//             };
//             Ok(vec)
//         }else{
//             Err(-1)
//         }
        
//     }
// }

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

// impl SerArray for f32 {
//     fn ser_array(slice: &[Self], parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
//         let ret = unsafe {
//             // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
//             // If the slice is > 0 length, `slice.as_ptr()` will be a
//             // valid pointer to an array of elements of type `$ty`. If the slice
//             // length is 0, `slice.as_ptr()` may be dangling, but this is safe
//             // since the pointer is not dereferenced if the length parameter is
//             // 0.
//             ipc_binding::CParcelWriteFloatArray(
//                 parcel.as_mut_raw(),
//                 slice.as_ptr(),
//                 slice.len().try_into().or(Err(-1)?,
//             )
//         };
//         result_status::<()>(ret, ())
//     }
// }

// impl DeArray for f32 {
//     fn de_array(parcel: &BorrowedMsgParcel<'_>) -> Result<Option<Vec<Self>>> {
//         let mut vec: Option<Vec<MaybeUninit<Self>>> = None;
//         let ok_status = unsafe {
//             // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
//             // `allocate_vec<T>` expects the opaque pointer to
//             // be of type `*mut Option<Vec<MaybeUninit<T>>>`, so `&mut vec` is
//             // correct for it.
//             ipc_binding::CParcelReadFloatArray(
//                 parcel.as_raw(),
//                 &mut vec as *mut _ as *mut c_void,
//                 allocate_vec_with_buffer,
//             )
//         };
//         if ok_status{
//             let vec: Option<Vec<Self>> = unsafe {
//                 // SAFETY: We are assuming that the NDK correctly
//                 // initialized every element of the vector by now, so we
//                 // know that all the MaybeUninits are now properly
//                 // initialized.
//                 vec.map(|vec| vec_assume_init(vec))
//             };
//             Ok(vec)
//         }else{
//             Err(-1)
//         }
//     }
// }

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

// impl SerArray for f64 {
//     fn ser_array(slice: &[Self], parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
//         let ret = unsafe {
//             // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
//             // If the slice is > 0 length, `slice.as_ptr()` will be a
//             // valid pointer to an array of elements of type `$ty`. If the slice
//             // length is 0, `slice.as_ptr()` may be dangling, but this is safe
//             // since the pointer is not dereferenced if the length parameter is
//             // 0.
//             ipc_binding::CParcelWriteDoubleArray(
//                 parcel.as_mut_raw(),
//                 slice.as_ptr(),
//                 slice.len()
//             )
//         };
//         result_status::<()>(ret, ())
//     }
// }

// impl DeArray for f64 {
//     fn de_array(parcel: &BorrowedMsgParcel<'_>) -> Result<Option<Vec<Self>>> {
//         let mut vec: Option<Vec<MaybeUninit<Self>>> = None;
//         let ok_status = unsafe {
//             // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
//             // `allocate_vec<T>` expects the opaque pointer to
//             // be of type `*mut Option<Vec<MaybeUninit<T>>>`, so `&mut vec` is
//             // correct for it.
//             ipc_binding::CParcelReadDoubleArray(
//                 parcel.as_raw(),
//                 &mut vec as *mut _ as *mut c_void,
//                 allocate_vec_with_buffer,
//             )
//         };
//         if ok_status{
//             let vec: Option<Vec<Self>> = unsafe {
//                 // SAFETY: We are assuming that the NDK correctly
//                 // initialized every element of the vector by now, so we
//                 // know that all the MaybeUninits are now properly
//                 // initialized.
//                 vec.map(|vec| vec_assume_init(vec))
//             };
//             Ok(vec)
//         }else{
//             Err(-1)
//         }
//     }
// }