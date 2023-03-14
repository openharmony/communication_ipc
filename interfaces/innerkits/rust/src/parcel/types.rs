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

/// # Example
///
/// ```ignore
/// impl_serde_option_for_parcelable!(i32, bool);
/// ```
#[macro_export]
macro_rules! impl_serde_option_for_parcelable {
    ($($ty:ty),*) => {
            $(
                impl SerOption for $ty {}
                impl DeOption for $ty {}
            )*
    };
}

pub mod bool;
pub mod integer;
pub mod option;
pub mod reference;
pub mod strings;
pub mod interface_token;
pub mod string16;
pub mod file_desc;
pub mod boxt;
pub mod const_array;
pub mod slices;
pub mod vector;

pub use self::string16::on_string16_writer;
pub use self::strings::vec_u16_to_string;
pub use self::strings::vec_to_string;

use crate::parcel::parcelable::*;
use std::ffi::{c_char, c_void};
use crate::{
    ipc_binding, BorrowedMsgParcel, AsRawPtr, status_result,
    IpcResult, IpcStatusCode, SerOption, DeOption
};
