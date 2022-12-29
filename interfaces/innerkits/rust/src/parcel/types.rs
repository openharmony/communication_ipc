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

pub mod bool;
pub mod integer;
pub mod option;
pub mod reference;
pub mod strings;
pub mod interface_token;
pub mod string16;
pub mod file_desc;
pub mod boxt;
// pub mod const_array;
// pub mod slices;
// pub mod vector;

use crate::parcel::parcelable::*;
use std::ffi::{c_char, c_void};
use crate::{ipc_binding, BorrowedMsgParcel, AsRawPtr, result_status, Result, SerOption, DeOption};