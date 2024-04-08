// Copyright (C) 2024 Huawei Device Co., Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Safe Rust interface to OHOS IPC/RPC
#![allow(clippy::missing_safety_doc)]
#![allow(missing_docs, unused)]

#[macro_use]
mod hilog;

mod errors;

pub mod ipc_async;
pub mod parcel;
pub mod process;
pub mod remote;

pub mod cxx_share;
mod skeleton;
// Export types of this crate
pub use crate::errors::{parse_status_code, status_result, IpcResult, IpcStatusCode};

/// First request code available for user IPC request(inclusive)
pub const FIRST_CALL_TRANSACTION: isize = 0x00000001;
/// Last request code available for user IPC request(inclusive)
pub const LAST_CALL_TRANSACTION: isize = 0x00ffffff;
use hilog_rust::{HiLogLabel, LogType};
pub use skeleton::Skeleton;

const LOG_LABEL: HiLogLabel = HiLogLabel {
    log_type: LogType::LogCore,
    domain: 0xD0057CA,
    tag: "IPC_RUST",
};
