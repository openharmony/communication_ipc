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

use std::error::Error;
use std::ffi::{c_char, CString};
use std::fmt;

/// IPC specific Result, error is i32 type
pub type IpcResult<T> = std::result::Result<T, IpcStatusCode>;

/// usage:
/// status_result::<()>(result, ())
/// or
/// status_result::<MsgParcel>(result, reply)
pub fn status_result<T>(code: i32, val: T) -> IpcResult<T> {
    debug!("rust status code: {}", code);
    match parse_status_code(code) {
        IpcStatusCode::Ok => Ok(val),
        e => Err(e),
    }
}

/// Parse status code
pub fn parse_status_code(code: i32) -> IpcStatusCode {
    match code {
        e if e == IpcStatusCode::Ok as i32 => IpcStatusCode::Ok,
        e if e == IpcStatusCode::Failed as i32 => IpcStatusCode::Failed,
        e if e == IpcStatusCode::Einval as i32 => IpcStatusCode::Einval,
        e if e == IpcStatusCode::ErrNullObject as i32 => IpcStatusCode::ErrNullObject,
        e if e == IpcStatusCode::ErrDeadObject as i32 => IpcStatusCode::ErrDeadObject,
        e if e == IpcStatusCode::InvalidValue as i32 => IpcStatusCode::InvalidValue,
        _ => IpcStatusCode::Unknow,
    }
}

/// IPC unified status code
#[derive(Hash, Eq, PartialEq, Ord, PartialOrd, Clone, Copy, Debug)]
#[non_exhaustive]
pub enum IpcStatusCode {
    /// success
    Ok = 1,
    /// failed
    Failed = -1,
    /// RemoteObj Err Code
    /// Invalide Params
    Einval = 22,
    /// Object is null
    ErrNullObject = 7,
    /// The object has died
    ErrDeadObject = -32,
    /// invail value
    InvalidValue = 0,
    /// unknow value
    Unknow = 99999,
}

impl Error for IpcStatusCode {}

/// # Safety
///
/// IpcStatusCode is an enumeration type that can exist in multiple threads.
unsafe impl Send for IpcStatusCode {}

impl fmt::Display for IpcStatusCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            IpcStatusCode::Ok => write!(f, "Call Ok"),
            IpcStatusCode::Failed => write!(f, "Call Failed"),
            IpcStatusCode::Einval => write!(f, "Invalid Params"),
            IpcStatusCode::ErrNullObject => write!(f, "Null Obj"),
            IpcStatusCode::ErrDeadObject => write!(f, "Dead Obj"),
            IpcStatusCode::InvalidValue => write!(f, "Invalid Value"),
            _ => write!(f, "Unknow Error"),
        }
    }
}
