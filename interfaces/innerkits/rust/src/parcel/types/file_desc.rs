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
use crate::{ipc_binding, BorrowedMsgParcel, AsRawPtr, status_result, IpcResult, IpcStatusCode};

use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::ffi::{CString};
use hilog_rust::{error, hilog, HiLogLabel, LogType};

const LOG_LABEL: HiLogLabel = HiLogLabel {
    log_type: LogType::LogCore,
    domain: 0xd001510,
    tag: "RustFileDesc"
};

/// Rust version of the Java class android.os.ParcelFileDescriptor
#[derive(Debug)]
pub struct FileDesc(File);

impl FileDesc {
    /// Create a FileDesc object with rust File object.
    pub fn new(file: File) -> Self {
        Self(file)
    }
}

impl AsRef<File> for FileDesc {
    fn as_ref(&self) -> &File {
        &self.0
    }
}

impl From<FileDesc> for File {
    fn from(file: FileDesc) -> File {
        file.0
    }
}

impl AsRawFd for FileDesc {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl IntoRawFd for FileDesc {
    fn into_raw_fd(self) -> RawFd {
        self.0.into_raw_fd()
    }
}

impl PartialEq for FileDesc {
    // Since ParcelFileDescriptors own the FD, if this function ever returns true (and it is used to
    // compare two different objects), then it would imply that an FD is double-owned.
    fn eq(&self, other: &Self) -> bool {
        self.as_raw_fd() == other.as_raw_fd()
    }
}

impl Eq for FileDesc {}

impl Serialize for FileDesc {
    fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> IpcResult<()> {
        let fd = self.0.as_raw_fd();
        let ret = unsafe {
            // SAFETY: `parcel` always contains a valid pointer to an `CParcel`.
            ipc_binding::CParcelWriteFileDescriptor(parcel.as_mut_raw(), fd)
        };
        status_result::<()>(ret as i32, ())
    }
}

impl SerOption for FileDesc {
    fn ser_option(this: Option<&Self>, parcel: &mut BorrowedMsgParcel<'_>) -> IpcResult<()> {
        if let Some(f) = this {
            f.serialize(parcel)
        } else {
            let ret = unsafe {
                // SAFETY: `parcel` always contains a valid pointer to an `CParcel`.
                // `CParcelWriteFileDescriptor` accepts the value `-1` as the file
                // descriptor to signify serializing a null file descriptor.
                ipc_binding::CParcelWriteFileDescriptor(parcel.as_mut_raw(), -1i32)
            };
            status_result::<()>(ret as i32, ())
        }
    }
}

impl DeOption for FileDesc {
    fn de_option(parcel: &BorrowedMsgParcel<'_>) -> IpcResult<Option<Self>> {
        let mut fd = -1i32;
        let ok_status = unsafe {
            // SAFETY: `parcel` always contains a valid pointer to an `CParcel`.
            // `CParcelWriteFileDescriptor` accepts the value `-1` as the file
            // descriptor to signify serializing a null file descriptor.
            // The read function passes ownership of the file
            // descriptor to its caller if it was non-null, so we must take
            // ownership of the file and ensure that it is eventually closed.
            ipc_binding::CParcelReadFileDescriptor(
                parcel.as_raw(),
                &mut fd,
            )
        };
        if ok_status{
            if fd < 0 {
                error!(LOG_LABEL, "file descriptor is invalid from native");
                Err(IpcStatusCode::Failed)
            } else {
                let file = unsafe {
                    // SAFETY: At this point, we know that the file descriptor was
                    // not -1, so must be a valid, owned file descriptor which we
                    // can safely turn into a `File`.
                    File::from_raw_fd(fd)
                };
                Ok(Some(FileDesc::new(file)))
            }
        } else {
            error!(LOG_LABEL, "read file descriptor failed from native");
            Err(IpcStatusCode::Failed)
        }
    }
}

impl Deserialize for FileDesc {
    fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> IpcResult<Self> {
        Deserialize::deserialize(parcel)
            .transpose()
            .unwrap_or(Err(IpcStatusCode::Failed))
    }
}