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

use crate::{ipc_binding, RawData, Result};
use crate::ipc_binding::CAshmem;
use std::ffi::CString;

/// Ashmem packed the native CAshmem
#[repr(C)]
pub struct Ashmem(*mut CAshmem);

impl Ashmem {
    /// Create a Ashmem object
    pub fn new(name: &str, size: i32) -> Option<Self> {
        if size <= 0 {
            return None;
        }
        let c_name = CString::new(name).expect("ashmem name is invalid!");
        // SAFETY:
        let native = unsafe {
            ipc_binding::CreateCAshmem(c_name.as_ptr(), size)
        };
        if native.is_null() {
            None
        } else {
            Some(Self(native))
        }
    }

    /// Extract a raw `CAshmem` pointer from this wrapper.
    /// # Safety
    pub unsafe fn as_inner(&self) -> *mut CAshmem {
        self.0
    }
}

/// Memory protection for mmap() PROT_NONE
pub const PROT_NONE: i32 = 0;
/// Memory protection for mmap() PROT_READ
pub const PROT_READ: i32 = 1;
/// Memory protection for mmap() PROT_WRITE
pub const PROT_WRITE: i32 = 2;
/// Memory protection for mmap() PROT_EXEC
pub const PROT_EXEC: i32 = 4;

impl Ashmem {
    /// Close Ashmem, the ashmem becomes invalid after closing.
    pub fn close(&self) {
        unsafe {
            // SAFETY: Rust Ashmem always hold a valid native CAshmem.
            ipc_binding::CloseCAshmem(self.as_inner());
        }
    }

    /// Set ashmem map type with above PROT_XXX by mmap()
    pub fn map(&self, map_type: i32) -> bool {
        unsafe {
            // SAFETY: Rust Ashmem always hold a valid native CAshmem.
            ipc_binding::MapCAshmem(self.as_inner(), map_type)
        }
    }

    /// Set ashmem map type with `PROT_READ | PROT_WRITE` by mmap()
    pub fn map_read_write(&self) -> bool {
        unsafe {
            // SAFETY: Rust Ashmem always hold a valid native CAshmem.
            ipc_binding::MapReadAndWriteCAshmem(self.as_inner())
        }
    }

    /// Set ashmem map type with `PROT_READ` by mmap()
    pub fn map_readonly(&self) -> bool {
        unsafe {
            // SAFETY: Rust Ashmem always hold a valid native CAshmem.
            ipc_binding::MapReadOnlyCAshmem(self.as_inner())
        }
    }

    /// unmap ashmem
    pub fn unmap(&self) {
        unsafe {
            // SAFETY: Rust Ashmem always hold a valid native CAshmem.
            ipc_binding::UnmapCAshmem(self.as_inner());
        }
    }

    /// Set ashmem map type with above PROT_XXX by ioctl()
    pub fn set_protection(&self, protection: i32) -> bool {
        unsafe {
            // SAFETY: Rust Ashmem always hold a valid native CAshmem.
            ipc_binding::SetCAshmemProtection(self.as_inner(), protection)
        }
    }

    /// Get ashmem map type
    pub fn get_protection(&self) -> i32 {
        unsafe {
            // SAFETY: Rust Ashmem always hold a valid native CAshmem.
            ipc_binding::GetCAshmemProtection(self.as_inner())
        }
    }

    /// Get ashmem size
    pub fn get_size(&self) -> i32 {
        unsafe {
            // SAFETY: Rust Ashmem always hold a valid native CAshmem.
            ipc_binding::GetCAshmemSize(self.as_inner())
        }
    }

    /// Write data to ashmem
    pub fn write(&self, data: &[u8], offset: i32) -> bool {
        let len = data.len() as i32;
        if offset < 0 || offset >= len {
            println!("invalid offset: {}, len: {}", offset, len);
            return false;
        }
        unsafe {
            // SAFETY: Rust Ashmem always hold a valid native CAshmem.
            ipc_binding::WriteToCAshmem(self.as_inner(),
                data.as_ptr(), len, offset)
        }
    }

    /// Read ashmem
    pub fn read(&self, size: i32, offset: i32) -> Result<RawData> {
        let raw_ptr = unsafe {
            // SAFETY: Rust Ashmem always hold a valid native CAshmem.
            ipc_binding::ReadFromCAshmem(self.as_inner(), size, offset)
        };
        if raw_ptr.is_null() { 
            Err(-1)
        } else {
            Ok(RawData::new(raw_ptr, size as u32))
        }
    }

    /// Get ashmem inner file descriptor
    pub fn get_fd(&self) -> i32 {
        unsafe {
            // SAFETY: Rust Ashmem always hold a valid native CAshmem.
            ipc_binding::GetCAshmemFd(self.as_inner())
        }
    }
}

impl Clone for Ashmem {
    fn clone(&self) -> Self {
        // SAFETY:
        unsafe {
            ipc_binding::CAshmemIncStrongRef(self.as_inner());
        }
        // SAFETY: no `None` here, cause `self` is valid 
        Self(self.0)
    }
}

impl Drop for Ashmem {
    fn drop(&mut self) {
        // SAFETY:
        unsafe {
            ipc_binding::CAshmemDecStrongRef(self.as_inner());
        }
    }
}