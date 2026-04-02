// Copyright (C) 2026 Huawei Device Co., Ltd.
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

use std::ffi::{CStr, CString};

use ipc::parcel::MsgParcel;
use ipc::IpcStatusCode;
use utils_rust::ashmem::create_ashmem_instance;

const TEST_ASHMEM_CONTENT: &[u8] = b"hello ashmem";
const TEST_ASHMEM_NAME: &str = "ipc_rust_ashmem";

/// UT test case for "ashmem_read_write_roundtrip"
///
/// # brief
/// 1. Create an ashmem instance and write test content into it
/// 2. Write the ashmem into MsgParcel
/// 3. Read ashmem back from MsgParcel
/// 4. Check ashmem size and content after read
#[test]
fn ashmem_read_write_roundtrip() {
    let ashmem = unsafe { create_ashmem_instance(TEST_ASHMEM_NAME, TEST_ASHMEM_CONTENT.len() as i32) }
        .expect("failed to create ashmem");
    assert!(ashmem.map_read_write_ashmem());

    let content = CString::new(TEST_ASHMEM_CONTENT).expect("invalid ashmem content");
    assert!(unsafe {
        ashmem.write_to_ashmem(
            content.as_ptr(),
            TEST_ASHMEM_CONTENT.len() as i32,
            0,
        )
    });

    let mut target = MsgParcel::new();
    assert!(
        target.write_ashmem(ashmem).is_ok(),
        "write_ashmem should succeed for a valid ashmem instance",
    );

    let read_ashmem = target
        .read_ashmem()
        .expect("read_ashmem should succeed after a successful write_ashmem");
    assert_eq!(read_ashmem.get_ashmem_size(), TEST_ASHMEM_CONTENT.len() as i32);
    assert!(read_ashmem.map_read_only_ashmem());
    let read_ptr = unsafe { read_ashmem.read_from_ashmem(TEST_ASHMEM_CONTENT.len() as i32, 0) };
    assert!(!read_ptr.is_null());

    let read_back = unsafe { CStr::from_ptr(read_ptr) };
    assert_eq!(read_back.to_bytes(), TEST_ASHMEM_CONTENT);
}

/// UT test case for "ashmem_read_fails_without_ashmem_payload"
///
/// # brief
/// 1. Create an empty MsgParcel
/// 2. Read ashmem from MsgParcel without ashmem payload
/// 3. Check the return error code
#[test]
fn ashmem_read_fails_without_ashmem_payload() {
    let mut msg = MsgParcel::new();
    match msg.read_ashmem() {
        Err(err) => assert_eq!(err, IpcStatusCode::Failed),
        Ok(_) => panic!("read_ashmem unexpectedly succeeded"),
    }
}
