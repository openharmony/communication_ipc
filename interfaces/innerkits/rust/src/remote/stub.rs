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

use std::fs::File;
use std::sync::Arc;

use crate::parcel::MsgParcel;
use crate::IpcResult;

/// Impl this trait to build a remote stub, that can be published to
/// SystemAbilityManager and handle remote requests.
pub trait RemoteStub {
    /// core method for RemoteStub, that handle remote request.
    fn on_remote_request(&self, code: u32, data: &mut MsgParcel, reply: &mut MsgParcel) -> i32;

    /// Dump the contents.
    fn dump(&self, _file: File, _args: Vec<String>) -> i32 {
        0
    }

    // RemoteStub Descriptor
    fn descriptor(&self) -> &'static str {
        ""
    }
}

impl<R: RemoteStub> RemoteStub for Arc<R> {
    fn on_remote_request(&self, code: u32, data: &mut MsgParcel, reply: &mut MsgParcel) -> i32 {
        R::on_remote_request(self, code, data, reply)
    }

    fn dump(&self, file: File, args: Vec<String>) -> i32 {
        R::dump(self, file, args)
    }
    fn descriptor(&self) -> &'static str {
        R::descriptor(self)
    }
}

#[cfg(test)]
mod test {
    use std::fs::{self, OpenOptions};
    use std::os::fd::AsRawFd;

    use super::*;
    use crate::remote::RemoteObj;

    const TEST_NUM: i32 = 2024;
    struct TestStub;
    impl RemoteStub for TestStub {
        fn on_remote_request(&self, code: u32, data: &mut MsgParcel, reply: &mut MsgParcel) -> i32 {
            0
        }
        fn dump(&self, _file: File, _args: Vec<String>) -> i32 {
            TEST_NUM
        }
        fn descriptor(&self) -> &'static str {
            "TEST STUB"
        }
    }

    #[test]
    fn remote_stub() {
        let remote = RemoteObj::from_stub(TestStub).unwrap();
        assert_eq!("TEST STUB", remote.interface_descriptor().unwrap());
        let file = File::create("ipc_rust_test_temp").unwrap();
        assert_eq!(TEST_NUM, remote.dump(file.as_raw_fd(), &[]));
        fs::remove_file("ipc_rust_test_temp").unwrap();
    }
}
