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

#![allow(missing_docs, unused)]
use std::io::{Read, Seek, SeekFrom, Write};

use ipc::parcel::{Deserialize, MsgOption, MsgParcel, Serialize};
use ipc::remote::{RemoteObj, RemoteStub};
use ipc::{IpcResult, Skeleton};

struct TestRemoteStub;

fn main() {
    use ipc::parcel::MsgParcel;
    
    let mut msg = MsgParcel::new();
    msg.write(&1i32).unwrap();
    msg.write(&2i32).unwrap();
    msg.skip_read(4);
    assert_eq!(2, msg.read().unwrap());
}
