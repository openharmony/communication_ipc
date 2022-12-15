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

use crate::{ipc_binding, MsgParcel, RemoteObj, IRemoteObj, InterFaceToken, String16};

fn get_samgr() -> Option<RemoteObj>
{
    unsafe {
        let samgr = ipc_binding::GetContextManager();
        RemoteObj::from_raw(samgr)
    }
}

pub fn add_service(service: &RemoteObj, said: i32)
{
    let samgr = get_samgr().expect("samgr is not null");
    let mut data = MsgParcel::new().expect("MsgParcel is not null");
    match data.write(&InterFaceToken::new("ohos.samgr.accessToken")) {
        Ok(()) => { println!("write token success") }
        Err(val) => { println!("write token fail: {}", val) }
    }
    match data.write(&said) {
        Ok(()) => { println!("write said success") }
        Err(val) => { println!("write said fail: {}", val) }
    }
    match data.write(service) {
        Ok(()) => { println!("write service success") }
        Err(val) => { println!("write service fail: {}", val) }
    }
    match data.write(&false) {
        Ok(()) => { println!("write bool success") }
        Err(val) => { println!("write bool fail: {}", val) }
    }
    match data.write(&0) {
        Ok(()) => { println!("write 0 success") }
        Err(val) => { println!("write 0 fail: {}", val) }
    }
    match data.write(&String16::new("")) {
        Ok(()) => { println!("write string16 111 success") }
        Err(val) => { println!("write string16 111 fail: {}", val) }
    }
    match data.write(&String16::new("")) {
        Ok(()) => { println!("write string16 222 success") }
        Err(val) => { println!("write string16 222 fail: {}", val) }
    }
    let reply = samgr.send_request(3, &data, false).expect("failed to register service");
    let replyValue: i32 = reply.read().expect("register service reply should 0");
    println!("register service result: {}", replyValue);
}

pub fn get_service(said: i32) -> RemoteObj
{
    let samgr = get_samgr().expect("samgr is not null");
    let mut data = MsgParcel::new().expect("MsgParcel is not null");
    match data.write(&InterFaceToken::new("ohos.samgr.accessToken")) {
        Ok(()) => { println!("write token success") }
        Err(val) => { println!("write token fail: {}", val) }
    }
    match data.write(&said) {
        Ok(()) => { println!("write said success") }
        Err(val) => { println!("write said fail: {}", val) }
    }
    let reply = samgr.send_request(2, &data, false).expect("Failed to get service");
    let remote: RemoteObj = reply.read().expect("Failed to read remote object");
    println!("register service result");
    return remote;
}

pub fn join_work_thread()
{
    unsafe { ipc_binding::JoinWorkThread(); }
}

pub fn init_access_token()
{
    unsafe {
        ipc_binding::InitTokenId();
    }
}
