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

use crate::{
    ipc_binding, MsgParcel, RemoteObj, IRemoteObj, InterfaceToken, String16,
    Result,
};

fn get_samgr() -> Option<RemoteObj>
{
    unsafe {
        let samgr = ipc_binding::GetContextManager();
        RemoteObj::from_raw(samgr)
    }
}

pub fn add_service(service: &RemoteObj, said: i32) -> Result<()>
{
    let samgr = get_samgr().expect("samgr is not null");
    let mut data = MsgParcel::new().expect("MsgParcel is not null");
    let _ = data.write(&InterfaceToken::new("ohos.samgr.accessToken"))?;
    let _ = data.write(&said)?;
    let _ = data.write(service)?;
    let _ = data.write(&false)?;
    let _ = data.write(&0)?;
    let _ = data.write(&String16::new(""))?;
    let _ = data.write(&String16::new(""))?;
    let reply = samgr.send_request(3, &data, false)?;
    let replyValue: i32 = reply.read()?;
    println!("register service result: {}", replyValue);
    if replyValue == 0 { Ok(())} else { Err(replyValue) }
}

pub fn get_service(said: i32) -> Result<RemoteObj>
{
    let samgr = get_samgr().expect("samgr is not null");
    let mut data = MsgParcel::new().expect("MsgParcel is not null");
    let _ = data.write(&InterfaceToken::new("ohos.samgr.accessToken"))?;
    let _ = data.write(&said)?;
    let reply = samgr.send_request(2, &data, false)?;
    let remote: RemoteObj = reply.read()?;
    println!("get service success");
    Ok(remote)
}

pub fn join_work_thread()
{
    unsafe {
        ipc_binding::JoinWorkThread();
    }
}

pub fn stop_work_thread()
{
    unsafe {
        ipc_binding::StopWorkThread()
    }
}

pub fn init_access_token()
{
    unsafe {
        ipc_binding::InitTokenId();
    }
}

pub fn get_calling_token_id() -> u64
{
    unsafe {
        ipc_binding::GetCallingTokenId()
    }
}

pub fn get_first_token_id() -> u64
{
    unsafe {
        ipc_binding::GetFirstToekenId()
    }
}

pub fn get_self_token_id() -> u64
{
    unsafe {
        ipc_binding::GetSelfToekenId()
    }
}

pub fn get_calling_pid() -> u64
{
    unsafe {
        ipc_binding::GetCallingPid()
    }
}

pub fn get_calling_uid() -> u64
{
    unsafe {
        ipc_binding::GetCallingUid()
    }
}