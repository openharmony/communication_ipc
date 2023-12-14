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

//! This create implement the IPC proxy and stub for "example.calc.ipc.ICalcService"

extern crate ipc_rust;

mod access_token;

use ipc_rust::{
    IRemoteBroker, IRemoteObj, RemoteStub, IpcResult,
    IpcStatusCode, RemoteObj, define_remote_object, FIRST_CALL_TRANSACTION,
};
use ipc_rust::{
    MsgParcel, BorrowedMsgParcel,
};
use std::convert::{TryFrom, TryInto};
pub use access_token::init_access_token;

/// add num1 + num2
pub fn add(num1: &i32, num2: &i32) -> i32 {
    num1 + num2
}

/// sub num1 + num2
pub fn sub(num1: &i32, num2: &i32) -> i32 {
    num1 - num2
}

/// mul num1 + num2
pub fn mul(num1: &i32, num2: &i32) -> i32 {
    num1 * num2
}

/// div num1 + num2
pub fn div(num1: &i32, num2: &i32) -> i32 {
    match num2 {
        0 => {
            println!("Zero cannot be divided");
            -1
        },
        _ => num1 / num2,
    }
}

/// SA ID for "example.calc.ipc.ICalcService"
pub const EXAMPLE_IPC_CALC_SERVICE_ID: i32 = 1118;

/// Function code of ICalcService
pub enum ICalcCode {
    /// add
    CodeAdd = FIRST_CALL_TRANSACTION,
    /// sub
    CodeSub,
    /// mul
    CodeMul,
    /// div
    CodeDiv,
}

impl TryFrom<u32> for ICalcCode {
    type Error = IpcStatusCode;
    fn try_from(code: u32) -> IpcResult<Self> {
        match code {
            _ if code == ICalcCode::CodeAdd as u32 => Ok(ICalcCode::CodeAdd),
            _ if code == ICalcCode::CodeSub as u32 => Ok(ICalcCode::CodeSub),
            _ if code == ICalcCode::CodeMul as u32 => Ok(ICalcCode::CodeMul),
            _ if code == ICalcCode::CodeDiv as u32 => Ok(ICalcCode::CodeDiv),
            _ => Err(IpcStatusCode::Failed),
        }
    }
}

/// Function between proxy and stub of ICalcService
pub trait ICalc: IRemoteBroker {
    /// Calc add num1 + num2
    fn add(&self, num1: i32, num2: i32) -> IpcResult<i32>;
    /// Calc sub num1 + num2
    fn sub(&self, num1: i32, num2: i32) -> IpcResult<i32>;
    /// Calc mul num1 + num2
    fn mul(&self, num1: i32, num2: i32) -> IpcResult<i32>;
    /// Calc div num1 + num2
    fn div(&self, num1: i32, num2: i32) -> IpcResult<i32>;
}

fn on_icalc_remote_request(stub: &dyn ICalc, code: u32, data: &BorrowedMsgParcel,
    reply: &mut BorrowedMsgParcel) -> IpcResult<()> {
    match code.try_into()? {
        ICalcCode::CodeAdd => {
            let num1: i32 = data.read().expect("Failed to read num1 in addition operation");
            let num2: i32 = data.read().expect("Failed to read num2 in addition operation");
            let ret = stub.add(num1, num2)?;
            reply.write(&ret)?;
            Ok(())
        }
        ICalcCode::CodeSub => {
            let num1: i32 = data.read().expect("Failed to read num1 in subtraction operation");
            let num2: i32 = data.read().expect("Failed to read num1 in subtraction operation");
            let ret = stub.sub(num1, num2)?;
            reply.write(&ret)?;
            Ok(())
        }
        ICalcCode::CodeMul => {
            let num1: i32 = data.read().expect("Failed to read num1 in multiplication operation");
            let num2: i32 = data.read().expect("Failed to read num1 in multiplication operation");
            let ret = stub.mul(num1, num2)?;
            reply.write(&ret)?;
            Ok(())
        }
        ICalcCode::CodeDiv => {
            let num1: i32 = data.read().expect("Failed to read num1 in division  operation");
            let num2: i32 = data.read().expect("Failed to read num1 in division  operation");
            let ret = stub.div(num1, num2)?;
            reply.write(&ret)?;
            Ok(())
        }
    }
}

define_remote_object!(
    ICalc["example.calc.ipc.ICalcService"] {
        stub: CalcStub(on_icalc_remote_request),
        proxy: CalcProxy,
    }
);

// Make RemoteStub<CalcStub> object can call ICalc function directly.
impl ICalc for RemoteStub<CalcStub> {
    fn add (&self, num1: i32, num2: i32) -> IpcResult<i32> {
        self.0.add(num1, num2)
    }
    fn sub (&self, num1: i32, num2: i32) -> IpcResult<i32> {
        self.0.sub(num1, num2)
    }
    fn mul (&self, num1: i32, num2: i32) -> IpcResult<i32> {
        self.0.mul(num1, num2)
    }
    fn div (&self, num1: i32, num2: i32) -> IpcResult<i32> {
        self.0.div(num1, num2)
    }
}

impl ICalc for CalcProxy {
    fn add(&self, num1: i32, num2: i32) -> IpcResult<i32> {
        let mut data = MsgParcel::new().expect("MsgParcel should success");
        data.write(&num1)?;
        data.write(&num2)?;
        let reply = self.remote.send_request(ICalcCode::CodeAdd as u32,
            &data, false)?;
        let ret: i32 = reply.read().expect("need reply i32");
        Ok(ret)
    }
    fn sub(&self, num1: i32, num2: i32) -> IpcResult<i32> {
        let mut data = MsgParcel::new().expect("MsgParcel should success");
        data.write(&num1)?;
        data.write(&num2)?;
        let reply = self.remote.send_request(ICalcCode::CodeSub as u32,
            &data, false)?;
        let ret: i32 = reply.read().expect("need reply i32");
        Ok(ret)
    }
    fn mul(&self, num1: i32, num2: i32) -> IpcResult<i32> {
        let mut data = MsgParcel::new().expect("MsgParcel should success");
        data.write(&num1)?;
        data.write(&num2)?;
        let reply = self.remote.send_request(ICalcCode::CodeMul as u32,
            &data, false)?;
        let ret: i32 = reply.read().expect("need reply i32");
        Ok(ret)
    }
    fn div(&self, num1: i32, num2: i32) -> IpcResult<i32> {
        let mut data = MsgParcel::new().expect("MsgParcel should success");
        data.write(&num1)?;
        data.write(&num2)?;
        let reply = self.remote.send_request(ICalcCode::CodeDiv as u32,
            &data, false)?;
        let ret: i32 = reply.read().expect("need reply i32");
        Ok(ret)
    }
}