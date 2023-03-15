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

//! IPC calc server

extern crate example_calc_ipc_service;
extern crate ipc_rust;

use example_calc_ipc_service::{ICalc, CalcStub, EXAMPLE_IPC_CALC_SERVICE_ID, init_access_token, add, sub, mul, div};
use ipc_rust::{IRemoteBroker, join_work_thread, IpcResult, add_service,};

/// example.calc.ipc.ICalcService type
pub struct CalcService;

impl ICalc for CalcService {
    fn add(&self, num1: i32, num2: i32) -> IpcResult<i32> {
        Ok(add(&num1, &num2))
    }
    fn sub(&self, num1: i32, num2: i32) -> IpcResult<i32> {
        Ok(sub(&num1, &num2))
    }
    fn mul(&self, num1: i32, num2: i32) -> IpcResult<i32> {
        Ok(mul(&num1, &num2))
    }
    fn div(&self, num1: i32, num2: i32) -> IpcResult<i32> {
        Ok(div(&num1, &num2))
    }
}

impl IRemoteBroker for CalcService {}

fn main() {
    init_access_token();
    // create stub
    let service = CalcStub::new_remote_stub(CalcService).expect("create CalcService success");
    add_service(&service.as_object().expect("get ICalc service failed"),
        EXAMPLE_IPC_CALC_SERVICE_ID).expect("add server to samgr failed"); 
    println!("join to ipc work thread");
    join_work_thread();   
}