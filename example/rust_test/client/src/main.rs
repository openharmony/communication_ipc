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

extern crate ipc_rust;
extern crate example_calc_ipc_service;

use ipc_rust::{FromRemoteObj, RemoteObjRef, get_service,};
use example_calc_ipc_service::{ICalc, EXAMPLE_IPC_CALC_SERVICE_ID};

fn get_calc_service() -> RemoteObjRef<dyn ICalc>
{
    let object = get_service(EXAMPLE_IPC_CALC_SERVICE_ID).expect("get icalc service failed");
    let remote = <dyn ICalc as FromRemoteObj>::try_from(object);
    let remote = match remote {
        Ok(x) => x,
        Err(error) => {
            println!("convert RemoteObj to CalcProxy failed: {}", error);
            panic!();
        }
    };
    remote
}

#[test]
fn calculator_ability() {
    let remote = get_calc_service();
    // add
    let ret = remote.add(5, 5).expect("add failed");
    assert_eq!(ret, 10);
    // sub
    let ret = remote.sub(5, 5).expect("sub failed");
    assert_eq!(ret, 0);
    // mul
    let ret = remote.mul(5, 5).expect("mul failed");
    assert_eq!(ret, 25);
    // div
    let ret = remote.div(5, 5).expect("div failed");
    assert_eq!(ret, 1);
}
