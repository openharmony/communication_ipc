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

impl Serialize for &[u8] {
    fn serialize(&self, parcel: &mut BorrowedMsgParcel<'_>) -> Result<()> {
        // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
        let ret = unsafe {
            ipc_binding::CParcelWriteBuffer(
                parcel.as_mut_raw(), 
                self.as_ptr() as *const void,
                self.len().try_into().unwrap()  
            )
        };
        result_status::<()>(ret, ())
}

impl Deserialize for Vec<u8> {
    fn deserialize(parcel: &BorrowedMsgParcel<'_>) -> Result<Self> {
        let mut vec: Option<Vec<u8>> = None;
        let status = unsafe {
            // SAFETY: `parcel` always contains a valid pointer to a  `CParcel`
            ipc_binding::CParcelReadBuffer(
                parcel.as_raw(), 
                &mut vec as *mut _ as *mut c_void,
                allocate_vec_with_buffer::<u8>
            )
        };

        if status {
            vec.transpose()
        }else{
            Err(-1)
        }
    }
}