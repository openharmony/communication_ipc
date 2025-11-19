/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "ipcprocessskeleton_fuzzer.h"
#include "ipc_process_skeleton.h"
#include "fuzz_data_generator.h"
#include "message_parcel.h"
#include "string_ex.h"

namespace OHOS {
void AttachObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    bool lockFlag = parcel.ReadBool();
    sptr<IRemoteObject> object = parcel.ReadRemoteObject();
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->AttachObject(object, lockFlag);
}

void DetachObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    sptr<IRemoteObject> object = parcel.ReadRemoteObject();
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->DetachObject(object);
}

void GetProxyObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int handle = parcel.ReadInt32();
    bool newFlag = parcel.ReadBool();
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->GetProxyObject(handle, newFlag);
}

void SetRegistryObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    sptr<IRemoteObject> object = parcel.ReadRemoteObject();
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    ipcSktPtr->SetRegistryObject(object);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::AttachObjectFuzzTest(data, size);
    OHOS::DetachObjectFuzzTest(data, size);
    OHOS::GetProxyObjectFuzzTest(data, size);
    OHOS::SetRegistryObjectFuzzTest(data, size);
    return 0;
}
