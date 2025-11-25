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
void IsHandleMadeByUserFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    uint32_t handle = parcel.ReadUint32();
    IPCProcessSkeleton::IsHandleMadeByUser(handle);
}

void SetIPCProxyLimitFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int ipcProxyLimitNum = parcel.ReadInt32();
    std::function<void(uint64_t num)> callback;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    current->SetIPCProxyLimit(ipcProxyLimitNum, callback);
}

void SetMaxWorkThreadFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int maxThreadNum = parcel.ReadInt32();
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->SetMaxWorkThread(maxThreadNum);
}

void MakeHandleDescriptorFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int handle = parcel.ReadInt32();
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->MakeHandleDescriptor(handle);
}

void OnThreadTerminatedFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    std::string threadName(reinterpret_cast<const char *>(data), size);
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->OnThreadTerminated(threadName);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::IsHandleMadeByUserFuzzTest(data, size);
    OHOS::SetIPCProxyLimitFuzzTest(data, size);
    OHOS::SetMaxWorkThreadFuzzTest(data, size);
    OHOS::MakeHandleDescriptorFuzzTest(data, size);
    OHOS::OnThreadTerminatedFuzzTest(data, size);
    return 0;
}
