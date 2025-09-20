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
void SpawnThreadFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int policy = parcel.ReadInt32();
    int proto = parcel.ReadInt32();
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(ipcSktPtr->threadPool_->mutex_);
        if (ipcSktPtr->threadPool_->threads_.size() >= IPCProcessSkeleton::DEFAULT_WORK_THREAD_NUM) {
            return;
        }
    }
    (void)ipcSktPtr->SpawnThread(policy, proto);
}

void FindOrNewObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int handle = parcel.ReadInt32();
    const dbinder_negotiation_data *dbinderData = nullptr;
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->FindOrNewObject(handle, dbinderData);
}

void IsContainsObjectFuzzTest(const uint8_t *data, size_t size)
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
    (void)ipcSktPtr->IsContainsObject(object);
}

void QueryObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    bool lockFlag = parcel.ReadBool();
    const char16_t *charData = reinterpret_cast<const char16_t *>(data);
    size_t charCount = size / sizeof(char16_t);
    std::u16string descriptor(charData, charCount);
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->QueryObject(descriptor, lockFlag);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::SpawnThreadFuzzTest(data, size);
    OHOS::FindOrNewObjectFuzzTest(data, size);
    OHOS::IsContainsObjectFuzzTest(data, size);
    OHOS::QueryObjectFuzzTest(data, size);
    return 0;
}
