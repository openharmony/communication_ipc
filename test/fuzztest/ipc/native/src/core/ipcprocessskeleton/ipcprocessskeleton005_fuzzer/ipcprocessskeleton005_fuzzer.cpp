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
void WakeUpDataThreadFuzzTest(FuzzedDataProvider &provider)
{
    std::thread::id threadId = std::this_thread::get_id();
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    current->AttachThreadLockInfo(std::make_shared<SocketThreadLockInfo>(), threadId);
    current->WakeUpDataThread(threadId);
}

void UIntToStringFuzzTest(FuzzedDataProvider &provider)
{
    OHOS::IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    uint32_t value = provider.ConsumeIntegral<uint32_t>();
    current->UIntToString(value);
}

void AttachOrUpdateAppAuthInfoFuzzTest(FuzzedDataProvider &provider)
{
    OHOS::IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    AppAuthInfo appAuthInfo;
    appAuthInfo.stubIndex = provider.ConsumeIntegral<uint64_t>();
    appAuthInfo.socketId = provider.ConsumeIntegral<int32_t>();
    appAuthInfo.pid = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.uid = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.tokenId = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.deviceId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    appAuthInfo.stub = nullptr;
    current->AttachOrUpdateAppAuthInfo(appAuthInfo);
    sptr<IPCObjectStub> stubObject = sptr<IPCObjectStub>::MakeSptr();
    if (stubObject == nullptr) {
        return;
    }
    appAuthInfo.stub = stubObject.GetRefPtr();
    current->AttachOrUpdateAppAuthInfo(appAuthInfo);
}

void DetachAppAuthInfoFuzzTest(FuzzedDataProvider &provider)
{
    OHOS::IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    AppAuthInfo appAuthInfo;
    appAuthInfo.stubIndex = provider.ConsumeIntegral<uint64_t>();
    appAuthInfo.socketId = provider.ConsumeIntegral<int32_t>();
    appAuthInfo.pid = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.uid = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.tokenId = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.deviceId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    sptr<IPCObjectStub> stubObject = sptr<IPCObjectStub>::MakeSptr();
    if (stubObject == nullptr) {
        return;
    }
    appAuthInfo.stub = stubObject.GetRefPtr();
    current->DetachAppAuthInfo(appAuthInfo);
    current->AttachOrUpdateAppAuthInfo(appAuthInfo);
    current->DetachAppAuthInfo(appAuthInfo);
}

void DetachAppAuthInfoBySocketIdFuzzTest(FuzzedDataProvider &provider)
{
    OHOS::IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    AppAuthInfo appAuthInfo;
    appAuthInfo.stubIndex = provider.ConsumeIntegral<uint64_t>();
    appAuthInfo.socketId = provider.ConsumeIntegral<int32_t>();
    appAuthInfo.pid = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.uid = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.tokenId = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.deviceId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    sptr<IPCObjectStub> stubObject = sptr<IPCObjectStub>::MakeSptr();
    if (stubObject == nullptr) {
        return;
    }
    appAuthInfo.stub = stubObject.GetRefPtr();
    current->AttachOrUpdateAppAuthInfo(appAuthInfo);
    current->DetachAppAuthInfoBySocketId(appAuthInfo.socketId);
}

void DetachAppAuthInfoByStubFuzzTest(FuzzedDataProvider &provider)
{
    OHOS::IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    AppAuthInfo appAuthInfo;
    appAuthInfo.stubIndex = provider.ConsumeIntegral<uint64_t>();
    appAuthInfo.socketId = provider.ConsumeIntegral<int32_t>();
    appAuthInfo.pid = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.uid = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.tokenId = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.deviceId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    sptr<IPCObjectStub> stubObject = sptr<IPCObjectStub>::MakeSptr();
    if (stubObject == nullptr) {
        return;
    }
    appAuthInfo.stub = stubObject.GetRefPtr();
    current->AttachOrUpdateAppAuthInfo(appAuthInfo);
    current->DetachAppAuthInfoByStub(stubObject.GetRefPtr(), appAuthInfo.stubIndex);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::WakeUpDataThreadFuzzTest(provider);
    OHOS::UIntToStringFuzzTest(provider);
    OHOS::AttachOrUpdateAppAuthInfoFuzzTest(provider);
    OHOS::DetachAppAuthInfoFuzzTest(provider);
    OHOS::DetachAppAuthInfoByStubFuzzTest(provider);
    return 0;
}
