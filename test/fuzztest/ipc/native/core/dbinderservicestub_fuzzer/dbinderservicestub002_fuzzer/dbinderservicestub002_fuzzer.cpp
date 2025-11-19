/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dbinderservicestub_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include "dbinder_service.h"
#include "dbinder_service_stub.h"
#include "ipc_skeleton.h"
#include "string_ex.h"

namespace OHOS {
static constexpr uint32_t DBINDER_HANDLE_BASE = 100000 * 6872;
static constexpr uint32_t INVALID_HANDLE_VALUE = 0xFFFFFFFF;
static constexpr uint32_t MAX_STRING_LEN = 100;

void AddDbinderDeathRecipientTwoTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    const std::string device = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);

    std::string descriptor = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    uint32_t handle = provider.ConsumeIntegralInRange<uint32_t>(DBINDER_HANDLE_BASE, INVALID_HANDLE_VALUE);
    sptr<IPCObjectProxy> callbackProxy = new (std::nothrow) IPCObjectProxy(handle, Str8ToStr16(descriptor));
    if (callbackProxy == nullptr) {
        return;
    }

    MessageParcel data;
    data.WriteRemoteObject(callbackProxy);
    dBinderServiceStub.AddDbinderDeathRecipient(data);
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        return;
    }
    dBinderServiceStub.AddDbinderDeathRecipient(data);
    dBinderService->DetachDeathRecipient(callbackProxy);
    dBinderServiceStub.AddDbinderDeathRecipient(data);
}

void RemoveDbinderDeathRecipientOneTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    const std::string device = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);

    MessageParcel data;
    dBinderServiceStub.RemoveDbinderDeathRecipient(data);

    std::string descriptor = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    uint32_t handle = provider.ConsumeIntegralInRange<uint32_t>(DBINDER_HANDLE_BASE, INVALID_HANDLE_VALUE);
    sptr<IPCObjectProxy> callbackProxy = new (std::nothrow) IPCObjectProxy(handle, Str8ToStr16(descriptor));
    if (callbackProxy == nullptr) {
        return;
    }

    MessageParcel dataOne;
    dataOne.WriteRemoteObject(callbackProxy);
    dBinderServiceStub.AddDbinderDeathRecipient(dataOne);
    dBinderServiceStub.RemoveDbinderDeathRecipient(dataOne);
    dBinderServiceStub.RemoveDbinderDeathRecipient(dataOne);
}

void RemoveDbinderDeathRecipientTwoTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    const std::string device = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);

    std::string descriptor = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    uint32_t handle = provider.ConsumeIntegralInRange<uint32_t>(DBINDER_HANDLE_BASE, INVALID_HANDLE_VALUE);
    sptr<IPCObjectProxy> callbackProxy = new (std::nothrow) IPCObjectProxy(handle, Str8ToStr16(descriptor));
    if (callbackProxy == nullptr) {
        return;
    }

    MessageParcel data;
    data.WriteRemoteObject(callbackProxy);
    dBinderServiceStub.AddDbinderDeathRecipient(data);
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        return;
    }
    dBinderService->DetachCallbackProxy(callbackProxy);
    dBinderServiceStub.RemoveDbinderDeathRecipient(data);
}

void MarshallingOneTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    const std::string device = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    sptr<IRemoteObject> stubObject = new (std::nothrow) DBinderServiceStub(Str8ToStr16(service), device, object);
    if (stubObject == nullptr) {
        return;
    }
    Parcel parcel;
    DBinderServiceStub::Marshalling(parcel, stubObject);
}

void GetAndSaveDBinderDataTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    const std::string device = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);

    pid_t pid = provider.ConsumeIntegral<pid_t>();
    uid_t uid = provider.ConsumeIntegral<pid_t>();
    dBinderServiceStub.GetAndSaveDBinderData(pid, uid);

    uid = IPCSkeleton::GetCallingUid();
    pid = IPCSkeleton::GetCallingPid();
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        return;
    }
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    if (sessionInfo == nullptr) {
        return;
    }
    binder_uintptr_t key = reinterpret_cast<binder_uintptr_t>(&dBinderServiceStub);
    dBinderService->AttachSessionObject(sessionInfo, key);
    sessionInfo->type = provider.ConsumeIntegral<int32_t>();
    dBinderServiceStub.GetAndSaveDBinderData(pid, uid);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::AddDbinderDeathRecipientTwoTest(provider);
    OHOS::RemoveDbinderDeathRecipientOneTest(provider);
    OHOS::RemoveDbinderDeathRecipientTwoTest(provider);
    OHOS::MarshallingOneTest(provider);
    OHOS::GetAndSaveDBinderDataTest(provider);
    return 0;
}
