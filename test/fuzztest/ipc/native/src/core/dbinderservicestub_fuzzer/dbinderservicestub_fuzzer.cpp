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

void OnRemoteRequestTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString();
    const std::string device = provider.ConsumeRandomLengthString();
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t code = provider.ConsumeIntegralInRange<int32_t>(FIRST_CALL_TRANSACTION, LAST_CALL_TRANSACTION);
    dBinderServiceStub.OnRemoteRequest(code, data, reply, option);
}

void ProcessProtoOneTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString();
    const std::string device = provider.ConsumeRandomLengthString();
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);
    binder_uintptr_t key = provider.ConsumeIntegral<uint64_t>();
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        return;
    }
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    if (sessionInfo == nullptr) {
        return;
    }
    dBinderService->AttachSessionObject(sessionInfo, key);
    uint32_t code = provider.ConsumeIntegralInRange<int32_t>(FIRST_CALL_TRANSACTION, LAST_CALL_TRANSACTION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    dBinderServiceStub.ProcessProto(code, data, reply, option);
}

void ProcessProtoTwoTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString();
    const std::string device = provider.ConsumeRandomLengthString();
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);
    binder_uintptr_t key = reinterpret_cast<binder_uintptr_t>(&dBinderServiceStub);
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        return;
    }
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    if (sessionInfo == nullptr) {
        return;
    }
    sessionInfo->type = provider.ConsumeIntegral<int32_t>();
    dBinderService->AttachSessionObject(sessionInfo, key);
    uint32_t code = provider.ConsumeIntegralInRange<int32_t>(FIRST_CALL_TRANSACTION, LAST_CALL_TRANSACTION);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    dBinderServiceStub.ProcessProto(code, data, reply, option);
}

void ProcessDeathRecipientTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString();
    const std::string device = provider.ConsumeRandomLengthString();
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t processType = provider.ConsumeIntegral<int32_t>();
    data.WriteInt32(processType);
    dBinderServiceStub.ProcessDeathRecipient(data);
}

void AddDbinderDeathRecipientOneTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString();
    const std::string device = provider.ConsumeRandomLengthString();
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);

    MessageParcel data;
    dBinderServiceStub.AddDbinderDeathRecipient(data);

    std::string descriptor = provider.ConsumeRandomLengthString();
    uint32_t handle = provider.ConsumeIntegralInRange<uint32_t>(0, DBINDER_HANDLE_BASE);
    sptr<IPCObjectProxy> callbackProxy = new (std::nothrow) IPCObjectProxy(handle, Str8ToStr16(descriptor));
    if (callbackProxy == nullptr) {
        return;
    }
    callbackProxy->SetObjectDied(true);
    MessageParcel dataOne;
    dataOne.WriteRemoteObject(callbackProxy);
    dBinderServiceStub.AddDbinderDeathRecipient(dataOne);
}

void AddDbinderDeathRecipientTwoTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString();
    const std::string device = provider.ConsumeRandomLengthString();
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);

    std::string descriptor = provider.ConsumeRandomLengthString();
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
    const std::string service = provider.ConsumeRandomLengthString();
    const std::string device = provider.ConsumeRandomLengthString();
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);

    MessageParcel data;
    dBinderServiceStub.RemoveDbinderDeathRecipient(data);

    std::string descriptor = provider.ConsumeRandomLengthString();
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
    const std::string service = provider.ConsumeRandomLengthString();
    const std::string device = provider.ConsumeRandomLengthString();
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);

    std::string descriptor = provider.ConsumeRandomLengthString();
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
    const std::string service = provider.ConsumeRandomLengthString();
    const std::string device = provider.ConsumeRandomLengthString();
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
    const std::string service = provider.ConsumeRandomLengthString();
    const std::string device = provider.ConsumeRandomLengthString();
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

void SaveDBinderDataTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString();
    const std::string device = provider.ConsumeRandomLengthString();
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);

    std::string localBusName = provider.ConsumeRandomLengthString();
    dBinderServiceStub.SaveDBinderData(localBusName);

    binder_uintptr_t key = reinterpret_cast<binder_uintptr_t>(&dBinderServiceStub);
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        return;
    }
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    if (sessionInfo == nullptr) {
        return;
    }
    dBinderService->AttachSessionObject(sessionInfo, key);
    dBinderServiceStub.SaveDBinderData(localBusName);
}

void GetServiceNameTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString();
    const std::string device = provider.ConsumeRandomLengthString();
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);

    dBinderServiceStub.GetServiceName();
}

void GetDeviceIDTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString();
    const std::string device = provider.ConsumeRandomLengthString();
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);

    dBinderServiceStub.GetDeviceID();
}

void GetBinderObjectTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString();
    const std::string device = provider.ConsumeRandomLengthString();
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);

    dBinderServiceStub.GetBinderObject();
}

void GetPeerPidTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString();
    const std::string device = provider.ConsumeRandomLengthString();
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);

    dBinderServiceStub.GetPeerPid();
}

void GetPeerUidTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString();
    const std::string device = provider.ConsumeRandomLengthString();
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);

    dBinderServiceStub.GetPeerUid();
}

void SetOrGetSeqNumberTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString();
    const std::string device = provider.ConsumeRandomLengthString();
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);
    uint32_t seqNum = provider.ConsumeIntegral<uint32_t>();
    dBinderServiceStub.SetSeqNumber(seqNum);
    dBinderServiceStub.GetSeqNumber();
}

void SetOrGetNegoStatusAndTimeTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString();
    const std::string device = provider.ConsumeRandomLengthString();
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);
    NegotiationStatus status = static_cast<NegotiationStatus>(provider.ConsumeIntegral<uint32_t>());
    uint64_t time = provider.ConsumeIntegral<uint64_t>();

    dBinderServiceStub.SetNegoStatusAndTime(status, time);
    dBinderServiceStub.GetNegoStatusAndTime(status, time);
}

}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::OnRemoteRequestTest(provider);
    OHOS::ProcessProtoOneTest(provider);
    OHOS::ProcessProtoTwoTest(provider);
    OHOS::ProcessDeathRecipientTest(provider);
    OHOS::AddDbinderDeathRecipientOneTest(provider);
    OHOS::AddDbinderDeathRecipientTwoTest(provider);
    OHOS::RemoveDbinderDeathRecipientOneTest(provider);
    OHOS::RemoveDbinderDeathRecipientTwoTest(provider);
    OHOS::MarshallingOneTest(provider);
    OHOS::GetAndSaveDBinderDataTest(provider);
    OHOS::SaveDBinderDataTest(provider);
    OHOS::GetServiceNameTest(provider);
    OHOS::GetDeviceIDTest(provider);
    OHOS::GetBinderObjectTest(provider);
    OHOS::GetPeerPidTest(provider);
    OHOS::GetPeerUidTest(provider);
    OHOS::SetOrGetSeqNumberTest(provider);
    OHOS::SetOrGetNegoStatusAndTimeTest(provider);
    return 0;
}
