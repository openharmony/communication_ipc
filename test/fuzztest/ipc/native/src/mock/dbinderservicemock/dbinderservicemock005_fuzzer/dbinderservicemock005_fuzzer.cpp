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

#include "dbinderservicemock_fuzzer.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <condition_variable>
#include <fuzzer/FuzzedDataProvider.h>

#include "dbinder_service.h"
#include "dbinder_service_stub.h"
#include "dbinder_remote_listener.h"
#include "dbinder_softbus_client.h"
#include "string_ex.h"

namespace OHOS {
const static size_t MAX_STRING_PARAM_LEN = 100;

void RegisterRemoteProxyTest(FuzzedDataProvider &provider)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        return;
    }
    std::string name = provider.ConsumeRandomLengthString(SERVICENAME_LENGTH);
    const std::u16string serviceName = Str8ToStr16(name);

    int handle = provider.ConsumeIntegral<int>();
    sptr<IRemoteObject> binderObject = new (std::nothrow) IPCObjectProxy(handle);
    if (binderObject == nullptr) {
        return;
    }
    dBinderService->RegisterRemoteProxy(serviceName, binderObject);

    binder_uintptr_t binder = (binder_uintptr_t)binderObject.GetRefPtr();
    dBinderService->GetRegisterService(binder);
}
void InvokerRemoteDBinderWhenWaitRspTest(FuzzedDataProvider &provider)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        return;
    }

    uint32_t pid = provider.ConsumeIntegral<uint32_t>();
    uint32_t uid = provider.ConsumeIntegral<uint32_t>();
    uint64_t num = provider.ConsumeIntegral<uint64_t>();
    uint32_t seqNumber = provider.ConsumeIntegral<uint32_t>();
    const std::u16string serviceName = Str8ToStr16(std::to_string(num));
    const std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
    sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
    if (stub == nullptr) {
        return;
    }
    std::shared_ptr<struct ThreadLockInfo> threadLockInfo = std::make_shared<struct ThreadLockInfo>();
    stub->SetNegoStatusAndTime(NegotiationStatus::NEGO_INIT, 1);
    dBinderService->InvokerRemoteDBinderWhenWaitRsp(stub, seqNumber, pid, uid, threadLockInfo);

    if (threadLockInfo == nullptr) {
        return;
    }
    dBinderService->AttachThreadLockInfo(seqNumber, deviceID, threadLockInfo);
    dBinderService->InvokerRemoteDBinderWhenWaitRsp(stub, seqNumber, pid, uid, threadLockInfo);
}

void OnRemoteMessageTaskTest(FuzzedDataProvider &provider)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        return;
    }
    dBinderService->OnRemoteMessageTask(nullptr);
    std::shared_ptr<struct DHandleEntryTxRx> message = std::make_shared<DHandleEntryTxRx>();
    if (message == nullptr) {
        return;
    }
    message->seqNumber = provider.ConsumeIntegral<uint32_t>();
    message->dBinderCode = DBinderCode::MESSAGE_AS_REMOTE_ERROR;
    dBinderService->OnRemoteMessageTask(message);
}

void ProcessOnSessionClosedTest(FuzzedDataProvider &provider)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        return;
    }
    std::string networkId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::string otherNetworkId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    uint32_t seqNumber = provider.ConsumeIntegral<uint32_t>();
    uint32_t otherSeqNumber = provider.ConsumeIntegral<uint32_t>();
    dBinderService->AttachThreadLockInfo(seqNumber, networkId, std::make_shared<ThreadLockInfo>());
    dBinderService->AttachThreadLockInfo(otherSeqNumber, otherNetworkId, std::make_shared<ThreadLockInfo>());

    dBinderService->ProcessOnSessionClosed(networkId);
    dBinderService->DetachThreadLockInfo(seqNumber);
    dBinderService->DetachThreadLockInfo(otherSeqNumber);
}

void IsInvalidStubTest(FuzzedDataProvider &provider)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        return;
    }
    const std::string serviceName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    const std::u16string serviceName16 = Str8ToStr16(serviceName);
    const std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    binder_uintptr_t binderObject = provider.ConsumeIntegral<binder_uintptr_t>();
    sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName16, deviceID, binderObject);
    if (stub == nullptr) {
        return;
    }
    binder_uintptr_t binderObjectPtr = reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr());
    binder_uintptr_t stubTag = dBinderService->stubTagNum_++;
    auto result = dBinderService->mapDBinderStubRegisters_.insert({stubTag, binderObjectPtr});
    if (!result.second) {
        return;
    }
    dBinderService->DBinderStubRegisted_.push_back(stub);
    auto replyMessage = std::make_shared<struct DHandleEntryTxRx>();
    if (replyMessage == nullptr) {
        return;
    }
    replyMessage->stub = stubTag;

    dBinderService->IsInvalidStub(replyMessage);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::RegisterRemoteProxyTest(provider);
    OHOS::InvokerRemoteDBinderWhenWaitRspTest(provider);
    OHOS::OnRemoteMessageTaskTest(provider);
    OHOS::ProcessOnSessionClosedTest(provider);
    OHOS::IsInvalidStubTest(provider);
    return 0;
}