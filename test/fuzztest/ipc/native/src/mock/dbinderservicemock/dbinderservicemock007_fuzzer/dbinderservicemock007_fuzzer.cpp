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
#include <fuzzer/FuzzedDataProvider.h>

#include "dbinder_service.h"
#include "dbinder_service_stub.h"
#include "dbinder_remote_listener.h"
#include "dbinder_softbus_client.h"
#include "string_ex.h"

namespace OHOS {
const static size_t MAX_STRING_PARAM_LEN = 100;

void ProcessCallbackProxyTest(FuzzedDataProvider &provider)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        return;
    }
    int handle = provider.ConsumeIntegral<int>();
    std::string serviceName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::u16string serviceName16 = Str8ToStr16(serviceName);
    std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    binder_uintptr_t binderObject = provider.ConsumeIntegral<binder_uintptr_t>();
    sptr<IPCObjectProxy> object = new (std::nothrow) IPCObjectProxy(handle);
    sptr<DBinderServiceStub> dBinderServiceStub =
        sptr<DBinderServiceStub>::MakeSptr(serviceName16, deviceID, binderObject);
    if (object == nullptr || dBinderServiceStub == nullptr) {
        return;
    }
    dBinderService->AttachCallbackProxy(object, dBinderServiceStub.GetRefPtr());
    std::vector<sptr<DBinderServiceStub>> dbStubs {dBinderServiceStub};
    dBinderService->ProcessCallbackProxy(dbStubs);
    dBinderService->DetachCallbackProxy(object);
}

void NoticeServiceDieInnerTest(FuzzedDataProvider &provider)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        return;
    }
    std::string serviceName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::u16string serviceName16 = Str8ToStr16(serviceName);
    std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    dBinderService->NoticeServiceDieInner(serviceName16, deviceID);
}

void FindServicesByDeviceIDTest(FuzzedDataProvider &provider)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        return;
    }
    std::string serviceName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::u16string serviceName16 = Str8ToStr16(serviceName);
    std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    binder_uintptr_t binderObject = provider.ConsumeIntegral<binder_uintptr_t>();
    sptr<DBinderServiceStub> dBinderServiceStub = new (std::nothrow) DBinderServiceStub(serviceName16,
        deviceID, binderObject);
    if (dBinderServiceStub == nullptr) {
        return;
    }
    dBinderService->DBinderStubRegisted_.push_back(dBinderServiceStub);
    dBinderService->FindServicesByDeviceID(deviceID);
}

void NoticeDeviceDieTest(FuzzedDataProvider &provider)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    std::shared_ptr<DBinderRemoteListener> remoteListener = std::make_shared<DBinderRemoteListener>();
    if (dBinderService == nullptr || remoteListener == nullptr) {
        return;
    }

    std::string serviceName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::u16string serviceName16 = Str8ToStr16(serviceName);
    std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    binder_uintptr_t binderObject = provider.ConsumeIntegral<binder_uintptr_t>();
    sptr<DBinderServiceStub> dBinderServiceStub = new (std::nothrow) DBinderServiceStub(serviceName16,
        deviceID, binderObject);
    if (dBinderServiceStub == nullptr) {
        return;
    }
    dBinderService->DBinderStubRegisted_.push_back(dBinderServiceStub);
    remoteListener->clientSocketInfos_[deviceID] = socketId;
    dBinderService->remoteListener_ = remoteListener;
    dBinderService->NoticeDeviceDie(deviceID);
}

void MakeSessionByReplyMessageTest(FuzzedDataProvider &provider)
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
    dBinderService->AttachSessionObject(std::make_shared<struct SessionInfo>(), binderObjectPtr);
    auto replyMessage = std::make_shared<struct DHandleEntryTxRx>();
    if (replyMessage == nullptr) {
        return;
    }
    replyMessage->stub = stubTag;
    replyMessage->serviceNameLength = strlen(replyMessage->serviceName);
    replyMessage->dBinderCode = MESSAGE_AS_REPLY;
    replyMessage->seqNumber = provider.ConsumeIntegral<uint32_t>();
    replyMessage->stubIndex = provider.ConsumeIntegral<uint64_t>();

    dBinderService->MakeSessionByReplyMessage(replyMessage);

    replyMessage->serviceNameLength = MAX_STRING_PARAM_LEN + 1;
    dBinderService->MakeSessionByReplyMessage(replyMessage);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::ProcessCallbackProxyTest(provider);
    OHOS::FindServicesByDeviceIDTest(provider);
    OHOS::NoticeDeviceDieTest(provider);
    OHOS::MakeSessionByReplyMessageTest(provider);
    return 0;
}