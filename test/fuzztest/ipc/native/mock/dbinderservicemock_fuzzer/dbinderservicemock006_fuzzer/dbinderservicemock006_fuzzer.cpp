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

void IsValidSessionNameTest(FuzzedDataProvider &provider)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<DHandleEntryTxRx>();
    if (dBinderService == nullptr || replyMessage == nullptr) {
        return;
    }

    replyMessage->serviceNameLength = SERVICENAME_LENGTH;
    dBinderService->IsValidSessionName(replyMessage);
    replyMessage->serviceNameLength = SERVICENAME_LENGTH + 1;
    dBinderService->IsValidSessionName(replyMessage);
}

void WakeupThreadByStubTest(FuzzedDataProvider &provider)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        return;
    }
    std::string networkId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    uint32_t seqNumber = provider.ConsumeIntegral<uint32_t>();
    dBinderService->AttachThreadLockInfo(seqNumber, networkId, std::make_shared<ThreadLockInfo>());
    dBinderService->WakeupThreadByStub(seqNumber);
    dBinderService->DetachThreadLockInfo(seqNumber);
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

void QueryProxyObjectTest(FuzzedDataProvider &provider)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        return;
    }
    binder_uintptr_t binderObject = provider.ConsumeIntegral<binder_uintptr_t>();
    dBinderService->AttachProxyObject(nullptr, binderObject);
    dBinderService->QueryProxyObject(binderObject);
    dBinderService->DetachProxyObject(binderObject);
}

void AttachSessionObjectTest(FuzzedDataProvider &provider)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<SessionInfo>();
    if (dBinderService == nullptr || sessionInfo == nullptr) {
        return;
    }

    binder_uintptr_t stub = provider.ConsumeIntegral<binder_uintptr_t>();
    dBinderService->AttachSessionObject(sessionInfo, stub);
    dBinderService->DetachSessionObject(stub);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::IsValidSessionNameTest(provider);
    OHOS::WakeupThreadByStubTest(provider);
    OHOS::NoticeServiceDieInnerTest(provider);
    OHOS::QueryProxyObjectTest(provider);
    OHOS::AttachSessionObjectTest(provider);
    return 0;
}