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

#include "dbinderservice_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include "dbinder_service.h"
#include "dbinder_service_stub.h"
#include "string_ex.h"

namespace OHOS {

    void InitializeSessionTest(FuzzedDataProvider &provider)
    {
        std::shared_ptr<struct SessionInfo> session = std::make_shared<struct SessionInfo>();
        std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<struct DHandleEntryTxRx>();
        if (session == nullptr || replyMessage == nullptr) {
            return;
        }
        session->type = provider.ConsumeIntegral<uint32_t>();
        replyMessage->transType = provider.ConsumeIntegral<uint32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.InitializeSession(session, replyMessage);
    }

    void MakeSessionByReplyMessageTest(FuzzedDataProvider &provider)
    {
        std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<struct DHandleEntryTxRx>();
        if (replyMessage == nullptr) {
            return;
        }
        replyMessage->transType = provider.ConsumeIntegral<uint32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.MakeSessionByReplyMessage(replyMessage);
    }

    void WakeupThreadByStubTest(FuzzedDataProvider &provider)
    {
        uint32_t seqNumber = provider.ConsumeIntegral<uint32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.WakeupThreadByStub(seqNumber);
    }

    void DetachThreadLockInfoTest(FuzzedDataProvider &provider)
    {
        uint32_t seqNumber = provider.ConsumeIntegral<uint32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.DetachThreadLockInfo(seqNumber);
    }

    void DetachProxyObjectTest(FuzzedDataProvider &provider)
    {
        binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        OHOS::DBinderService dBinderService;
        dBinderService.DetachProxyObject(binderObject);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::InitializeSessionTest(provider);
    OHOS::MakeSessionByReplyMessageTest(provider);
    OHOS::WakeupThreadByStubTest(provider);
    OHOS::DetachThreadLockInfoTest(provider);
    OHOS::DetachProxyObjectTest(provider);
    return 0;
}
