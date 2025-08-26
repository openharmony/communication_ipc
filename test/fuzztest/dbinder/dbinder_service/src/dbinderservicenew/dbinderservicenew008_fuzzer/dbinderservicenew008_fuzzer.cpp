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

#include "dbinderservicenew_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include "dbinder_service.h"
#include "dbinder_service_stub.h"
#include "string_ex.h"

namespace OHOS {

    void OnRemoteReplyMessageTest(FuzzedDataProvider &provider)
    {
        std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<struct DHandleEntryTxRx>();
        if (replyMessage == nullptr) {
            return;
        }
        replyMessage->transType = provider.ConsumeIntegral<uint32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.OnRemoteReplyMessage(replyMessage);
    }

    void IsSameSessionTest(FuzzedDataProvider &provider)
    {
        std::shared_ptr<struct SessionInfo> oldSession = std::make_shared<struct SessionInfo>();
        std::shared_ptr<struct SessionInfo> newSession = std::make_shared<struct SessionInfo>();
        if (oldSession == nullptr && newSession == nullptr) {
            return;
        }
        oldSession->type = provider.ConsumeIntegral<uint32_t>();
        newSession->type = provider.ConsumeIntegral<uint32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.IsSameSession(oldSession, newSession);
    }

    void IsInvalidStubTest(FuzzedDataProvider &provider)
    {
        std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<struct DHandleEntryTxRx>();
        if (replyMessage == nullptr) {
            return;
        }
        replyMessage->transType = provider.ConsumeIntegral<uint32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.IsInvalidStub(replyMessage);
    }

    void CopyDeviceIdInfoTest(FuzzedDataProvider &provider)
    {
        std::shared_ptr<struct SessionInfo> session = std::make_shared<struct SessionInfo>();
        std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<struct DHandleEntryTxRx>();
        if (session == nullptr && replyMessage == nullptr) {
            return;
        }
        session->type = provider.ConsumeIntegral<uint32_t>();
        replyMessage->transType = provider.ConsumeIntegral<uint32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.CopyDeviceIdInfo(session, replyMessage);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::OnRemoteReplyMessageTest(provider);
    OHOS::IsSameSessionTest(provider);
    OHOS::IsInvalidStubTest(provider);
    OHOS::CopyDeviceIdInfoTest(provider);
    return 0;
}
