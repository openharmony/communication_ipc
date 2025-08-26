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
    const static size_t MAX_STRING_PARAM_LEN = 100;

    void OnRemoteInvokerDataBusMessageTest(FuzzedDataProvider &provider)
    {
        int handle = provider.ConsumeIntegral<int>();
        sptr<IPCObjectProxy> proxy = new (std::nothrow) IPCObjectProxy(handle);
        if (proxy == nullptr) {
            return;
        }
        std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<struct DHandleEntryTxRx>();
        if (replyMessage == nullptr) {
            return;
        }
        replyMessage->transType = provider.ConsumeIntegral<uint32_t>();
        std::string remoteDeviceId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        int pid = provider.ConsumeIntegral<int>();
        int uid = provider.ConsumeIntegral<int>();
        uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();

        OHOS::DBinderService dBinderService;
        dBinderService.OnRemoteInvokerDataBusMessage(proxy, replyMessage, remoteDeviceId, pid, uid, tokenId);
    }

    void GetRegisterServiceTest(FuzzedDataProvider &provider)
    {
        binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        OHOS::DBinderService dBinderService;
        dBinderService.GetRegisterService(binderObject);
    }

    void ProcessOnSessionClosedTest(FuzzedDataProvider &provider)
    {
        std::string networkId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        OHOS::DBinderService dBinderService;
        dBinderService.ProcessOnSessionClosed(networkId);
    }

    void OnRemoteErrorMessageTest(FuzzedDataProvider &provider)
    {
        std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<struct DHandleEntryTxRx>();
        if (replyMessage == nullptr) {
            return;
        }
        replyMessage->transType = provider.ConsumeIntegral<uint32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.OnRemoteErrorMessage(replyMessage);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::OnRemoteInvokerDataBusMessageTest(provider);
    OHOS::GetRegisterServiceTest(provider);
    OHOS::ProcessOnSessionClosedTest(provider);
    OHOS::OnRemoteErrorMessageTest(provider);
    return 0;
}
