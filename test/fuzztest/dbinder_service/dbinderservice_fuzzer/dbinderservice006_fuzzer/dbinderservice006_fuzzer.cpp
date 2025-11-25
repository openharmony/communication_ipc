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
    const static size_t MAX_STRING_PARAM_LEN = 100;

    void CheckDeviceIdIllegalTest(FuzzedDataProvider &provider)
    {
        std::string remoteDeviceId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        OHOS::DBinderService dBinderService;
        dBinderService.CheckDeviceIdIllegal(remoteDeviceId);
    }

    void CheckSessionNameIsEmptyTest(FuzzedDataProvider &provider)
    {
        std::string sessionName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        OHOS::DBinderService dBinderService;
        dBinderService.CheckSessionNameIsEmpty(sessionName);
    }

    void CheckInvokeListenThreadIllegalTest(FuzzedDataProvider &provider)
    {
        std::string sessionName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        int handle = provider.ConsumeIntegral<int>();
        sptr<IPCObjectProxy> proxy = new (std::nothrow) IPCObjectProxy(handle);
        if (proxy == nullptr) {
            return;
        }
        MessageParcel parcel;
        MessageParcel reply;
        OHOS::DBinderService dBinderService;
        dBinderService.CheckInvokeListenThreadIllegal(proxy, parcel, reply);
    }

    void CheckStubIndexAndSessionNameIllegalTest(FuzzedDataProvider &provider)
    {
        uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
        std::string serverSessionName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        std::string deviceId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        int handle = provider.ConsumeIntegral<int>();
        sptr<IPCObjectProxy> proxy = new (std::nothrow) IPCObjectProxy(handle);
        if (proxy == nullptr) {
            return;
        }
        OHOS::DBinderService dBinderService;
        dBinderService.CheckStubIndexAndSessionNameIllegal(stubIndex, serverSessionName, deviceId, proxy);
    }

    void SetReplyMessageTest(FuzzedDataProvider &provider)
    {
        std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<struct DHandleEntryTxRx>();
        if (replyMessage == nullptr) {
            return;
        }
        replyMessage->transType = provider.ConsumeIntegral<uint32_t>();
        uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
        std::string serverSessionName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        uint32_t selfTokenId = provider.ConsumeIntegral<uint32_t>();
        int handle = provider.ConsumeIntegral<int>();
        sptr<IPCObjectProxy> proxy = new (std::nothrow) IPCObjectProxy(handle);
        if (proxy == nullptr) {
            return;
        }
        OHOS::DBinderService dBinderService;
        dBinderService.SetReplyMessage(replyMessage, stubIndex, serverSessionName, selfTokenId, proxy);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::CheckDeviceIdIllegalTest(provider);
    OHOS::CheckSessionNameIsEmptyTest(provider);
    OHOS::CheckInvokeListenThreadIllegalTest(provider);
    OHOS::CheckStubIndexAndSessionNameIllegalTest(provider);
    OHOS::SetReplyMessageTest(provider);
    return 0;
}
