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

    void LoadSystemAbilityComplete1Test(FuzzedDataProvider &provider)
    {
        std::string srcNetworkId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        int handle = provider.ConsumeIntegral<int>();
        sptr<IRemoteObject> remoteObject = new (std::nothrow) IPCObjectProxy(handle);
        if (remoteObject == nullptr) {
            return;
        }
        int32_t systemAbilityId = provider.ConsumeIntegral<int32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.LoadSystemAbilityComplete(srcNetworkId, systemAbilityId, remoteObject);
    }

    void LoadSystemAbilityComplete2Test(FuzzedDataProvider &provider)
    {
        std::string srcNetworkId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        sptr<IRemoteObject> remoteObject = nullptr;
        int32_t systemAbilityId = provider.ConsumeIntegral<int32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.LoadSystemAbilityComplete(srcNetworkId, systemAbilityId, remoteObject);
    }

    void CheckAndAmendSaIdTest(FuzzedDataProvider &provider)
    {
        auto message = std::make_shared<DHandleEntryTxRx>();
        if (message == nullptr) {
            return;
        }
        message->transType = provider.ConsumeIntegral<int32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.CheckAndAmendSaId(message);
    }

    void OnRemoteInvokerMessageTest(FuzzedDataProvider &provider)
    {
        auto message = std::make_shared<DHandleEntryTxRx>();
        if (message == nullptr) {
            return;
        }
        message->transType = provider.ConsumeIntegral<int32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.OnRemoteInvokerMessage(message);
    }

    void CreateDatabusNameTest(FuzzedDataProvider &provider)
    {
        int uid = provider.ConsumeIntegral<int>();
        int pid = provider.ConsumeIntegral<int>();
        OHOS::DBinderService dBinderService;
        dBinderService.CreateDatabusName(uid, pid);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::LoadSystemAbilityComplete1Test(provider);
    OHOS::LoadSystemAbilityComplete2Test(provider);
    OHOS::CheckAndAmendSaIdTest(provider);
    OHOS::OnRemoteInvokerMessageTest(provider);
    OHOS::CreateDatabusNameTest(provider);
    return 0;
}
