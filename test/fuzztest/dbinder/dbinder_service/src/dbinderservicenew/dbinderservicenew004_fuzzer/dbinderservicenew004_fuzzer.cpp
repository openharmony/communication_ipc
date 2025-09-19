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

    void SendEntryToRemoteTest(FuzzedDataProvider &provider)
    {
        OHOS::DBinderService dBinderService;
        const std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        const std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
        if (stub == nullptr) {
            return;
        }
        uint32_t seqNumber = provider.ConsumeIntegral<uint32_t>();
        uint32_t pid = provider.ConsumeIntegral<uint32_t>();
        uint32_t uid = provider.ConsumeIntegral<uint32_t>();
        dBinderService.SendEntryToRemote(stub, seqNumber, pid, uid);
        dBinderService.StopRemoteListener();
    }

    void InvokerRemoteDBinderTest(FuzzedDataProvider &provider)
    {
        const std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        const std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
        if (stub == nullptr) {
            return;
        }
        uint32_t seqNumber = provider.ConsumeIntegral<uint32_t>();
        uint32_t pid = provider.ConsumeIntegral<uint32_t>();
        uint32_t uid = provider.ConsumeIntegral<uint32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.InvokerRemoteDBinder(stub, seqNumber, pid, uid);
    }

    void CheckSystemAbilityIdTest(FuzzedDataProvider &provider)
    {
        int32_t systemAbilityId = provider.ConsumeIntegral<int32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.CheckSystemAbilityId(systemAbilityId);
    }

    void IsSameLoadSaItemTest(FuzzedDataProvider &provider)
    {
        std::string srcNetworkId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        int32_t systemAbilityId = provider.ConsumeIntegral<int32_t>();
        std::shared_ptr<DHandleEntryTxRx> loadSaItem = std::make_shared<DHandleEntryTxRx>();
        if (loadSaItem == nullptr) {
            return;
        }
        OHOS::DBinderService dBinderService;
        dBinderService.IsSameLoadSaItem(srcNetworkId, systemAbilityId, loadSaItem);
    }

    void PopLoadSaItemTest(FuzzedDataProvider &provider)
    {
        std::string srcNetworkId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        int32_t systemAbilityId = provider.ConsumeIntegral<int32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.PopLoadSaItem(srcNetworkId, systemAbilityId);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::SendEntryToRemoteTest(provider);
    OHOS::InvokerRemoteDBinderTest(provider);
    OHOS::CheckSystemAbilityIdTest(provider);
    OHOS::IsSameLoadSaItemTest(provider);
    OHOS::PopLoadSaItemTest(provider);
    return 0;
}
