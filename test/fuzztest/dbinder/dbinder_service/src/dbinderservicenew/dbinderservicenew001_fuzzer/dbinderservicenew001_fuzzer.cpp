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
    class TestRpcSystemAbilityCallback : public RpcSystemAbilityCallback {
    public:
        sptr<IRemoteObject> GetSystemAbilityFromRemote(int32_t systemAbilityId) override
        {
            return nullptr;
        }

        bool LoadSystemAbilityFromRemote(const std::string& srcNetworkId, int32_t systemAbilityId) override
        {
            return isLoad_;
        }
        bool IsDistributedSystemAbility(int32_t systemAbilityId) override
        {
            return isSystemAbility_;
        }
        bool isSystemAbility_ = true;
        bool isLoad_ = true;
    };

    void StartDBinderServiceTest(FuzzedDataProvider &provider)
    {
        OHOS::DBinderService dBinderService;
        std::shared_ptr<RpcSystemAbilityCallback> callbackImpl = nullptr;
        dBinderService.StartDBinderService(callbackImpl);
        callbackImpl = std::make_shared<TestRpcSystemAbilityCallback>();
        if (callbackImpl == nullptr) {
            return;
        }
        int32_t systemAbilityId = provider.ConsumeIntegral<int32_t>();
        callbackImpl->IsDistributedSystemAbility(systemAbilityId);

        dBinderService.StartDBinderService(callbackImpl);
        dBinderService.StopRemoteListener();
    }

    void AddStubByTagTest(FuzzedDataProvider &provider)
    {
        const std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        const std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
        if (stub == nullptr) {
            return;
        }
        binder_uintptr_t binderObjectPtr = reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr());
        OHOS::DBinderService dBinderService;
        dBinderService.AddStubByTag(binderObjectPtr);
    }

    void CheckBinderObject1Test(FuzzedDataProvider &provider)
    {
        const std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        const std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
        if (stub == nullptr) {
            return;
        }
        binder_uintptr_t binderObjectPtr = reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr());
        OHOS::DBinderService dBinderService;
        dBinderService.CheckBinderObject(stub, binderObjectPtr);
    }

    void CheckBinderObject2Test(FuzzedDataProvider &provider)
    {
        const std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        const std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
        if (stub == nullptr) {
            return;
        }
        OHOS::DBinderService dBinderService;
        dBinderService.CheckBinderObject(stub, binderObject);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::StartDBinderServiceTest(provider);
    OHOS::AddStubByTagTest(provider);
    OHOS::CheckBinderObject1Test(provider);
    OHOS::CheckBinderObject2Test(provider);
    return 0;
}
