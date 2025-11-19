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

    class TestDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        TestDeathRecipient() {}
        virtual ~TestDeathRecipient() {}
        void OnRemoteDied(const wptr<IRemoteObject>& object) override {}
    };

    void HasDBinderStubTest(FuzzedDataProvider &provider)
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
        dBinderService.HasDBinderStub(binderObjectPtr);
    }

    void IsSameStubObject1Test(FuzzedDataProvider &provider)
    {
        const std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        const std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
        if (stub == nullptr) {
            return;
        }
        OHOS::DBinderService dBinderService;
        dBinderService.IsSameStubObject(stub, serviceName, deviceID);
    }

    void IsSameStubObject2Test(FuzzedDataProvider &provider)
    {
        std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        sptr<DBinderServiceStub> stub = nullptr;
        OHOS::DBinderService dBinderService;
        dBinderService.IsSameStubObject(stub, serviceName, deviceID);
    }

    void FindDBinderStubTest(FuzzedDataProvider &provider)
    {
        std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        std::string device = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        OHOS::DBinderService dBinderService;
        dBinderService.FindDBinderStub(serviceName, device);
    }

    void DeleteDBinderStubTest(FuzzedDataProvider &provider)
    {
        std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        std::string device = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        OHOS::DBinderService dBinderService;
        dBinderService.DeleteDBinderStub(serviceName, device);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::HasDBinderStubTest(provider);
    OHOS::IsSameStubObject1Test(provider);
    OHOS::IsSameStubObject2Test(provider);
    OHOS::FindDBinderStubTest(provider);
    OHOS::DeleteDBinderStubTest(provider);
    return 0;
}
