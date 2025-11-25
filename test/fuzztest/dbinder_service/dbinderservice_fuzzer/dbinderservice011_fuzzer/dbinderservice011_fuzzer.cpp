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

    void AttachDeathRecipientTest(FuzzedDataProvider &provider)
    {
        int handle = provider.ConsumeIntegral<int>();
        sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(handle);
        if (object == nullptr) {
            return;
        }
        sptr<IRemoteObject::DeathRecipient> deathRecipient = new (std::nothrow) TestDeathRecipient();
        if (deathRecipient == nullptr) {
            return;
        }
        OHOS::DBinderService dBinderService;
        dBinderService.AttachDeathRecipient(object, deathRecipient);
    }

    void QueryDeathRecipientTest(FuzzedDataProvider &provider)
    {
        int handle = provider.ConsumeIntegral<int>();
        sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(handle);
        if (object == nullptr) {
            return;
        }
        OHOS::DBinderService dBinderService;
        dBinderService.QueryDeathRecipient(object);
    }

    void DetachCallbackProxyTest(FuzzedDataProvider &provider)
    {
        int handle = provider.ConsumeIntegral<int>();
        sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(handle);
        if (object == nullptr) {
            return;
        }
        OHOS::DBinderService dBinderService;
        dBinderService.DetachCallbackProxy(object);
    }

    void AttachCallbackProxyTest(FuzzedDataProvider &provider)
    {
        int handle = provider.ConsumeIntegral<int>();
        sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(handle);
        if (object == nullptr) {
            return;
        }
        std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        binder_uintptr_t stub = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        sptr<DBinderServiceStub> dBinderServiceStub
            = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, stub);
        if (dBinderServiceStub == nullptr) {
            return;
        }
        OHOS::DBinderService dBinderService;
        dBinderService.AttachCallbackProxy(object, dBinderServiceStub.GetRefPtr());
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::AttachDeathRecipientTest(provider);
    OHOS::QueryDeathRecipientTest(provider);
    OHOS::DetachCallbackProxyTest(provider);
    OHOS::AttachCallbackProxyTest(provider);
    return 0;
}
