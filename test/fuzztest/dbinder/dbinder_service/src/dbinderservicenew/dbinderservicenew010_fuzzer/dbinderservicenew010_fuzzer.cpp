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

    void AttachProxyObjectTest(FuzzedDataProvider &provider)
    {
        int handle = provider.ConsumeIntegral<int>();
        sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(handle);
        if (object == nullptr) {
            return;
        }
        binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        OHOS::DBinderService dBinderService;
        dBinderService.AttachProxyObject(object, binderObject);
    }

    void QueryProxyObjectTest(FuzzedDataProvider &provider)
    {
        binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        OHOS::DBinderService dBinderService;
        dBinderService.QueryProxyObject(binderObject);
    }

    void DetachSessionObjectTest(FuzzedDataProvider &provider)
    {
        binder_uintptr_t stub = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        OHOS::DBinderService dBinderService;
        dBinderService.DetachSessionObject(stub);
    }

    void DetachDeathRecipientTest(FuzzedDataProvider &provider)
    {
        int handle = provider.ConsumeIntegral<int>();
        sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(handle);
        if (object == nullptr) {
            return;
        }
        OHOS::DBinderService dBinderService;
        dBinderService.DetachDeathRecipient(object);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::AttachProxyObjectTest(provider);
    OHOS::QueryProxyObjectTest(provider);
    OHOS::DetachSessionObjectTest(provider);
    OHOS::DetachDeathRecipientTest(provider);
    return 0;
}
