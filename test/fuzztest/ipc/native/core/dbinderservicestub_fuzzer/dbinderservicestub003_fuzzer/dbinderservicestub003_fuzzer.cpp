/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dbinderservicestub_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include "dbinder_service.h"
#include "dbinder_service_stub.h"
#include "ipc_skeleton.h"
#include "string_ex.h"

namespace OHOS {
static constexpr uint32_t MAX_STRING_LEN = 100;

void SaveDBinderDataTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    const std::string device = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);

    std::string localBusName = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    dBinderServiceStub.SaveDBinderData(localBusName);

    binder_uintptr_t key = reinterpret_cast<binder_uintptr_t>(&dBinderServiceStub);
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        return;
    }
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    if (sessionInfo == nullptr) {
        return;
    }
    dBinderService->AttachSessionObject(sessionInfo, key);
    dBinderServiceStub.SaveDBinderData(localBusName);
}

void GetServiceNameTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    const std::string device = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);

    dBinderServiceStub.GetServiceName();
}

void GetDeviceIDTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    const std::string device = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);

    dBinderServiceStub.GetDeviceID();
}

void GetBinderObjectTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    const std::string device = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);

    dBinderServiceStub.GetBinderObject();
}

void GetPeerPidTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    const std::string device = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);

    dBinderServiceStub.GetPeerPid();
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::SaveDBinderDataTest(provider);
    OHOS::GetServiceNameTest(provider);
    OHOS::GetDeviceIDTest(provider);
    OHOS::GetBinderObjectTest(provider);
    OHOS::GetPeerPidTest(provider);
    return 0;
}
