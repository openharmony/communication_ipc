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

void GetPeerUidTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    const std::string device = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);

    dBinderServiceStub.GetPeerUid();
}

void SetOrGetSeqNumberTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    const std::string device = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);
    uint32_t seqNum = provider.ConsumeIntegral<uint32_t>();
    dBinderServiceStub.SetSeqNumber(seqNum);
    dBinderServiceStub.GetSeqNumber();
}

void SetOrGetNegoStatusAndTimeTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    const std::string device = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);
    NegotiationStatus status = static_cast<NegotiationStatus>(provider.ConsumeIntegral<uint32_t>());
    uint64_t time = provider.ConsumeIntegral<uint64_t>();

    dBinderServiceStub.SetNegoStatusAndTime(status, time);
    dBinderServiceStub.GetNegoStatusAndTime(status, time);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::GetPeerUidTest(provider);
    OHOS::SetOrGetSeqNumberTest(provider);
    OHOS::SetOrGetNegoStatusAndTimeTest(provider);
    return 0;
}
