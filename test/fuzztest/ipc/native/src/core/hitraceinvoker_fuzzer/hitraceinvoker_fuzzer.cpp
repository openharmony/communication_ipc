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

#include "hitraceinvoker_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "hitrace_invoker.h"

namespace OHOS {
void TraceClientSendFuzzTest(FuzzedDataProvider &provider)
{
    int32_t handle = provider.ConsumeIntegral<int32_t>();
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    uint32_t flags = provider.ConsumeIntegral<uint32_t>();
    HiTraceIdStruct id;
    id.valid = provider.ConsumeIntegralInRange<int>(HITRACE_ID_INVALID, HITRACE_ID_VALID);
    id.ver = provider.ConsumeIntegral<uint64_t>();
    id.chainId = provider.ConsumeIntegral<uint64_t>();
    id.flags = provider.ConsumeIntegral<uint64_t>();
    id.spanId = provider.ConsumeIntegral<uint64_t>();
    id.parentSpanId = provider.ConsumeIntegral<uint64_t>();
    HiviewDFX::HiTraceId traceId(id);
    HitraceInvoker::TraceClientSend(handle, code, data, flags, traceId);
}

void TraceClientReceieveFuzzTest(FuzzedDataProvider &provider)
{
    int32_t handle = provider.ConsumeIntegral<int32_t>();
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    uint32_t flags = provider.ConsumeIntegral<uint32_t>();
    HiTraceIdStruct id;
    id.valid = provider.ConsumeIntegralInRange<int>(HITRACE_ID_INVALID, HITRACE_ID_VALID);
    id.ver = provider.ConsumeIntegral<uint64_t>();
    id.chainId = provider.ConsumeIntegral<uint64_t>();
    id.flags = provider.ConsumeIntegral<uint64_t>();
    id.spanId = provider.ConsumeIntegral<uint64_t>();
    id.parentSpanId = provider.ConsumeIntegral<uint64_t>();
    HiviewDFX::HiTraceId traceId(id);
    HiviewDFX::HiTraceId childId;
    HitraceInvoker::TraceClientReceieve(handle, code, flags, traceId, childId);
}

void RecoveryDataAndFlagFuzzTest(FuzzedDataProvider &provider)
{
    Parcel data;
    size_t size = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(size);
    data.WriteBuffer(bytes.data(), bytes.size());
    uint32_t flags = provider.ConsumeIntegral<uint32_t>();
    size_t oldReadPosition = provider.ConsumeIntegral<size_t>();
    uint8_t idLen = provider.ConsumeIntegral<uint8_t>();
    HitraceInvoker::RecoveryDataAndFlag(data, flags, oldReadPosition, idLen);
}

void TraceServerReceieveFuzzTest(FuzzedDataProvider &provider)
{
    uint64_t handle = provider.ConsumeIntegral<uint64_t>();
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    uint32_t flags = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    size_t size = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(size);
    data.WriteBuffer(bytes.data(), bytes.size());
    HitraceInvoker::TraceServerReceieve(handle, code, data, flags);
}

void TraceServerSendFuzzTest(FuzzedDataProvider &provider)
{
    uint64_t handle = provider.ConsumeIntegral<uint64_t>();
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    bool isServerTraced = provider.ConsumeBool();
    uint32_t flags = provider.ConsumeIntegral<uint32_t>();
    HitraceInvoker::TraceServerSend(handle, code, isServerTraced, flags);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::TraceClientSendFuzzTest(provider);
    OHOS::TraceClientReceieveFuzzTest(provider);
    OHOS::RecoveryDataAndFlagFuzzTest(provider);
    OHOS::TraceServerReceieveFuzzTest(provider);
    OHOS::TraceServerSendFuzzTest(provider);
    return 0;
}
