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

#include "ipcprocessskeleton_fuzzer.h"
#include "ipc_process_skeleton.h"
#include "fuzz_data_generator.h"
#include "message_parcel.h"
#include "string_ex.h"

namespace OHOS {
void DetachDBinderCallbackStubByProxyFuzzTest(FuzzedDataProvider &provider)
{
    OHOS::IPCProcessSkeleton *current = OHOS::IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    int handle = provider.ConsumeIntegral<int>();
    sptr<IPCObjectProxy> proxy = sptr<IPCObjectProxy>::MakeSptr(handle);
    if (proxy == nullptr) {
        return;
    }
    current->DetachDBinderCallbackStubByProxy(proxy.GetRefPtr());
}

void DetachDBinderCallbackStubFuzzTest(FuzzedDataProvider &provider)
{
    OHOS::IPCProcessSkeleton *current = OHOS::IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    int handle = provider.ConsumeIntegral<int>();
    std::string descriptor = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::u16string descriptor16 = Str8ToStr16(descriptor);
    std::string service = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::string device = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::string localDevice = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
    int proto = provider.ConsumeIntegral<int>();
    sptr<IPCObjectProxy> proxy = sptr<IPCObjectProxy>::MakeSptr(handle, descriptor16, proto);
    sptr<DBinderCallbackStub> stub =
        sptr<DBinderCallbackStub>::MakeSptr(service, device, localDevice, stubIndex, handle, tokenId);
    if (proxy == nullptr || stub == nullptr) {
        return;
    }
    current->AttachDBinderCallbackStub(proxy, stub);
    current->DetachDBinderCallbackStub(stub.GetRefPtr());
}

void QueryDBinderCallbackStubFuzzTest(FuzzedDataProvider &provider)
{
    OHOS::IPCProcessSkeleton *current = OHOS::IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    int handle = provider.ConsumeIntegral<int>();
    std::string descriptor = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::u16string descriptor16 = Str8ToStr16(descriptor);
    uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
    std::string service = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::string device = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::string localDevice = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    int proto = provider.ConsumeIntegral<int>();
    sptr<IPCObjectProxy> proxy = sptr<IPCObjectProxy>::MakeSptr(handle, descriptor16, proto);
    sptr<DBinderCallbackStub> stub =
        sptr<DBinderCallbackStub>::MakeSptr(service, device, localDevice, stubIndex, handle, tokenId);
    if (proxy == nullptr || stub == nullptr) {
        return;
    }
    current->QueryDBinderCallbackStub(proxy);
    current->AttachDBinderCallbackStub(proxy, stub);
    current->QueryDBinderCallbackStub(proxy);
}

void QueryDBinderCallbackProxyFuzzTest(FuzzedDataProvider &provider)
{
    OHOS::IPCProcessSkeleton *current = OHOS::IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    int handle = provider.ConsumeIntegral<int>();
    std::string descriptor = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::u16string descriptor16 = Str8ToStr16(descriptor);
    uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
    std::string service = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::string device = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::string localDevice = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    int proto = provider.ConsumeIntegral<int>();
    sptr<IPCObjectProxy> proxy = sptr<IPCObjectProxy>::MakeSptr(handle, descriptor16, proto);
    sptr<DBinderCallbackStub> stub =
        sptr<DBinderCallbackStub>::MakeSptr(service, device, localDevice, stubIndex, handle, tokenId);
    if (proxy == nullptr || stub == nullptr) {
        return;
    }
    current->QueryDBinderCallbackProxy(stub);
    current->AttachDBinderCallbackStub(proxy, stub);
    current->QueryDBinderCallbackProxy(stub);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::DetachDBinderCallbackStubByProxyFuzzTest(provider);
    OHOS::DetachDBinderCallbackStubFuzzTest(provider);
    OHOS::QueryDBinderCallbackStubFuzzTest(provider);
    OHOS::QueryDBinderCallbackProxyFuzzTest(provider);
    return 0;
}
