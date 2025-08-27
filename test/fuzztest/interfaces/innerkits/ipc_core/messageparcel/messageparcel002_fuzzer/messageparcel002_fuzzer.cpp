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

#include "messageparcel_fuzzer.h"

namespace OHOS {
void AcquireObjectFuzzTest001(FuzzedDataProvider &provider)
{
    flat_binder_object flat;
    flat.hdr.type = provider.ConsumeIntegralInRange<uint32_t>(BINDER_TYPE_FDA, BINDER_TYPE_WEAK_HANDLE);
    flat.flags = provider.ConsumeIntegral<uint32_t>();
    flat.handle = provider.ConsumeIntegral<binder_uintptr_t>();
    flat.cookie = 0;
    AcquireObject(&flat, nullptr);
}

void AcquireObjectFuzzTest002(FuzzedDataProvider &provider)
{
    AcquireObject(nullptr, nullptr);
    flat_binder_object flat;
    flat.flags = provider.ConsumeIntegral<uint32_t>();
    flat.handle = provider.ConsumeIntegral<binder_uintptr_t>();
    flat.cookie = 0;
    for (auto item : type) {
        flat.hdr.type = item;
        AcquireObject(&flat, nullptr);
    }
}

void WriteDBinderProxyFuzzTest001(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    sptr<IPCObjectProxy> object = new (std::nothrow) IPCObjectProxy(handle);
    if (object == nullptr) {
        return;
    }
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    parcel.WriteDBinderProxy(object, handle, stubIndex);
}

void WriteDBinderProxyFuzzTest002(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    std::string serviceName = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    std::string deviceId = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
    sptr<IPCObjectProxy> object = new (std::nothrow) IPCObjectProxy(handle);
    if (object == nullptr) {
        return;
    }
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    std::shared_ptr<DBinderSessionObject> callbackStub =
        std::make_shared<DBinderSessionObject>(serviceName, deviceId, stubIndex, nullptr, tokenId);
    if (current == nullptr || callbackStub == nullptr) {
        return;
    }
    current->ProxyAttachDBinderSession(handle, callbackStub);
    parcel.WriteDBinderProxy(object, handle, stubIndex);
}

void WriteRemoteObjectFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    sptr<IPCObjectProxy> proxy = new (std::nothrow) IPCObjectProxy(handle);
    if (proxy == nullptr) {
        return;
    }
    parcel.WriteRemoteObject(proxy);
    sptr<IPCObjectStub> stub = sptr<IPCObjectStub>::MakeSptr();
    parcel.WriteRemoteObject(stub);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::AcquireObjectFuzzTest001(provider);
    OHOS::AcquireObjectFuzzTest002(provider);
    OHOS::WriteDBinderProxyFuzzTest001(provider);
    OHOS::WriteDBinderProxyFuzzTest002(provider);
    OHOS::WriteRemoteObjectFuzzTest(provider);
    return 0;
}
