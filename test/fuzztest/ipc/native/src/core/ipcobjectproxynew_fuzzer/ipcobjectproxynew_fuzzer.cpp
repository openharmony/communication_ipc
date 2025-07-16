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

#include "ipcobjectproxynew_fuzzer.h"
#include "ipc_object_proxy.h"
#include "message_parcel.h"
#include "sys_binder.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
sptr<IPCObjectProxy> CreateIPCObjectProxy(FuzzedDataProvider &provider)
{
    int32_t handle = provider.ConsumeIntegral<int32_t>();
    int32_t proto = provider.ConsumeIntegral<int32_t>();
    std::string descriptor = provider.ConsumeRandomLengthString();
    std::u16string descriptor16(descriptor.begin(), descriptor.end());
    return sptr<IPCObjectProxy>::MakeSptr(handle, descriptor16, proto);
}

void SendRequestInnerFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectProxy> proxy = CreateIPCObjectProxy(provider);
    if (proxy == nullptr) {
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    data.WriteBuffer(bytes.data(), bytes.size());
    bool isLocal = provider.ConsumeBool();
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    proxy->SendRequestInner(isLocal, code, data, reply, option);
}

void WaitForInitFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectProxy> proxy = CreateIPCObjectProxy(provider);
    if (proxy == nullptr) {
        return;
    }
    dbinder_negotiation_data dbinderData;
    dbinderData.proto = provider.ConsumeIntegral<uint32_t>();
    proxy->WaitForInit(&dbinderData);
}

void SetProtoFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectProxy> proxy = CreateIPCObjectProxy(provider);
    if (proxy == nullptr) {
        return;
    }
    uint32_t proto = provider.ConsumeIntegral<uint32_t>();
    proxy->SetProto(proto);
}

void MakeDBinderTransSessionFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectProxy> proxy = CreateIPCObjectProxy(provider);
    if (proxy == nullptr) {
        return;
    }
    DBinderNegotiationData binderData;
    binderData.peerPid = provider.ConsumeIntegral<pid_t>();
    binderData.peerUid = provider.ConsumeIntegral<pid_t>();
    binderData.peerTokenId = provider.ConsumeIntegral<uint32_t>();
    binderData.stubIndex = provider.ConsumeIntegral<uint64_t>();
    binderData.peerServiceName = provider.ConsumeRandomLengthString();
    binderData.peerDeviceId = provider.ConsumeRandomLengthString();
    binderData.localServiceName = provider.ConsumeRandomLengthString();
    binderData.localDeviceId = provider.ConsumeRandomLengthString();
    proxy->MakeDBinderTransSession(binderData);
}

void GetDBinderNegotiationDataFuzzTest001(FuzzedDataProvider &provider)
{
    sptr<IPCObjectProxy> proxy = CreateIPCObjectProxy(provider);
    if (proxy == nullptr) {
        return;
    }
    MessageParcel reply;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    reply.WriteBuffer(bytes.data(), bytes.size());
    int handle = provider.ConsumeIntegral<int32_t>();
    DBinderNegotiationData binderData;
    proxy->GetDBinderNegotiationData(handle, reply, binderData);
}

void GetDBinderNegotiationDataFuzzTest002(FuzzedDataProvider &provider)
{
    sptr<IPCObjectProxy> proxy = CreateIPCObjectProxy(provider);
    if (proxy == nullptr) {
        return;
    }
    proxy->dbinderData_ = std::make_unique<uint8_t[]>(sizeof(dbinder_negotiation_data));
    DBinderNegotiationData binderData;
    proxy->GetDBinderNegotiationData(binderData);
}

void UpdateDatabusClientSessionFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectProxy> proxy = CreateIPCObjectProxy(provider);
    if (proxy == nullptr) {
        return;
    }
    MessageParcel reply;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    reply.WriteBuffer(bytes.data(), bytes.size());
    int handle = provider.ConsumeIntegral<int32_t>();
    proxy->UpdateDatabusClientSession(handle, reply);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::SendRequestInnerFuzzTest(provider);
    OHOS::WaitForInitFuzzTest(provider);
    OHOS::SetProtoFuzzTest(provider);
    OHOS::MakeDBinderTransSessionFuzzTest(provider);
    OHOS::GetDBinderNegotiationDataFuzzTest001(provider);
    OHOS::GetDBinderNegotiationDataFuzzTest002(provider);
    OHOS::UpdateDatabusClientSessionFuzzTest(provider);
    return 0;
}
