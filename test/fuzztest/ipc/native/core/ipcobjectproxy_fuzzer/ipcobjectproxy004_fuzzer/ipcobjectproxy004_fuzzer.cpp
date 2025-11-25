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

#include "ipcobjectproxy_fuzzer.h"

namespace OHOS {
void GetDBinderNegotiationDataFuzzTest001(FuzzedDataProvider &provider)
{
    sptr<IPCObjectProxy> proxy = CreateIPCObjectProxy(provider);
    if (proxy == nullptr) {
        return;
    }
    MessageParcel reply;
    size_t maxSize = sizeof(DBinderNegotiationData);
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(0, maxSize + maxSize);
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

void GetDBinderNegotiationDataFuzzTest003(FuzzedDataProvider &provider)
{
    sptr<IPCObjectProxy> proxy = CreateIPCObjectProxy(provider);
    if (proxy == nullptr) {
        return;
    }
    DBinderNegotiationData binderData;
    proxy->dbinderData_ = std::make_unique<uint8_t[]>(sizeof(dbinder_negotiation_data));
    if (proxy->dbinderData_ == nullptr) {
        return;
    }
    auto data = reinterpret_cast<dbinder_negotiation_data *>(proxy->dbinderData_.get());
    strncpy_s(data->target_name, sizeof(data->target_name), "DBinder1_1", sizeof("DBinder1_1") - 1);
    proxy->GetDBinderNegotiationData(binderData);
}

void GetDBinderNegotiationDataFuzzTest004(FuzzedDataProvider &provider)
{
    sptr<IPCObjectProxy> proxy = CreateIPCObjectProxy(provider);
    if (proxy == nullptr) {
        return;
    }
    MessageParcel reply;
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    std::string peerServiceName = provider.ConsumeRandomLengthString(STR_MAX_LEN);
    std::string peerDeviceId = provider.ConsumeRandomLengthString(STR_MAX_LEN);
    std::string localDeviceId = provider.ConsumeRandomLengthString(STR_MAX_LEN);
    std::string localServiceName = provider.ConsumeRandomLengthString(STR_MAX_LEN);
    uint32_t peerTokenId = provider.ConsumeIntegral<uint32_t>();
    reply.WriteUint64(stubIndex);
    reply.WriteString(peerServiceName);
    reply.WriteString(peerDeviceId);
    reply.WriteString(localDeviceId);
    reply.WriteString(localServiceName);
    reply.WriteUint32(peerTokenId);
    int handle = provider.ConsumeIntegral<int32_t>();
    DBinderNegotiationData binderData;
    proxy->GetDBinderNegotiationData(handle, reply, binderData);
}

void AddDeathRecipientFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectProxy> proxy = CreateIPCObjectProxy(provider);
    if (proxy == nullptr) {
        return;
    }
    proxy->AddDeathRecipient(nullptr);
    sptr<MockDeathRecipient> recipient = sptr<MockDeathRecipient>::MakeSptr();
    if (recipient == nullptr) {
        return;
    }
    proxy->AddDeathRecipient(recipient);
    proxy->SetObjectDied(true);
    proxy->AddDeathRecipient(recipient);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::GetDBinderNegotiationDataFuzzTest001(provider);
    OHOS::GetDBinderNegotiationDataFuzzTest002(provider);
    OHOS::GetDBinderNegotiationDataFuzzTest003(provider);
    OHOS::GetDBinderNegotiationDataFuzzTest004(provider);
    OHOS::AddDeathRecipientFuzzTest(provider);
    return 0;
}
