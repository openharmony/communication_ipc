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

#include "ipcobjectstub_fuzzer.h"

namespace OHOS {
void DBinderPingTransactionFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectStub> ipcObjectStub = CreateIPCObjectStub(provider);
    if (ipcObjectStub == nullptr) {
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    ipcObjectStub->DBinderPingTransaction(code, data, reply, option);
}

void DBinderSearchDescriptorFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectStub> ipcObjectStub = CreateIPCObjectStub(provider);
    if (ipcObjectStub == nullptr) {
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    ipcObjectStub->DBinderSearchDescriptor(code, data, reply, option);
}

void DBinderSearchRefCountFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectStub> ipcObjectStub = CreateIPCObjectStub(provider);
    if (ipcObjectStub == nullptr) {
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    ipcObjectStub->DBinderSearchRefCount(code, data, reply, option);
}

void DBinderDumpTransactionFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectStub> ipcObjectStub = CreateIPCObjectStub(provider);
    if (ipcObjectStub == nullptr) {
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    ipcObjectStub->DBinderDumpTransaction(code, data, reply, option);
}

void DBinderInvokeListenThreadFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectStub> ipcObjectStub = CreateIPCObjectStub(provider);
    if (ipcObjectStub == nullptr) {
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    ipcObjectStub->DBinderInvokeListenThread(code, data, reply, option);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::DBinderPingTransactionFuzzTest(provider);
    OHOS::DBinderSearchDescriptorFuzzTest(provider);
    OHOS::DBinderSearchRefCountFuzzTest(provider);
    OHOS::DBinderDumpTransactionFuzzTest(provider);
    OHOS::DBinderInvokeListenThreadFuzzTest(provider);
    return 0;
}
