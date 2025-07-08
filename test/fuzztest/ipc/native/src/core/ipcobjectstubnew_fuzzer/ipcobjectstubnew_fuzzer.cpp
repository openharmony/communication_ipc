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

#include "ipcobjectstubnew_fuzzer.h"
#include "ipc_object_stub.h"
#include "ipc_skeleton.h"
#include "message_parcel.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
sptr<IPCObjectStub> CreateIPCObjectStub(FuzzedDataProvider &provider)
{
    std::string descriptor = provider.ConsumeRandomLengthString();
    std::u16string descriptor16(descriptor.begin(), descriptor.end());
    bool serialInvokeFlag = provider.ConsumeBool();
    return sptr<IPCObjectStub>::MakeSptr(descriptor16, serialInvokeFlag);
}

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

void DBinderIncRefsTransactionFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectStub> ipcObjectStub = CreateIPCObjectStub(provider);
    if (ipcObjectStub == nullptr) {
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    ipcObjectStub->DBinderIncRefsTransaction(code, data, reply, option);
}

void DBinderDecRefsTransactionFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectStub> ipcObjectStub = CreateIPCObjectStub(provider);
    if (ipcObjectStub == nullptr) {
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    ipcObjectStub->DBinderDecRefsTransaction(code, data, reply, option);
}

void DBinderAddCommAuthFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectStub> ipcObjectStub = CreateIPCObjectStub(provider);
    if (ipcObjectStub == nullptr) {
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    ipcObjectStub->DBinderAddCommAuth(code, data, reply, option);
}

void DBinderGetSessionNameFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectStub> ipcObjectStub = CreateIPCObjectStub(provider);
    if (ipcObjectStub == nullptr) {
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    ipcObjectStub->DBinderGetSessionName(code, data, reply, option);
}

void DBinderGetGrantedSessionNameFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectStub> ipcObjectStub = CreateIPCObjectStub(provider);
    if (ipcObjectStub == nullptr) {
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    ipcObjectStub->DBinderGetGrantedSessionName(code, data, reply, option);
}

void DBinderGetPidUidFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectStub> ipcObjectStub = CreateIPCObjectStub(provider);
    if (ipcObjectStub == nullptr) {
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    ipcObjectStub->DBinderGetPidUid(code, data, reply, option);
}

void DBinderRemoveSessionNameFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectStub> ipcObjectStub = CreateIPCObjectStub(provider);
    if (ipcObjectStub == nullptr) {
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    ipcObjectStub->DBinderRemoveSessionName(code, data, reply, option);
}

void SendRequestInnerFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectStub> ipcObjectStub = CreateIPCObjectStub(provider);
    if (ipcObjectStub == nullptr) {
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    ipcObjectStub->SendRequestInner(code, data, reply, option);
}

void SendRequestFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectStub> ipcObjectStub = CreateIPCObjectStub(provider);
    if (ipcObjectStub == nullptr) {
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    ipcObjectStub->SendRequest(code, data, reply, option);
}

void GetGrantedSessionNameFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectStub> ipcObjectStub = CreateIPCObjectStub(provider);
    if (ipcObjectStub == nullptr) {
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    ipcObjectStub->GetGrantedSessionName(code, data, reply, option);
}

void GetSessionNameForPidUidFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectStub> ipcObjectStub = CreateIPCObjectStub(provider);
    if (ipcObjectStub == nullptr) {
        return;
    }
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t pid = IPCSkeleton::GetCallingPid();
    uint32_t uid = IPCSkeleton::GetCallingUid();
    data.WriteUint32(pid);
    data.WriteUint32(uid);
    ipcObjectStub->GetSessionNameForPidUid(code, data, reply, option);
}

void CreateSessionNameFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectStub> ipcObjectStub = CreateIPCObjectStub(provider);
    if (ipcObjectStub == nullptr) {
        return;
    }
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    int32_t uid = provider.ConsumeIntegral<int32_t>();
    ipcObjectStub->CreateSessionName(uid, pid);
}

void RemoveSessionNameFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectStub> ipcObjectStub = CreateIPCObjectStub(provider);
    if (ipcObjectStub == nullptr) {
        return;
    }
    MessageParcel data;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    data.WriteBuffer(bytes.data(), bytes.size());
    ipcObjectStub->RemoveSessionName(data);
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
    OHOS::DBinderIncRefsTransactionFuzzTest(provider);
    OHOS::DBinderDecRefsTransactionFuzzTest(provider);
    OHOS::DBinderAddCommAuthFuzzTest(provider);
    OHOS::DBinderGetSessionNameFuzzTest(provider);
    OHOS::DBinderGetGrantedSessionNameFuzzTest(provider);
    OHOS::DBinderGetPidUidFuzzTest(provider);
    OHOS::DBinderRemoveSessionNameFuzzTest(provider);
    OHOS::SendRequestInnerFuzzTest(provider);
    OHOS::SendRequestFuzzTest(provider);
    OHOS::GetGrantedSessionNameFuzzTest(provider);
    OHOS::GetSessionNameForPidUidFuzzTest(provider);
    OHOS::CreateSessionNameFuzzTest(provider);
    OHOS::RemoveSessionNameFuzzTest(provider);
    return 0;
}
