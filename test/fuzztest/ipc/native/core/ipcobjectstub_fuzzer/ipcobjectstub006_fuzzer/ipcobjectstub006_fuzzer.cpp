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
void GetSessionNameForPidUidFuzzTest001(FuzzedDataProvider &provider)
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

void GetSessionNameForPidUidFuzzTest002(FuzzedDataProvider &provider)
{
    sptr<IPCObjectStub> ipcObjectStub = CreateIPCObjectStub(provider);
    if (ipcObjectStub == nullptr) {
        return;
    }
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t pid = provider.ConsumeIntegral<uint32_t>();
    uint32_t uid = provider.ConsumeIntegral<uint32_t>();
    data.WriteUint32(pid);
    data.WriteUint32(uid);
    ipcObjectStub->GetSessionNameForPidUid(code, data, reply, option);
}

void DBinderGetSessionNameForPidUidFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectStub> ipcObjectStub = CreateIPCObjectStub(provider);
    if (ipcObjectStub == nullptr) {
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    uint32_t pid = IPCSkeleton::GetCallingPid();
    uint32_t uid = IPCSkeleton::GetCallingUid();
    data.WriteUint32(pid);
    data.WriteUint32(uid);
    ipcObjectStub->DBinderGetSessionNameForPidUid(code, data, reply, option);
    auto instance = ProcessSkeleton::GetInstance();
    if (instance == nullptr) {
        return;
    }
    instance->SetSamgrFlag(true);
    ipcObjectStub->DBinderGetSessionNameForPidUid(code, data, reply, option);
    instance->SetSamgrFlag(false);
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

void InvokerDataBusThreadFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectStub> ipcObjectStub = CreateIPCObjectStub(provider);
    if (ipcObjectStub == nullptr) {
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    std::string deviceId = provider.ConsumeRandomLengthString(STR_MAX_LEN);
    uint32_t remotePid = IPCSkeleton::GetCallingPid();
    uint32_t remoteUid = IPCSkeleton::GetCallingUid();
    std::string remoteDeviceId = provider.ConsumeRandomLengthString(STR_MAX_LEN);
    std::string sessionName = provider.ConsumeRandomLengthString(STR_MAX_LEN);
    uint32_t remoteTokenId = provider.ConsumeIntegral<uint32_t>();
    data.WriteString(deviceId);
    data.WriteUint32(remotePid);
    data.WriteUint32(remoteUid);
    data.WriteString(remoteDeviceId);
    data.WriteString(sessionName);
    data.WriteUint32(remoteTokenId);
    ipcObjectStub->InvokerDataBusThread(data, reply);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::GetSessionNameForPidUidFuzzTest001(provider);
    OHOS::GetSessionNameForPidUidFuzzTest002(provider);
    OHOS::CreateSessionNameFuzzTest(provider);
    OHOS::RemoveSessionNameFuzzTest(provider);
    OHOS::DBinderGetSessionNameForPidUidFuzzTest(provider);
    return 0;
}
