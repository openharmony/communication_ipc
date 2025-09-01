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
static constexpr uint32_t MAX_STRING_LEN = 100;

sptr<IPCObjectStub> CreateIPCObjectStub(FuzzedDataProvider &provider)
{
    std::string descriptor = provider.ConsumeRandomLengthString(MAX_STRING_LEN);
    std::u16string descriptor16(descriptor.begin(), descriptor.end());
    bool serialInvokeFlag = provider.ConsumeBool();
    return sptr<IPCObjectStub>::MakeSptr(descriptor16, serialInvokeFlag);
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
    OHOS::GetSessionNameForPidUidFuzzTest(provider);
    OHOS::CreateSessionNameFuzzTest(provider);
    OHOS::RemoveSessionNameFuzzTest(provider);
    return 0;
}
