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
void NoticeServiceDieFuzzTest(FuzzedDataProvider &provider)
{
    int handle = provider.ConsumeIntegral<int>();
    sptr<IPCObjectStub> ipcObjectStub = CreateIPCObjectStub(provider);
    sptr<IPCObjectProxy> ipcObjectProxy = sptr<IPCObjectProxy>::MakeSptr(handle);
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (ipcObjectStub == nullptr || current == nullptr || ipcObjectProxy == nullptr) {
        return;
    }
    current->AttachCallbackStub(ipcObjectProxy.GetRefPtr(), ipcObjectStub);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    ipcObjectStub->NoticeServiceDie(data, reply, option);
}

void OnRemoteDumpFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel parcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    parcel.WriteBuffer(bytes.data(), bytes.size());
    parcel.WriteFileDescriptor(-1);
    MessageParcel reply;
    MessageOption option;
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.OnRemoteDump(code, parcel, reply, option);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::NoticeServiceDieFuzzTest(provider);
    OHOS::OnRemoteDumpFuzzTest(provider);
    return 0;
}
