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

#include "dbindercallbackstub_fuzzer.h"

namespace OHOS {
sptr<DBinderCallbackStub> CreateDBinderCallbackStubInstance(FuzzedDataProvider &provider)
{
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
    std::string service = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    std::string device = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    std::string localDevice = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    sptr<DBinderCallbackStub> stub =
        new (std::nothrow) DBinderCallbackStub(service, device, localDevice, stubIndex, handle, tokenId);
    return stub;
}

void ProcessProtoFuzzTest(FuzzedDataProvider &provider)
{
    sptr<DBinderCallbackStub> stub = CreateDBinderCallbackStubInstance(provider);
    if (stub == nullptr) {
        return;
    }
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    stub->ProcessProto(code, data, reply, option);
}

void ProcessDataFuzzTest(FuzzedDataProvider &provider)
{
    sptr<DBinderCallbackStub> stub = CreateDBinderCallbackStubInstance(provider);
    if (stub == nullptr) {
        return;
    }
    int uid = provider.ConsumeIntegral<int>();
    int pid = provider.ConsumeIntegral<int>();
    MessageParcel data;
    MessageParcel reply;
    std::string sessionName = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    stub->ProcessData(uid, pid, sessionName, data, reply);
}

void MarshallingFuzzTest001(FuzzedDataProvider &provider)
{
    sptr<DBinderCallbackStub> stub = CreateDBinderCallbackStubInstance(provider);
    if (stub == nullptr) {
        return;
    }
    Parcel parcel;
    stub->Marshalling(parcel);
}

void MarshallingFuzzTest002(FuzzedDataProvider &provider)
{
    sptr<DBinderCallbackStub> stub = CreateDBinderCallbackStubInstance(provider);
    if (stub == nullptr) {
        return;
    }
    Parcel parcel;
    DBinderCallbackStub::Marshalling(parcel, stub);
}

void AddDBinderCommAuthFuzzTest(FuzzedDataProvider &provider)
{
    sptr<DBinderCallbackStub> stub = CreateDBinderCallbackStubInstance(provider);
    if (stub == nullptr) {
        return;
    }
    pid_t pid = provider.ConsumeIntegral<pid_t>();
    uid_t uid = provider.ConsumeIntegral<uid_t>();
    std::string sessionName = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    stub->AddDBinderCommAuth(pid, uid, sessionName);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::ProcessProtoFuzzTest(provider);
    OHOS::ProcessDataFuzzTest(provider);
    OHOS::MarshallingFuzzTest001(provider);
    OHOS::MarshallingFuzzTest002(provider);
    OHOS::AddDBinderCommAuthFuzzTest(provider);
    return 0;
}
