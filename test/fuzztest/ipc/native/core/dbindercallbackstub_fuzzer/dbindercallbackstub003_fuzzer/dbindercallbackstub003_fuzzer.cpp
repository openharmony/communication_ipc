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

void SaveDBinderDataFuzzTest(FuzzedDataProvider &provider)
{
    sptr<DBinderCallbackStub> stub = CreateDBinderCallbackStubInstance(provider);
    if (stub == nullptr) {
        return;
    }
    std::string sessionName = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    stub->SaveDBinderData(sessionName);
    stub->dbinderData_ = nullptr;
    stub->SaveDBinderData(sessionName);
}

void GetAndSaveDBinderDataFuzzTest(FuzzedDataProvider &provider)
{
    sptr<DBinderCallbackStub> stub = CreateDBinderCallbackStubInstance(provider);
    if (stub == nullptr) {
        return;
    }
    pid_t pid = provider.ConsumeIntegral<pid_t>();
    uid_t uid = provider.ConsumeIntegral<uid_t>();
    stub->GetAndSaveDBinderData(pid, uid);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::SaveDBinderDataFuzzTest(provider);
    OHOS::GetAndSaveDBinderDataFuzzTest(provider);
    return 0;
}
