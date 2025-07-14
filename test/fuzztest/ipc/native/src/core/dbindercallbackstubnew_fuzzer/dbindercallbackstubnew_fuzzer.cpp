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

#include "dbindercallbackstubnew_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include "dbinder_callback_stub.h"
#include "message_parcel.h"

namespace OHOS {
    void ProcessProtoFuzzTest(FuzzedDataProvider &provider)
    {
        uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
        uint32_t handle = provider.ConsumeIntegral<uint32_t>();
        uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
        std::string service = provider.ConsumeRandomLengthString();
        std::string device = provider.ConsumeRandomLengthString();
        std::string localDevice = provider.ConsumeRandomLengthString();
        auto stub = new (std::nothrow) DBinderCallbackStub(service, device, localDevice, stubIndex, handle, tokenId);
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
        uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
        uint32_t handle = provider.ConsumeIntegral<uint32_t>();
        uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
        std::string service = provider.ConsumeRandomLengthString();
        std::string device = provider.ConsumeRandomLengthString();
        std::string localDevice = provider.ConsumeRandomLengthString();
        auto stub = new (std::nothrow) DBinderCallbackStub(service, device, localDevice, stubIndex, handle, tokenId);
        if (stub == nullptr) {
            return;
        }
        int uid = provider.ConsumeIntegral<int>();
        int pid = provider.ConsumeIntegral<int>();
        MessageParcel data;
        MessageParcel reply;
        std::string sessionName = provider.ConsumeRandomLengthString();
        stub->ProcessData(uid, pid, sessionName, data, reply);
    }

    void MarshallingFuzzTest(FuzzedDataProvider &provider)
    {
        uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
        uint32_t handle = provider.ConsumeIntegral<uint32_t>();
        uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
        std::string service = provider.ConsumeRandomLengthString();
        std::string device = provider.ConsumeRandomLengthString();
        std::string localDevice = provider.ConsumeRandomLengthString();
        auto stub = new (std::nothrow) DBinderCallbackStub(service, device, localDevice, stubIndex, handle, tokenId);
        if (stub == nullptr) {
            return;
        }
        Parcel parcel;
        stub->Marshalling(parcel);
    }

    void AddDBinderCommAuthFuzzTest(FuzzedDataProvider &provider)
    {
        uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
        uint32_t handle = provider.ConsumeIntegral<uint32_t>();
        uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
        std::string service = provider.ConsumeRandomLengthString();
        std::string device = provider.ConsumeRandomLengthString();
        std::string localDevice = provider.ConsumeRandomLengthString();
        auto stub = new (std::nothrow) DBinderCallbackStub(service, device, localDevice, stubIndex, handle, tokenId);
        if (stub == nullptr) {
            return;
        }
        pid_t pid = provider.ConsumeIntegral<pid_t>();
        uid_t uid = provider.ConsumeIntegral<uid_t>();
        std::string sessionName = provider.ConsumeRandomLengthString();
        stub->AddDBinderCommAuth(pid, uid, sessionName);
    }

    void SaveDBinderDataFuzzTest(FuzzedDataProvider &provider)
    {
        uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
        uint32_t handle = provider.ConsumeIntegral<uint32_t>();
        uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
        std::string service = provider.ConsumeRandomLengthString();
        std::string device = provider.ConsumeRandomLengthString();
        std::string localDevice = provider.ConsumeRandomLengthString();
        auto stub = new (std::nothrow) DBinderCallbackStub(service, device, localDevice, stubIndex, handle, tokenId);
        if (stub == nullptr) {
            return;
        }
        std::string sessionName = provider.ConsumeRandomLengthString();
        stub->SaveDBinderData(sessionName);
    }

    void GetAndSaveDBinderDataFuzzTest(FuzzedDataProvider &provider)
    {
        uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
        uint32_t handle = provider.ConsumeIntegral<uint32_t>();
        uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
        std::string service = provider.ConsumeRandomLengthString();
        std::string device = provider.ConsumeRandomLengthString();
        std::string localDevice = provider.ConsumeRandomLengthString();
        auto stub = new (std::nothrow) DBinderCallbackStub(service, device, localDevice, stubIndex, handle, tokenId);
        if (stub == nullptr) {
            return;
        }
        pid_t pid = provider.ConsumeIntegral<pid_t>();
        uid_t uid = provider.ConsumeIntegral<uid_t>();
        stub->GetAndSaveDBinderData(pid, uid);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::ProcessProtoFuzzTest(provider);
    OHOS::ProcessDataFuzzTest(provider);
    OHOS::ProcessDataFuzzTest(provider);
    OHOS::AddDBinderCommAuthFuzzTest(provider);
    OHOS::SaveDBinderDataFuzzTest(provider);
    OHOS::GetAndSaveDBinderDataFuzzTest(provider);
    return 0;
}
