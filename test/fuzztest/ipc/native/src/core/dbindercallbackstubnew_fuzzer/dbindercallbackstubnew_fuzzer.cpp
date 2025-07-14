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
        uint32_t code = provider.ConsumeIntegral<uint32_t>();
        MessageParcel data;
        MessageParcel reply;
        MessageOption option;
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
        stub->ProcessProto(code, data, reply, option);
    }

    void ProcessDataFuzzTest(FuzzedDataProvider &provider)
    {
        int uid = provider.ConsumeIntegral<int>();
        int pid = provider.ConsumeIntegral<int>();
        MessageParcel data;
        MessageParcel reply;
        std::string sessionName = provider.ConsumeRandomLengthString();
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
        stub->ProcessData(uid, pid, sessionName, data, reply);
    }

    void MarshallingFuzzTest(FuzzedDataProvider &provider)
    {
        Parcel parcel;
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
        stub->Marshalling(parcel);
    }

    void AddDBinderCommAuthFuzzTest(FuzzedDataProvider &provider)
    {
        pid_t pid = static_cast<pid_t>(provider.ConsumeIntegral<int32_t>());
        uid_t uid = static_cast<uid_t>(provider.ConsumeIntegral<int32_t>());
        std::string sessionName = provider.ConsumeRandomLengthString();
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
        stub->AddDBinderCommAuth(pid, uid, sessionName);
    }

    void SaveDBinderDataFuzzTest(FuzzedDataProvider &provider)
    {
        std::string sessionName = provider.ConsumeRandomLengthString();
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
        stub->SaveDBinderData(sessionName);
    }

    void GetAndSaveDBinderDataFuzzTest(FuzzedDataProvider &provider)
    {
        pid_t pid = static_cast<pid_t>(provider.ConsumeIntegral<int32_t>());
        uid_t uid = static_cast<uid_t>(provider.ConsumeIntegral<int32_t>());
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
