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
#include "dbinder_callback_stub.h"
#include "message_parcel.h"

namespace OHOS {
void DBinderCallbackStubFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    uint64_t stubIndex = parcel.ReadUint64();
    uint32_t handle = parcel.ReadUint32();
    uint32_t tokenId = parcel.ReadUint32();
    size_t length = parcel.GetReadableBytes();
    if (length == 0) {
        return;
    }
    const char *bufData = reinterpret_cast<const char *>(parcel.ReadBuffer(length));
    if (bufData == nullptr) {
        return;
    }
    std::string service(bufData, length);
    std::string device(bufData, length);
    std::string localDevice(bufData, length);

    auto stub = new DBinderCallbackStub(service, device, localDevice, stubIndex, handle, tokenId);
    delete stub;
}

void MarshallingFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    uint64_t stubIndex = parcel.ReadUint64();
    uint32_t handle = parcel.ReadUint32();
    uint32_t tokenId = parcel.ReadUint32();
    size_t length = parcel.GetReadableBytes();
    if (length == 0) {
        return;
    }
    const char *bufData = reinterpret_cast<const char *>(parcel.ReadBuffer(length));
    if (bufData == nullptr) {
        return;
    }
    std::string service(bufData, length);
    std::string device(bufData, length);
    std::string localDevice(bufData, length);
    auto stub = new DBinderCallbackStub(service, device, localDevice, stubIndex, handle, tokenId);

    stub->Marshalling(parcel);
    delete stub;
}

void MarshallingPSFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    sptr<IRemoteObject> testStub = parcel.ReadRemoteObject();

    DBinderCallbackStub::Marshalling(parcel, testStub);
}

void GetAndSaveDBinderDataFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    uint64_t stubIndex = parcel.ReadUint64();
    uint32_t handle = parcel.ReadUint32();
    uint32_t tokenId = parcel.ReadUint32();
    int32_t uid = parcel.ReadInt32();
    int32_t pid = parcel.ReadInt32();
    size_t length = parcel.GetReadableBytes();
    if (length == 0) {
        return;
    }
    const char *bufData = reinterpret_cast<const char *>(parcel.ReadBuffer(length));
    if (bufData == nullptr) {
        return;
    }
    std::string service(bufData, length);
    std::string device(bufData, length);
    std::string localDevice(bufData, length);

    auto stub = new DBinderCallbackStub(service, device, localDevice, stubIndex, handle, tokenId);

    stub->GetAndSaveDBinderData(pid, uid);
    delete stub;
}

void ProcessProtoFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    uint64_t stubIndex = parcel.ReadUint64();
    uint32_t handle = parcel.ReadUint32();
    uint32_t tokenId = parcel.ReadUint32();
    uint32_t code = parcel.ReadUint32();
    size_t length = parcel.GetReadableBytes();
    if (length == 0) {
        return;
    }
    const char *bufData = reinterpret_cast<const char *>(parcel.ReadBuffer(length));
    if (bufData == nullptr) {
        return;
    }
    std::string service(bufData, length);
    std::string device(bufData, length);
    std::string localDevice(bufData, length);

    auto stub = new DBinderCallbackStub(service, device, localDevice, stubIndex, handle, tokenId);
    MessageOption option;

    stub->ProcessProto(code, parcel, parcel, option);
    delete stub;
}

void OnRemoteRequestFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    uint64_t stubIndex = parcel.ReadUint64();
    uint32_t handle = parcel.ReadUint32();
    uint32_t tokenId = parcel.ReadUint32();
    uint32_t code = parcel.ReadUint32();
    size_t length = parcel.GetReadableBytes();
    if (length == 0) {
        return;
    }
    const char *bufData = reinterpret_cast<const char *>(parcel.ReadBuffer(length));
    if (bufData == nullptr) {
        return;
    }
    std::string service(bufData, length);
    std::string device(bufData, length);
    std::string localDevice(bufData, length);

    auto stub = new DBinderCallbackStub(service, device, localDevice, stubIndex, handle, tokenId);
    MessageOption option;

    stub->OnRemoteRequest(code, parcel, parcel, option);
    delete stub;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::DBinderCallbackStubFuzzTest(data, size);
    OHOS::MarshallingFuzzTest(data, size);
    OHOS::MarshallingPSFuzzTest(data, size);
    OHOS::GetAndSaveDBinderDataFuzzTest(data, size);
    OHOS::ProcessProtoFuzzTest(data, size);
    OHOS::OnRemoteRequestFuzzTest(data, size);
    return 0;
}
