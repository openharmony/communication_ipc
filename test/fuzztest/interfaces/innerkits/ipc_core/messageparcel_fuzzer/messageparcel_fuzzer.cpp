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

#include "messageparcel_fuzzer.h"
#include "ipc_object_stub.h"
#include "iremote_object.h"
#include "message_parcel.cpp"
#include "message_parcel.h"
#include "sys_binder.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>

namespace OHOS {
void WriteRawDataFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteRawData((const void *)data, size);
}

void WriteRemoteObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    const sptr<IRemoteObject> object = parcel.ReadRemoteObject();
    parcel.WriteRemoteObject(object);
}

void WriteInterfaceTokenFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    size_t length = parcel.GetReadableBytes();
    if (length == 0) {
        return;
    }
    const char *bufData = reinterpret_cast<const char *>(parcel.ReadBuffer(length));
    if (bufData == nullptr) {
        return;
    }
    std::string tokenStr(bufData, length);
    std::u16string token(tokenStr.begin(), tokenStr.end());
    parcel.WriteInterfaceToken(token);
}

void WriteFileDescriptorFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int fd = parcel.ReadInt32();
    parcel.WriteFileDescriptor(fd);
}

void ReadRawDataFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    size_t len = parcel.ReadUint64();
    parcel.ReadRawData(len);
}

void PrintBufferFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteRawData((const void *)data, size);
    parcel.PrintBuffer(__FUNCTION__, __LINE__);
}

void AcquireObjectFuzzTest(FuzzedDataProvider &provider)
{
    flat_binder_object flat;
    flat.hdr.type = provider.ConsumeIntegralInRange<uint32_t>(BINDER_TYPE_FDA, BINDER_TYPE_WEAK_HANDLE);
    flat.flags = provider.ConsumeIntegral<uint32_t>();
    flat.handle = provider.ConsumeIntegral<binder_uintptr_t>();
    flat.cookie = 0;
    AcquireObject(&flat, nullptr);
}

void WriteDBinderProxyFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    sptr<IPCObjectProxy> object = sptr<IPCObjectProxy>::MakeSptr(handle);
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    parcel.WriteDBinderProxy(object, handle, stubIndex);
}

void WriteRemoteObjectFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    sptr<IPCObjectProxy> proxy = sptr<IPCObjectProxy>::MakeSptr(handle);
    parcel.WriteRemoteObject(proxy);
    sptr<IPCObjectStub> stub = sptr<IPCObjectStub>::MakeSptr();
    parcel.WriteRemoteObject(stub);
}

void WriteInterfaceTokenFuzzTest(FuzzedDataProvider &provider)
{
    std::string interfaceToken = provider.ConsumeRandomLengthString();
    std::u16string interfaceToken16(interfaceToken.begin(), interfaceToken.end());
    MessageParcel parcel;
    parcel.WriteInterfaceToken(interfaceToken16);
}

void WriteRawDataFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    size_t bytesSize =
        provider.ConsumeIntegralInRange<size_t>(MessageParcel::MIN_RAWDATA_SIZE, MessageParcel::MAX_RAWDATA_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    parcel.WriteRawData(bytes.data(), bytes.size());
}

void RestoreRawDataFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    size_t size = provider.ConsumeIntegral<size_t>();
    std::shared_ptr<char> rawData = std::make_shared<char>();
    parcel.RestoreRawData(nullptr, size);
    parcel.RestoreRawData(rawData, size);
}

void ReadRawDataFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    size_t bytesSize =
        provider.ConsumeIntegralInRange<size_t>(MessageParcel::MIN_RAWDATA_SIZE, MessageParcel::MAX_RAWDATA_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    bytesSize = bytes.size();
    parcel.WriteRawData(bytes.data(), bytesSize);
    parcel.ReadRawData(bytesSize);
}

void WriteAshmemFuzzTest(FuzzedDataProvider &provider)
{
    std::string name = provider.ConsumeRandomLengthString();
    int memorySize = provider.ConsumeIntegral<int>();
    sptr<Ashmem> ashmem = Ashmem::CreateAshmem(name.c_str(), memorySize);
    if (ashmem == nullptr) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteAshmem(ashmem);
}

void AppendFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    MessageParcel dataParcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    dataParcel.WriteBuffer(bytes.data(), bytes.size());
    parcel.Append(dataParcel);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::WriteRawDataFuzzTest(data, size);
    OHOS::WriteRemoteObjectFuzzTest(data, size);
    OHOS::WriteInterfaceTokenFuzzTest(data, size);
    OHOS::WriteFileDescriptorFuzzTest(data, size);
    OHOS::ReadRawDataFuzzTest(data, size);
    OHOS::PrintBufferFuzzTest(data, size);

    FuzzedDataProvider provider(data, size);
    OHOS::AcquireObjectFuzzTest(provider);
    OHOS::WriteDBinderProxyFuzzTest(provider);
    OHOS::WriteRemoteObjectFuzzTest(provider);
    OHOS::WriteInterfaceTokenFuzzTest(provider);
    OHOS::WriteRawDataFuzzTest(provider);
    OHOS::RestoreRawDataFuzzTest(provider);
    OHOS::ReadRawDataFuzzTest(provider);
    OHOS::WriteAshmemFuzzTest(provider);
    OHOS::AppendFuzzTest(provider);
    return 0;
}
