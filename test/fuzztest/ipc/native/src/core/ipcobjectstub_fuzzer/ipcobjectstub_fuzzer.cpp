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
#include "ipc_object_stub.h"
#include "message_parcel.h"

namespace OHOS {
void IPCObjectStubFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    bool serialInvokeFlag = parcel.ReadBool();
    size_t length = parcel.GetReadableBytes();
    if (length == 0) {
        return;
    }
    const char *bufData = reinterpret_cast<const char *>(parcel.ReadBuffer(length));
    if (bufData == nullptr) {
        return;
    }
    std::string descriptor_str(bufData, length);
    std::u16string descriptor(descriptor_str.begin(), descriptor_str.end());
    IPCObjectStub *ipcObjectStub = new IPCObjectStub(descriptor, serialInvokeFlag);
    delete ipcObjectStub;
}

void DumpFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int fd = parcel.ReadInt32();
    size_t length = parcel.GetReadableBytes();
    if (length == 0) {
        return;
    }
    const char *bufData = reinterpret_cast<const char *>(parcel.ReadBuffer(length));
    if (bufData == nullptr) {
        return;
    }
    std::string descriptor_str(bufData, length);
    std::u16string descriptor(descriptor_str.begin(), descriptor_str.end());
    std::vector<std::u16string> args;
    args.push_back(descriptor);
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.Dump(fd, args);
}

void OnRemoteRequestFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    uint32_t code = parcel.ReadUint32();
    MessageOption option;
    MessageParcel reply;
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.OnRemoteRequest(code, parcel, reply, option);
}

void OnRemoteDumpFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    uint32_t code = parcel.ReadUint32();
    MessageOption option;
    MessageParcel reply;
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.OnRemoteDump(code, parcel, reply, option);
}

void ProcessProtoFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    uint32_t code = parcel.ReadUint32();
    MessageOption option;
    MessageParcel reply;
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.ProcessProto(code, parcel, reply, option);
}

void SetRequestSidFlagFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    bool flag = parcel.ReadBool();
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.SetRequestSidFlag(flag);
}

void GetAndSaveDBinderDataFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    pid_t pid = parcel.ReadInt32();
    uid_t uid = parcel.ReadInt32();
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.GetAndSaveDBinderData(pid, uid);
}

void InvokerThreadFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    uint32_t code = parcel.ReadUint32();
    MessageOption option;
    MessageParcel reply;
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.InvokerThread(code, parcel, reply, option);
}

void NoticeServiceDieFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    MessageOption option;
    MessageParcel reply;
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.NoticeServiceDie(parcel, reply, option);
}

void InvokerDataBusThreadFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    MessageParcel reply;
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.InvokerDataBusThread(parcel, reply);
}

void AddAuthInfoFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    uint32_t code = parcel.ReadUint32();
    MessageParcel reply;
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.AddAuthInfo(parcel, reply, code);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::IPCObjectStubFuzzTest(data, size);
    OHOS::DumpFuzzTest(data, size);
    OHOS::OnRemoteRequestFuzzTest(data, size);
    OHOS::OnRemoteDumpFuzzTest(data, size);
    OHOS::ProcessProtoFuzzTest(data, size);
    OHOS::SetRequestSidFlagFuzzTest(data, size);
    OHOS::GetAndSaveDBinderDataFuzzTest(data, size);
    OHOS::InvokerThreadFuzzTest(data, size);
    OHOS::NoticeServiceDieFuzzTest(data, size);
    OHOS::InvokerDataBusThreadFuzzTest(data, size);
    OHOS::AddAuthInfoFuzzTest(data, size);
    return 0;
}
