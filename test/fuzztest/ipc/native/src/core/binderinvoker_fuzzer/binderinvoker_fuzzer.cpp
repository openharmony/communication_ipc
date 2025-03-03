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

#include "binderinvoker_fuzzer.h"
#include "binder_invoker.h"
#include "ipc_object_stub.h"
#include "message_parcel.h"

namespace OHOS {
void AddDeathRecipientFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int32_t handle = parcel.ReadInt32();
    uintptr_t point = parcel.ReadPointer();
    BinderInvoker invoker;
    
    invoker.AddDeathRecipient(handle, reinterpret_cast<void*>(point));
}

void FlattenObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    BinderInvoker binderInvoker;
    const IRemoteObject* iRemoteObject = parcel.ReadRemoteObject();
    binderInvoker.FlattenObject(parcel, iRemoteObject);
}

void FlushCommandsFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    BinderInvoker binderInvoker;
    IRemoteObject* iRemoteObject = parcel.ReadRemoteObject();
    binderInvoker.FlushCommands(iRemoteObject);
}

void FreeBufferFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    uintptr_t point = parcel.ReadPointer();
    BinderInvoker invoker;
    invoker.FreeBuffer(reinterpret_cast<void*>(point));
}

void GetStrongRefCountForStubFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    uint32_t handle = parcel.ReadUint32();
    BinderInvoker *invoker = new BinderInvoker();
    if (invoker == nullptr) {
        return;
    }
    invoker->GetStrongRefCountForStub(handle);
    delete invoker;
}

void JoinProcessThreadFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    bool result = parcel.ReadBool();
    BinderInvoker invoker;
    invoker.JoinProcessThread(result);
}

void JoinThreadFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    bool result = parcel.ReadBool();
    BinderInvoker invoker;
    invoker.JoinThread(result);
}

void PingServiceFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int32_t handle = parcel.ReadInt32();
    BinderInvoker invoker;
    invoker.PingService(handle);
}

void ReadFileDescriptorFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    BinderInvoker invoker;
    invoker.ReadFileDescriptor(parcel);
}

void RegisteriiFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int32_t prot = parcel.ReadInt32();
    IRemoteInvoker* invoker = nullptr;
    auto creator = [&invoker]() -> IRemoteInvoker* {
        invoker = new (std::nothrow) BinderInvoker();
        if (invoker == nullptr) {
            return nullptr;
        }
        return invoker;
    };
    InvokerFactory::Get().Register(prot, creator);
    if (invoker != nullptr) {
        delete invoker;
        invoker = nullptr;
    }
}

void ReleaseHandleFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int32_t handle = parcel.ReadInt32();
    BinderInvoker invoker;
    invoker.ReleaseHandle(handle);
}

void RemoveDeathRecipientIVFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    BinderInvoker invoker;
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int32_t handle = parcel.ReadInt32();
    void* point = reinterpret_cast<void*>(parcel.ReadPointer());
    invoker.RemoveDeathRecipient(handle, point);
}

void SendReplyFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int32_t result = parcel.ReadInt32();
    BinderInvoker invoker;
    invoker.SendReply(parcel, 0, result);
}

void SendRequestFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel dataParcel;
    MessageParcel reply;
    dataParcel.WriteBuffer(data, size);
    int32_t handle = dataParcel.ReadInt32();
    uint32_t code = dataParcel.ReadUint32();
    BinderInvoker invoker;
    MessageOption option{ MessageOption::TF_ASYNC };
    invoker.SendRequest(handle, code, dataParcel, reply, option);
}

void SetMaxWorkThreadFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int32_t maxThreadNum = parcel.ReadInt32();
    BinderInvoker invoker;
    invoker.SetMaxWorkThread(maxThreadNum);
}

void SetRegistryObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    BinderInvoker invoker;
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    BinderInvoker binderInvoker;
    sptr<IRemoteObject> iRemoteObject = parcel.ReadRemoteObject();
    invoker.SetRegistryObject(iRemoteObject);
}

void SetStatusFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    uint32_t status = parcel.ReadUint32();
    BinderInvoker invoker;
    invoker.SetStatus(status);
}

void TranslateIRemoteObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int32_t cmd = parcel.ReadInt32();
    size_t length = parcel.GetReadableBytes();
    if (length == 0) {
        return;
    }
    const uint8_t *bufData = parcel.ReadBuffer(length);
    if (bufData == nullptr) {
        return;
    }
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
    const std::u16string testStubName = converter.from_bytes(
        reinterpret_cast<const char*>(bufData),
        reinterpret_cast<const char*>(bufData + length)
    );
    BinderInvoker binderInvoker;
    sptr<IRemoteObject> testStub = new IPCObjectStub(testStubName);
    binderInvoker.TranslateIRemoteObject(cmd, testStub);
}

void UnFlattenObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    BinderInvoker binderInvoker;
    binderInvoker.UnflattenObject(parcel);
}

void WriteFileDescriptorFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    int32_t fd = parcel.ReadInt32();
    bool takeOwnership = parcel.ReadBool();
    BinderInvoker invoker;
    
    invoker.WriteFileDescriptor(parcel, fd, takeOwnership);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::AddDeathRecipientFuzzTest(data, size);
    OHOS::FlattenObjectFuzzTest(data, size);
    OHOS::FlushCommandsFuzzTest(data, size);
    OHOS::FreeBufferFuzzTest(data, size);
    OHOS::GetStrongRefCountForStubFuzzTest(data, size);
    OHOS::JoinProcessThreadFuzzTest(data, size);
    OHOS::JoinThreadFuzzTest(data, size);
    OHOS::PingServiceFuzzTest(data, size);
    OHOS::ReadFileDescriptorFuzzTest(data, size);
    OHOS::RegisteriiFuzzTest(data, size);
    OHOS::ReleaseHandleFuzzTest(data, size);
    OHOS::RemoveDeathRecipientIVFuzzTest(data, size);
    OHOS::SendReplyFuzzTest(data, size);
    OHOS::SendRequestFuzzTest(data, size);
    OHOS::SetMaxWorkThreadFuzzTest(data, size);
    OHOS::SetRegistryObjectFuzzTest(data, size);
    OHOS::SetStatusFuzzTest(data, size);
    OHOS::TranslateIRemoteObjectFuzzTest(data, size);
    OHOS::UnFlattenObjectFuzzTest(data, size);
    OHOS::WriteFileDescriptorFuzzTest(data, size);
    return 0;
}
