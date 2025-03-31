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
#define private public
#include "binder_invoker.h"
#undef private
#include "ipc_object_stub.h"
#include "message_parcel.h"

namespace OHOS {
void TransactionFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(binder_transaction_data_secctx)) {
        return;
    }

    BinderInvoker invoker;
    binder_transaction_data_secctx trSecctx = *(reinterpret_cast<const binder_transaction_data_secctx *>(data));
    trSecctx.transaction_data.target.ptr = 0;
    trSecctx.transaction_data.offsets_size = 0;
    trSecctx.transaction_data.flags = 0;
    trSecctx.secctx = 0;
    invoker.Transaction(trSecctx);
}

void AddDeathRecipientFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int32_t handle = parcel.ReadInt32();
    sptr<IRemoteObject> point = parcel.ReadRemoteObject();
    BinderInvoker invoker;
    invoker.AddDeathRecipient(handle, reinterpret_cast<void*>(point.GetRefPtr()));
}

void FlattenObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);

    int handle;
    int proto;
    if (!parcel.ReadInt32(handle) || !parcel.ReadInt32(proto)) {
        return;
    }
    sptr<IRemoteObject> obj = new IPCObjectProxy(handle, u"proxyTest", proto);
    IRemoteObject *object = obj.GetRefPtr();
    BinderInvoker binderInvoker;
    binderInvoker.FlattenObject(parcel, object);
    binderInvoker.UnflattenObject(parcel);
}

void GetCallerInfoFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);

    int32_t status = parcel.ReadInt32();
    pid_t pid = static_cast<pid_t>(parcel.ReadInt32());

    BinderInvoker invoker;
    invoker.SetStatus(status);
    invoker.invokerInfo_.pid = pid;

    invoker.GetCallerSid();
    invoker.GetCallerPid();
    invoker.GetCallerRealPid();
    invoker.GetCallerUid();
    invoker.GetCallerTokenID();
    invoker.GetFirstCallerTokenID();
    invoker.GetSelfTokenID();
    invoker.GetSelfFirstCallerTokenID();
    invoker.IsLocalCalling();
    invoker.GetStatus();
    invoker.GetLocalDeviceID();
    invoker.GetCallerDeviceID();
    invoker.ExitCurrentThread();
}

void SetCallingIdentityFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);

    bool flag = parcel.ReadBool();

    std::string identity;
    size_t length = parcel.GetReadableBytes();
    if (length != 0) {
        const char *bufData = reinterpret_cast<const char *>(parcel.ReadBuffer(length));
        if (bufData == nullptr) {
            return;
        }
        identity.assign(bufData, length);
    }

    BinderInvoker invoker;
    invoker.SetCallingIdentity(identity, flag);
}

void ResetCallingIdentityFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);

    int32_t status = parcel.ReadInt32();
    pid_t pid = static_cast<pid_t>(parcel.ReadInt32());

    BinderInvoker invoker;
    invoker.SetStatus(status);
    invoker.invokerInfo_.pid = pid;

    invoker.ResetCallingIdentity();
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
    BinderInvoker invoker;
    invoker.GetStrongRefCountForStub(handle);
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

void SetRegistryObjectFuzzTest001(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    sptr<IRemoteObject> object = parcel.ReadRemoteObject();
    BinderInvoker invoker;
    invoker.SetRegistryObject(object);
}

void SetRegistryObjectFuzzTest002(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);

    int32_t handle = parcel.ReadInt32();
    int32_t proto = parcel.ReadInt32();
    std::u16string desc;
    size_t length = parcel.GetReadableBytes();
    if (length != 0) {
        const char16_t *bufData = reinterpret_cast<const char16_t *>(parcel.ReadBuffer(length));
        if (bufData == nullptr) {
            return;
        }
        size_t charCount = length / sizeof(char16_t);
        desc.assign(bufData, charCount);
    }

    sptr<IRemoteObject> proxy = new IPCObjectProxy(handle, desc, proto);
    if (proxy == nullptr) {
        return;
    }
    BinderInvoker invoker;
    invoker.SetRegistryObject(proxy);
}

void SetRegistryObjectFuzzTest003(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);

    bool serialInvokeFlag = parcel.ReadBool();
    std::u16string desc;
    size_t length = parcel.GetReadableBytes();
    if (length != 0) {
        const char16_t *bufData = reinterpret_cast<const char16_t *>(parcel.ReadBuffer(length));
        if (bufData == nullptr) {
            return;
        }
        size_t charCount = length / sizeof(char16_t);
        desc.assign(bufData, charCount);
    }

    sptr<IRemoteObject> stub = new IPCObjectStub(desc, serialInvokeFlag);
    if (stub == nullptr) {
        return;
    }
    BinderInvoker invoker;
    invoker.SetRegistryObject(stub);
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

void WriteFileDescriptorFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int32_t fd = parcel.ReadInt32();
    bool takeOwnership = parcel.ReadBool();

    MessageParcel dataParcel;
    BinderInvoker invoker;
    (void)invoker.WriteFileDescriptor(dataParcel, fd, takeOwnership);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::TransactionFuzzTest(data, size);
    OHOS::AddDeathRecipientFuzzTest(data, size);
    OHOS::FlattenObjectFuzzTest(data, size);
    OHOS::GetCallerInfoFuzzTest(data, size);
    OHOS::SetCallingIdentityFuzzTest(data, size);
    OHOS::FlushCommandsFuzzTest(data, size);
    OHOS::FreeBufferFuzzTest(data, size);
    OHOS::GetStrongRefCountForStubFuzzTest(data, size);
    OHOS::JoinProcessThreadFuzzTest(data, size);
    OHOS::PingServiceFuzzTest(data, size);
    OHOS::ReadFileDescriptorFuzzTest(data, size);
    OHOS::RegisteriiFuzzTest(data, size);
    OHOS::ReleaseHandleFuzzTest(data, size);
    OHOS::RemoveDeathRecipientIVFuzzTest(data, size);
    OHOS::SendReplyFuzzTest(data, size);
    OHOS::SendRequestFuzzTest(data, size);
    OHOS::SetMaxWorkThreadFuzzTest(data, size);
    OHOS::SetRegistryObjectFuzzTest001(data, size);
    OHOS::SetRegistryObjectFuzzTest002(data, size);
    OHOS::SetRegistryObjectFuzzTest003(data, size);
    OHOS::SetStatusFuzzTest(data, size);
    OHOS::WriteFileDescriptorFuzzTest(data, size);
    return 0;
}
