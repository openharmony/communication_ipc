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

#include "ipcthreadskeleton_fuzzer.h"
#include "ipc_object_proxy.h"
#include "ipc_thread_skeleton.h"
#include "message_parcel.h"

namespace OHOS {
void GetRemoteInvokerFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int32_t statue = parcel.ReadInt32();
    switch (statue) {
        case IRemoteObject::IF_PROT_DEFAULT:
            IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DEFAULT);
            break;
        case IRemoteObject::IF_PROT_DATABUS:
            IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS);
            break;
        case IRemoteObject::IF_PROT_ERROR:
            IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_ERROR);
            break;
        default:
            break;
    }
}

void GetProxyInvokerFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    sptr<IRemoteObject> object = parcel.ReadRemoteObject();
    IPCThreadSkeleton *skeleton = IPCThreadSkeleton::GetCurrent();
    if (skeleton ==nullptr) {
        return;
    }
    skeleton->GetProxyInvoker(object);
}

void SaveThreadNameFuzzTest(const uint8_t *data, size_t size)
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
    std::string name(bufData, length);
    IPCThreadSkeleton::SaveThreadName(name);
}

void IsInstanceExceptionFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    std::atomic<uint32_t> flag = parcel.ReadUint32();
    IPCThreadSkeleton::IsInstanceException(flag);
}

void SetThreadTypeFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    bool type = parcel.ReadBool();
    if (type) {
        IPCThreadSkeleton::SetThreadType(ThreadType::IPC_THREAD);
    } else {
        IPCThreadSkeleton::SetThreadType(ThreadType::NORMAL_THREAD);
    }
}

void StopWorkThreadFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int32_t statue = parcel.ReadInt32();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    if (current != nullptr) {
        switch (statue) {
            case IRemoteObject::IF_PROT_DEFAULT:
                current->StopWorkThread(IRemoteObject::IF_PROT_DEFAULT);
                break;
            case IRemoteObject::IF_PROT_DATABUS:
                current->StopWorkThread(IRemoteObject::IF_PROT_DATABUS);
                break;
            case IRemoteObject::IF_PROT_ERROR:
                current->StopWorkThread(IRemoteObject::IF_PROT_ERROR);
                break;
            default:
                break;
        }
    }
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::GetRemoteInvokerFuzzTest(data, size);
    OHOS::GetProxyInvokerFuzzTest(data, size);
    OHOS::SaveThreadNameFuzzTest(data, size);
    OHOS::IsInstanceExceptionFuzzTest(data, size);
    OHOS::SetThreadTypeFuzzTest(data, size);
    OHOS::StopWorkThreadFuzzTest(data, size);
    return 0;
}
