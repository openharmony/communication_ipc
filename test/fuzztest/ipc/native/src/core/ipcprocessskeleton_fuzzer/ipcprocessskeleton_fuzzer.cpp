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

#include "ipcprocessskeleton_fuzzer.h"
#define private public
#include "ipc_process_skeleton.h"
#undef private
#include "message_parcel.h"

namespace OHOS {
void ConvertToSecureStringFuzzTest(const uint8_t *data, size_t size)
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
    std::string secureString(bufData, length);
    IPCProcessSkeleton::ConvertToSecureString(secureString);
}

void ConvertChannelID2IntFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int64_t databusChannelId = parcel.ReadInt64();
    IPCProcessSkeleton::ConvertChannelID2Int(databusChannelId);
}

void IsHandleMadeByUserFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    uint32_t handle = parcel.ReadUint32();
    IPCProcessSkeleton::IsHandleMadeByUser(handle);
}

void SetIPCProxyLimitFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int ipcProxyLimitNum = parcel.ReadInt32();
    std::function<void(uint64_t num)> callback;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    current->SetIPCProxyLimit(ipcProxyLimitNum, callback);
}

void SetMaxWorkThreadFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int maxThreadNum = parcel.ReadInt32();
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->SetMaxWorkThread(maxThreadNum);
}

void MakeHandleDescriptorFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int handle = parcel.ReadInt32();
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->MakeHandleDescriptor(handle);
}

void OnThreadTerminatedFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    std::string threadName(reinterpret_cast<const char *>(data), size);
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->OnThreadTerminated(threadName);
}

void SpawnThreadFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int policy = parcel.ReadInt32();
    int proto = parcel.ReadInt32();
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(ipcSktPtr->threadPool_->mutex_);
    if (ipcSktPtr->threadPool_->threads_.size() < IPCProcessSkeleton::DEFAULT_WORK_THREAD_NUM) {
        (void)ipcSktPtr->SpawnThread(policy, proto);
    }
}

void FindOrNewObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int handle = parcel.ReadInt32();
    const dbinder_negotiation_data *dbinderData = nullptr;
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->FindOrNewObject(handle, dbinderData);
}

void IsContainsObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    sptr<IRemoteObject> object = parcel.ReadRemoteObject();
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->IsContainsObject(object);
}

void QueryObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    bool lockFlag = parcel.ReadBool();
    const char16_t *charData = reinterpret_cast<const char16_t *>(data);
    size_t charCount = size / sizeof(char16_t);
    std::u16string descriptor(charData, charCount);
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->QueryObject(descriptor, lockFlag);
}

void AttachObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    bool lockFlag = parcel.ReadBool();
    sptr<IRemoteObject> object = parcel.ReadRemoteObject();
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->AttachObject(object, lockFlag);
}

void DetachObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    sptr<IRemoteObject> object = parcel.ReadRemoteObject();
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->DetachObject(object);
}

void GetProxyObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int handle = parcel.ReadInt32();
    bool newFlag = parcel.ReadBool();
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->GetProxyObject(handle, newFlag);
}

void SetRegistryObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    sptr<IRemoteObject> object = parcel.ReadRemoteObject();
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    ipcSktPtr->SetRegistryObject(object);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::ConvertToSecureStringFuzzTest(data, size);
    OHOS::ConvertChannelID2IntFuzzTest(data, size);
    OHOS::IsHandleMadeByUserFuzzTest(data, size);
    OHOS::SetIPCProxyLimitFuzzTest(data, size);
    OHOS::SetMaxWorkThreadFuzzTest(data, size);
    OHOS::MakeHandleDescriptorFuzzTest(data, size);
    OHOS::OnThreadTerminatedFuzzTest(data, size);
    OHOS::SpawnThreadFuzzTest(data, size);
    OHOS::FindOrNewObjectFuzzTest(data, size);
    OHOS::IsContainsObjectFuzzTest(data, size);
    OHOS::QueryObjectFuzzTest(data, size);
    OHOS::AttachObjectFuzzTest(data, size);
    OHOS::DetachObjectFuzzTest(data, size);
    OHOS::GetProxyObjectFuzzTest(data, size);
    OHOS::SetRegistryObjectFuzzTest(data, size);
    return 0;
}
