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

#include "dbindersessionobject_fuzzer.h"
#include "dbinder_session_object.h"
#include "message_parcel.h"

namespace OHOS {
void DBinderSessionObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);

    uint64_t stubIndex = parcel.ReadUint64();
    uint32_t tokenId = parcel.ReadUint32();
    size_t length = parcel.GetReadableBytes();
    if (length == 0) {
        return;
    }
    const char *bufData = reinterpret_cast<const char *>(parcel.ReadBuffer(length));
    if (bufData == nullptr) {
        return;
    }
    std::string serviceName(bufData, length);
    std::string serverDeviceId(bufData, length);
    IPCObjectProxy *proxy = nullptr;

    DBinderSessionObject object(serviceName, serverDeviceId, stubIndex, proxy, tokenId);
}

void SetServiceNameFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);

    uint64_t stubIndex = parcel.ReadUint64();
    uint32_t tokenId = parcel.ReadUint32();
    size_t length = parcel.GetReadableBytes();
    if (length == 0) {
        return;
    }
    const char *bufData = reinterpret_cast<const char *>(parcel.ReadBuffer(length));
    if (bufData == nullptr) {
        return;
    }
    std::string serviceName(bufData, length);
    std::string serverDeviceId(bufData, length);
    IPCObjectProxy *proxy = nullptr;

    DBinderSessionObject object(serviceName, serverDeviceId, stubIndex, proxy, tokenId);
    object.SetServiceName(serviceName);
}

void SetDeviceIdFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);

    uint64_t stubIndex = parcel.ReadUint64();
    uint32_t tokenId = parcel.ReadUint32();
    size_t length = parcel.GetReadableBytes();
    if (length == 0) {
        return;
    }
    const char *bufData = reinterpret_cast<const char *>(parcel.ReadBuffer(length));
    if (bufData == nullptr) {
        return;
    }
    std::string serviceName(bufData, length);
    std::string serverDeviceId(bufData, length);
    IPCObjectProxy *proxy = nullptr;

    DBinderSessionObject object(serviceName, serverDeviceId, stubIndex, proxy, tokenId);
    object.SetDeviceId(serverDeviceId);
}

void SetProxyFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);

    uint64_t stubIndex = parcel.ReadUint64();
    uint32_t tokenId = parcel.ReadUint32();
    size_t length = parcel.GetReadableBytes();
    if (length == 0) {
        return;
    }
    const char *bufData = reinterpret_cast<const char *>(parcel.ReadBuffer(length));
    if (bufData == nullptr) {
        return;
    }
    std::string serviceName(bufData, length);
    std::string serverDeviceId(bufData, length);
    IPCObjectProxy *proxy = nullptr;

    DBinderSessionObject object(serviceName, serverDeviceId, stubIndex, proxy, tokenId);
    object.SetProxy(proxy);
}

void SetSocketIdFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);

    uint64_t stubIndex = parcel.ReadUint64();
    uint32_t tokenId = parcel.ReadUint32();
    int32_t socketId = parcel.ReadInt32();
    size_t length = parcel.GetReadableBytes();
    if (length == 0) {
        return;
    }
    const char *bufData = reinterpret_cast<const char *>(parcel.ReadBuffer(length));
    if (bufData == nullptr) {
        return;
    }
    std::string serviceName(bufData, length);
    std::string serverDeviceId(bufData, length);
    IPCObjectProxy *proxy = nullptr;

    DBinderSessionObject object(serviceName, serverDeviceId, stubIndex, proxy, tokenId);
    object.SetSocketId(socketId);
}

void SetPeerPidFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);

    uint64_t stubIndex = parcel.ReadUint64();
    uint32_t tokenId = parcel.ReadUint32();
    int32_t pid = parcel.ReadInt32();
    size_t length = parcel.GetReadableBytes();
    if (length == 0) {
        return;
    }
    const char *bufData = reinterpret_cast<const char *>(parcel.ReadBuffer(length));
    if (bufData == nullptr) {
        return;
    }
    std::string serviceName(bufData, length);
    std::string serverDeviceId(bufData, length);
    IPCObjectProxy *proxy = nullptr;

    DBinderSessionObject object(serviceName, serverDeviceId, stubIndex, proxy, tokenId);
    object.SetPeerPid(pid);
}

void SetPeerUidFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);

    uint64_t stubIndex = parcel.ReadUint64();
    uint32_t tokenId = parcel.ReadUint32();
    int32_t uid = parcel.ReadInt32();
    size_t length = parcel.GetReadableBytes();
    if (length == 0) {
        return;
    }
    const char *bufData = reinterpret_cast<const char *>(parcel.ReadBuffer(length));
    if (bufData == nullptr) {
        return;
    }
    std::string name(bufData, length);
    std::string serviceName(bufData, length);
    std::string serverDeviceId(bufData, length);
    IPCObjectProxy *proxy = nullptr;

    DBinderSessionObject object(serviceName, serverDeviceId, stubIndex, proxy, tokenId);
    object.SetPeerUid(uid);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::DBinderSessionObjectFuzzTest(data, size);
    OHOS::SetServiceNameFuzzTest(data, size);
    OHOS::SetDeviceIdFuzzTest(data, size);
    OHOS::SetProxyFuzzTest(data, size);
    OHOS::SetSocketIdFuzzTest(data, size);
    OHOS::SetPeerPidFuzzTest(data, size);
    OHOS::SetPeerUidFuzzTest(data, size);
    return 0;
}
