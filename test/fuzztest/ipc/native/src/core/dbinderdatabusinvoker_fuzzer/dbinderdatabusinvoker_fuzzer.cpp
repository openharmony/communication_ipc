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

#include "dbinderdatabusinvoker_fuzzer.h"
#define private public
#define protected public
#include "dbinder_base_invoker_process.h"
#include "dbinder_databus_invoker.h"
#undef protected
#undef private
#include "securec.h"

using OHOS::DatabusSocketListener;

namespace OHOS {
static void AcquireHandleFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    int32_t handle = -1;
    if (!parcel.ReadInt32(handle)) {
        return;
    }

    DBinderDatabusInvoker invoker;
    (void)invoker.AcquireHandle(handle);
}

static void ReleaseHandleFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    int32_t handle = -1;
    if (!parcel.ReadInt32(handle)) {
        return;
    }

    DBinderDatabusInvoker invoker;
    (void)invoker.ReleaseHandle(handle);
    invoker.StopWorkThread();
}

static void FlattenObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    DBinderDatabusInvoker invoker;
    invoker.FlattenObject(parcel, nullptr);
}

static void UnflattenObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    DBinderDatabusInvoker invoker;
    (void)invoker.UnflattenObject(parcel);
}

static void ReadFileDescriptorFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    DBinderDatabusInvoker invoker;
    (void)invoker.ReadFileDescriptor(parcel);
}

static void WriteFileDescriptorFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < (sizeof(int32_t) + sizeof(bool))) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    int32_t fd = -1;
    if (!parcel.ReadInt32(fd)) {
        return;
    }

    bool takeOwnership = false;
    if (!parcel.ReadBool(takeOwnership)) {
        return;
    }

    DBinderDatabusInvoker invoker;
    (void)invoker.WriteFileDescriptor(parcel, fd, takeOwnership);
    invoker.GetCallerSid();
    invoker.GetCallerPid();
    invoker.GetCallerRealPid();
    invoker.GetCallerUid();
    invoker.GetCallerTokenID();
    invoker.GetSelfTokenID();
    invoker.GetSelfFirstCallerTokenID();
    invoker.GetStatus();
    invoker.GetClientFd();
    invoker.IsLocalCalling();
    invoker.GetLocalDeviceID();
    invoker.GetCallerDeviceID();
}

static void UpdateClientSessionFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < 0) {
        return;
    }

    std::string serviceName(reinterpret_cast<const char *>(data), size);
    std::string deviceId(reinterpret_cast<const char *>(data), size);
    uint64_t stubIndex = 0;
    uint32_t tokenId = 0;
    auto dbinderSession = std::make_shared<DBinderSessionObject>(serviceName, deviceId, stubIndex, nullptr, tokenId);
    if (dbinderSession == nullptr) {
        return;
    }
    DBinderDatabusInvoker invoker;
    (void)invoker.UpdateClientSession(dbinderSession);
}

static void QueryClientSessionObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    uint32_t databusHandle = -1;
    if (!parcel.ReadUint32(databusHandle)) {
        return;
    }

    DBinderDatabusInvoker invoker;
    (void)invoker.QueryClientSessionObject(databusHandle);
}

static void QueryServerSessionObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    uint32_t handle = -1;
    if (!parcel.ReadUint32(handle)) {
        return;
    }

    DBinderDatabusInvoker invoker;
    (void)invoker.QueryServerSessionObject(handle);
}

static void CreateServerSessionObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(binder_uintptr_t)) {
        return;
    }

    binder_uintptr_t binder = -1;
    if (memcpy_s(&binder, sizeof(binder_uintptr_t), data, sizeof(binder_uintptr_t)) != EOK) {
        return;
    }

    const char *str = reinterpret_cast<const char *>(data + sizeof(binder_uintptr_t));
    const size_t strLen = size - sizeof(binder_uintptr_t);
    std::string serviceName(str, strLen);
    std::string deviceId(str, strLen);
    uint64_t stubIndex = 0;
    uint32_t tokenId = 0;
    auto dbinderSession = std::make_shared<DBinderSessionObject>(serviceName, deviceId, stubIndex, nullptr, tokenId);
    if (dbinderSession == nullptr) {
        return;
    }

    DBinderDatabusInvoker invoker;
    (void)invoker.CreateServerSessionObject(binder, dbinderSession);
}

static void OnDatabusSessionServerSideClosedFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    int32_t socketId = -1;
    if (!parcel.ReadInt32(socketId)) {
        return;
    }

    DBinderDatabusInvoker invoker;
    (void)invoker.OnDatabusSessionServerSideClosed(socketId);
}

static void OnDatabusSessionClientSideClosedFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    int32_t socketId = -1;
    if (!parcel.ReadInt32(socketId)) {
        return;
    }

    DBinderDatabusInvoker invoker;
    (void)invoker.OnDatabusSessionClientSideClosed(socketId);
}

static void OnReceiveNewConnectionFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < (sizeof(int32_t) + sizeof(int) + sizeof(int))) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    int32_t socketId = -1;
    int32_t peerPid = -1;
    int32_t peerUid = -1;
    if (!parcel.ReadInt32(socketId) || !parcel.ReadInt32(peerPid) || !parcel.ReadInt32(peerUid)) {
        return;
    }

    std::string peerName;
    std::string networkId;
    size_t strSize = parcel.GetReadableBytes();
    if (strSize > 0) {
        const char *buf = reinterpret_cast<const char *>(parcel.ReadBuffer(strSize));
        if (buf != nullptr) {
            peerName.assign(buf, strSize);
            networkId.assign(buf, strSize);
        }
    }
    DBinderDatabusInvoker invoker;
    (void)invoker.OnReceiveNewConnection(socketId, peerPid, peerUid, peerName, networkId);
}

static void SetCallingIdentityFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(bool)) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    bool flag = false;
    if (!parcel.ReadBool(flag)) {
        return;
    }

    std::string identity;
    size_t strSize = parcel.GetReadableBytes();
    if (strSize > 0) {
        const char *buf = reinterpret_cast<const char *>(parcel.ReadBuffer(strSize));
        if (buf != nullptr) {
            identity.assign(buf, strSize);
        }
    }

    DBinderDatabusInvoker invoker;
    (void)invoker.SetCallingIdentity(identity, flag);
    (void)invoker.ResetCallingIdentity();
}

static void TranslateIRemoteObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    int32_t cmd = -1;
    if (!parcel.ReadInt32(cmd)) {
        return;
    }

    DBinderDatabusInvoker invoker;
    invoker.TranslateIRemoteObject(cmd, nullptr);
}

static void OnMessageAvailableFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    int32_t socketId = -1;
    if (!parcel.ReadInt32(socketId)) {
        return;
    }

    std::string strData;
    size_t strSize = parcel.GetReadableBytes();
    if (strSize > 0) {
        const char *buf = reinterpret_cast<const char *>(parcel.ReadBuffer(strSize));
        if (buf != nullptr) {
            strData.assign(buf, strSize);
        }
    }

    DBinderDatabusInvoker invoker;
    invoker.OnMessageAvailable(socketId, strData.c_str(), strData.size());
    invoker.OnMessageAvailable(socketId, nullptr, 0);
}

static void TriggerSystemIPCThreadReclaimFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(bool)) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    bool enable = false;
    if (!parcel.ReadBool(enable)) {
        return;
    }

    DBinderDatabusInvoker invoker;
    invoker.TriggerSystemIPCThreadReclaim();
    invoker.EnableIPCThreadReclaim(enable);
}

static void MakeThreadProcessInfoFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    uint32_t handle = 0;
    if (!parcel.ReadUint32(handle)) {
        return;
    }

    std::string strData;
    size_t strSize = parcel.GetReadableBytes();
    if (strSize > 0) {
        const char *buf = reinterpret_cast<const char *>(parcel.ReadBuffer(strSize));
        if (buf != nullptr) {
            strData.assign(buf, strSize);
        }
    }

    DBinderDatabusInvoker invoker;
    (void)invoker.MakeThreadProcessInfo(handle, strData.c_str(), strData.size());
    (void)invoker.MakeThreadProcessInfo(handle, nullptr, 0);
}

static void ProcessTransactionFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    uint32_t listenFd = 0;
    if (!parcel.ReadUint32(listenFd)) {
        return;
    }

    dbinder_transaction_data *tr = new dbinder_transaction_data();
    if (tr == nullptr) {
        return;
    }
    DBinderDatabusInvoker invoker;
    invoker.ProcessTransaction(tr, listenFd);
    delete tr;
}

static void CheckTransactionDataFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    const uint8_t *buf = parcel.ReadBuffer(sizeof(dbinder_transaction_data));
    if (buf == nullptr) {
        return;
    }

    dbinder_transaction_data *tr = new dbinder_transaction_data();
    if (tr == nullptr) {
        return;
    }

    if (memcpy_s(tr, sizeof(dbinder_transaction_data), buf, sizeof(dbinder_transaction_data)) != EOK) {
        delete tr;
        return;
    }

    DBinderDatabusInvoker invoker;
    (void)invoker.CheckTransactionData(tr);
    delete tr;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::AcquireHandleFuzzTest(data, size);
    OHOS::ReleaseHandleFuzzTest(data, size);
    OHOS::FlattenObjectFuzzTest(data, size);
    OHOS::UnflattenObjectFuzzTest(data, size);
    OHOS::ReadFileDescriptorFuzzTest(data, size);
    OHOS::WriteFileDescriptorFuzzTest(data, size);
    OHOS::UpdateClientSessionFuzzTest(data, size);
    OHOS::QueryClientSessionObjectFuzzTest(data, size);
    OHOS::QueryServerSessionObjectFuzzTest(data, size);
    OHOS::CreateServerSessionObjectFuzzTest(data, size);
    OHOS::OnDatabusSessionServerSideClosedFuzzTest(data, size);
    OHOS::OnDatabusSessionClientSideClosedFuzzTest(data, size);
    OHOS::OnReceiveNewConnectionFuzzTest(data, size);
    OHOS::SetCallingIdentityFuzzTest(data, size);
    OHOS::TranslateIRemoteObjectFuzzTest(data, size);
    OHOS::OnMessageAvailableFuzzTest(data, size);
    OHOS::TriggerSystemIPCThreadReclaimFuzzTest(data, size);
    OHOS::MakeThreadProcessInfoFuzzTest(data, size);
    OHOS::ProcessTransactionFuzzTest(data, size);
    OHOS::CheckTransactionDataFuzzTest(data, size);
    return 0;
}
