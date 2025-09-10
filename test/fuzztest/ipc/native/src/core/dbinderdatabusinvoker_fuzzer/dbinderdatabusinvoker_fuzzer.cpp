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
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#define protected public
#include "dbinder_base_invoker_process.h"
#include "dbinder_databus_invoker.h"
#undef protected
#undef private
#include "securec.h"

using OHOS::DatabusSocketListener;

namespace OHOS {

static constexpr size_t MAX_STR_LEN = 100;

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

dbinder_transaction_data CreateDbinderTransactionData(FuzzedDataProvider &provider)
{
    dbinder_transaction_data data;
    data.sizeOfSelf = sizeof(dbinder_transaction_data);
    data.magic = provider.ConsumeIntegral<__u32>();
    data.version = provider.ConsumeIntegral<__u32>();
    data.cmd = provider.ConsumeIntegral<int>();
    data.code = provider.ConsumeIntegral<__u32>();
    data.flags = provider.ConsumeIntegral<__u32>();
    data.cookie = provider.ConsumeIntegral<__u64>();
    data.seqNumber = provider.ConsumeIntegral<__u64>();
    data.buffer_size = provider.ConsumeIntegral<binder_size_t>();
    data.offsets_size = provider.ConsumeIntegral<binder_size_t>();
    data.offsets = provider.ConsumeIntegral<binder_uintptr_t>();
    return data;
}

std::shared_ptr<DBinderSessionObject> CreateDBinderSessionObject(FuzzedDataProvider &provider)
{
    std::string serviceName = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    std::string serverDeviceId = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
    return std::make_shared<DBinderSessionObject>(serviceName, serverDeviceId, stubIndex, nullptr, tokenId);
}

void GetSessionForProxyFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    std::shared_ptr<DBinderSessionObject> session = CreateDBinderSessionObject(provider);
    sptr<IPCObjectProxy> ipcProxy = sptr<IPCObjectProxy>::MakeSptr(handle);
    if (session == nullptr || ipcProxy == nullptr) {
        return;
    }
    std::string localDeviceId = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    DBinderDatabusInvoker invoker;
    invoker.GetSessionForProxy(ipcProxy, session, localDeviceId);
}

void QueryClientSessionObjectFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t databusHandle = provider.ConsumeIntegral<uint32_t>();
    DBinderDatabusInvoker invoker;
    invoker.QueryClientSessionObject(databusHandle);
}

void QueryServerSessionObjectFuzzTest(FuzzedDataProvider &provider)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    std::shared_ptr<DBinderSessionObject> object = CreateDBinderSessionObject(provider);
    if (object == nullptr) {
        return;
    }
    current->ProxyAttachDBinderSession(handle, object);
    DBinderDatabusInvoker invoker;
    invoker.QueryServerSessionObject(handle);
}

void OnReceiveNewConnectionFuzzTest(FuzzedDataProvider &provider)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    int peerPid = provider.ConsumeIntegral<int>();
    int peerUid = provider.ConsumeIntegral<int>();
    std::string peerName = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    int32_t tokenId = provider.ConsumeIntegral<int32_t>();
    std::string deviceId = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    sptr<IPCObjectStub> stub = sptr<IPCObjectStub>::MakeSptr();
    if (stub == nullptr) {
        return;
    }
    current->AttachCommAuthInfo(stub.GetRefPtr(), peerPid, peerUid, tokenId, deviceId);
    DBinderDatabusInvoker invoker;
    invoker.OnReceiveNewConnection(socketId, peerPid, peerUid, peerName, deviceId);
}

void OnRawDataAvailableFuzzTest(FuzzedDataProvider &provider)
{
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(0, MAX_RAWDATA_SIZE);
    std::vector<char> bytes = provider.ConsumeBytes<char>(bytesSize);
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    uint64_t seqNumber = provider.ConsumeIntegral<uint64_t>();
    DBinderDatabusInvoker invoker;
    invoker.OnRawDataAvailable(socketId, seqNumber, bytes.data(), bytes.size());
}

void OnSendMessageFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<DBinderSessionObject> sessionOfPeer = CreateDBinderSessionObject(provider);
    if (sessionOfPeer == nullptr) {
        return;
    }
    DBinderDatabusInvoker invoker;
    invoker.OnSendMessage(nullptr);
    invoker.OnSendMessage(sessionOfPeer);
}

void SendDataFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<BufferObject> sessionBuff = std::make_shared<BufferObject>();
    if (sessionBuff == nullptr) {
        return;
    }
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    DBinderDatabusInvoker invoker;
    invoker.SendData(sessionBuff, socketId);
}

void OnSendRawDataFuzzTest(FuzzedDataProvider &provider)
{
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    std::shared_ptr<DBinderSessionObject> session = CreateDBinderSessionObject(provider);
    if (session == nullptr) {
        return;
    }
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    session->SetSocketId(socketId);
    DBinderDatabusInvoker invoker;
    invoker.OnSendRawData(nullptr, bytes.data(), bytes.size());
    invoker.OnSendRawData(session, bytes.data(), bytes.size());
}

void FlattenSessionFuzzTest(FuzzedDataProvider &provider)
{
    FlatDBinderSession flatSession;
    std::shared_ptr<DBinderSessionObject> connectSession = CreateDBinderSessionObject(provider);
    if (connectSession == nullptr) {
        return;
    }
    std::string deviceId = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    connectSession->SetDeviceId(deviceId);
    uint32_t binderVersion = provider.ConsumeIntegral<uint32_t>();
    DBinderDatabusInvoker invoker;
    invoker.FlattenSession(reinterpret_cast<unsigned char *>(&flatSession), connectSession, binderVersion);
}

void UnFlattenSessionFuzzTest(FuzzedDataProvider &provider)
{
    FlatDBinderSession flatSession;
    flatSession.stubIndex = provider.ConsumeIntegral<uint64_t>();
    flatSession.version = provider.ConsumeIntegral<uint16_t>();
    flatSession.magic = provider.ConsumeIntegral<uint32_t>();
    flatSession.tokenId = provider.ConsumeIntegral<uint32_t>();
    uint32_t binderVersion = provider.ConsumeIntegral<uint32_t>();
    DBinderDatabusInvoker invoker;
    invoker.UnFlattenSession(reinterpret_cast<unsigned char *>(&flatSession), binderVersion);
}

void UpdateClientSessionFuzzTest(FuzzedDataProvider &provider)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    current->sessionName_ = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    std::shared_ptr<DBinderSessionObject> sessionObject = CreateDBinderSessionObject(provider);
    if (sessionObject == nullptr) {
        return;
    }
    DBinderDatabusInvoker invoker;
    invoker.UpdateClientSession(sessionObject);
}

void OnDatabusSessionClientSideClosedFuzzTest(FuzzedDataProvider &provider)
{
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    DBinderDatabusInvoker invoker;
    invoker.OnDatabusSessionClientSideClosed(socketId);
}

void OnDatabusSessionServerSideClosedFuzzTest(FuzzedDataProvider &provider)
{
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    DBinderDatabusInvoker invoker;
    invoker.OnDatabusSessionServerSideClosed(socketId);
}

void QueryHandleBySessionFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<DBinderSessionObject> session = CreateDBinderSessionObject(provider);
    if (session == nullptr) {
        return;
    }
    DBinderDatabusInvoker invoker;
    invoker.QueryHandleBySession(session);
}

void SetClientFdFuzzTest(FuzzedDataProvider &provider)
{
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    DBinderDatabusInvoker invoker;
    invoker.SetClientFd(fd);
}

void SetCallerDeviceIDFuzzTest(FuzzedDataProvider &provider)
{
    std::string deviceId = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    DBinderDatabusInvoker invoker;
    invoker.SetCallerDeviceID(deviceId);
}

void SetCallerTokenIDFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
    DBinderDatabusInvoker invoker;
    invoker.SetCallerTokenID(tokenId);
}

void CheckAndSetCallerInfoFuzzTest(FuzzedDataProvider &provider)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    uint32_t socketId = provider.ConsumeIntegral<uint32_t>();
    std::shared_ptr<DBinderSessionObject> object = CreateDBinderSessionObject(provider);
    if (object == nullptr) {
        return;
    }
    uint64_t stubIndex = object->GetStubIndex();
    DBinderDatabusInvoker invoker;
    invoker.CheckAndSetCallerInfo(socketId, stubIndex);
    current->StubAttachDBinderSession(socketId, object);
    uint32_t pid = provider.ConsumeIntegral<uint32_t>();
    uint32_t uid = provider.ConsumeIntegral<uint32_t>();
    uint32_t tokenId = object->GetTokenId();
    std::string deviceId = object->GetDeviceId();
    int32_t listenFd = provider.ConsumeIntegral<int32_t>();
    current->AttachAppInfoToStubIndex(pid, uid, tokenId, deviceId, stubIndex, listenFd);
    invoker.CheckAndSetCallerInfo(socketId, stubIndex);
}

void SetCallerInfoFuzzTest(FuzzedDataProvider &provider)
{
    DBinderDatabusInvoker::DBinderBaseInvoker::DBinderCallerInfo callerInfo;
    callerInfo.callerPid = provider.ConsumeIntegral<pid_t>();
    callerInfo.callerUid = provider.ConsumeIntegral<pid_t>();
    callerInfo.clientFd = provider.ConsumeIntegral<int32_t>();
    callerInfo.callerTokenID = provider.ConsumeIntegral<uint64_t>();
    callerInfo.firstTokenID = provider.ConsumeIntegral<uint64_t>();
    callerInfo.callerDeviceID = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    DBinderDatabusInvoker invoker;
    invoker.SetCallerInfo(callerInfo);
}

void ConnectRemoteObject2SessionFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    sptr<IPCObjectProxy> object = sptr<IPCObjectProxy>::MakeSptr(handle);
    if (object == nullptr) {
        return;
    }
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    std::shared_ptr<DBinderSessionObject> sessionObject = CreateDBinderSessionObject(provider);
    if (sessionObject == nullptr) {
        return;
    }
    DBinderDatabusInvoker invoker;
    invoker.ConnectRemoteObject2Session(object.GetRefPtr(), stubIndex, nullptr);
    invoker.ConnectRemoteObject2Session(object.GetRefPtr(), stubIndex, sessionObject);
}

void FlushCommandsFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    sptr<IPCObjectProxy> object = sptr<IPCObjectProxy>::MakeSptr(handle);
    if (object == nullptr) {
        return;
    }
    DBinderDatabusInvoker invoker;
    invoker.FlushCommands(nullptr);
    invoker.FlushCommands(object.GetRefPtr());
}

void HasRawDataPackageFuzzTest001(FuzzedDataProvider &provider)
{
    dbinder_transaction_data data = CreateDbinderTransactionData(provider);
    DBinderDatabusInvoker invoker;
    invoker.HasRawDataPackage(reinterpret_cast<const char *>(&data), sizeof(dbinder_transaction_data));
}

void HasRawDataPackageFuzzTest002(FuzzedDataProvider &provider)
{
    dbinder_transaction_data data;
    data.magic = DBINDER_MAGICWORD;
    data.cmd = BC_SEND_RAWDATA;
    data.sizeOfSelf = provider.ConsumeIntegral<uint32_t>();
    ssize_t len = provider.ConsumeIntegral<ssize_t>();
    DBinderDatabusInvoker invoker;
    invoker.HasRawDataPackage(reinterpret_cast<const char *>(&data), len);

    data.sizeOfSelf = sizeof(dbinder_transaction_data);
    invoker.HasRawDataPackage(reinterpret_cast<const char *>(&data), sizeof(dbinder_transaction_data));
}

void HasCompletePackageFuzzTest001(FuzzedDataProvider &provider)
{
    dbinder_transaction_data data = CreateDbinderTransactionData(provider);
    uint32_t readCursor = 0;
    DBinderDatabusInvoker invoker;
    invoker.HasCompletePackage(reinterpret_cast<const char *>(&data), readCursor, sizeof(dbinder_transaction_data));
}

void HasCompletePackageFuzzTest002(FuzzedDataProvider &provider)
{
    dbinder_transaction_data data;
    data.magic = DBINDER_MAGICWORD;
    data.sizeOfSelf = provider.ConsumeIntegral<uint32_t>();
    data.buffer_size = provider.ConsumeIntegral<binder_size_t>();
    data.offsets = provider.ConsumeIntegral<binder_uintptr_t>();
    data.flags = provider.ConsumeIntegral<uint32_t>();
    data.offsets_size = provider.ConsumeIntegral<binder_size_t>();
    uint32_t readCursor = 0;
    ssize_t len = provider.ConsumeIntegral<ssize_t>();
    DBinderDatabusInvoker invoker;
    invoker.HasCompletePackage(reinterpret_cast<const char *>(&data), readCursor, len);

    data.sizeOfSelf = sizeof(dbinder_transaction_data);
    invoker.HasCompletePackage(reinterpret_cast<const char *>(&data), readCursor, sizeof(dbinder_transaction_data));
}

void NewSessionOfBinderProxyFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<DBinderSessionObject> session = CreateDBinderSessionObject(provider);
    if (session == nullptr) {
        return;
    }
    DBinderDatabusInvoker invoker;
    uint32_t handle = -1;
    invoker.NewSessionOfBinderProxy(handle, nullptr);
    invoker.NewSessionOfBinderProxy(handle, session);
}

void MakeDefaultServerSessionObjectFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<DBinderSessionObject> sessionObject = CreateDBinderSessionObject(provider);
    if (sessionObject == nullptr) {
        return;
    }
    uint64_t stubIndex = sessionObject->GetStubIndex();
    DBinderDatabusInvoker invoker;
    invoker.MakeDefaultServerSessionObject(stubIndex, sessionObject);
}

void SetCallingIdentityFuzzTest(FuzzedDataProvider &provider)
{
    std::string identity = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    bool flag = provider.ConsumeBool();
    DBinderDatabusInvoker invoker;
    invoker.SetCallingIdentity(identity, flag);
}

void CreateServerSessionObjectFuzzTest(FuzzedDataProvider &provider)
{
    std::string serviceName = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    std::string serverDeviceId = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
    std::shared_ptr<DBinderSessionObject> dbinderSession =
        std::make_shared<DBinderSessionObject>(serviceName, serverDeviceId, stubIndex, nullptr, tokenId);
    if (dbinderSession == nullptr) {
        return;
    }
    binder_uintptr_t binder = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
    DBinderDatabusInvoker invoker;
    invoker.CreateServerSessionObject(binder, dbinderSession);
}

void MakeStubIndexByRemoteObjectFuzzTest(FuzzedDataProvider &provider)
{
    int handle = provider.ConsumeIntegral<int>();
    int proto = provider.ConsumeIntegral<int>();
    sptr<IRemoteObject> obj = new (std::nothrow) IPCObjectProxy(handle, u"proxyTest", proto);
    if (obj == nullptr) {
        return;
    }
    DBinderDatabusInvoker invoker;
    invoker.MakeStubIndexByRemoteObject(obj.GetRefPtr());
}

void GetCallerInfoFuzzTest(FuzzedDataProvider &provider)
{
    DBinderDatabusInvoker::DBinderBaseInvoker::DBinderCallerInfo callerInfo;
    callerInfo.callerPid = provider.ConsumeIntegral<pid_t>();
    callerInfo.callerUid = provider.ConsumeIntegral<pid_t>();
    callerInfo.clientFd = provider.ConsumeIntegral<int32_t>();
    callerInfo.callerTokenID = provider.ConsumeIntegral<uint64_t>();
    callerInfo.firstTokenID = provider.ConsumeIntegral<uint64_t>();
    callerInfo.callerDeviceID = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    DBinderDatabusInvoker invoker;
    invoker.GetCallerInfo(callerInfo);
}

void SetCallerPidFuzzTest(FuzzedDataProvider &provider)
{
    pid_t pid = provider.ConsumeIntegral<pid_t>();
    DBinderDatabusInvoker invoker;
    invoker.SetCallerPid(pid);
}

void SetCallerUidFuzzTest(FuzzedDataProvider &provider)
{
    pid_t uid = provider.ConsumeIntegral<pid_t>();
    DBinderDatabusInvoker invoker;
    invoker.SetCallerUid(uid);
}

void SetStatusFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t status = provider.ConsumeIntegral<uint32_t>();
    DBinderDatabusInvoker invoker;
    invoker.SetStatus(status);
}

void WriteFileDescriptorFuzzTest(FuzzedDataProvider &provider)
{
    Parcel parcel;
    int fd = provider.ConsumeIntegral<int>();
    bool takeOwnership = provider.ConsumeBool();
    DBinderDatabusInvoker invoker;
    invoker.WriteFileDescriptor(parcel, fd, takeOwnership);
}

void AuthSession2ProxyFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t handle = 0;
    DBinderDatabusInvoker invoker;
    invoker.AuthSession2Proxy(handle, nullptr);
}

void OnMessageAvailableFuzzTest(FuzzedDataProvider &provider)
{
    dbinder_transaction_data data;
    data.magic = provider.ConsumeIntegral<uint32_t>();
    data.cmd = provider.ConsumeIntegral<int>();
    data.sizeOfSelf = sizeof(dbinder_transaction_data);
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    DBinderDatabusInvoker invoker;
    invoker.OnMessageAvailable(socketId, reinterpret_cast<const char *>(&data), sizeof(dbinder_transaction_data));
}

void DBinderDatabusInvokerTwoFuzzTest(FuzzedDataProvider &provider)
{
    OHOS::HasRawDataPackageFuzzTest001(provider);
    OHOS::HasRawDataPackageFuzzTest002(provider);
    OHOS::HasCompletePackageFuzzTest001(provider);
    OHOS::HasCompletePackageFuzzTest002(provider);
    OHOS::NewSessionOfBinderProxyFuzzTest(provider);
    OHOS::MakeDefaultServerSessionObjectFuzzTest(provider);
    OHOS::SetCallingIdentityFuzzTest(provider);
    OHOS::CreateServerSessionObjectFuzzTest(provider);
    OHOS::MakeStubIndexByRemoteObjectFuzzTest(provider);
    OHOS::GetCallerInfoFuzzTest(provider);
    OHOS::SetCallerPidFuzzTest(provider);
    OHOS::SetCallerUidFuzzTest(provider);
    OHOS::SetStatusFuzzTest(provider);
    OHOS::WriteFileDescriptorFuzzTest(provider);
    OHOS::AuthSession2ProxyFuzzTest(provider);
    OHOS::OnMessageAvailableFuzzTest(provider);
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
    OHOS::OnMessageAvailableFuzzTest(data, size);
    OHOS::TriggerSystemIPCThreadReclaimFuzzTest(data, size);
    OHOS::MakeThreadProcessInfoFuzzTest(data, size);
    OHOS::ProcessTransactionFuzzTest(data, size);
    OHOS::CheckTransactionDataFuzzTest(data, size);

    FuzzedDataProvider provider(data, size);
    OHOS::GetSessionForProxyFuzzTest(provider);
    OHOS::QueryClientSessionObjectFuzzTest(provider);
    OHOS::QueryServerSessionObjectFuzzTest(provider);
    OHOS::OnReceiveNewConnectionFuzzTest(provider);
    OHOS::OnRawDataAvailableFuzzTest(provider);
    OHOS::OnSendMessageFuzzTest(provider);
    OHOS::SendDataFuzzTest(provider);
    OHOS::OnSendRawDataFuzzTest(provider);
    OHOS::FlattenSessionFuzzTest(provider);
    OHOS::UnFlattenSessionFuzzTest(provider);
    OHOS::UpdateClientSessionFuzzTest(provider);
    OHOS::OnDatabusSessionClientSideClosedFuzzTest(provider);
    OHOS::OnDatabusSessionServerSideClosedFuzzTest(provider);
    OHOS::QueryHandleBySessionFuzzTest(provider);
    OHOS::SetClientFdFuzzTest(provider);
    OHOS::SetCallerDeviceIDFuzzTest(provider);
    OHOS::SetCallerTokenIDFuzzTest(provider);
    OHOS::CheckAndSetCallerInfoFuzzTest(provider);
    OHOS::SetCallerInfoFuzzTest(provider);
    OHOS::ConnectRemoteObject2SessionFuzzTest(provider);
    OHOS::FlushCommandsFuzzTest(provider);
    OHOS::DBinderDatabusInvokerTwoFuzzTest(provider);
    return 0;
}
