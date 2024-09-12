/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "dbinder_databus_invoker.h"

#include <cinttypes>
#include "string_ex.h"
#include "securec.h"
#include "sys_binder.h"

#include "databus_socket_listener.h"
#include "dbinder_error_code.h"
#include "ipc_object_stub.h"
#include "ipc_object_proxy.h"
#include "ipc_process_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "ipc_debug.h"
#include "log_tags.h"

namespace OHOS {
using namespace OHOS::HiviewDFX;
DBinderDatabusInvoker::DBinderDatabusInvoker()
    : stopWorkThread_(false), callerPid_(getpid()), callerUid_(getuid()), callerDeviceID_(""),
    callerTokenID_(0), firstTokenID_(0), status_(0)
{
}

DBinderDatabusInvoker::~DBinderDatabusInvoker()
{
}

bool DBinderDatabusInvoker::AcquireHandle(int32_t handle)
{
    ZLOGI(LOG_LABEL, "handle:%{public}d", handle);
    return true;
}

bool DBinderDatabusInvoker::ReleaseHandle(int32_t handle)
{
    ZLOGI(LOG_LABEL, "handle:%{public}d", handle);
    return true;
}

std::shared_ptr<DBinderSessionObject> DBinderDatabusInvoker::NewSessionOfBinderProxy(uint32_t handle,
    std::shared_ptr<DBinderSessionObject> session)
{
    if (session == nullptr) {
        ZLOGE(LOG_LABEL, "remote session is nullptr");
        DfxReportFailHandleEvent(DbinderErrorCode::RPC_DRIVER, handle, RADAR_ERR_INVALID_DATA, __FUNCTION__);
        return nullptr;
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "IPCProcessSkeleton is nullptr");
        DfxReportFailHandleEvent(DbinderErrorCode::RPC_DRIVER, handle, RADAR_IPC_PROCESS_SKELETON_NULL, __FUNCTION__);
        return nullptr;
    }
    sptr<IPCObjectProxy> ipcProxy = reinterpret_cast<IPCObjectProxy *>(current->FindOrNewObject(handle).GetRefPtr());
    if (ipcProxy == nullptr) {
        ZLOGE(LOG_LABEL, "attempt to send a invalid handle:%{public}u", handle);
        DfxReportFailHandleEvent(DbinderErrorCode::RPC_DRIVER, handle, RADAR_SEND_INVALID_HANDLE, __FUNCTION__);
        return nullptr;
    }

    if (ipcProxy->GetProto() != IRemoteObject::IF_PROT_BINDER) {
        ZLOGE(LOG_LABEL, "attempt to send a distributed proxy, handle:%{public}u", handle);
        DfxReportFailHandleEvent(DbinderErrorCode::RPC_DRIVER, handle, RADAR_SEND_DISTRIBUTED_PROXY, __FUNCTION__);
        return nullptr;
    }

    std::string localDeviceID = current->GetLocalDeviceID();
    if (localDeviceID.empty()) {
        ZLOGE(LOG_LABEL, "get localDeviceID error, handle:%{public}u", handle);
    }

    return GetSessionForProxy(ipcProxy, session, localDeviceID);
}

std::shared_ptr<DBinderSessionObject> DBinderDatabusInvoker::GetSessionForProxy(sptr<IPCObjectProxy> ipcProxy,
    std::shared_ptr<DBinderSessionObject> session, const std::string &localDeviceID)
{
    uint32_t handle = ipcProxy->GetHandle();
    std::string sessionName = ipcProxy->GetSessionName();
    if (sessionName.empty()) {
        ZLOGE(LOG_LABEL, "get bus name error, handle:%{public}u", handle);
        DfxReportFailHandleEvent(DbinderErrorCode::RPC_DRIVER, handle, RADAR_GET_SESSION_NAME_FAIL, __FUNCTION__);
        return nullptr;
    }
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteUint32(IRemoteObject::DATABUS_TYPE) || !data.WriteString(localDeviceID) ||
        !data.WriteUint32(session->GetPeerPid()) || !data.WriteUint32(session->GetPeerUid()) ||
        !data.WriteString(session->GetDeviceId()) || !data.WriteString(sessionName) ||
        !data.WriteUint32(session->GetTokenId())) {
        ZLOGE(LOG_LABEL, "write to parcel fail, handle:%{public}u", handle);
        DfxReportFailHandleEvent(DbinderErrorCode::RPC_DRIVER, handle, RADAR_WRITE_TO_PARCEL_FAIL, __FUNCTION__);
        return nullptr;
    }
    int err = ipcProxy->InvokeListenThread(data, reply);
    if (err != ERR_NONE) {
        ZLOGE(LOG_LABEL, "start service listen error:%{public}d handle:%{public}u", err, handle);
        DfxReportFailHandleEvent(DbinderErrorCode::RPC_DRIVER, handle, RADAR_START_LISTEN_FAIL, __FUNCTION__);
        return nullptr;
    }

    uint64_t stubIndex = reply.ReadUint64();
    if (stubIndex == 0) {
        ZLOGE(LOG_LABEL, "stubindex error:%{public}" PRIu64 " handle:%{public}u", stubIndex, handle);
        DfxReportFailHandleEvent(DbinderErrorCode::RPC_DRIVER, handle, RADAR_STUB_INVALID, __FUNCTION__);
        return nullptr;
    }
    std::string serverName = reply.ReadString();
    std::string deviceId = reply.ReadString();
    uint32_t peerTokenId = reply.ReadUint32();

    ZLOGI(LOG_LABEL, "serverName:%{public}s stubIndex:%{public}" PRIu64 " peerTokenId:%{public}u deviceId:%{public}s",
        serverName.c_str(), stubIndex, peerTokenId, IPCProcessSkeleton::ConvertToSecureString(deviceId).c_str());
    std::shared_ptr<DBinderSessionObject> connectSession =
        std::make_shared<DBinderSessionObject>(serverName, deviceId, stubIndex, nullptr, peerTokenId);
    if (connectSession == nullptr) {
        ZLOGE(LOG_LABEL, "new server session fail, handle:%{public}u", handle);
        DfxReportFailHandleEvent(DbinderErrorCode::RPC_DRIVER, handle, RADAR_NEW_SERVER_SESSION_FAIL, __FUNCTION__);
        return nullptr;
    }

    return connectSession;
}

bool DBinderDatabusInvoker::AuthSession2Proxy(uint32_t handle, const std::shared_ptr<DBinderSessionObject> session)
{
    if (session == nullptr) {
        ZLOGE(LOG_LABEL, "remote session is nullptr, handle:%{public}u", handle);
        return false;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteUint32(session->GetPeerPid()) || !data.WriteUint32(session->GetPeerUid()) ||
        !data.WriteString(session->GetDeviceId()) || !data.WriteUint64(session->GetStubIndex()) ||
        !data.WriteUint32(session->GetTokenId())) {
        ZLOGE(LOG_LABEL, "write to MessageParcel fail, handle:%{public}u", handle);
        return false;
    }

    int err = SendRequest(handle, DBINDER_ADD_COMMAUTH, data, reply, option);
    if (err != ERR_NONE) {
        ZLOGE(LOG_LABEL, "send auth info to remote fail, handle:%{public}u", handle);
        return false;
    }
    return true;
}

std::shared_ptr<DBinderSessionObject> DBinderDatabusInvoker::QuerySessionOfBinderProxy(uint32_t handle,
    std::shared_ptr<DBinderSessionObject> session)
{
    if (AuthSession2Proxy(handle, session) != true) {
        ZLOGE(LOG_LABEL, "auth handle:%{public}u to socketId failed, socketId:%{public}d", handle,
            session->GetSocketId());
        return nullptr;
    }
    return QueryServerSessionObject(handle);
}

std::shared_ptr<DBinderSessionObject> DBinderDatabusInvoker::QueryClientSessionObject(uint32_t databusHandle)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "IPCProcessSkeleton is nullptr");
        return nullptr;
    }
    std::shared_ptr<DBinderSessionObject> sessionOfPeer = current->StubQueryDBinderSession(databusHandle);
    if (sessionOfPeer == nullptr) {
        ZLOGE(LOG_LABEL, "no session attach to this proxy:%{public}u", databusHandle);
        return nullptr;
    }
    ZLOGI(LOG_LABEL, "socketId:%{public}d", sessionOfPeer->GetSocketId());
    return sessionOfPeer;
}

std::shared_ptr<DBinderSessionObject> DBinderDatabusInvoker::QueryServerSessionObject(uint32_t handle)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "IPCProcessSkeleton is nullptr");
        return nullptr;
    }

    std::shared_ptr<DBinderSessionObject> sessionOfPeer = current->ProxyQueryDBinderSession(handle);
    if (sessionOfPeer == nullptr) {
        ZLOGI(LOG_LABEL, "no session attach to this handle:%{public}u", handle);
        return nullptr;
    }

    return sessionOfPeer;
}

bool DBinderDatabusInvoker::OnReceiveNewConnection(int32_t socketId, int peerPid, int peerUid,
    std::string peerName, std::string networkId)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "IPCProcessSkeleton is nullptr");
        return false;
    }

    AppAuthInfo appAuthInfo = { peerPid, peerUid, 0, socketId, 0, nullptr, networkId };
    if (!current->QueryCommAuthInfo(appAuthInfo)) {
        ZLOGE(LOG_LABEL, "remote device is not auth, socket:%{public}d, peerName:%{public}s",
            socketId, peerName.c_str());
        return false;
    }
    uint32_t peerTokenId = appAuthInfo.tokenId;
    uint32_t oldTokenId = 0;
    if (current->StubDetachDBinderSession(socketId, oldTokenId)) {
        ZLOGI(LOG_LABEL, "delete left socketId:%{public}d device:%{public}s oldTokenId:%{public}u", socketId,
            IPCProcessSkeleton::ConvertToSecureString(networkId).c_str(), oldTokenId);
    }
    std::shared_ptr<DBinderSessionObject> sessionObject = std::make_shared<DBinderSessionObject>(
        peerName, networkId, 0, nullptr, peerTokenId);
    sessionObject->SetSocketId(socketId);
    sessionObject->SetPeerPid(peerPid);
    sessionObject->SetPeerUid(peerUid);
    if (!current->StubAttachDBinderSession(socketId, sessionObject)) {
        ZLOGE(LOG_LABEL, "attach session to process skeleton failed, socketId:%{public}d", socketId);
        return false;
    }
    ZLOGI(LOG_LABEL, "pid:%{public}u uid:%{public}u deviceId:%{public}s tokenId:%{public}u "
        "oldTokenId:%{public}u socketId:%{public}d", peerPid, peerUid,
        IPCProcessSkeleton::ConvertToSecureString(networkId).c_str(),
        peerTokenId, oldTokenId, socketId);
    // update socketId
    current->AttachOrUpdateAppAuthInfo(appAuthInfo);
    return true;
}

bool DBinderDatabusInvoker::CreateProcessThread()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "IPCProcessSkeleton is nullptr");
        return false;
    }
    /*  epoll thread obtained one thread, so idle thread must more than 1 */
    if (current->GetSocketIdleThreadNum() > 0) {
        current->SpawnThread(IPCWorkThread::PROCESS_PASSIVE, IRemoteObject::IF_PROT_DATABUS);
        ZLOGI(LOG_LABEL, "success");
        return true;
    }

    ZLOGE(LOG_LABEL, "failed, no idle socket thread left");
    return false;
}

void DBinderDatabusInvoker::OnRawDataAvailable(int32_t socketId, const char *data, uint32_t dataSize)
{
    ZLOGI(LOG_LABEL, "socketId:%{public}d, size:%{public}u", socketId, dataSize);
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "IPCProcessSkeleton is nullptr");
        return;
    }

    uint32_t rawDataSize = dataSize - sizeof(dbinder_transaction_data);
    if (rawDataSize > 0 && rawDataSize <= MAX_RAWDATA_SIZE - sizeof(dbinder_transaction_data)) {
        std::shared_ptr<InvokerRawData> invokerRawData = std::make_shared<InvokerRawData>(rawDataSize);
        if (memcpy_s(invokerRawData->GetData().get(), rawDataSize, data + sizeof(dbinder_transaction_data),
            rawDataSize) != EOK) {
            ZLOGE(LOG_LABEL, "memcpy_s failed , size:%{public}u", rawDataSize);
            return;
        }
        if (!current->AttachRawData(socketId, invokerRawData)) {
            return;
        }
    }
    return;
}

/*
 * Write             64K=SOCKET_BUFF_SIZE
 * +------------------+-------------------------+----------------|
 * |0<---processed--->|Read <----need process-->|<--idle buffer-->
 * -cursor
 *
 * when idle buffer less 1k, move need process to buffer head, then update R/W cursor
 * when idle buffer can not put a full package, also move need process package to buffer head
 */
void DBinderDatabusInvoker::OnMessageAvailable(int32_t socketId, const char *data, ssize_t len)
{
    if (socketId <= 0 || data == nullptr || len > static_cast<ssize_t>(MAX_RAWDATA_SIZE) ||
        len < static_cast<ssize_t>(sizeof(dbinder_transaction_data))) {
        ZLOGE(LOG_LABEL, "wrong inputs, data length:%{public}zd(expected size:%{public}zu) "
            " socketId:%{public}d", len, sizeof(dbinder_transaction_data), socketId);
        return;
    }

    uint32_t packageSize = HasRawDataPackage(data, len);
    if (packageSize > 0) {
        // Only one set of big data can be transferred at a time.
        return OnRawDataAvailable(socketId, data, packageSize);
    }

    uint32_t readSize = 0;
    do {
        packageSize = HasCompletePackage(data, readSize, len);
        if (packageSize > 0) {
            StartProcessLoop(socketId, data + readSize, packageSize);
            readSize += packageSize;
        } else {
            // If the current is abnormal, the subsequent is no longer processed.
            ZLOGE(LOG_LABEL, "not complete message, socketId:%{public}d", socketId);
            break;
        }
    } while (readSize + sizeof(dbinder_transaction_data) < static_cast<uint32_t>(len));
}

int DBinderDatabusInvoker::OnSendMessage(std::shared_ptr<DBinderSessionObject> sessionOfPeer)
{
    if (sessionOfPeer == nullptr) {
        ZLOGE(LOG_LABEL, "sessionOfPeer is null");
        return -RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    int32_t socketId = sessionOfPeer->GetSocketId();
    if (socketId <= 0) {
        ZLOGE(LOG_LABEL, "socket id is invalid");
        return -RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    std::shared_ptr<BufferObject> sessionBuff = sessionOfPeer->GetSessionBuff();
    if (sessionBuff == nullptr) {
        ZLOGE(LOG_LABEL, "databus session buff is null");
        return -RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    return SendData(sessionBuff, socketId);
}

int DBinderDatabusInvoker::SendData(std::shared_ptr<BufferObject> sessionBuff, int32_t socketId)
{
    char *sendBuffer = sessionBuff->GetSendBufferAndLock(SOCKET_DEFAULT_BUFF_SIZE);
    /* session buffer contain mutex, need release mutex */
    if (sendBuffer == nullptr) {
        ZLOGE(LOG_LABEL, "buffer alloc failed in session");
        return -RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }
    sessionBuff->UpdateSendBuffer(0); // 0 means do not expand buffer when send it
    ssize_t writeCursor = sessionBuff->GetSendBufferWriteCursor();
    ssize_t readCursor = sessionBuff->GetSendBufferReadCursor();
    if (writeCursor < readCursor) {
        ZLOGE(LOG_LABEL, "no data to send, write cursor:%{public}zu, read cursor:%{public}zu",
            writeCursor, readCursor);
        sessionBuff->ReleaseSendBufferLock();
        return -RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }
    if (writeCursor == readCursor) {
        ZLOGE(LOG_LABEL, "no data to send, write cursor:%{public}zu, read cursor:%{public}zu",
            writeCursor, readCursor);
        sessionBuff->ReleaseSendBufferLock();
        return ERR_NONE;
    }
    ssize_t size = writeCursor - readCursor;

    int32_t ret = DBinderSoftbusClient::GetInstance().SendBytes(
        socketId, static_cast<const void *>(sendBuffer + readCursor), size);
    if (ret != 0) {
        ZLOGE(LOG_LABEL, "SendBytes fail, ret:%{public}d seq:%{public}" PRIu64
            " size:%{public}zd, socketId:%{public}d", ret, seqNumber_, size, socketId);
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_SEND_BYTES_FAIL, __FUNCTION__);
        sessionBuff->ReleaseSendBufferLock();
        return ret;
    }

    readCursor += size;
    sessionBuff->SetSendBufferReadCursor(readCursor);
    sessionBuff->SetSendBufferWriteCursor(writeCursor);
    ZLOGI(LOG_LABEL, "succ, seq:%{public}" PRIu64 " size:%{public}zd, socketId:%{public}d",
        seqNumber_, size, socketId);

    sessionBuff->ReleaseSendBufferLock();
    return ret;
}

int DBinderDatabusInvoker::OnSendRawData(std::shared_ptr<DBinderSessionObject> session, const void *data, size_t size)
{
    if (session == nullptr) {
        ZLOGE(LOG_LABEL, "sessionOfPeer is null");
        return -RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    int32_t socketId = session->GetSocketId();
    if (socketId <= 0) {
        ZLOGE(LOG_LABEL, "socketId is invalid");
        return -RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    int ret = DBinderSoftbusClient::GetInstance().SendBytes(socketId, data, size);
    if (ret != 0) {
        ZLOGE(LOG_LABEL, "fail, ret:%{public}d seq:%{public}" PRIu64 " size:%{public}zu socketId:%{public}d",
            ret, seqNumber_, size, socketId);
        return ret;
    }

    ZLOGI(LOG_LABEL, "succ, seq:%{public}" PRIu64 " size:%{public}zu, socketId:%{public}d",
        seqNumber_, size, socketId);

    return ret;
}

void DBinderDatabusInvoker::JoinThread(bool initiative) {}

void DBinderDatabusInvoker::JoinProcessThread(bool initiative)
{
    std::thread::id threadId = std::this_thread::get_id();
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "IPCProcessSkeleton is nullptr");
        return;
    }

    std::shared_ptr<ThreadProcessInfo> processInfo = nullptr;
    do {
        current->AddDataThreadInWait(threadId);
        while ((processInfo = current->PopDataInfoFromThread(threadId)) != nullptr) {
            OnTransaction(processInfo);
            processInfo = nullptr;
        }
    } while (!stopWorkThread_);
}

void DBinderDatabusInvoker::StopWorkThread()
{
    stopWorkThread_ = true;
}

uint32_t DBinderDatabusInvoker::FlattenSession(char *sessionOffset,
    const std::shared_ptr<DBinderSessionObject> connectSession, uint32_t binderVersion)
{
    FlatDBinderSession *flatSession = reinterpret_cast<FlatDBinderSession *>(sessionOffset);
    (void)memset_s(flatSession, sizeof(struct FlatDBinderSession), 0, sizeof(struct FlatDBinderSession));

    flatSession->stubIndex = connectSession->GetStubIndex();
    flatSession->version = binderVersion;
    flatSession->magic = TOKENID_MAGIC;
    flatSession->tokenId = connectSession->GetTokenId();
    flatSession->deviceIdLength = connectSession->GetDeviceId().length();
    if (flatSession->deviceIdLength == 0 || flatSession->deviceIdLength > DEVICEID_LENGTH) {
        ZLOGE(LOG_LABEL, "wrong devices id length:%{public}u", flatSession->deviceIdLength);
        return 0;
    }
    int memcpyResult = memcpy_s(flatSession->deviceId, DEVICEID_LENGTH, connectSession->GetDeviceId().data(),
        flatSession->deviceIdLength);
    if (memcpyResult != 0) {
        ZLOGE(LOG_LABEL, "memcpy_s failed , devices id length:%{public}hu", flatSession->deviceIdLength);
        return 0;
    }
    flatSession->deviceId[flatSession->deviceIdLength] = '\0';

    flatSession->serviceNameLength = connectSession->GetServiceName().length();
    if (flatSession->serviceNameLength == 0 || flatSession->serviceNameLength > SUPPORT_TOKENID_SERVICENAME_LENGTH) {
        ZLOGE(LOG_LABEL, "wrong service name length:%{public}u", flatSession->serviceNameLength);
        return 0;
    }
    memcpyResult = memcpy_s(flatSession->serviceName, SUPPORT_TOKENID_SERVICENAME_LENGTH,
        connectSession->GetServiceName().data(), flatSession->serviceNameLength);
    if (memcpyResult != 0) {
        ZLOGE(LOG_LABEL, "memcpy_s failed , service name length:%{public}u", flatSession->serviceNameLength);
        return 0;
    }
    flatSession->serviceName[flatSession->serviceNameLength] = '\0';

    ZLOGI(LOG_LABEL, "serviceName:%{public}s stubIndex:%{public}" PRIu64 " tokenId:%{public}u",
        flatSession->serviceName, flatSession->stubIndex, flatSession->tokenId);

    return sizeof(struct FlatDBinderSession);
}

std::shared_ptr<DBinderSessionObject> DBinderDatabusInvoker::UnFlattenSession(char *sessionOffset,
    uint32_t binderVersion)
{
    FlatDBinderSession *flatSession = reinterpret_cast<FlatDBinderSession *>(sessionOffset);
    if (flatSession->stubIndex == 0) {
        ZLOGE(LOG_LABEL, "stubIndex err");
        return nullptr;
    }

    uint32_t tokenId = 0;
    if (binderVersion >= SUPPORT_TOKENID_VERSION_NUM && flatSession->version >= SUPPORT_TOKENID_VERSION_NUM &&
        flatSession->magic == TOKENID_MAGIC) {
        tokenId = flatSession->tokenId;
    }
    /* makes sure end with a null terminator */
    flatSession->deviceId[DEVICEID_LENGTH] = '\0';
    flatSession->serviceName[SUPPORT_TOKENID_SERVICENAME_LENGTH] = '\0';
    ZLOGI(LOG_LABEL, "serviceName:%{public}s stubIndex:%{public}" PRIu64 " tokenId:%{public}u",
        flatSession->serviceName, flatSession->stubIndex, tokenId);

    return std::make_shared<DBinderSessionObject>(
        flatSession->serviceName, flatSession->deviceId, flatSession->stubIndex, nullptr, tokenId);
}

bool DBinderDatabusInvoker::FlattenObject(Parcel &parcel, const IRemoteObject *object) const
{
    return true;
}

sptr<IRemoteObject> DBinderDatabusInvoker::UnflattenObject(Parcel &parcel)
{
    return nullptr;
}

int DBinderDatabusInvoker::ReadFileDescriptor(Parcel &parcel)
{
    return -1;
}

bool DBinderDatabusInvoker::WriteFileDescriptor(Parcel &parcel, int fd, bool takeOwnership)
{
    return true;
}

bool DBinderDatabusInvoker::UpdateClientSession(std::shared_ptr<DBinderSessionObject> sessionObject)
{
    ZLOGI(LOG_LABEL, "enter");
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current process skeleton is nullptr");
        return false;
    }

    std::string ownName = current->GetDatabusName();
    if (ownName.empty()) {
        ZLOGE(LOG_LABEL, "fail to get session name");
        return false;
    }

    std::shared_ptr<DatabusSocketListener> listener =
        DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        ZLOGE(LOG_LABEL, "listener is nullptr");
        return false;
    }

    int32_t socketId = listener->CreateClientSocket(ownName,
        sessionObject->GetServiceName(), sessionObject->GetDeviceId());
    if (socketId <= 0) {
        ZLOGE(LOG_LABEL, "fail to creat client Socket");
        return false;
    }
    std::string serviceName = sessionObject->GetServiceName();
    std::string str = serviceName.substr(DBINDER_SOCKET_NAME_PREFIX.length());
    std::string::size_type pos = str.find("_");
    std::string peerUid = str.substr(0, pos);
    std::string peerPid = str.substr(pos + 1);
    sessionObject->SetSocketId(socketId);
    sessionObject->SetPeerPid(std::stoi(peerPid));
    sessionObject->SetPeerUid(std::stoi(peerUid));

    ZLOGI(LOG_LABEL, "create socket succ, ownName:%{public}s peerName:%{public}s deviceId:%{public}s "
        "socketId:%{public}d", ownName.c_str(), serviceName.c_str(),
        IPCProcessSkeleton::ConvertToSecureString(sessionObject->GetDeviceId()).c_str(),
        socketId);
    return true;
}

void DBinderDatabusInvoker::OnDatabusSessionClientSideClosed(int32_t socketId)
{
    std::vector<uint32_t> proxyHandle;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "IPCProcessSkeleton is nullptr");
        return;
    }
    if (!current->QueryProxyBySocketId(socketId, proxyHandle)) {
        ZLOGE(LOG_LABEL, "session id:%{public}d is invalid", socketId);
        return;
    }
    if (proxyHandle.empty()) {
        ZLOGE(LOG_LABEL, "proxy handle is empty");
        return;
    }
    for (auto it = proxyHandle.begin(); it != proxyHandle.end(); ++it) {
        std::u16string descriptor = current->MakeHandleDescriptor(*it);
        const std::string descStr8 = Str16ToStr8(descriptor);
        sptr<IRemoteObject> remoteObject = current->QueryObject(descriptor);
        if (remoteObject != nullptr) {
            IPCObjectProxy *remoteProxy = reinterpret_cast<IPCObjectProxy *>(remoteObject.GetRefPtr());
            // No need to close session again here. First erase session and then notify user session has been closed.
            current->ProxyDetachDBinderSession(*it, remoteProxy);
            if (remoteProxy->IsSubscribeDeathNotice()) {
                ZLOGD(LOG_LABEL, "SendObituary begin, desc:%{public}s", descStr8.c_str());
                remoteProxy->SendObituary();
                ZLOGD(LOG_LABEL, "SendObituary end, desc:%{public}s", descStr8.c_str());
            } else {
                ZLOGW(LOG_LABEL, "desc:%{public}s does not subscribe death notice",
                    descStr8.c_str());
            }
        } else {
            ZLOGE(LOG_LABEL, "cannot find proxy with desc:%{public}s", descStr8.c_str());
        }
    }
    ZLOGI(LOG_LABEL, "close:%{public}d sussess", socketId);
    return;
}

void DBinderDatabusInvoker::OnDatabusSessionServerSideClosed(int32_t socketId)
{
    uint32_t tokenId = 0;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "IPCProcessSkeleton is nullptr");
        return;
    }
    bool ret = current->StubDetachDBinderSession(socketId, tokenId);
    // detach info whose socketId equals the given one
    std::list<uint64_t> stubIndexs = current->DetachAppAuthInfoBySocketId(socketId);
    std::lock_guard<std::mutex> lockGuard(GetObjectMutex());
    for (auto it = stubIndexs.begin(); it != stubIndexs.end(); it++) {
        // note that we canont remove mapping from stub to index here because other session may still be used
        IRemoteObject *stub = current->QueryStubByIndex(*it);
        if (stub == nullptr) {
            continue;
        }
        // a proxy doesn't refers this stub, we need to dec ref
        stub->DecStrongRef(this);
    }
    ZLOGI(LOG_LABEL, "socketId:%{public}d ret:%{public}d", socketId, ret);
}

uint32_t DBinderDatabusInvoker::QueryHandleBySession(std::shared_ptr<DBinderSessionObject> session)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "IPCProcessSkeleton is nullptr");
        return 0;
    }
    return current->QueryHandleByDatabusSession(session->GetServiceName(), session->GetDeviceId(),
        session->GetStubIndex());
}

uint64_t DBinderDatabusInvoker::GetSeqNum() const
{
    return seqNumber_;
}

void DBinderDatabusInvoker::SetSeqNum(uint64_t seq)
{
    seqNumber_ = seq;
}

int32_t DBinderDatabusInvoker::GetClientFd() const
{
    return clientFd_;
}

void DBinderDatabusInvoker::SetClientFd(int32_t fd)
{
    clientFd_ = fd;
}

std::string DBinderDatabusInvoker::GetCallerSid() const
{
    return "";
}

pid_t DBinderDatabusInvoker::GetCallerPid() const
{
    return callerPid_;
}

pid_t DBinderDatabusInvoker::GetCallerRealPid() const
{
    return callerPid_;
}

void DBinderDatabusInvoker::SetStatus(uint32_t status)
{
    status_ = status;
}

uint32_t DBinderDatabusInvoker::GetStatus()
{
    return status_;
}

void DBinderDatabusInvoker::SetCallerPid(pid_t pid)
{
    callerPid_ = pid;
}

uid_t DBinderDatabusInvoker::GetCallerUid() const
{
    return callerUid_;
}

void DBinderDatabusInvoker::SetCallerUid(pid_t uid)
{
    callerUid_ = uid;
}

uint64_t DBinderDatabusInvoker::GetCallerTokenID() const
{
    return callerTokenID_;
}

uint64_t DBinderDatabusInvoker::GetFirstCallerTokenID() const
{
    return firstTokenID_;
}

uint64_t DBinderDatabusInvoker::GetSelfTokenID() const
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
    if (invoker != nullptr) {
        return invoker->GetSelfTokenID();
    }
    return 0;
}

uint64_t DBinderDatabusInvoker::GetSelfFirstCallerTokenID() const
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
    if (invoker != nullptr) {
        return invoker->GetSelfFirstCallerTokenID();
    }
    return 0;
}

void DBinderDatabusInvoker::SetCallerDeviceID(const std::string &deviceId)
{
    callerDeviceID_ = deviceId;
}

void DBinderDatabusInvoker::SetCallerTokenID(const uint32_t tokenId)
{
    callerTokenID_ = tokenId;
    firstTokenID_ = tokenId;
}

bool DBinderDatabusInvoker::IsLocalCalling()
{
    return false;
}

int DBinderDatabusInvoker::CheckAndSetCallerInfo(int32_t socketId, uint64_t stubIndex)
{
    std::shared_ptr<DBinderSessionObject> session = QueryClientSessionObject(socketId);
    if (session == nullptr) {
        ZLOGE(LOG_LABEL, "get databus session fail");
        return RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    int pid = static_cast<int>(session->GetPeerPid());
    int uid = static_cast<int>(session->GetPeerUid());
    std::string deviceId = session->GetDeviceId();
    if (uid < 0 || deviceId.length() > DEVICEID_LENGTH) {
        ZLOGE(LOG_LABEL, "user id and device id error");
        return RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current process skeleton is nullptr");
        return IPC_SKELETON_ERR;
    }
    uint32_t callerTokenId = session->GetTokenId();
    AppAuthInfo appAuthInfo = { pid, uid, callerTokenId, socketId, stubIndex, nullptr, deviceId };
    if (current->QueryAppInfoToStubIndex(appAuthInfo) == false) {
        ZLOGE(LOG_LABEL, "stubIndex:%{public}" PRIu64 " is NOT belong to caller, pid:%{public}d uid:%{public}d"
            " deviceId:%{public}s socketId:%{public}d callerTokenId:%{public}u", stubIndex, pid, uid,
            IPCProcessSkeleton::ConvertToSecureString(deviceId).c_str(), socketId, callerTokenId);
        return RPC_DATABUS_INVOKER_INVALID_STUB_INDEX;
    }
    callerPid_ = pid;
    callerUid_ = uid;
    callerDeviceID_ = deviceId;
    clientFd_ = socketId;
    callerTokenID_ = callerTokenId;
    firstTokenID_ = callerTokenId;
    return ERR_NONE;
}

std::string DBinderDatabusInvoker::GetLocalDeviceID()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current process skeleton is nullptr");
        return "";
    }

    return current->GetLocalDeviceID();
}

std::string DBinderDatabusInvoker::GetCallerDeviceID() const
{
    return callerDeviceID_;
}

uint64_t DBinderDatabusInvoker::MakeStubIndexByRemoteObject(IRemoteObject *stubObject)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "IPCProcessSkeleton is nullptr");
        return 0;
    }

    if (!current->IsContainsObject(stubObject)) {
        ZLOGE(LOG_LABEL, "fail to find stub");
        return 0;
    }

    uint64_t stubIndex = current->AddStubByIndex(stubObject);
    if (!stubIndex) {
        ZLOGE(LOG_LABEL, "fail to add stub");
        return 0;
    }
    return stubIndex;
}

std::shared_ptr<DBinderSessionObject> DBinderDatabusInvoker::MakeDefaultServerSessionObject(uint64_t stubIndex,
    const std::shared_ptr<DBinderSessionObject> sessionObject)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "IPCProcessSkeleton is nullptr");
        return nullptr;
    }
    std::string serviceName = current->GetDatabusName();
    std::string deviceId = current->GetLocalDeviceID();
    if (serviceName.empty() || deviceId.empty()) {
        ZLOGE(LOG_LABEL, "fail to get databus name:%{public}s or deviceId length:%{public}zu",
            serviceName.c_str(), deviceId.length());
        return nullptr;
    }

    auto session = std::make_shared<DBinderSessionObject>(serviceName, deviceId, stubIndex, nullptr,
        sessionObject->GetTokenId());
    if (session == nullptr) {
        ZLOGE(LOG_LABEL, "new server session fail, service:%{public}s deviceId:%{public}s stubIndex:%{public}" PRIu64,
            serviceName.c_str(), IPCProcessSkeleton::ConvertToSecureString(deviceId).c_str(), stubIndex);
        return nullptr;
    }
    return session;
}

bool DBinderDatabusInvoker::ConnectRemoteObject2Session(IRemoteObject *stubObject, uint64_t stubIndex,
    const std::shared_ptr<DBinderSessionObject> sessionObject)
{
    if (sessionObject == nullptr) {
        ZLOGE(LOG_LABEL, "session object is nullptr");
        return false;
    }
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "IPCProcessSkeleton is nullptr");
        return false;
    }

    int peerPid = sessionObject->GetPeerPid();
    int peerUid = sessionObject->GetPeerUid();
    uint32_t tokenId = sessionObject->GetTokenId();
    std::string deviceId = sessionObject->GetDeviceId();
    ZLOGI(LOG_LABEL, "pid:%{public}d uid:%{public}d deviceId:%{public}s tokenId:%{public}u "
        "stubIndex:%{public}" PRIu64, peerPid, peerUid, IPCProcessSkeleton::ConvertToSecureString(deviceId).c_str(),
        tokenId, stubIndex);
    // mark socketId as 0
    AppAuthInfo appAuthInfo = { peerPid, peerUid, tokenId, 0, stubIndex, stubObject, deviceId };
    if (current->AttachOrUpdateAppAuthInfo(appAuthInfo)) {
        // first time send this stub to proxy indicating by deviceId, pid, uid
        stubObject->IncStrongRef(this);
    }
    return true;
}

std::shared_ptr<DBinderSessionObject> DBinderDatabusInvoker::CreateServerSessionObject(binder_uintptr_t binder,
    std::shared_ptr<DBinderSessionObject> sessionObject)
{
    IRemoteObject *stubObject = reinterpret_cast<IPCObjectStub *>(binder);
    if (stubObject == nullptr) {
        ZLOGE(LOG_LABEL, "binder is nullptr");
        return nullptr;
    }

    uint64_t stubIndex = MakeStubIndexByRemoteObject(stubObject);
    if (stubIndex == 0) {
        ZLOGE(LOG_LABEL, "fail to add stub");
        return nullptr;
    }
    if (ConnectRemoteObject2Session(stubObject, stubIndex, sessionObject) != true) {
        ZLOGE(LOG_LABEL, "fail to connect stub to session, stubIndex:%{public}" PRIu64, stubIndex);
        return nullptr;
    }
    return MakeDefaultServerSessionObject(stubIndex, sessionObject);
}

int DBinderDatabusInvoker::FlushCommands(IRemoteObject *object)
{
    if (object == nullptr || !object->IsProxyObject()) {
        ZLOGE(LOG_LABEL, "proxy is invalid");
        return RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    IPCObjectProxy *proxy = reinterpret_cast<IPCObjectProxy *>(object);

    std::shared_ptr<DBinderSessionObject> session = QueryServerSessionObject(proxy->GetHandle());
    if (session == nullptr) {
        ZLOGE(LOG_LABEL, "session is nullptr");
        return RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    (void)OnSendMessage(session);
    return ERR_NONE;
}

std::string DBinderDatabusInvoker::ResetCallingIdentity()
{
    std::string token = std::to_string(((static_cast<uint64_t>(callerUid_) << PID_LEN)
        | static_cast<uint64_t>(callerPid_)));
    std::string identity = callerDeviceID_ + token;
    char buf[ACCESS_TOKEN_MAX_LEN + 1] = {0};
    int ret = sprintf_s(buf, ACCESS_TOKEN_MAX_LEN + 1, "%010" PRIu64, callerTokenID_);
    if (ret < 0) {
        ZLOGE(LOG_LABEL, "sprintf callerTokenID:%{public}" PRIu64 " failed", callerTokenID_);
        return "";
    }
    std::string accessToken(buf);
    callerUid_ = (pid_t)getuid();
    callerPid_ = getpid();
    callerDeviceID_ = GetLocalDeviceID();
    callerTokenID_ = GetSelfTokenID();
    return accessToken + identity;
}

bool DBinderDatabusInvoker::SetCallingIdentity(std::string &identity, bool flag)
{
    (void)flag;
    if (identity.empty() || identity.length() <= DEVICEID_LENGTH) {
        return false;
    }
    std::string tokenIdStr;
    if (!ProcessSkeleton::GetSubStr(identity, tokenIdStr, 0, ACCESS_TOKEN_MAX_LEN) ||
        !ProcessSkeleton::IsNumStr(tokenIdStr)) {
        ZLOGE(LOG_LABEL, "Identity param tokenId is invalid");
        return false;
    }
    std::string deviceId;
    if (!ProcessSkeleton::GetSubStr(identity, deviceId, ACCESS_TOKEN_MAX_LEN, DEVICEID_LENGTH)) {
        ZLOGE(LOG_LABEL, "Identity param deviceId is invalid");
        return false;
    }
    std::string tokenStr;
    size_t offset = ACCESS_TOKEN_MAX_LEN + DEVICEID_LENGTH;
    if (identity.length() <= offset) {
        ZLOGE(LOG_LABEL, "Identity param no token, len:%{public}zu, offset:%{public}zu", identity.length(), offset);
        return false;
    }
    size_t subLen = identity.length() - offset;
    if (!ProcessSkeleton::GetSubStr(identity, tokenStr, offset, subLen) || !ProcessSkeleton::IsNumStr(tokenStr)) {
        ZLOGE(LOG_LABEL, "Identity param token is invalid");
        return false;
    }
    uint64_t tokenId = std::stoull(tokenIdStr.c_str());
    uint64_t token = std::stoull(tokenStr.c_str());
    callerUid_ = static_cast<int>(token >> PID_LEN);
    callerPid_ = static_cast<int>(token);
    callerDeviceID_ = deviceId;
    callerTokenID_ = tokenId;

    return true;
}

int DBinderDatabusInvoker::TranslateIRemoteObject(int32_t cmd, const sptr<IRemoteObject> &obj)
{
    return -IPC_INVOKER_TRANSLATE_ERR;
}

uint32_t DBinderDatabusInvoker::HasRawDataPackage(const char *data, ssize_t len)
{
    const dbinder_transaction_data *tr = reinterpret_cast<const dbinder_transaction_data *>(data);
    if ((tr->magic == DBINDER_MAGICWORD) && (tr->cmd == BC_SEND_RAWDATA) &&
        (tr->sizeOfSelf == static_cast<uint32_t>(len))) {
        if (tr->sizeOfSelf > MAX_RAWDATA_SIZE) {
            return MAX_RAWDATA_SIZE;
        }
        return tr->sizeOfSelf;
    }
    return 0;
}

uint32_t DBinderDatabusInvoker::HasCompletePackage(const char *data, uint32_t readCursor, ssize_t len)
{
    const dbinder_transaction_data *tr = reinterpret_cast<const dbinder_transaction_data *>(data + readCursor);
    if ((tr->magic == DBINDER_MAGICWORD) &&
        (tr->sizeOfSelf <= SOCKET_MAX_BUFF_SIZE + sizeof(dbinder_transaction_data)) &&
        (readCursor + tr->sizeOfSelf <= static_cast<uint32_t>(len)) && CheckTransactionData(tr)) {
        return tr->sizeOfSelf;
    }
    return 0;
}
} // namespace OHOS
