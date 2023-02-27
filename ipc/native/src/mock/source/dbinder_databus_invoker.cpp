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

#include "access_token_adapter.h"
#include "ipc_object_stub.h"
#include "ipc_object_proxy.h"
#include "ipc_process_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "ipc_debug.h"
#include "log_tags.h"
#include "databus_session_callback.h"
#include "rpc_feature_set.h"

namespace OHOS {
using namespace OHOS::HiviewDFX;
DBinderDatabusInvoker::DBinderDatabusInvoker()
    : stopWorkThread_(false), callerPid_(getpid()), callerUid_(getuid()), callerDeviceID_(""),
    callerTokenID_(0), firstTokenID_(0), status_(0)
{
    ZLOGI(LOG_LABEL, "Create DBinderDatabusInvoker");
}

DBinderDatabusInvoker::~DBinderDatabusInvoker()
{
    ZLOGI(LOG_LABEL, "Clean DBinderDatabusInvoker");
}

bool DBinderDatabusInvoker::AcquireHandle(int32_t handle)
{
    ZLOGI(LOG_LABEL, "Acquire Handle %{public}d", handle);
    return true;
}

bool DBinderDatabusInvoker::ReleaseHandle(int32_t handle)
{
    ZLOGI(LOG_LABEL, "Release Handle %{public}d", handle);
    return true;
}

std::shared_ptr<DBinderSessionObject> DBinderDatabusInvoker::NewSessionOfBinderProxy(uint32_t handle,
    std::shared_ptr<DBinderSessionObject> remoteSession)
{
    if (remoteSession == nullptr) {
        ZLOGE(LOG_LABEL, "remote session is nullptr");
        return nullptr;
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current ipc process skeleton is nullptr");
        return nullptr;
    }
    sptr<IPCObjectProxy> ipcProxy = reinterpret_cast<IPCObjectProxy *>(current->FindOrNewObject(handle).GetRefPtr());
    if (ipcProxy == nullptr) {
        ZLOGE(LOG_LABEL, "attempt to send a invalid handle = %u", handle);
        return nullptr;
    }

    if (ipcProxy->GetProto() != IRemoteObject::IF_PROT_BINDER) {
        ZLOGE(LOG_LABEL, "attempt to send a distributed proxy, handle = %u", handle);
        return nullptr;
    }

    std::string sessionName = ipcProxy->GetPidAndUidInfo(0);
    if (sessionName.empty()) {
        ZLOGE(LOG_LABEL, "get bus name error");
        return nullptr;
    }

    std::shared_ptr<Session> session = remoteSession->GetBusSession();
    if (session == nullptr) {
        ZLOGE(LOG_LABEL, "get databus session fail");
        return nullptr;
    }

    MessageParcel data, reply;
    if (!data.WriteUint32(IRemoteObject::DATABUS_TYPE) || !data.WriteString(current->GetLocalDeviceID()) ||
        !data.WriteUint32((uint32_t)(session->GetPeerPid())) || !data.WriteUint32(session->GetPeerUid()) ||
        !data.WriteString(session->GetPeerDeviceId()) || !data.WriteString(sessionName)) {
        ZLOGE(LOG_LABEL, "write to parcel fail");
        return nullptr;
    }
    int err = ipcProxy->InvokeListenThread(data, reply);
    if (err != ERR_NONE) {
        ZLOGE(LOG_LABEL, "start service listen error = %d", err);
        return nullptr;
    }

    uint64_t stubIndex = reply.ReadUint64();
    if (stubIndex == 0) {
        ZLOGE(LOG_LABEL, "stubindex error = %" PRIu64 "", stubIndex);
        return nullptr;
    }

    if (!current->AttachHandleToIndex(handle, stubIndex)) {
        ZLOGE(LOG_LABEL, "add stub index err stubIndex = %" PRIu64 ", handle = %u", stubIndex, handle);
        // do nothing, Sending an object repeatedly
    }

    std::string serverName = reply.ReadString();
    std::string deviceId = reply.ReadString();
    ZLOGI(LOG_LABEL, "NewSessionOfBinderProxy serverName= %s", serverName.c_str());

    std::shared_ptr<DBinderSessionObject> connectSession =
        std::make_shared<DBinderSessionObject>(nullptr, serverName, deviceId);
    if (connectSession == nullptr) {
        ZLOGE(LOG_LABEL, "new server session fail!");
        return nullptr;
    }

    return connectSession;
}

bool DBinderDatabusInvoker::AuthSession2Proxy(uint32_t handle,
    const std::shared_ptr<DBinderSessionObject> databusSession)
{
    if (databusSession == nullptr) {
        ZLOGE(LOG_LABEL, "remote session is nullptr");
        return false;
    }

    std::shared_ptr<Session> session = databusSession->GetBusSession();
    if (session == nullptr) {
        ZLOGE(LOG_LABEL, "get databus session fail");
        return false;
    }

    std::shared_ptr<FeatureSetData> feature = databusSession->GetFeatureSet();
    if (feature == nullptr) {
        ZLOGE(LOG_LABEL, "get feature fail");
        return false;
    }

    MessageParcel data, reply;
    MessageOption option;

    if (!data.WriteUint32((uint32_t)(session->GetPeerPid())) || !data.WriteUint32(session->GetPeerUid()) ||
        !data.WriteString(session->GetPeerDeviceId()) || !data.WriteUint32(feature->featureSet)) {
        ZLOGE(LOG_LABEL, "write to MessageParcel fail");
        return false;
    }

    int32_t err = SendRequest(handle, DBINDER_ADD_COMMAUTH, data, reply, option);
    if (err != ERR_NONE) {
        ZLOGE(LOG_LABEL, "send auth info to remote fail");
        return false;
    }
    return true;
}

std::shared_ptr<DBinderSessionObject> DBinderDatabusInvoker::QuerySessionOfBinderProxy(uint32_t handle,
    std::shared_ptr<DBinderSessionObject> session)
{
    if (AuthSession2Proxy(handle, session) != true) {
        ZLOGE(LOG_LABEL, "auth handle =%{public}u to session failed", handle);
        return nullptr;
    }
    return QueryServerSessionObject(handle);
}

std::shared_ptr<DBinderSessionObject> DBinderDatabusInvoker::QueryClientSessionObject(uint32_t databusHandle)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current ipc process skeleton is nullptr");
        return nullptr;
    }
    std::shared_ptr<DBinderSessionObject> sessionOfPeer = current->StubQueryDBinderSession(databusHandle);
    if (sessionOfPeer == nullptr) {
        ZLOGE(LOG_LABEL, "no session attach to this proxy = %{public}u", databusHandle);
        return nullptr;
    }
    return sessionOfPeer;
}

std::shared_ptr<DBinderSessionObject> DBinderDatabusInvoker::QueryServerSessionObject(uint32_t handle)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current ipc process skeleton is nullptr");
        return nullptr;
    }

    std::shared_ptr<DBinderSessionObject> sessionOfPeer = current->ProxyQueryDBinderSession(handle);
    if (sessionOfPeer == nullptr) {
        ZLOGI(LOG_LABEL, "no session attach to this handle = %{public}u", handle);
        return nullptr;
    }

    return sessionOfPeer;
}

bool DBinderDatabusInvoker::OnReceiveNewConnection(std::shared_ptr<Session> session)
{
    uint32_t handle = IPCProcessSkeleton::ConvertChannelID2Int(session->GetChannelId());
    if (handle == 0) {
        return false;
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current ipc process skeleton is nullptr");
        return false;
    }

    auto featureSet = current->QueryIsAuth(session->GetPeerPid(), (int32_t)(session->GetPeerUid()),
        session->GetPeerDeviceId());
    if (featureSet == nullptr) {
        ZLOGE(LOG_LABEL, "query auth failed, remote device featureSet is null");
        return false;
    }

    std::shared_ptr<DBinderSessionObject> sessionObject =
        std::make_shared<DBinderSessionObject>(session, session->GetPeerSessionName(), session->GetPeerDeviceId());
    sessionObject->SetFeatureSet(featureSet);

    if (!current->StubAttachDBinderSession(handle, sessionObject)) {
        ZLOGE(LOG_LABEL, "attach session to process skeleton failed, handle =%u", handle);
    }
    return true;
}

bool DBinderDatabusInvoker::CreateProcessThread()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current ipc process skeleton is nullptr");
        return false;
    }
    /*  epoll thread obtained one thread, so idle thread must more than 1 */
    if (current->GetSocketIdleThreadNum() > 0) {
        current->SpawnThread(IPCWorkThread::PROCESS_PASSIVE, IRemoteObject::IF_PROT_DATABUS);
        ZLOGI(LOG_LABEL, "create Process thread success");
        return true;
    }

    ZLOGE(LOG_LABEL, "no idle socket thread left, fail to CreateProcessThread");
    return false;
}

void DBinderDatabusInvoker::OnRawDataAvailable(std::shared_ptr<Session> session, const char *data, uint32_t dataSize)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current ipc process skeleton is nullptr");
        return;
    }

    uint32_t rawDataSize = dataSize - sizeof(dbinder_transaction_data);
    if (rawDataSize > 0 && rawDataSize <= MAX_RAWDATA_SIZE - sizeof(dbinder_transaction_data)) {
        std::shared_ptr<InvokerRawData> invokerRawData = std::make_shared<InvokerRawData>(rawDataSize);
        if (memcpy_s(invokerRawData->GetData().get(), rawDataSize, data + sizeof(dbinder_transaction_data),
            rawDataSize) != EOK) {
            ZLOGE(LOG_LABEL, "memcpy_s failed , size = %u", rawDataSize);
            return;
        }
        if (!current->AttachRawData(IPCProcessSkeleton::ConvertChannelID2Int(session->GetChannelId()),
            invokerRawData)) {
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
void DBinderDatabusInvoker::OnMessageAvailable(std::shared_ptr<Session> session, const char *data, ssize_t len)
{
    if (session == nullptr || data == nullptr || len > static_cast<ssize_t>(MAX_RAWDATA_SIZE) ||
        len < static_cast<ssize_t>(sizeof(dbinder_transaction_data))) {
        ZLOGE(LOG_LABEL, "session has wrong inputs");
        return;
    }

    uint32_t packageSize = HasRawDataPackage(data, len);
    if (packageSize > 0) {
        // Only one set of big data can be transferred at a time.
        return OnRawDataAvailable(session, data, packageSize);
    }

    uint32_t handle = IPCProcessSkeleton::ConvertChannelID2Int(session->GetChannelId());
    uint32_t readSize = 0;
    do {
        packageSize = HasCompletePackage(data, readSize, len);
        if (packageSize > 0) {
            StartProcessLoop(handle, data + readSize, packageSize);
            readSize += packageSize;
        } else {
            // If the current is abnormal, the subsequent is no longer processed.
            ZLOGE(LOG_LABEL, "not complete message");
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

    std::shared_ptr<Session> session = sessionOfPeer->GetBusSession();
    if (session == nullptr) {
        ZLOGE(LOG_LABEL, "databus session is null");
        return -RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    std::shared_ptr<BufferObject> sessionBuff = sessionOfPeer->GetSessionBuff();
    if (sessionBuff == nullptr) {
        ZLOGE(LOG_LABEL, "databus session buff is null");
        return -RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    char *sendBuffer = sessionBuff->GetSendBufferAndLock(SOCKET_DEFAULT_BUFF_SIZE);
    /* session buffer contain mutex, need release mutex */
    if (sendBuffer == nullptr) {
        ZLOGE(LOG_LABEL, "buffer alloc failed in session");
        return -RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }
    sessionBuff->UpdateSendBuffer();
    ssize_t writeCursor = sessionBuff->GetSendBufferWriteCursor();
    ssize_t readCursor = sessionBuff->GetSendBufferReadCursor();
    if (writeCursor <= readCursor) {
        sessionBuff->ReleaseSendBufferLock();
        return -RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    ssize_t size = writeCursor - readCursor;
    int ret = session->SendBytes(static_cast<const void *>(sendBuffer + readCursor), size);
    if (ret == 0) {
        readCursor += size;
        sessionBuff->SetSendBufferReadCursor(readCursor);
        sessionBuff->SetSendBufferWriteCursor(writeCursor);
    }
    ZLOGI(LOG_LABEL, "sendNormalData len: %{public}u, ret: %{public}d", static_cast<uint32_t>(size), ret);
    sessionBuff->ReleaseSendBufferLock();
    return ret;
}

int DBinderDatabusInvoker::OnSendRawData(std::shared_ptr<DBinderSessionObject> session, const void *data, size_t size)
{
    if (session == nullptr) {
        ZLOGE(LOG_LABEL, "sessionOfPeer is null");
        return -RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    std::shared_ptr<Session> dataBusSession = session->GetBusSession();
    if (dataBusSession == nullptr) {
        ZLOGE(LOG_LABEL, "databus session is null");
        return -RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    int ret = dataBusSession->SendBytes(data, size);
    ZLOGI(LOG_LABEL, "sendRawData len: %{public}u, ret: %{public}d", static_cast<uint32_t>(size), ret);
    return ret;
}

void DBinderDatabusInvoker::JoinThread(bool initiative) {}

void DBinderDatabusInvoker::JoinProcessThread(bool initiative)
{
    std::thread::id threadId = std::this_thread::get_id();
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current ipc process skeleton is nullptr");
        return;
    }

    std::shared_ptr<ThreadProcessInfo> processInfo = nullptr;
    do {
        current->AddDataThreadInWait(threadId);
        while ((processInfo = current->PopDataInfoFromThread(threadId)) != nullptr) {
            OnTransaction(processInfo);
        }
    } while (!stopWorkThread_);
}

void DBinderDatabusInvoker::StopWorkThread()
{
    stopWorkThread_ = true;
}

uint32_t DBinderDatabusInvoker::FlattenSession(char *sessionOffset,
    const std::shared_ptr<DBinderSessionObject> connectSession, uint64_t stubIndex)
{
    FlatDBinderSession *flatSession = reinterpret_cast<FlatDBinderSession *>(sessionOffset);
    flatSession->stubIndex = stubIndex;

    flatSession->deviceIdLength = connectSession->GetDeviceId().length();
    if (flatSession->deviceIdLength == 0 || flatSession->deviceIdLength > DEVICEID_LENGTH) {
        ZLOGE(LOG_LABEL, "wrong devices id");
        return 0;
    }
    int memcpyResult = memcpy_s(flatSession->deviceId, DEVICEID_LENGTH, connectSession->GetDeviceId().data(),
        flatSession->deviceIdLength);
    if (memcpyResult != 0) {
        ZLOGE(LOG_LABEL, "memcpy_s failed , ID Size = %hu", flatSession->deviceIdLength);
        return 0;
    }
    flatSession->deviceId[flatSession->deviceIdLength] = '\0';

    flatSession->serviceNameLength = connectSession->GetServiceName().length();
    if (flatSession->serviceNameLength == 0 || flatSession->serviceNameLength > SERVICENAME_LENGTH) {
        ZLOGE(LOG_LABEL, "wrong service name");
        return 0;
    }
    memcpyResult = memcpy_s(flatSession->serviceName, SERVICENAME_LENGTH, connectSession->GetServiceName().data(),
        flatSession->serviceNameLength);
    if (memcpyResult != 0) {
        ZLOGE(LOG_LABEL, "memcpy_s failed , name Size = %hu", flatSession->serviceNameLength);
        return 0;
    }
    flatSession->serviceName[flatSession->serviceNameLength] = '\0';

    ZLOGI(LOG_LABEL, "serviceName = %s, stubIndex = %" PRIu64 "", flatSession->serviceName, flatSession->stubIndex);

    return sizeof(struct FlatDBinderSession);
}

std::shared_ptr<DBinderSessionObject> DBinderDatabusInvoker::UnFlattenSession(char *sessionOffset, uint64_t &stubIndex)
{
    FlatDBinderSession *flatSession = reinterpret_cast<FlatDBinderSession *>(sessionOffset);
    /* force end true string length */
    flatSession->deviceId[DEVICEID_LENGTH] = '\0';
    flatSession->serviceName[SERVICENAME_LENGTH] = '\0';

    ZLOGI(LOG_LABEL, "serviceName = %s, stubIndex = %" PRIu64 "", flatSession->serviceName, flatSession->stubIndex);
    stubIndex = flatSession->stubIndex;
    if (stubIndex == 0) {
        ZLOGE(LOG_LABEL, "stubIndex err");
        return nullptr;
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current process skeleton is nullptr");
        return nullptr;
    }

    std::shared_ptr<DBinderSessionObject> sessionObject =
        current->QuerySessionByInfo(flatSession->serviceName, flatSession->deviceId);
    if (sessionObject != nullptr) {
        return sessionObject;
    }
    return std::make_shared<DBinderSessionObject>(nullptr, flatSession->serviceName, flatSession->deviceId);
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

bool DBinderDatabusInvoker::UpdateClientSession(uint32_t handle, std::shared_ptr<DBinderSessionObject> sessionObject)
{
    ZLOGI(LOG_LABEL, "update client session enter");

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current process skeleton is nullptr");
        return false;
    }

    std::shared_ptr<ISessionService> manager = ISessionService::GetInstance();
    if (manager == nullptr) {
        ZLOGE(LOG_LABEL, "fail to get softbus manager");
        return false;
    }

    std::string sessionName = current->GetDatabusName();
    if (sessionName.empty()) {
        ZLOGE(LOG_LABEL, "fail to get session name");
        return false;
    }

    std::shared_ptr<Session> session = manager->OpenSession(sessionName, sessionObject->GetServiceName(),
        sessionObject->GetDeviceId(), std::string(""), Session::TYPE_BYTES);
    if (session == nullptr) {
        ZLOGE(LOG_LABEL, "get databus session fail");
        return false;
    }

    sessionObject->SetBusSession(session);

    if (!current->ProxyAttachDBinderSession(handle, sessionObject)) {
        ZLOGE(LOG_LABEL, "fail to attach session");
        if (current->QuerySessionByInfo(sessionObject->GetServiceName(),
            sessionObject->GetDeviceId()) == nullptr) {
            sessionObject->CloseDatabusSession();
        }
        return false;
    }

    return true;
}

bool DBinderDatabusInvoker::OnDatabusSessionClosed(std::shared_ptr<Session> session)
{
    if (session == nullptr) {
        ZLOGE(LOG_LABEL, "databus session to be closed is nullptr");
        return false;
    }
    /* means close socket */
    ZLOGI(LOG_LABEL, "close databus session, own session name = %{public}s, peer session name = %{public}s",
        session->GetMySessionName().c_str(), session->GetPeerSessionName().c_str());
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current ipc process skeleton is nullptr");
        return false;
    }

    if (current->StubDetachDBinderSession(IPCProcessSkeleton::ConvertChannelID2Int(session->GetChannelId()))) {
        current->DetachStubRefInfo(session->GetPeerPid(), session->GetPeerDeviceId());
        // No need to clear proxy objects
        return true;
    }

    std::vector<uint32_t> proxy;
    if (!current->QueryProxyBySessionHandle(IPCProcessSkeleton::ConvertChannelID2Int(session->GetChannelId()), proxy)) {
        return false;
    }

    if (proxy.empty()) {
        ZLOGE(LOG_LABEL, "proxy handle is empty");
        return false;
    }

    for (auto it = proxy.begin(); it != proxy.end(); ++it) {
        std::u16string descriptor = current->MakeHandleDescriptor(*it);
        IRemoteObject *remoteObject = current->QueryObject(descriptor);
        if (remoteObject != nullptr) {
            (void)current->ProxyDetachDBinderSession(*it);
            (void)current->DetachHandleToIndex(*it);
            IPCObjectProxy *remoteProxy = reinterpret_cast<IPCObjectProxy *>(remoteObject);
            if (remoteProxy->IsSubscribeDeathNotice()) {
                remoteProxy->SendObituary();
            }
        }
    }

    ZLOGI(LOG_LABEL, "closet socket sussess");
    return true;
}

uint32_t DBinderDatabusInvoker::QueryHandleBySession(std::shared_ptr<DBinderSessionObject> session, uint64_t stubIndex)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current ipc process skeleton is nullptr");
        return 0;
    }

    return current->QueryHandleByDatabusSession(session->GetServiceName(), session->GetDeviceId(), stubIndex);
}

uint64_t DBinderDatabusInvoker::GetSeqNum() const
{
    return seqNumber_;
}

void DBinderDatabusInvoker::SetSeqNum(uint64_t seq)
{
    seqNumber_ = seq;
}

uint32_t DBinderDatabusInvoker::GetClientFd() const
{
    return clientFd_;
}

void DBinderDatabusInvoker::SetClientFd(uint32_t fd)
{
    clientFd_ = fd;
}

pid_t DBinderDatabusInvoker::GetCallerPid() const
{
    return callerPid_;
}

void DBinderDatabusInvoker::SetStatus(uint32_t status)
{
    status_ = status;
}

uint32_t DBinderDatabusInvoker::GetStatus() const
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

uint32_t DBinderDatabusInvoker::GetCallerTokenID() const
{
    return callerTokenID_;
}

uint32_t DBinderDatabusInvoker::GetFirstTokenID() const
{
    return firstTokenID_;
}

void DBinderDatabusInvoker::SetCallerDeviceID(const std::string &deviceId)
{
    callerDeviceID_ = deviceId;
}

void DBinderDatabusInvoker::SetCallerTokenID(const uint32_t tokenId)
{
    callerTokenID_ = tokenId;
}

bool DBinderDatabusInvoker::IsLocalCalling()
{
    return false;
}

bool DBinderDatabusInvoker::SetTokenId(const dbinder_transaction_data *tr,
    std::shared_ptr<DBinderSessionObject> sessionObject)
{
    if (sessionObject == nullptr) {
        ZLOGE(LOG_LABEL, "sessionObject is null");
        return false;
    }
    std::shared_ptr<FeatureSetData> feature = sessionObject->GetFeatureSet();
    if (feature == nullptr) {
        ZLOGE(LOG_LABEL, "feature is null");
        return false;
    }
    if (IsATEnable(feature->featureSet) == true) {
        uint32_t bufferUseSize = tr->sizeOfSelf - sizeof(struct dbinder_transaction_data) - GetFeatureSize();
        uint32_t tokenId = GetTokenFromData((FeatureTransData *)(tr->buffer + bufferUseSize), GetFeatureSize());
        SetCallerTokenID(tokenId);
    }
    return true;
}

int DBinderDatabusInvoker::CheckAndSetCallerInfo(uint32_t listenFd, uint64_t stubIndex)
{
    std::shared_ptr<DBinderSessionObject> sessionObject = QueryClientSessionObject(listenFd);
    if (sessionObject == nullptr) {
        ZLOGE(LOG_LABEL, "session is not exist for listenFd = %{public}u", listenFd);
        return RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    std::shared_ptr<Session> session = sessionObject->GetBusSession();
    if (session == nullptr) {
        ZLOGE(LOG_LABEL, "get databus session fail");
        return RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    int pid = session->GetPeerPid();
    int uid = (int)(session->GetPeerUid());
    std::string deviceId = session->GetPeerDeviceId();
    if (uid < 0 || deviceId.length() > DEVICEID_LENGTH) {
        ZLOGE(LOG_LABEL, "user id and device id error");
        return RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current process skeleton is nullptr");
        return IPC_SKELETON_ERR;
    }
    if (current->QueryAppInfoToStubIndex((uint32_t)pid, (uint32_t)uid, deviceId, stubIndex) == false) {
        ZLOGE(LOG_LABEL, "stub index is NOT belong to caller,serviceName = %{public}s, listenFd = %{public}u",
            deviceId.c_str(), listenFd);
        return RPC_DATABUS_INVOKER_INVALID_STUB_INDEX;
    }
    callerPid_ = pid;
    callerUid_ = uid;
    callerDeviceID_ = deviceId;
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

std::shared_ptr<DBinderSessionObject> DBinderDatabusInvoker::MakeDefaultServerSessionObject()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "IPCProcessSkeleton is nullptr");
        return nullptr;
    }
    std::string serviceName = current->GetDatabusName();
    if (serviceName.empty()) {
        ZLOGE(LOG_LABEL, "fail to get databus name");
        return nullptr;
    }
    std::shared_ptr<DBinderSessionObject> connectSession =
        std::make_shared<DBinderSessionObject>(nullptr, serviceName, current->GetLocalDeviceID());
    if (connectSession == nullptr) {
        ZLOGE(LOG_LABEL, "new server session fail!");
        return nullptr;
    }
    return connectSession;
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
    std::shared_ptr<Session> session = sessionObject->GetBusSession();
    if (session == nullptr) {
        ZLOGE(LOG_LABEL, "get databus session fail");
        return false;
    }

    int peerPid = session->GetPeerPid();
    int peerUid = (int)(session->GetPeerUid());
    std::string deviceId = session->GetPeerDeviceId();
    if (!current->AttachAppInfoToStubIndex((uint32_t)peerPid, (uint32_t)peerUid, deviceId, stubIndex)) {
        ZLOGI(LOG_LABEL, "fail to attach appinfo to stub index, when proxy call we check appinfo");
        // attempt attach again, if failed, do nothing
    }

    if (!current->AttachCommAuthInfo(stubObject, peerPid, peerUid, deviceId, sessionObject->GetFeatureSet())) {
        ZLOGI(LOG_LABEL, "fail to attach comm auth info, maybe attached already");
        // attempt attach again, if failed, do nothing
    }

    if (current->AttachStubSendRefInfo(stubObject, peerPid, deviceId)) {
        if (!current->IncStubRefTimes(stubObject)) {
            ZLOGE(LOG_LABEL, "Inc Stub RefTimes fail");
            current->DetachCommAuthInfo(stubObject, peerPid, peerUid, deviceId);
            current->DetachAppInfoToStubIndex((uint32_t)peerPid, (uint32_t)peerUid, deviceId, stubIndex);
            return false;
        }
        stubObject->IncStrongRef(this);
    }
    return true;
}

std::shared_ptr<DBinderSessionObject> DBinderDatabusInvoker::CreateServerSessionObject(binder_uintptr_t binder,
    uint64_t &stubIndex, std::shared_ptr<DBinderSessionObject> sessionObject)
{
    IRemoteObject *stubObject = reinterpret_cast<IPCObjectStub *>(binder);
    if (stubObject == nullptr) {
        ZLOGE(LOG_LABEL, "binder is nullptr");
        return nullptr;
    }

    stubIndex = MakeStubIndexByRemoteObject(stubObject);
    if (stubIndex == 0) {
        ZLOGE(LOG_LABEL, "fail to add stub");
        return nullptr;
    }
    if (ConnectRemoteObject2Session(stubObject, stubIndex, sessionObject) != true) {
        ZLOGE(LOG_LABEL, "fail to connect stub to session");
        return nullptr;
    }
    return MakeDefaultServerSessionObject();
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
    int ret = sprintf_s(buf, ACCESS_TOKEN_MAX_LEN + 1, "%010u", callerTokenID_);
    if (ret < 0) {
        ZLOGE(LOG_LABEL, "sprintf callerTokenID_ %u failed", callerTokenID_);
        return "";
    }
    std::string accessToken(buf);
    callerUid_ = (pid_t)getuid();
    callerPid_ = getpid();
    callerDeviceID_ = GetLocalDeviceID();
    callerTokenID_ = RpcGetSelfTokenID();
    return accessToken + identity;
}

bool DBinderDatabusInvoker::SetCallingIdentity(std::string &identity)
{
    if (identity.empty() || identity.length() <= DEVICEID_LENGTH) {
        return false;
    }

    uint32_t tokenId = std::stoul(identity.substr(0, ACCESS_TOKEN_MAX_LEN));
    std::string deviceId = identity.substr(ACCESS_TOKEN_MAX_LEN, DEVICEID_LENGTH);
    uint64_t token = std::stoull(identity.substr(ACCESS_TOKEN_MAX_LEN + DEVICEID_LENGTH,
        identity.length() - ACCESS_TOKEN_MAX_LEN - DEVICEID_LENGTH).c_str());

    callerUid_ = static_cast<int>(token >> PID_LEN);
    callerPid_ = static_cast<int>(token);
    callerDeviceID_ = deviceId;
    callerTokenID_ = tokenId;

    return true;
}

int DBinderDatabusInvoker::TranslateProxy(uint32_t handle, uint32_t flag)
{
    return -IPC_INVOKER_TRANSLATE_ERR;
}

int DBinderDatabusInvoker::TranslateStub(binder_uintptr_t cookie, binder_uintptr_t ptr, uint32_t flag, int cmd)
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
