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

#include "ipc_object_stub.h"
#include "ipc_object_proxy.h"
#include "ipc_process_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "ipc_debug.h"
#include "log_tags.h"
#include "databus_session_callback.h"

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

    std::string sessionName = ipcProxy->GetSessionName();
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
        !data.WriteUint32(session->GetPeerPid()) || !data.WriteUint32(session->GetPeerUid()) ||
        !data.WriteString(session->GetPeerDeviceId()) || !data.WriteString(sessionName) ||
        !data.WriteUint32(remoteSession->GetTokenId())) {
        ZLOGE(LOG_LABEL, "write to parcel fail");
        return nullptr;
    }
    int err = ipcProxy->InvokeListenThread(data, reply);
    if (err != ERR_NONE) {
        ZLOGE(LOG_LABEL, "start service listen error = %d", err);
        return nullptr;
    }

    uint64_t stubIndex = reply.ReadUint64();
    std::string serverName = reply.ReadString();
    std::string deviceId = reply.ReadString();
    uint32_t peerTokenId = reply.ReadUint32();
    if (stubIndex == 0) {
        ZLOGE(LOG_LABEL, "stubindex error = %" PRIu64 "", stubIndex);
        return nullptr;
    }
    ZLOGI(LOG_LABEL, "serverName = %{public}s, peerTokenId = %{public}u", serverName.c_str(), peerTokenId);
    std::shared_ptr<DBinderSessionObject> connectSession =
        std::make_shared<DBinderSessionObject>(nullptr, serverName, deviceId, stubIndex, nullptr, peerTokenId);
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

    MessageParcel data, reply;
    MessageOption option;

    if (!data.WriteUint32(session->GetPeerPid()) || !data.WriteUint32(session->GetPeerUid()) ||
        !data.WriteString(session->GetPeerDeviceId()) || !data.WriteUint64(databusSession->GetStubIndex()) ||
        !data.WriteUint32(databusSession->GetTokenId())) {
        ZLOGE(LOG_LABEL, "write to MessageParcel fail");
        return false;
    }

    int err = SendRequest(handle, DBINDER_ADD_COMMAUTH, data, reply, option);
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
    uint32_t peerTokenId = 0;
    if (!current->QueryCommAuthInfo(session->GetPeerPid(), session->GetPeerUid(), peerTokenId,
        session->GetPeerDeviceId())) {
        ZLOGE(LOG_LABEL, "remote device is not auth");
        return false;
    }
    uint32_t oldTokenId = 0;
    if (current->StubDetachDBinderSession(handle, oldTokenId) == true) {
        ZLOGI(LOG_LABEL, "delete left session: %{public}u, device: %{public}s, oldTokenId: %{public}u", handle,
            IPCProcessSkeleton::ConvertToSecureString(session->GetPeerDeviceId()).c_str(), oldTokenId);
    }
    std::shared_ptr<DBinderSessionObject> sessionObject = std::make_shared<DBinderSessionObject>(session,
        session->GetPeerSessionName(), session->GetPeerDeviceId(), 0, nullptr, peerTokenId);
    if (!current->StubAttachDBinderSession(handle, sessionObject)) {
        ZLOGE(LOG_LABEL, "attach session to process skeleton failed, handle = %{public}u", handle);
        return false;
    }
    ZLOGE(LOG_LABEL, "pid %{public}u uid %{public}u deviceId %{public}s tokenId %{public}u "
        "oldTokenId %{public}u, listendFd %{public}u", session->GetPeerPid(), session->GetPeerUid(),
        IPCProcessSkeleton::ConvertToSecureString(session->GetPeerDeviceId()).c_str(),
        peerTokenId, oldTokenId, handle);
    // update listen fd
    current->AttachAppInfoToStubIndex(session->GetPeerPid(), session->GetPeerUid(), peerTokenId,
        session->GetPeerDeviceId(), handle);
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
    sessionBuff->UpdateSendBuffer(0); // 0 means do not expand buffer when send it
    ssize_t writeCursor = sessionBuff->GetSendBufferWriteCursor();
    ssize_t readCursor = sessionBuff->GetSendBufferReadCursor();
    if (writeCursor < readCursor) {
        ZLOGE(LOG_LABEL, "no data to send, write cursor: %{public}zu, read cursor: %{public}zu",
            writeCursor, readCursor);
        sessionBuff->ReleaseSendBufferLock();
        return -RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }
    if (writeCursor == readCursor) {
        ZLOGE(LOG_LABEL, "no data to send, write cursor: %{public}zu, read cursor: %{public}zu",
            writeCursor, readCursor);
        sessionBuff->ReleaseSendBufferLock();
        return ERR_NONE;
    }
    ssize_t size = writeCursor - readCursor;
    int ret = session->SendBytes(static_cast<const void *>(sendBuffer + readCursor), size);
    if (ret == 0) {
        readCursor += size;
        sessionBuff->SetSendBufferReadCursor(readCursor);
        sessionBuff->SetSendBufferWriteCursor(writeCursor);
        ZLOGE(LOG_LABEL, "SendBytes succ, buffer length = %{public}zd, session: %{public}" PRIu64 "",
            size, session->GetChannelId());
    } else {
        ZLOGE(LOG_LABEL, "ret = %{public}d, send buffer failed with length = %{public}zd, session: %{public}" PRIu64 "",
            ret, size, session->GetChannelId());
    }
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
    if (flatSession->serviceNameLength == 0 || flatSession->serviceNameLength > SUPPORT_TOKENID_SERVICENAME_LENGTH) {
        ZLOGE(LOG_LABEL, "wrong service name");
        return 0;
    }
    memcpyResult = memcpy_s(flatSession->serviceName, SUPPORT_TOKENID_SERVICENAME_LENGTH,
        connectSession->GetServiceName().data(), flatSession->serviceNameLength);
    if (memcpyResult != 0) {
        ZLOGE(LOG_LABEL, "memcpy_s failed , name Size = %hu", flatSession->serviceNameLength);
        return 0;
    }
    flatSession->serviceName[flatSession->serviceNameLength] = '\0';

    ZLOGI(LOG_LABEL, "serviceName = %{public}s, stubIndex = %{public}" PRIu64 ", tokenId = %{public}u",
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
    ZLOGI(LOG_LABEL, "serviceName = %{public}s, stubIndex = %{public}" PRIu64 "tokenId = %{public}u",
        flatSession->serviceName, flatSession->stubIndex, tokenId);

    return std::make_shared<DBinderSessionObject>(nullptr,
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
    return true;
}

bool DBinderDatabusInvoker::OnDatabusSessionServerSideClosed(std::shared_ptr<Session> session)
{
    int64_t channelId = session->GetChannelId();
    uint32_t tokenId = 0;

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current ipc process skeleton is nullptr");
        return false;
    }
    bool ret = current->StubDetachDBinderSession(IPCProcessSkeleton::ConvertChannelID2Int(channelId), tokenId);
    // detach info whose listen fd equals the given one
    std::list<uint64_t> stubIndexs = current->DetachAppInfoToStubIndex(session->GetPeerPid(), session->GetPeerUid(),
        tokenId, session->GetPeerDeviceId(), IPCProcessSkeleton::ConvertChannelID2Int(channelId));
    for (auto it = stubIndexs.begin(); it != stubIndexs.end(); it++) {
        // note that we canont remove mapping from stub to index here because other session may still be used
        IRemoteObject *stub = current->QueryStubByIndex(*it);
        if (stub == nullptr) {
            continue;
        }
        current->DetachCommAuthInfo(stub, session->GetPeerPid(), session->GetPeerUid(), tokenId,
            session->GetPeerDeviceId());
        // a proxy doesn't refers this stub, we need to dec ref
        stub->DecStrongRef(this);
        ZLOGI(LOG_LABEL, "pid %{public}u uid %{public}u deviceId %{public}s stubIndex %{public}" PRIu64,
            session->GetPeerPid(), session->GetPeerUid(),
            IPCProcessSkeleton::ConvertToSecureString(session->GetPeerDeviceId()).c_str(), *it);
    }
    ZLOGI(LOG_LABEL, "detach stub to session = %{public}" PRId64 ", ret:%{public}d", channelId, ret);
    return true;
}

bool DBinderDatabusInvoker::OnDatabusSessionClientSideClosed(std::shared_ptr<Session> session)
{
    int64_t channelId = session->GetChannelId();
    std::vector<uint32_t> proxy;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current ipc process skeleton is nullptr");
        return false;
    }
    if (!current->QueryProxyBySessionHandle(IPCProcessSkeleton::ConvertChannelID2Int(channelId), proxy)) {
        ZLOGE(LOG_LABEL, "session id is invalid: %{public}" PRId64 " ", channelId);
        return false;
    }
    if (proxy.empty()) {
        ZLOGE(LOG_LABEL, "proxy handle is empty");
        return false;
    }
    for (auto it = proxy.begin(); it != proxy.end(); ++it) {
        std::u16string descriptor = current->MakeHandleDescriptor(*it);
        sptr<IRemoteObject> remoteObject = current->QueryObject(descriptor);
        if (remoteObject != nullptr) {
            IPCObjectProxy *remoteProxy = reinterpret_cast<IPCObjectProxy *>(remoteObject.GetRefPtr());
            // No need to close session again here. First erase session and then notify user session has been closed.
            current->ProxyDetachDBinderSession(*it, remoteProxy);
            if (remoteProxy->IsSubscribeDeathNotice()) {
                remoteProxy->SendObituary();
            } else {
                ZLOGE(LOG_LABEL, "descriptor: %{public}s does not subscribe death notice",
                    Str16ToStr8(descriptor).c_str());
            }
        } else {
            ZLOGE(LOG_LABEL, "cannot find proxy with descriptor: %{public}s", Str16ToStr8(descriptor).c_str());
        }
    }
    ZLOGI(LOG_LABEL, "close socket sussess %{public}" PRId64 " ", channelId);
    return true;
}

bool DBinderDatabusInvoker::OnDatabusSessionClosed(std::shared_ptr<Session> session)
{
    if (session == nullptr) {
        ZLOGE(LOG_LABEL, "OnDatabusSessionClosed session is nullptr");
        return false;
    }
    int64_t channelId = session->GetChannelId();
    /* means close socket */
    ZLOGI(LOG_LABEL, "own session name = %{public}s, peer session name = %{public}s, session = %{public}" PRId64 "",
        session->GetMySessionName().c_str(), session->GetPeerSessionName().c_str(), channelId);

    bool result = false;
    if (session->IsServerSide()) {
        result = OnDatabusSessionServerSideClosed(session);
    } else {
        result = OnDatabusSessionClientSideClosed(session);
    }
    ZLOGI(LOG_LABEL, "close socket sussess %{public}" PRId64, channelId);
    return result;
}

uint32_t DBinderDatabusInvoker::QueryHandleBySession(std::shared_ptr<DBinderSessionObject> session)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current ipc process skeleton is nullptr");
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

    int pid = static_cast<int>(session->GetPeerPid());
    int uid = static_cast<int>(session->GetPeerUid());
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
    uint32_t callerTokenId = sessionObject->GetTokenId();
    if (current->QueryAppInfoToStubIndex(pid, uid, callerTokenId, deviceId, stubIndex, listenFd) == false) {
        ZLOGE(LOG_LABEL, "stubIndex is NOT belong to caller,pid:%{public}d, uid:%{public}d,stubIndex:%{public}" PRIu64
            ", deviceId:%{public}s, listenFd = %{public}u, callerTokenId = %{public}u", pid, uid, stubIndex,
            IPCProcessSkeleton::ConvertToSecureString(deviceId).c_str(), listenFd, callerTokenId);
        return RPC_DATABUS_INVOKER_INVALID_STUB_INDEX;
    }
    callerPid_ = pid;
    callerUid_ = uid;
    callerDeviceID_ = deviceId;
    clientFd_ = listenFd;
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
        ZLOGE(LOG_LABEL, "fail to get databus name or deviceId");
        return nullptr;
    }
    auto session = std::make_shared<DBinderSessionObject>(nullptr, serviceName, deviceId, stubIndex, nullptr,
        sessionObject->GetTokenId());
    if (session == nullptr) {
        ZLOGE(LOG_LABEL, "new server session fail!");
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
    std::shared_ptr<Session> session = sessionObject->GetBusSession();
    if (session == nullptr) {
        ZLOGE(LOG_LABEL, "get databus session fail");
        return false;
    }

    int peerPid = static_cast<int>(session->GetPeerPid());
    int peerUid = static_cast<int>(session->GetPeerUid());
    uint32_t tokenId = sessionObject->GetTokenId();
    std::string deviceId = session->GetPeerDeviceId();
    ZLOGI(LOG_LABEL, "peerPid:%{public}d, peerUid:%{public}d, peerDeviceId:%{public}s,tokenId:%{public}u, "
        "stubIndex:%{public}" PRIu64, peerPid, peerUid, IPCProcessSkeleton::ConvertToSecureString(deviceId).c_str(),
        tokenId, stubIndex);
    // mark listen fd as 0
    if (!current->AttachAppInfoToStubIndex(peerPid, peerUid, tokenId, deviceId, stubIndex, 0)) {
        ZLOGI(LOG_LABEL, "app info already existed, replace with 0");
    }
    if (current->AttachCommAuthInfo(stubObject, peerPid, peerUid, tokenId, deviceId)) {
        // first time send this stub to proxy indicating by deviceId, pid, uid
        stubObject->IncStrongRef(this);
    } else {
        ZLOGI(LOG_LABEL, "comm auth info attached already");
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
        ZLOGE(LOG_LABEL, "fail to connect stub to session");
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
        ZLOGE(LOG_LABEL, "sprintf callerTokenID_ %{public}" PRIu64 " failed", callerTokenID_);
        return "";
    }
    std::string accessToken(buf);
    callerUid_ = (pid_t)getuid();
    callerPid_ = getpid();
    callerDeviceID_ = GetLocalDeviceID();
    callerTokenID_ = GetSelfTokenID();
    return accessToken + identity;
}

bool DBinderDatabusInvoker::SetCallingIdentity(std::string &identity)
{
    if (identity.empty() || identity.length() <= DEVICEID_LENGTH) {
        return false;
    }

    uint64_t tokenId = std::stoull(identity.substr(0, ACCESS_TOKEN_MAX_LEN).c_str());
    std::string deviceId = identity.substr(ACCESS_TOKEN_MAX_LEN, DEVICEID_LENGTH);
    uint64_t token = std::stoull(identity.substr(ACCESS_TOKEN_MAX_LEN + DEVICEID_LENGTH,
        identity.length() - ACCESS_TOKEN_MAX_LEN - DEVICEID_LENGTH).c_str());

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
