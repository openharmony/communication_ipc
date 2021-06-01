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

#ifndef TITLE
#define TITLE __PRETTY_FUNCTION__
#endif

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_RPC, "DBinderDatabusInvoker" };
#define DBINDER_LOGE(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Error(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)
#define DBINDER_LOGI(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Info(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)

DBinderDatabusInvoker::DBinderDatabusInvoker()
    : stopWorkThread_(false), callerPid_(getpid()), callerUid_(getuid()), callerDeviceID_(""), status_(0)
{
    DBINDER_LOGI("Create DBinderDatabusInvoker");
}

DBinderDatabusInvoker::~DBinderDatabusInvoker()
{
    DBINDER_LOGI("Clean DBinderDatabusInvoker");
}

bool DBinderDatabusInvoker::AcquireHandle(int32_t handle)
{
    DBINDER_LOGI("Acquire Handle %{public}d", handle);
    return true;
}

bool DBinderDatabusInvoker::ReleaseHandle(int32_t handle)
{
    DBINDER_LOGI("Release Handle %{public}d", handle);
    return true;
}

std::shared_ptr<DBinderSessionObject> DBinderDatabusInvoker::NewSessionOfBinderProxy(uint32_t handle,
    std::shared_ptr<DBinderSessionObject> remoteSession)
{
    if (remoteSession == nullptr) {
        DBINDER_LOGE("remote session is nullptr");
        return nullptr;
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        DBINDER_LOGE("current ipc process skeleton is nullptr");
        return nullptr;
    }

    IPCObjectProxy *ipcProxy = reinterpret_cast<IPCObjectProxy *>(current->FindOrNewObject(handle));
    if (ipcProxy == nullptr) {
        DBINDER_LOGE("attempt to send a invalid handle = %u", handle);
        return nullptr;
    }

    if (ipcProxy->GetProto() != IRemoteObject::IF_PROT_BINDER) {
        DBINDER_LOGE("attempt to send a distributed proxy, handle = %u", handle);
        return nullptr;
    }

    std::string sessionName = ipcProxy->GetPidAndUidInfo();
    if (sessionName.empty()) {
        DBINDER_LOGE("get bus name error");
        return nullptr;
    }

    std::shared_ptr<Session> session = remoteSession->GetBusSession();
    if (session == nullptr) {
        DBINDER_LOGE("get databus session fail");
        return nullptr;
    }

    MessageParcel data, reply;
    if (!data.WriteUint32(IRemoteObject::DATABUS_TYPE) || !data.WriteString(current->GetLocalDeviceID()) ||
        !data.WriteUint32(session->GetPeerPid()) || !data.WriteUint32(session->GetPeerUid()) ||
        !data.WriteString(session->GetPeerDeviceId()) || !data.WriteString(sessionName)) {
        DBINDER_LOGE("write to parcel fail");
        return nullptr;
    }
    int err = ipcProxy->InvokeListenThread(data, reply);
    if (err != ERR_NONE) {
        DBINDER_LOGE("start service listen error = %d", err);
        return nullptr;
    }

    uint64_t stubIndex = reply.ReadUint64();
    if (stubIndex == 0) {
        DBINDER_LOGE("stubindex error = %" PRIu64 "", stubIndex);
        return nullptr;
    }

    if (!current->AttachHandleToIndex(handle, stubIndex)) {
        DBINDER_LOGE("add stub index err stubIndex = %" PRIu64 ", handle = %u", stubIndex, handle);
        // do nothing, Sending an object repeatedly
    }

    std::string serverName = reply.ReadString();
    std::string deviceId = reply.ReadString();
    DBINDER_LOGI("NewSessionOfBinderProxy serverName= %s", serverName.c_str());

    std::shared_ptr<DBinderSessionObject> connectSession =
        std::make_shared<DBinderSessionObject>(nullptr, serverName, deviceId);
    if (connectSession == nullptr) {
        DBINDER_LOGE("new server session fail!");
        return nullptr;
    }

    return connectSession;
}

bool DBinderDatabusInvoker::AuthSession2Proxy(uint32_t handle,
    const std::shared_ptr<DBinderSessionObject> databusSession)
{
    if (databusSession == nullptr) {
        DBINDER_LOGE("remote session is nullptr");
        return false;
    }

    std::shared_ptr<Session> session = databusSession->GetBusSession();
    if (session == nullptr) {
        DBINDER_LOGE("get databus session fail");
        return false;
    }

    MessageParcel data, reply;
    MessageOption option;

    if (!data.WriteUint32(session->GetPeerPid()) || !data.WriteUint32(session->GetPeerUid()) ||
        !data.WriteString(session->GetPeerDeviceId())) {
        DBINDER_LOGE("write to MessageParcel fail");
        return false;
    }

    uint32_t err = SendRequest(handle, DBINDER_ADD_COMMAUTH, data, reply, option);
    if (err != ERR_NONE) {
        DBINDER_LOGE("send auth info to remote fail");
        return false;
    }
    return true;
}

std::shared_ptr<DBinderSessionObject> DBinderDatabusInvoker::QuerySessionOfBinderProxy(uint32_t handle,
    std::shared_ptr<DBinderSessionObject> session)
{
    if (AuthSession2Proxy(handle, session) != true) {
        DBINDER_LOGE("auth handle =%{public}u to session failed", handle);
        return nullptr;
    }
    return QueryServerSessionObject(handle);
}

std::shared_ptr<DBinderSessionObject> DBinderDatabusInvoker::QueryClientSessionObject(uint32_t databusHandle)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        DBINDER_LOGE("current ipc process skeleton is nullptr");
        return nullptr;
    }
    std::shared_ptr<DBinderSessionObject> sessionOfPeer = current->StubQueryDBinderSession(databusHandle);
    if (sessionOfPeer == nullptr) {
        DBINDER_LOGE("no session attach to this proxy = %{public}u", databusHandle);
        return nullptr;
    }
    return sessionOfPeer;
}

std::shared_ptr<DBinderSessionObject> DBinderDatabusInvoker::QueryServerSessionObject(uint32_t handle)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        DBINDER_LOGE("current ipc process skeleton is nullptr");
        return nullptr;
    }

    std::shared_ptr<DBinderSessionObject> sessionOfPeer = current->ProxyQueryDBinderSession(handle);
    if (sessionOfPeer == nullptr) {
        DBINDER_LOGI("no session attach to this handle = %{public}u", handle);
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
        DBINDER_LOGE("current ipc process skeleton is nullptr");
        return false;
    }

    if (!current->QueryIsAuth(session->GetPeerPid(), session->GetPeerUid(), session->GetPeerDeviceId())) {
        DBINDER_LOGE("remote device is not auth");
        return false;
    }

    std::shared_ptr<DBinderSessionObject> sessionObject =
        std::make_shared<DBinderSessionObject>(session, session->GetPeerSessionName(), session->GetPeerDeviceId());

    if (!current->StubAttachDBinderSession(handle, sessionObject)) {
        DBINDER_LOGE("attach session to process skeleton failed, handle =%u", handle);
    }
    return true;
}

bool DBinderDatabusInvoker::CreateProcessThread()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        DBINDER_LOGE("current ipc process skeleton is nullptr");
        return false;
    }
    /*  epoll thread obtained one thread, so idle thread must more than 1 */
    if (current->GetSocketIdleThreadNum() > 0) {
        current->SpawnThread(IPCWorkThread::PROCESS_PASSIVE, IRemoteObject::IF_PROT_DATABUS);
        DBINDER_LOGI("create Process thread success");
        return true;
    }

    DBINDER_LOGE("no idle socket thread left, fail to CreateProcessThread");
    return false;
}

void DBinderDatabusInvoker::OnRawDataAvailable(std::shared_ptr<Session> session, const char *data, uint32_t dataSize)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        DBINDER_LOGE("current ipc process skeleton is nullptr");
        return;
    }

    uint32_t rawDataSize = dataSize - sizeof(dbinder_transaction_data);
    if (rawDataSize > 0 && rawDataSize <= MAX_RAWDATA_SIZE - sizeof(dbinder_transaction_data)) {
        std::shared_ptr<InvokerRawData> invokerRawData = std::make_shared<InvokerRawData>(rawDataSize);
        if (memcpy_s(invokerRawData->GetData().get(), rawDataSize, data + sizeof(dbinder_transaction_data),
            rawDataSize) != EOK) {
            DBINDER_LOGE("memcpy_s failed , size = %u", rawDataSize);
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
        DBINDER_LOGE("session has wrong inputs");
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
            break;
        }
    } while (readSize + sizeof(dbinder_transaction_data) < static_cast<uint32_t>(len));
}

int DBinderDatabusInvoker::OnSendMessage(std::shared_ptr<DBinderSessionObject> sessionOfPeer)
{
    if (sessionOfPeer == nullptr) {
        DBINDER_LOGE("sessionOfPeer is null");
        return -RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    std::shared_ptr<Session> session = sessionOfPeer->GetBusSession();
    if (session == nullptr) {
        DBINDER_LOGE("databus session is null");
        return -RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    std::shared_ptr<BufferObject> sessionBuff = sessionOfPeer->GetSessionBuff();
    if (sessionBuff == nullptr) {
        DBINDER_LOGE("databus session buff is null");
        return -RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    char *sendBuffer = sessionBuff->GetSendBufferAndLock(SOCKET_DEFAULT_BUFF_SIZE);
    /* session buffer contain mutex, need release mutex */
    if (sendBuffer == nullptr) {
        DBINDER_LOGE("buffer alloc failed in session");
        return -RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }
    sessionBuff->UpdateSendBuffer();
    size_t writeCursor = sessionBuff->GetSendBufferWriteCursor();
    size_t readCursor = sessionBuff->GetSendBufferReadCursor();
    if (writeCursor <= readCursor) {
        sessionBuff->ReleaseSendBufferLock();
        return -RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    size_t size = writeCursor - readCursor;
    int ret = session->SendBytes(static_cast<const void *>(sendBuffer + readCursor), static_cast<ssize_t>(size));
    if (ret == 0) {
        readCursor += size;
        sessionBuff->SetSendBufferReadCursor(readCursor);
        sessionBuff->SetSendBufferWriteCursor(writeCursor);
    } else {
        DBINDER_LOGE("ret = %{public}d, send buffer failed with length = %{public}zu, send in next time", ret, size);
    }
    sessionBuff->ReleaseSendBufferLock();
    return ret;
}

int DBinderDatabusInvoker::OnSendRawData(std::shared_ptr<DBinderSessionObject> session, const void *data, size_t size)
{
    if (session == nullptr) {
        DBINDER_LOGE("sessionOfPeer is null");
        return -RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    std::shared_ptr<Session> dataBusSession = session->GetBusSession();
    if (dataBusSession == nullptr) {
        DBINDER_LOGE("databus session is null");
        return -RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    int ret = dataBusSession->SendBytes(data, size);
    if (ret != 0) {
        DBINDER_LOGE("ret = %{public}d, send buffer overflow with length = %{public}zu", ret, size);
    }

    return ret;
}

void DBinderDatabusInvoker::JoinThread(bool initiative) {}

void DBinderDatabusInvoker::JoinProcessThread(bool initiative)
{
    std::thread::id threadId = std::this_thread::get_id();
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        DBINDER_LOGE("current ipc process skeleton is nullptr");
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
        DBINDER_LOGE("wrong devices id");
        return 0;
    }
    int memcpyResult = memcpy_s(flatSession->deviceId, DEVICEID_LENGTH, connectSession->GetDeviceId().data(),
        flatSession->deviceIdLength);
    if (memcpyResult != 0) {
        DBINDER_LOGE("memcpy_s failed , ID Size = %hu", flatSession->deviceIdLength);
        return 0;
    }
    flatSession->deviceId[flatSession->deviceIdLength] = '\0';

    flatSession->serviceNameLength = connectSession->GetServiceName().length();
    if (flatSession->serviceNameLength == 0 || flatSession->serviceNameLength > SERVICENAME_LENGTH) {
        DBINDER_LOGE("wrong service name");
        return 0;
    }
    memcpyResult = memcpy_s(flatSession->serviceName, SERVICENAME_LENGTH, connectSession->GetServiceName().data(),
        flatSession->serviceNameLength);
    if (memcpyResult != 0) {
        DBINDER_LOGE("memcpy_s failed , name Size = %hu", flatSession->serviceNameLength);
        return 0;
    }
    flatSession->serviceName[flatSession->serviceNameLength] = '\0';

    DBINDER_LOGI("serviceName = %s, stubIndex = %" PRIu64 "", flatSession->serviceName, flatSession->stubIndex);

    return sizeof(struct FlatDBinderSession);
}

std::shared_ptr<DBinderSessionObject> DBinderDatabusInvoker::UnFlattenSession(char *sessionOffset, uint64_t &stubIndex)
{
    FlatDBinderSession *flatSession = reinterpret_cast<FlatDBinderSession *>(sessionOffset);
    /* force end true string length */
    flatSession->deviceId[DEVICEID_LENGTH] = '\0';
    flatSession->serviceName[SERVICENAME_LENGTH] = '\0';

    DBINDER_LOGI("serviceName = %s, stubIndex = %" PRIu64 "", flatSession->serviceName, flatSession->stubIndex);
    stubIndex = flatSession->stubIndex;
    if (stubIndex == 0) {
        DBINDER_LOGE("stubIndex err");
        return nullptr;
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        DBINDER_LOGE("current process skeleton is nullptr");
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

IRemoteObject *DBinderDatabusInvoker::UnflattenObject(Parcel &parcel)
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
    DBINDER_LOGI("update client session enter");

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        DBINDER_LOGE("current process skeleton is nullptr");
        return false;
    }

    std::shared_ptr<ISessionService> manager = ISessionService::GetInstance();
    if (manager == nullptr) {
        DBINDER_LOGE("fail to get softbus manager");
        return false;
    }

    std::string sessionName = current->GetDatabusName();
    if (sessionName.empty()) {
        DBINDER_LOGE("fail to get session name");
        return false;
    }

    std::shared_ptr<Session> session = manager->OpenSession(sessionName, sessionObject->GetServiceName(),
        sessionObject->GetDeviceId(), std::string(""), Session::TYPE_BYTES);
    if (session == nullptr) {
        DBINDER_LOGE("get databus session fail");
        return false;
    }

    sessionObject->SetBusSession(session);

    if (!current->ProxyAttachDBinderSession(handle, sessionObject)) {
        DBINDER_LOGE("fail to attach session");
        return false;
    }

    return true;
}

bool DBinderDatabusInvoker::OnDatabusSessionClosed(std::shared_ptr<Session> session)
{
    if (session == nullptr) {
        DBINDER_LOGE("databus session to be closed is nullptr");
        return false;
    }
    /* means close socket */
    DBINDER_LOGI("close databus session, own session name = %{public}s, peer session name = %{public}s",
        session->GetMySessionName().c_str(), session->GetPeerSessionName().c_str());
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        DBINDER_LOGE("current ipc process skeleton is nullptr");
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
        DBINDER_LOGE("proxy handle is empty");
        return false;
    }

    for (auto it = proxy.begin(); it != proxy.end(); ++it) {
        std::u16string descriptor = current->MakeHandleDescriptor(*it);
        IRemoteObject *remoteObject = current->QueryObject(descriptor);
        if (remoteObject != nullptr) {
            IPCObjectProxy *remoteProxy = reinterpret_cast<IPCObjectProxy *>(remoteObject);
            if (remoteProxy->IsSubscribeDeathNotice()) {
                remoteProxy->SendObituary();
            }
            (void)current->ProxyDetachDBinderSession(*it);
            (void)current->DetachHandleToIndex(*it);
        }
    }

    DBINDER_LOGI("closet socket sussess");
    return true;
}

uint32_t DBinderDatabusInvoker::QueryHandleBySession(std::shared_ptr<DBinderSessionObject> session, uint64_t stubIndex)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        DBINDER_LOGE("current ipc process skeleton is nullptr");
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

void DBinderDatabusInvoker::SetCallerDeviceID(const std::string &deviceId)
{
    callerDeviceID_ = deviceId;
}

bool DBinderDatabusInvoker::IsLocalCalling()
{
    return false;
}

int DBinderDatabusInvoker::CheckAndSetCallerInfo(uint32_t listenFd, uint64_t stubIndex)
{
    std::shared_ptr<DBinderSessionObject> sessionObject = QueryClientSessionObject(listenFd);
    if (sessionObject == nullptr) {
        DBINDER_LOGE("session is not exist for listenFd = %u", listenFd);
        return RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    std::shared_ptr<Session> session = sessionObject->GetBusSession();
    if (session == nullptr) {
        DBINDER_LOGE("get databus session fail");
        return RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    int pid = session->GetPeerPid();
    int uid = session->GetPeerUid();
    std::string deviceId = session->GetPeerDeviceId();
    if (uid < 0 || deviceId.length() > DEVICEID_LENGTH) {
        DBINDER_LOGE("user id and device id error");
        return RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        DBINDER_LOGE("current process skeleton is nullptr");
        return IPC_SKELETON_ERR;
    }
    if (current->QueryAppInfoToStubIndex(pid, uid, deviceId, stubIndex) == false) {
        DBINDER_LOGE("stub index is NOT belong to caller,serviceName = %{public}s, listenFd = %{public}u",
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
        DBINDER_LOGE("current process skeleton is nullptr");
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
        DBINDER_LOGE("IPCProcessSkeleton is nullptr");
        return 0;
    }

    if (!current->IsContainsObject(stubObject)) {
        DBINDER_LOGE("fail to find stub");
        return 0;
    }

    uint64_t stubIndex = current->AddStubByIndex(stubObject);
    if (!stubIndex) {
        DBINDER_LOGE("fail to add stub");
        return 0;
    }
    return stubIndex;
}

std::shared_ptr<DBinderSessionObject> DBinderDatabusInvoker::MakeDefaultServerSessionObject()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        DBINDER_LOGE("IPCProcessSkeleton is nullptr");
        return nullptr;
    }
    std::string serviceName = current->GetDatabusName();
    if (serviceName.empty()) {
        DBINDER_LOGE("fail to get databus name");
        return nullptr;
    }
    std::shared_ptr<DBinderSessionObject> connectSession =
        std::make_shared<DBinderSessionObject>(nullptr, serviceName, current->GetLocalDeviceID());
    if (connectSession == nullptr) {
        DBINDER_LOGE("new server session fail!");
        return nullptr;
    }
    return connectSession;
}

bool DBinderDatabusInvoker::ConnectRemoteObject2Session(IRemoteObject *stubObject, uint64_t stubIndex,
    const std::shared_ptr<DBinderSessionObject> sessionObject)
{
    if (sessionObject == nullptr) {
        DBINDER_LOGE("session object is nullptr");
        return false;
    }
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        DBINDER_LOGE("IPCProcessSkeleton is nullptr");
        return false;
    }
    std::shared_ptr<Session> session = sessionObject->GetBusSession();
    if (session == nullptr) {
        DBINDER_LOGE("get databus session fail");
        return false;
    }

    int peerPid = session->GetPeerPid();
    int peerUid = session->GetPeerUid();
    std::string deviceId = session->GetPeerDeviceId();
    if (!current->AttachAppInfoToStubIndex(peerPid, peerUid, deviceId, stubIndex)) {
        DBINDER_LOGI("fail to attach appinfo to stub index, when proxy call we check appinfo");
        // attempt attach again, if failed, do nothing
    }
    if (!current->AttachCommAuthInfo(stubObject, peerPid, peerUid, deviceId)) {
        DBINDER_LOGI("fail to attach comm auth info, maybe attached already");
        // attempt attach again, if failed, do nothing
    }

    if (current->AttachStubSendRefInfo(stubObject, peerPid, deviceId)) {
        if (!current->IncStubRefTimes(stubObject)) {
            DBINDER_LOGE("Inc Stub RefTimes fail");
            current->DetachCommAuthInfo(stubObject, peerPid, peerUid, deviceId);
            current->DetachAppInfoToStubIndex(peerPid, peerUid, deviceId, stubIndex);
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
        DBINDER_LOGE("binder is nullptr");
        return nullptr;
    }

    stubIndex = MakeStubIndexByRemoteObject(stubObject);
    if (stubIndex == 0) {
        DBINDER_LOGE("fail to add stub");
        return nullptr;
    }
    if (ConnectRemoteObject2Session(stubObject, stubIndex, sessionObject) != true) {
        DBINDER_LOGE("fail to connect stub to session");
        return nullptr;
    }
    return MakeDefaultServerSessionObject();
}

int DBinderDatabusInvoker::FlushCommands(IRemoteObject *object)
{
    if (object == nullptr || !object->IsProxyObject()) {
        DBINDER_LOGE("proxy is invalid");
        return RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    IPCObjectProxy *proxy = reinterpret_cast<IPCObjectProxy *>(object);

    std::shared_ptr<DBinderSessionObject> session = QueryServerSessionObject(proxy->GetHandle());
    if (session == nullptr) {
        DBINDER_LOGE("session is nullptr");
        return RPC_DATABUS_INVOKER_INVALID_DATA_ERR;
    }

    (void)OnSendMessage(session);
    return ERR_NONE;
}

std::string DBinderDatabusInvoker::ResetCallingIdentity()
{
    std::string token = std::to_string(((static_cast<int64_t>(callerUid_) << PID_LEN) | callerPid_));
    std::string identity = callerDeviceID_ + token;
    callerUid_ = getuid();
    callerPid_ = getpid();
    callerDeviceID_ = GetLocalDeviceID();
    return identity;
}

bool DBinderDatabusInvoker::SetCallingIdentity(std::string &identity)
{
    if (identity.empty() || identity.length() <= DEVICEID_LENGTH) {
        return false;
    }

    std::string deviceId = identity.substr(0, DEVICEID_LENGTH);
    int64_t token = std::atoll(identity.substr(DEVICEID_LENGTH, identity.length() - DEVICEID_LENGTH).c_str());

    callerUid_ = static_cast<int>(token >> PID_LEN);
    callerPid_ = static_cast<int>(token);
    callerDeviceID_ = deviceId;

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
