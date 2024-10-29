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

#include "ipc_object_stub.h"

#include <cstdint>
#include <ctime>
#include <string>

#include "hilog/log_c.h"
#include "hilog/log_cpp.h"
#include "iosfwd"
#include "ipc_debug.h"
#include "ipc_payload_statistics_impl.h"
#include "ipc_process_skeleton.h"
#include "ipc_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "ipc_types.h"
#include "iremote_invoker.h"
#include "iremote_object.h"
#include "log_tags.h"
#include "message_option.h"
#include "message_parcel.h"
#include "process_skeleton.h"
#include "refbase.h"
#include "string_ex.h"
#include "sys_binder.h"
#include "unistd.h"
#include "vector"

#ifndef CONFIG_IPC_SINGLE
#include "dbinder_databus_invoker.h"
#include "dbinder_error_code.h"
#endif

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
using namespace IPC_SINGLE;
#endif
using namespace OHOS::HiviewDFX;
static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC_STUB, "IPCObjectStub" };
#ifndef CONFIG_IPC_SINGLE
// Authentication information can be added only for processes with system permission.
static constexpr pid_t ALLOWED_UID = 10000;
#endif
static constexpr int SHELL_UID = 2000;
static constexpr int HIDUMPER_SERVICE_UID = 1212;
static constexpr int COEFF_MILLI_TO_MICRO = 1000;
static constexpr int IPC_CMD_PROCESS_WARN_TIME = 500 * COEFF_MILLI_TO_MICRO; // 500 ms

IPCObjectStub::IPCObjectStub(std::u16string descriptor, bool serialInvokeFlag)
    : IRemoteObject(descriptor), serialInvokeFlag_(serialInvokeFlag), lastRequestTime_(0)
{
    ZLOGD(LABEL, "desc:%{public}s, %{public}u",
        ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(descriptor_)).c_str(),
        ProcessSkeleton::ConvertAddr(this));
    auto start = std::chrono::steady_clock::now();
    lastRequestTime_ = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        start.time_since_epoch()).count());
    ProcessSkeleton *current = ProcessSkeleton::GetInstance();
    if (current == nullptr) {
        ZLOGE(LABEL, "ProcessSkeleton is null");
        return;
    }
    if (current->GetSamgrFlag()) {
        SetRequestSidFlag(true);
    }
    std::u16string str(descriptor_);
    current->AttachValidObject(this, str);
}

IPCObjectStub::~IPCObjectStub()
{
    ZLOGD(LABEL, "desc:%{public}s, %{public}u",
        ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(descriptor_)).c_str(),
        ProcessSkeleton::ConvertAddr(this));
    ProcessSkeleton *current = ProcessSkeleton::GetInstance();
    if (current == nullptr) {
        ZLOGE(LABEL, "ProcessSkeleton is null");
        return;
    }
    uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
    current->DetachValidObject(this);
}

bool IPCObjectStub::IsDeviceIdIllegal(const std::string &deviceID)
{
    if (deviceID.empty() || deviceID.length() > DEVICEID_LENGTH) {
        return true;
    }
    return false;
}

int32_t IPCObjectStub::GetObjectRefCount()
{
    return GetSptrRefCount();
}

int IPCObjectStub::Dump(int fd, const std::vector<std::u16string> &args)
{
    const size_t numArgs = args.size();
    ZLOGE(LABEL, "Invalid call on Stub, fd:%{public}d args:%{public}zu", fd, numArgs);
    return ERR_NONE;
}

int IPCObjectStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int result = ERR_NONE;
    switch (code) {
#ifndef CONFIG_IPC_SINGLE
        case DBINDER_OBITUARY_TRANSACTION: {
            ZLOGW(LABEL, "recv DBINDER_OBITUARY_TRANSACTION, desc:%{public}s",
                ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(descriptor_)).c_str());
            if (data.ReadInt32() == IRemoteObject::DeathRecipient::NOTICE_DEATH_RECIPIENT) {
                result = NoticeServiceDie(data, reply, option);
            } else {
                result = IPC_STUB_INVALID_DATA_ERR;
            }
            break;
        }
#endif
        default:
            result = IPC_STUB_UNKNOW_TRANS_ERR;
            uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
            ZLOGW(LABEL, "unknown code:%{public}u desc:%{public}s time:%{public}" PRIu64, code,
                ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(descriptor_)).c_str(), curTime);
            break;
    }
    return result;
}

int IPCObjectStub::OnRemoteDump(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int result = ERR_NONE;
    int fd = data.ReadFileDescriptor();
    std::vector<std::u16string> args;
    if (fd != INVALID_FD) {
        if (data.ReadString16Vector(&args)) {
            result = Dump(fd, args);
        }
        ::close(fd);
    } else {
        result = IPC_STUB_INVALID_DATA_ERR;
    }
    return result;
}

int IPCObjectStub::DBinderPingTransaction(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (!reply.WriteInt32(ERR_NONE)) {
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

int IPCObjectStub::DBinderSearchDescriptor(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    std::u16string descriptor = GetObjectDescriptor();
    if (!reply.WriteString16(descriptor)) {
        ZLOGE(LABEL, "write to parcel fail");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

int IPCObjectStub::DBinderSearchRefCount(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int refCount = GetObjectRefCount();
    // when handle transaction the invoker would try to acquire
    // the object's reference to defense the object being released
    // so the actual we should decrement the temporary reference.
    if (IPCSkeleton::IsLocalCalling()) {
        --refCount;
    }
    reply.WriteInt32(refCount);
    return ERR_NONE;
}

int IPCObjectStub::DBinderDumpTransaction(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    pid_t uid = IPCSkeleton::GetCallingUid();
    if (!IPCSkeleton::IsLocalCalling() || (uid != 0 && uid != SHELL_UID && uid != HIDUMPER_SERVICE_UID)) {
        ZLOGE(LABEL, "do not allow dump, uid:%{public}u", uid);
        return ERR_NONE;
    }
    return OnRemoteDump(code, data, reply, option);
}

#ifndef CONFIG_IPC_SINGLE
int IPCObjectStub::DBinderInvokeListenThread(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    pid_t uid = IPCSkeleton::GetCallingUid();
    if (!IPCSkeleton::IsLocalCalling() || uid >= ALLOWED_UID) {
        ZLOGE(LABEL, "INVOKE_LISTEN_THREAD unauthenticated user, desc:%{public}s, uid:%{public}u",
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(descriptor_)).c_str(), uid);
        return IPC_STUB_INVALID_DATA_ERR;
    }
    return InvokerThread(code, data, reply, option);
}

int IPCObjectStub::DBinderIncRefsTransaction(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (IPCSkeleton::IsLocalCalling()) {
        ZLOGE(LABEL, "dbinder incref in the same device is invalid");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    pid_t callerPid = IPCSkeleton::GetCallingPid();
    pid_t callerUid = IPCSkeleton::GetCallingUid();
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
    std::string callerDevId = IPCSkeleton::GetCallingDeviceID();
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    uint64_t stubIndex = current->QueryStubIndex(this);
    DBinderDatabusInvoker *invoker = reinterpret_cast<DBinderDatabusInvoker *>(
        IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS));
    if (invoker == nullptr) {
        return IPC_STUB_INVALID_DATA_ERR;
    }
    int32_t listenFd = invoker->GetClientFd();
    // update listenFd
    ZLOGW(LABEL, "update app info, listenFd:%{public}d stubIndex:%{public}" PRIu64 " tokenId:%{public}u",
        listenFd, stubIndex, tokenId);
    AppAuthInfo appAuthInfo = { callerPid, callerUid, tokenId, listenFd, stubIndex, nullptr, callerDevId };
    current->AttachOrUpdateAppAuthInfo(appAuthInfo);
    return ERR_NONE;
}

int IPCObjectStub::DBinderDecRefsTransaction(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (IPCSkeleton::IsLocalCalling()) {
        ZLOGE(LABEL, "dbinder decref in the same device is invalid");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    // stub's refcount will be decreased either in this case or OnSessionClosed callback
    // we may race with OnSessionClosed callback, thus dec refcount only when removing appInfo sucessfully
    pid_t callerPid = IPCSkeleton::GetCallingPid();
    pid_t callerUid = IPCSkeleton::GetCallingUid();
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
    std::string callerDevId = IPCSkeleton::GetCallingDeviceID();
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    uint64_t stubIndex = current->QueryStubIndex(this);
    DBinderDatabusInvoker *invoker = reinterpret_cast<DBinderDatabusInvoker *>(
        IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS));
    if (invoker == nullptr) {
        return IPC_STUB_INVALID_DATA_ERR;
    }
    int32_t listenFd = invoker->GetClientFd();
    // detach info whose listen fd equals the given one
    AppAuthInfo appAuthInfo = { callerPid, callerUid, tokenId, listenFd, stubIndex, this, callerDevId };
    if (current->DetachAppAuthInfo(appAuthInfo)) {
        DecStrongRef(this);
    }
    return ERR_NONE;
}

int IPCObjectStub::DBinderAddCommAuth(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    pid_t uid = IPCSkeleton::GetCallingUid();
    if (IPCSkeleton::IsLocalCalling() || uid >= ALLOWED_UID) {
        ZLOGE(LABEL, "DBINDER_ADD_COMMAUTH unauthenticated user, desc:%{public}s, uid:%{public}u",
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(descriptor_)).c_str(), uid);
        return IPC_STUB_INVALID_DATA_ERR;
    }
    return AddAuthInfo(data, reply, code);
}

int IPCObjectStub::DBinderGetSessionName(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (!IPCSkeleton::IsLocalCalling()) {
        ZLOGE(LABEL, "GET_UIDPID_INFO message is not from sa manager");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    std::string sessionName = GetSessionName();
    if (sessionName.empty()) {
        ZLOGE(LABEL, "sessionName is empty");
        return IPC_STUB_CREATE_BUS_SERVER_ERR;
    }
    if (!reply.WriteString(sessionName)) {
        ZLOGE(LABEL, "write to parcel fail");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    return ERR_NONE;
}

int IPCObjectStub::DBinderGetGrantedSessionName(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (!IPCSkeleton::IsLocalCalling() || !IsSamgrCall()) {
        ZLOGE(LABEL, "GRANT_DATABUS_NAME message is excluded in sa manager");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    return GetGrantedSessionName(code, data, reply, option);
}

int IPCObjectStub::DBinderGetSessionNameForPidUid(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (!IPCSkeleton::IsLocalCalling() || !IsSamgrCall()) {
        ZLOGE(LABEL, "TRANS_DATABUS_NAME message is excluded in sa manager");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    return GetSessionNameForPidUid(code, data, reply, option);
}

int IPCObjectStub::DBinderGetPidUid(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (!IPCSkeleton::IsLocalCalling()) {
        return IPC_STUB_INVALID_DATA_ERR;
    }
    return GetPidUid(data, reply);
}

int IPCObjectStub::DBinderRemoveSessionName(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (!IPCSkeleton::IsLocalCalling() || !IsSamgrCall()) {
        ZLOGE(LABEL, "REMOVE_SESSION_NAME message is excluded in sa manager");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    return RemoveSessionName(data);
}
#endif

int IPCObjectStub::SendRequestInner(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int result = ERR_NONE;
    std::unique_lock<std::recursive_mutex> lockGuard(serialRecursiveMutex_, std::defer_lock);
    if (serialInvokeFlag_) {
        lockGuard.lock();
    }
    auto start = std::chrono::steady_clock::now();
    lastRequestTime_ = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        start.time_since_epoch()).count());
    result = OnRemoteRequest(code, data, reply, option);
    auto finish = std::chrono::steady_clock::now();
    uint32_t duration = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::microseconds>(
        finish - start).count());
    if (duration >= IPC_CMD_PROCESS_WARN_TIME) {
        ZLOGW(LABEL, "stub:%{public}s deal request code:%{public}u cost time:%{public}ums",
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(GetObjectDescriptor())).c_str(),
            code, duration / COEFF_MILLI_TO_MICRO);
    }

    IPCPayloadStatisticsImpl& instance = IPCPayloadStatisticsImpl::GetInstance();
    if (instance.GetStatisticsStatus()) {
        int32_t currentPid = IPCSkeleton::GetCallingPid();
        std::u16string currentDesc = GetObjectDescriptor();
        int32_t currentCode = static_cast<int32_t>(code);
        if (!instance.UpdatePayloadInfo(currentPid, currentDesc, currentCode, duration)) {
            ZLOGE(LABEL, "Process load information update failed");
        }
    }
    return result;
}

int IPCObjectStub::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    switch (code) {
        case PING_TRANSACTION:
            return DBinderPingTransaction(code, data, reply, option);
        case INTERFACE_TRANSACTION:
            return DBinderSearchDescriptor(code, data, reply, option);
        case SYNCHRONIZE_REFERENCE:
            return DBinderSearchRefCount(code, data, reply, option);
        case DUMP_TRANSACTION:
            return DBinderDumpTransaction(code, data, reply, option);
        case GET_PROTO_INFO:
            return ProcessProto(code, data, reply, option);
#ifndef CONFIG_IPC_SINGLE
        case INVOKE_LISTEN_THREAD:
            return DBinderInvokeListenThread(code, data, reply, option);
        case DBINDER_INCREFS_TRANSACTION:
            return DBinderIncRefsTransaction(code, data, reply, option);
        case DBINDER_DECREFS_TRANSACTION:
            return DBinderDecRefsTransaction(code, data, reply, option);
        case DBINDER_ADD_COMMAUTH:
            return DBinderAddCommAuth(code, data, reply, option);
        case GET_SESSION_NAME:
            return DBinderGetSessionName(code, data, reply, option);
        case GET_GRANTED_SESSION_NAME:
            return DBinderGetGrantedSessionName(code, data, reply, option);
        case GET_SESSION_NAME_PID_UID:
            return DBinderGetSessionNameForPidUid(code, data, reply, option);
        case GET_PID_UID:
            return DBinderGetPidUid(code, data, reply, option);
        case REMOVE_SESSION_NAME:
            return DBinderRemoveSessionName(code, data, reply, option);
#endif
        default:
            return SendRequestInner(code, data, reply, option);
    }
    return ERR_NONE;
}

void IPCObjectStub::OnFirstStrongRef(const void *objectId)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();

    if (current != nullptr) {
        current->AttachObject(this);
    }
}

void IPCObjectStub::OnLastStrongRef(const void *objectId)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();

    if (current != nullptr) {
        current->DetachObject(this);
#ifndef CONFIG_IPC_SINGLE
        // we only need to erase stub index here, commAuth and appInfo
        // has already been removed either in dbinder dec refcount case
        // or OnSessionClosed, we also remove commAuth and appInfo in case of leak
        uint64_t stubIndex = current->EraseStubIndex(this);
        current->DetachAppAuthInfoByStub(this, stubIndex);
#endif
    }
}

bool IPCObjectStub::AddDeathRecipient(const sptr<DeathRecipient> &recipient)
{
    (void)recipient;
    return false;
}

bool IPCObjectStub::RemoveDeathRecipient(const sptr<DeathRecipient> &recipient)
{
    (void)recipient;
    return false;
}

pid_t IPCObjectStub::GetCallingPid()
{
    return IPCSkeleton::GetCallingPid();
}

pid_t IPCObjectStub::GetCallingUid()
{
    return IPCSkeleton::GetCallingUid();
}

uint32_t IPCObjectStub::GetCallingTokenID()
{
    return IPCSkeleton::GetCallingTokenID();
}

uint64_t IPCObjectStub::GetCallingFullTokenID()
{
    return IPCSkeleton::GetCallingFullTokenID();
}

uint32_t IPCObjectStub::GetFirstTokenID()
{
    return IPCSkeleton::GetFirstTokenID();
}

uint64_t IPCObjectStub::GetFirstFullTokenID()
{
    return IPCSkeleton::GetFirstFullTokenID();
}

int IPCObjectStub::GetObjectType() const
{
    return OBJECT_TYPE_NATIVE;
}

int32_t IPCObjectStub::ProcessProto(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int result = ERR_NONE;
    ZLOGD(LABEL, "normal stub object, des:%{public}s",
        ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(descriptor_)).c_str());
    if (!reply.WriteUint32(IRemoteObject::IF_PROT_BINDER) || !reply.WriteString16(descriptor_)) {
        ZLOGE(LABEL, "write to parcel fail");
        result = IPC_STUB_WRITE_PARCEL_ERR;
    }
    return result;
}

uint64_t IPCObjectStub::GetLastRequestTime()
{
    return lastRequestTime_;
}

#ifndef CONFIG_IPC_SINGLE
int32_t IPCObjectStub::InvokerThread(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    switch (data.ReadUint32()) {
        case IRemoteObject::DATABUS_TYPE: {
            if (InvokerDataBusThread(data, reply) != ERR_NONE) {
                ZLOGE(LABEL, "Invoker databus thread fail");
                return IPC_STUB_INVOKE_THREAD_ERR;
            }
            break;
        }
        default: {
            ZLOGE(LABEL, "InvokerThread Invalid Type");
            return IPC_STUB_INVALID_DATA_ERR;
        }
    }

    return ERR_NONE;
}

int32_t IPCObjectStub::InvokerDataBusThread(MessageParcel &data, MessageParcel &reply)
{
    ZLOGI(LABEL, "enter");
    std::string deviceId = data.ReadString();
    uint32_t remotePid = data.ReadUint32();
    uint32_t remoteUid = data.ReadUint32();
    std::string remoteDeviceId = data.ReadString();
    std::string sessionName = data.ReadString();
    uint32_t remoteTokenId = data.ReadUint32();
    if (IsDeviceIdIllegal(deviceId) || IsDeviceIdIllegal(remoteDeviceId) || sessionName.empty()) {
        ZLOGE(LABEL, "device ID is invalid or session name nil, desc:%{public}s",
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(descriptor_)).c_str());
        return IPC_STUB_INVALID_DATA_ERR;
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "IPCProcessSkeleton is nullptr");
        return IPC_STUB_CURRENT_NULL_ERR;
    }
    if (!current->CreateSoftbusServer(sessionName)) {
        ZLOGE(LABEL, "fail to create databus server, desc:%{public}s sessionName:%{public}s",
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(descriptor_)).c_str(), sessionName.c_str());
        return IPC_STUB_CREATE_BUS_SERVER_ERR;
    }

    uint64_t stubIndex = current->AddStubByIndex(this);
    if (stubIndex == 0) {
        ZLOGE(LABEL, "add stub fail, desc:%{public}s",
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(descriptor_)).c_str());
        return IPC_STUB_INVALID_DATA_ERR;
    }

    uint32_t selfTokenId = static_cast<uint32_t>(IPCSkeleton::GetSelfTokenID());
    ZLOGI(LABEL, "invoke databus thread, local deviceId:%{public}s remote deviceId:%{public}s "
        "stubIndex:%{public}" PRIu64 " sessionName:%{public}s",
        IPCProcessSkeleton::ConvertToSecureString(deviceId).c_str(),
        IPCProcessSkeleton::ConvertToSecureString(remoteDeviceId).c_str(), stubIndex, sessionName.c_str());
    if (!reply.WriteUint64(stubIndex) || !reply.WriteString(sessionName) || !reply.WriteString(deviceId) ||
        !reply.WriteUint32(selfTokenId)) {
        ZLOGE(LABEL, "write to parcel fail");
        return IPC_STUB_INVALID_DATA_ERR;
    }

    // mark socketId as 0
    AppAuthInfo appAuthInfo = { remotePid, remoteUid, remoteTokenId, 0, stubIndex, this, remoteDeviceId };
    if (current->AttachOrUpdateAppAuthInfo(appAuthInfo)) {
        IncStrongRef(this);
    }
    return ERR_NONE;
}

int32_t IPCObjectStub::NoticeServiceDie(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ZLOGW(LABEL, "enter, desc:%{public}s", ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(descriptor_)).c_str());
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "current is null");
        return IPC_STUB_CURRENT_NULL_ERR;
    }

    sptr<IPCObjectProxy> ipcProxy = current->QueryCallbackProxy(this);
    if (ipcProxy == nullptr) {
        ZLOGE(LABEL, "ipc proxy is null, desc:%{public}s",
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(descriptor_)).c_str());
        return IPC_STUB_INVALID_DATA_ERR;
    }

    ipcProxy->SendObituary();
    return ERR_NONE;
}

int32_t IPCObjectStub::AddAuthInfo(MessageParcel &data, MessageParcel &reply, uint32_t code)
{
    uint32_t remotePid = data.ReadUint32();
    uint32_t remoteUid = data.ReadUint32();
    std::string remoteDeviceId = data.ReadString();
    uint64_t stubIndex = data.ReadUint64();
    uint32_t tokenId = data.ReadUint32();
    if (IsDeviceIdIllegal(remoteDeviceId)) {
        ZLOGE(LABEL, "remote deviceId is null, desc:%{public}s",
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(descriptor_)).c_str());
        return IPC_STUB_INVALID_DATA_ERR;
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "current is null");
        return IPC_STUB_CURRENT_NULL_ERR;
    }

    if (stubIndex == 0) {
        // keep compatible with proxy that doesn't write stubIndex when adding auth info to stub
        stubIndex = current->QueryStubIndex(this);
        if (stubIndex == 0) {
            ZLOGE(LABEL, "stub index is null");
            return BINDER_CALLBACK_STUBINDEX_ERR;
        }
    }
    ZLOGW(LABEL, "add auth info, pid:%{public}u uid:%{public}u deviceId:%{public}s "
        "stubIndex:%{public}" PRIu64 " tokenId:%{public}u", remotePid, remoteUid,
        IPCProcessSkeleton::ConvertToSecureString(remoteDeviceId).c_str(), stubIndex, tokenId);
    // mark listen fd as 0
    AppAuthInfo appAuthInfo = { remotePid, remoteUid, tokenId, 0, stubIndex, this, remoteDeviceId };
    if (current->AttachOrUpdateAppAuthInfo(appAuthInfo)) {
        IncStrongRef(this);
    }
    return ERR_NONE;
}

std::string IPCObjectStub::GetSessionName()
{
    ZLOGI(LABEL, "enter");
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "get current is null");
        return std::string("");
    }
    sptr<IRemoteObject> object = current->GetSAMgrObject();
    if (object == nullptr) {
        ZLOGE(LABEL, "get object is null");
        return std::string("");
    }
    if (!object->IsProxyObject()) {
        ZLOGE(LABEL, "object is not a proxy pbject");
        return std::string("");
    }

    IPCObjectProxy *samgr = reinterpret_cast<IPCObjectProxy *>(object.GetRefPtr());
    return samgr->GetGrantedSessionName();
}

int32_t IPCObjectStub::GetGrantedSessionName(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    ZLOGI(LABEL, "enter");
    int pid = IPCSkeleton::GetCallingPid();
    int uid = IPCSkeleton::GetCallingUid();
    std::string sessionName = CreateSessionName(uid, pid);
    if (sessionName.empty()) {
        ZLOGE(LABEL, "pid(%{public}d)/uid(%{public}d) is invalid", pid, uid);
        return IPC_STUB_INVALID_DATA_ERR;
    }
    if (!reply.WriteUint32(IRemoteObject::IF_PROT_DATABUS) || !reply.WriteString(sessionName)) {
        ZLOGE(LABEL, "write to parcel fail");
        return IPC_STUB_INVALID_DATA_ERR;
    }

    return ERR_NONE;
}

int32_t IPCObjectStub::GetSessionNameForPidUid(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    uint32_t remotePid = data.ReadUint32();
    uint32_t remoteUid = data.ReadUint32();
    if (remotePid == static_cast<uint32_t>(IPCSkeleton::GetCallingPid())) {
        ZLOGE(LABEL, "pid(%{public}d)/uid(%{public}d) is invalid", remotePid, remoteUid);
        return IPC_STUB_INVALID_DATA_ERR;
    }
    std::string sessionName = CreateSessionName(remoteUid, remotePid);
    if (sessionName.empty()) {
        ZLOGE(LABEL, "pid(%{public}d)/uid(%{public}d) is invalid", remotePid, remoteUid);
        return IPC_STUB_INVALID_DATA_ERR;
    }
    if (!reply.WriteUint32(IRemoteObject::IF_PROT_DATABUS) || !reply.WriteString(sessionName)) {
        ZLOGE(LABEL, "write to parcel fail");
        return IPC_STUB_INVALID_DATA_ERR;
    }

    return ERR_NONE;
}

int IPCObjectStub::GetPidUid(MessageParcel &data, MessageParcel &reply)
{
    if (!reply.WriteUint32(getpid()) || !reply.WriteUint32(getuid())) {
        ZLOGE(LABEL, "write to parcel fail");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    return ERR_NONE;
}

std::string IPCObjectStub::CreateSessionName(int uid, int pid)
{
    std::string sessionName = DBINDER_SOCKET_NAME_PREFIX +
        std::to_string(uid) + std::string("_") + std::to_string(pid);
    if (DBinderSoftbusClient::GetInstance().DBinderGrantPermission(uid, pid, sessionName) != ERR_NONE) {
        ZLOGE(LABEL, "DBinderGrantPermission fail, %{public}s", sessionName.c_str());
        return "";
    }

    return sessionName;
}

int IPCObjectStub::RemoveSessionName(MessageParcel &data)
{
    std::string sessionName = data.ReadString();
    if (sessionName.empty()) {
        ZLOGE(LABEL, "read parcel fail");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    if (DBinderSoftbusClient::GetInstance().DBinderRemovePermission(sessionName) != ERR_NONE) {
        ZLOGE(LABEL, "DBinderRemovePermission fail, %{public}s", sessionName.c_str());
        return IPC_STUB_REMOVE_SESSION_NAME_ERR;
    }

    ZLOGI(LABEL, "%{public}s", sessionName.c_str());
    return ERR_NONE;
}

bool IPCObjectStub::IsSamgrCall()
{
    return ProcessSkeleton::GetInstance()->GetSamgrFlag();
}
#endif

bool IPCObjectStub::GetRequestSidFlag() const
{
    return requestSidFlag_;
}

void IPCObjectStub::SetRequestSidFlag(bool flag)
{
#ifdef WITH_SELINUX
    requestSidFlag_ = flag;
#endif
}

int IPCObjectStub::GetAndSaveDBinderData(pid_t pid, uid_t uid)
{
    (void)pid;
    (void)uid;
    ZLOGW(LABEL, "unexpected call");
    return ERR_INVALID_STATE;
}
} // namespace OHOS
