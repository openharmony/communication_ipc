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
#include "ISessionService.h"
#endif

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
using namespace IPC_SINGLE;
#endif

using namespace OHOS::HiviewDFX;
static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "IPCObjectStub" };
#ifndef CONFIG_IPC_SINGLE
// Authentication information can be added only for processes with system permission.
static constexpr pid_t ALLOWED_UID = 10000;
#endif
static constexpr int SHELL_UID = 2000;
static constexpr int HIDUMPER_SERVICE_UID = 1212;

IPCObjectStub::IPCObjectStub(std::u16string descriptor) : IRemoteObject(descriptor)
{
}

IPCObjectStub::~IPCObjectStub()
{
    ZLOGD(LABEL, "destroy, desc: %{public}s", Str16ToStr8(descriptor_).c_str());
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
    ZLOGE(LABEL, "Invalid call on Stub:fd:%d, args:%zu", fd, numArgs);
    return ERR_NONE;
}

int IPCObjectStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int result = ERR_NONE;
    switch (code) {
#ifndef CONFIG_IPC_SINGLE
        case DBINDER_OBITUARY_TRANSACTION: {
            ZLOGW(LABEL, "%{public}s: recv DBINDER_OBITUARY_TRANSACTION", __func__);
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
            ZLOGE(LABEL, "unknown OnRemoteRequest code = %{public}u, descriptor: %{public}s", code,
                Str16ToStr8(descriptor_).c_str());
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

int IPCObjectStub::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int result = ERR_NONE;
    switch (code) {
        case PING_TRANSACTION: {
            if (!reply.WriteInt32(ERR_NONE)) {
                result = IPC_STUB_WRITE_PARCEL_ERR;
            }
            break;
        }
        case INTERFACE_TRANSACTION: {
            std::u16string descriptor = GetObjectDescriptor();
            if (!reply.WriteString16(descriptor)) {
                ZLOGE(LABEL, "write to parcel fail");
                result = IPC_STUB_WRITE_PARCEL_ERR;
            }
            break;
        }
        case SYNCHRONIZE_REFERENCE: {
            int refCount = GetObjectRefCount();
            // when handle transaction the invoker would try to acquire
            // the object's reference to defense the object being released
            // so the actual we should decrement the temporary reference.
            if (IPCSkeleton::IsLocalCalling()) {
                --refCount;
            }
            reply.WriteInt32(refCount);
            break;
        }
        case DUMP_TRANSACTION: {
            pid_t uid = IPCSkeleton::GetCallingUid();
            if (!IPCSkeleton::IsLocalCalling() || (uid != 0 && uid != SHELL_UID && uid != HIDUMPER_SERVICE_UID)) {
                ZLOGE(LABEL, "do not allow dump");
                break;
            }
            result = OnRemoteDump(code, data, reply, option);
            break;
        }
        case GET_PROTO_INFO: {
            result = ProcessProto(code, data, reply, option);
            break;
        }
#ifndef CONFIG_IPC_SINGLE
        case INVOKE_LISTEN_THREAD: {
            if (!IPCSkeleton::IsLocalCalling() || IPCSkeleton::GetCallingUid() >= ALLOWED_UID) {
                ZLOGE(LABEL, "%{public}s: INVOKE_LISTEN_THREAD unauthenticated user ", __func__);
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
            result = InvokerThread(code, data, reply, option);
            break;
        }
        case DBINDER_INCREFS_TRANSACTION: {
            if (IPCSkeleton::IsLocalCalling()) {
                ZLOGE(LABEL, "dbinder incref in the same device is invalid");
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
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
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
            uint32_t listenFd = invoker->GetClientFd();
            // update listenFd
            ZLOGW(LABEL, "update app info listenFd: %{public}u, stubIndex: %{public}" PRIu64 ", tokenId: %{public}u",
                listenFd, stubIndex, tokenId);
            current->AttachAppInfoToStubIndex(callerPid, callerUid, tokenId, callerDevId, stubIndex, listenFd);
            break;
        }
        case DBINDER_DECREFS_TRANSACTION: {
            if (IPCSkeleton::IsLocalCalling()) {
                ZLOGE(LABEL, "dbinder decref in the same device is invalid");
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
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
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
            uint32_t listenFd = invoker->GetClientFd();
            // detach info whose listen fd equals the given one
            if (current->DetachAppInfoToStubIndex(callerPid, callerUid, tokenId, callerDevId, stubIndex, listenFd)) {
                current->DetachCommAuthInfo(this, callerPid, callerUid, tokenId, callerDevId);
                DecStrongRef(this);
            }
            break;
        }
        case DBINDER_ADD_COMMAUTH: {
            if (IPCSkeleton::IsLocalCalling() || IPCSkeleton::GetCallingUid() >= ALLOWED_UID) {
                ZLOGE(LABEL, "DBINDER_ADD_COMMAUTH unauthenticated user ");
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
            result = AddAuthInfo(data, reply, code);
            break;
        }
        case GET_SESSION_NAME: {
            if (!IPCSkeleton::IsLocalCalling()) {
                ZLOGE(LABEL, "GET_UIDPID_INFO message is not from sa manager");
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
            std::string sessionName = GetSessionName();
            if (sessionName.empty()) {
                ZLOGE(LABEL, "sessionName is empty");
                result = IPC_STUB_CREATE_BUS_SERVER_ERR;
                break;
            }
            if (!reply.WriteString(sessionName)) {
                ZLOGE(LABEL, "write to parcel fail");
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
            break;
        }
        case GET_GRANTED_SESSION_NAME: {
            if (!IPCSkeleton::IsLocalCalling() || !IsSamgrCall()) {
                ZLOGE(LABEL, "GRANT_DATABUS_NAME message is excluded in sa manager");
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
            result = GetGrantedSessionName(code, data, reply, option);
            break;
        }
        case GET_SESSION_NAME_PID_UID: {
            if (!IPCSkeleton::IsLocalCalling() || !IsSamgrCall()) {
                ZLOGE(LABEL, "TRANS_DATABUS_NAME message is excluded in sa manager");
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
            result = GetSessionNameForPidUid(code, data, reply, option);
            break;
        }
        case GET_PID_UID: {
            if (!IPCSkeleton::IsLocalCalling()) {
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
            result = GetPidUid(data, reply);
            break;
        }
#endif
        default:
            result = OnRemoteRequest(code, data, reply, option);
            break;
    }

    return result;
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
        current->DetachCommAuthInfoByStub(this);
        uint64_t stubIndex = current->EraseStubIndex(this);
        current->DetachAppInfoToStubIndex(stubIndex);
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
    ZLOGD(LABEL, "IPCObjectStub::ProcessProto called, type = 0, normal stub object");
    if (!reply.WriteUint32(IRemoteObject::IF_PROT_BINDER)) {
        ZLOGE(LABEL, "write to parcel fail");
        result = IPC_STUB_WRITE_PARCEL_ERR;
    }
    return result;
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
    std::string deviceId = data.ReadString();
    uint32_t remotePid = data.ReadUint32();
    uint32_t remoteUid = data.ReadUint32();
    std::string remoteDeviceId = data.ReadString();
    std::string sessionName = data.ReadString();
    uint32_t remoteTokenId = data.ReadUint32();
    if (IsDeviceIdIllegal(deviceId) || IsDeviceIdIllegal(remoteDeviceId) || sessionName.empty()) {
        ZLOGE(LABEL, "%{public}s: device ID is invalid or session name nil", __func__);
        return IPC_STUB_INVALID_DATA_ERR;
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "IPCProcessSkeleton is nullptr");
        return IPC_STUB_CURRENT_NULL_ERR;
    }
    if (!current->CreateSoftbusServer(sessionName)) {
        ZLOGE(LABEL, "%{public}s: fail to create databus server", __func__);
        return IPC_STUB_CREATE_BUS_SERVER_ERR;
    }

    uint64_t stubIndex = current->AddStubByIndex(this);
    if (stubIndex == 0) {
        ZLOGE(LABEL, "%{public}s: add stub fail", __func__);
        return IPC_STUB_INVALID_DATA_ERR;
    }

    uint32_t selfTokenId = static_cast<uint32_t>(IPCSkeleton::GetSelfTokenID());
    ZLOGW(LABEL,
        "invoke databus thread, local deviceId: %{public}s, remotePid: %{public}u, remoteUid: %{public}u, "
        "stubIndex: %{public}" PRIu64 ", remote deviceId: %{public}s, tokenId: %{public}u, selfTokenId: %{public}u",
        IPCProcessSkeleton::ConvertToSecureString(deviceId).c_str(), remotePid, remoteUid, stubIndex,
        IPCProcessSkeleton::ConvertToSecureString(remoteDeviceId).c_str(), remoteTokenId, selfTokenId);
    if (!reply.WriteUint64(stubIndex) || !reply.WriteString(sessionName) || !reply.WriteString(deviceId) ||
        !reply.WriteUint32(selfTokenId)) {
        ZLOGE(LABEL, "%{public}s: write to parcel fail", __func__);
        return IPC_STUB_INVALID_DATA_ERR;
    }
    // mark listen fd as 0
    if (!current->AttachAppInfoToStubIndex(remotePid, remoteUid, remoteTokenId, remoteDeviceId, stubIndex, 0)) {
        ZLOGW(LABEL, "app info already existed, replace with 0");
    }
    if (current->AttachCommAuthInfo(this, remotePid, remoteUid, remoteTokenId, remoteDeviceId)) {
        IncStrongRef(this);
    } else {
        ZLOGW(LABEL, "comm auth info attached already");
    }

    return ERR_NONE;
}

int32_t IPCObjectStub::NoticeServiceDie(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ZLOGE(LABEL, "%{public}s enter, desc:%{public}s", __func__, Str16ToStr8(descriptor_).c_str());
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "%{public}s: current is null", __func__);
        return IPC_STUB_CURRENT_NULL_ERR;
    }

    sptr<IPCObjectProxy> ipcProxy = current->QueryCallbackProxy(this);
    if (ipcProxy == nullptr) {
        ZLOGE(LABEL, "%{public}s: ipc proxy is null", __func__);
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
        ZLOGE(LABEL, "%{public}s: remote deviceId is null", __func__);
        return IPC_STUB_INVALID_DATA_ERR;
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "%{public}s: current is null", __func__);
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

    ZLOGW(LABEL, "add auth info pid: %{public}u, uid: %{public}u, devId: %{public}s, stubIndex: %{public}" PRIu64
        ", tokenId: %{public}u", remotePid, remoteUid,
        IPCProcessSkeleton::ConvertToSecureString(remoteDeviceId).c_str(), stubIndex, tokenId);
    // mark listen fd as 0
    if (!current->AttachAppInfoToStubIndex(remotePid, remoteUid, tokenId, remoteDeviceId, stubIndex, 0)) {
        ZLOGW(LABEL, "app info already attached, replace with 0");
    }
    if (current->AttachCommAuthInfo(this, remotePid, remoteUid, tokenId, remoteDeviceId)) {
        IncStrongRef(this);
    } else {
        ZLOGW(LABEL, "comm auth info attached already");
    }
    return ERR_NONE;
}

std::string IPCObjectStub::GetSessionName()
{
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

    IPCObjectProxy *samgr = reinterpret_cast<IPCObjectProxy *>(object.GetRefPtr());
    return samgr->GetGrantedSessionName();
}

int32_t IPCObjectStub::GetGrantedSessionName(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    int pid = IPCSkeleton::GetCallingPid();
    int uid = IPCSkeleton::GetCallingUid();
    std::string sessionName = CreateSessionName(uid, pid);
    if (sessionName.empty()) {
        ZLOGE(LABEL, "pid/uid is invalid, pid = %{public}d, uid = %{public}d", pid, uid);
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
        ZLOGE(LABEL, "pid/uid is invalid, pid = %{public}d, uid = %{public}d", remotePid, remoteUid);
        return IPC_STUB_INVALID_DATA_ERR;
    }
    std::string sessionName = CreateSessionName(remoteUid, remotePid);
    if (sessionName.empty()) {
        ZLOGE(LABEL, "pid/uid is invalid, pid = %{public}d, uid = %{public}d", remotePid, remoteUid);
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
    std::shared_ptr<ISessionService> softbusManager = ISessionService::GetInstance();
    if (softbusManager == nullptr) {
        ZLOGE(LABEL, "fail to get softbus service");
        return "";
    }

    std::string sessionName = "DBinder" + std::to_string(uid) + std::string("_") + std::to_string(pid);
    if (softbusManager->GrantPermission(uid, pid, sessionName) != ERR_NONE) {
        ZLOGE(LABEL, "fail to Grant Permission softbus name");
        return "";
    }

    return sessionName;
}

bool IPCObjectStub::IsSamgrCall()
{
    return ProcessSkeleton::GetInstance()->GetSamgrFlag();
}
#endif
} // namespace OHOS
