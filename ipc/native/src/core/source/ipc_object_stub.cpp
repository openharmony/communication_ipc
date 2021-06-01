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
#include <string>
#include "ipc_types.h"
#include "ipc_debug.h"
#include "ipc_process_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "log_tags.h"
#include "ipc_skeleton.h"

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
// Only the samgr can obtain the UID and PID.
static constexpr pid_t SYSTEM_SERVER_UID = 1000;
#endif
static constexpr pid_t SHELL_UID = 2000;

IPCObjectStub::IPCObjectStub(std::u16string descriptor) : IRemoteObject(descriptor) {}

IPCObjectStub::~IPCObjectStub()
{
    ZLOGW(LABEL, "IPCObjectStub destroyed");
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
    int kRefCount = 0;
    int refCount = GetSptrRefCount();
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DEFAULT);

    if (invoker != nullptr) {
        kRefCount = invoker->GetObjectRefCount(this);
    }

    /* the kernel has already acquire the reference
     * on this object, so we need to decrement by 1.
     */
    if (kRefCount > 0) {
        refCount += kRefCount - 1;
    }

    return refCount;
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
            if (IPCSkeleton::GetCallingUid() != SYSTEM_SERVER_UID) {
                ZLOGE(LABEL, "%s: DBINDER_OBITUARY_TRANSACTION unauthenticated user ", __func__);
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
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
            ZLOGI(LABEL, "unknown OnRemoteRequest code = %{public}u", code);
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
            --refCount;
            reply.WriteInt32(refCount);
            break;
        }
        case DUMP_TRANSACTION: {
            pid_t uid = IPCSkeleton::GetCallingUid();
            if (!IPCSkeleton::IsLocalCalling() || (uid != 0 && uid != SHELL_UID)) {
                ZLOGE(LABEL, "do not allow dump");
                break;
            }
            result = OnRemoteDump(code, data, reply, option);
            break;
        }
#ifndef CONFIG_IPC_SINGLE
        case INVOKE_LISTEN_THREAD: {
            if (!IPCSkeleton::IsLocalCalling() || IPCSkeleton::GetCallingUid() >= ALLOWED_UID) {
                ZLOGE(LABEL, "%s: INVOKE_LISTEN_THREAD unauthenticated user ", __func__);
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
            result = InvokerThread(code, data, reply, option);
            break;
        }
        case GET_PROTO_INFO: {
            result = ProcessProto(code, data, reply, option);
            break;
        }
        case DBINDER_INCREFS_TRANSACTION: {
            if (IPCSkeleton::IsLocalCalling()) {
                ZLOGE(LABEL, "%s: cannot be called in same device", __func__);
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
            result = IncStubRefs(data, reply);
            break;
        }
        case DBINDER_DECREFS_TRANSACTION: {
            if (IPCSkeleton::IsLocalCalling()) {
                ZLOGE(LABEL, "%s: cannot be called in same device", __func__);
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
            result = DecStubRefs(data, reply);
            break;
        }
        case DBINDER_ADD_COMMAUTH: {
            if (IPCSkeleton::IsLocalCalling() || IPCSkeleton::GetCallingUid() >= ALLOWED_UID) {
                ZLOGE(LABEL, "%s: DBINDER_ADD_COMMAUTH unauthenticated user ", __func__);
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
            result = AddAuthInfo(data, reply);
            break;
        }
        case GET_UIDPID_INFO: {
            if (!IPCSkeleton::IsLocalCalling()) {
                ZLOGE(LABEL, "GET_UIDPID_INFO message is not from sa manager");
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
            std::string sessionName = GetDataBusName();
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
        case GRANT_DATABUS_NAME: {
            if (!IPCSkeleton::IsLocalCalling() || getuid() != SYSTEM_SERVER_UID) {
                ZLOGE(LABEL, "GRANT_DATABUS_NAME message is excluded in sa manager");
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
            result = GrantDataBusName(code, data, reply, option);
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
        current->DetachStubRecvRefInfo(this);
        current->DetachStubSendRefInfo(this);
        (void)current->DetachStubRefTimes(this);
        current->DetachCommAuthInfoByStub(this);
        uint64_t stubIndex = current->EraseStubIndex(reinterpret_cast<IRemoteObject *>(this));
        current->DetachAppInfoToStubIndex(stubIndex);
#endif
    }
}

bool IPCObjectStub::AddDeathRecipient(const sptr<DeathRecipient> &recipient)
{
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

int32_t IPCObjectStub::ProcessProto(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int result = ERR_NONE;
    ZLOGE(LABEL, "IPCObjectStub::ProcessProto called, type = 0, normal stub object");
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
    if (IsDeviceIdIllegal(deviceId) || IsDeviceIdIllegal(remoteDeviceId) || sessionName.empty()) {
        ZLOGE(LABEL, "%s: device ID is invalid or session name nil", __func__);
        return IPC_STUB_INVALID_DATA_ERR;
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "IPCProcessSkeleton is nullptr");
        return IPC_STUB_CURRENT_NULL_ERR;
    }
    if (!current->CreateSoftbusServer(sessionName)) {
        ZLOGE(LABEL, "%s: fail to create databus server", __func__);
        return IPC_STUB_CREATE_BUS_SERVER_ERR;
    }

    uint64_t stubIndex = current->AddStubByIndex(this);
    if (stubIndex == 0) {
        ZLOGE(LABEL, "%s: add stub fail", __func__);
        return IPC_STUB_INVALID_DATA_ERR;
    }
    if (!reply.WriteUint64(stubIndex) || !reply.WriteString(sessionName) || !reply.WriteString(deviceId)) {
        ZLOGE(LABEL, "%s: write to parcel fail", __func__);
        return IPC_STUB_INVALID_DATA_ERR;
    }
    if (!current->AttachAppInfoToStubIndex(remotePid, remoteUid, remoteDeviceId, stubIndex)) {
        ZLOGE(LABEL, "fail to attach appinfo to stubIndex, maybe attach already");
    }
    if (!current->AttachCommAuthInfo(this, remotePid, remoteUid, remoteDeviceId)) {
        ZLOGE(LABEL, "fail to attach comm auth info");
    }

    return ERR_NONE;
}

int32_t IPCObjectStub::NoticeServiceDie(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "%s: current is null", __func__);
        return IPC_STUB_CURRENT_NULL_ERR;
    }

    IPCObjectProxy *ipcProxy = current->QueryCallbackProxy(this);
    if (ipcProxy == nullptr) {
        ZLOGE(LABEL, "%s: ipc proxy is null", __func__);
        return IPC_STUB_INVALID_DATA_ERR;
    }

    ipcProxy->SendObituary();

    if (!current->DetachCallbackStub(this)) {
        ZLOGE(LABEL, "%s: fail to detach callback stub", __func__);
        // do nothing, RemoveDeathRecipient can delete this too
    }

    return ERR_NONE;
}

int32_t IPCObjectStub::IncStubRefs(MessageParcel &data, MessageParcel &reply)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "%s: current is null", __func__);
        return IPC_STUB_CURRENT_NULL_ERR;
    }

    std::string deviceId = IPCSkeleton::GetCallingDeviceID();
    if (deviceId.empty()) {
        ZLOGE(LABEL, "%s: calling error", __func__);
        return IPC_STUB_INVALID_DATA_ERR;
    }
    if (!current->AttachStubRecvRefInfo(this, IPCSkeleton::GetCallingPid(), deviceId)) {
        ZLOGE(LABEL, "%s: attach stub ref info err, already in", __func__);
        return ERR_NONE;
    }

    if (!current->DecStubRefTimes(this)) {
        this->IncStrongRef(this);
    }

    return ERR_NONE;
}

int32_t IPCObjectStub::DecStubRefs(MessageParcel &data, MessageParcel &reply)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "%s: current is null", __func__);
        return IPC_STUB_CURRENT_NULL_ERR;
    }

    std::string deviceId = IPCSkeleton::GetCallingDeviceID();
    current->DetachStubRefInfo(this, IPCSkeleton::GetCallingPid(), deviceId);
    return ERR_NONE;
}

int32_t IPCObjectStub::AddAuthInfo(MessageParcel &data, MessageParcel &reply)
{
    uint32_t remotePid = data.ReadUint32();
    uint32_t remoteUid = data.ReadUint32();
    std::string remoteDeviceId = data.ReadString();
    if (IsDeviceIdIllegal(remoteDeviceId)) {
        ZLOGE(LABEL, "%s: remote deviceId is null", __func__);
        return IPC_STUB_INVALID_DATA_ERR;
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "%s: current is null", __func__);
        return IPC_STUB_CURRENT_NULL_ERR;
    }

    if (!current->AttachCommAuthInfo(this, remotePid, remoteUid, remoteDeviceId)) {
        ZLOGE(LABEL, "fail to attach comm auth info fail");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    return ERR_NONE;
}

std::string IPCObjectStub::GetDataBusName()
{
    sptr<IRemoteObject> object = IPCProcessSkeleton::GetCurrent()->GetSAMgrObject();
    if (object == nullptr) {
        ZLOGE(LABEL, "get object is null");
        return std::string("");
    }

    IPCObjectProxy *samgr = reinterpret_cast<IPCObjectProxy *>(object.GetRefPtr());
    return samgr->GetDataBusName();
}

int32_t IPCObjectStub::GrantDataBusName(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int pid = IPCSkeleton::GetCallingPid();
    int uid = IPCSkeleton::GetCallingUid();
    std::string sessionName = CreateDatabusName(uid, pid);
    if (sessionName.empty()) {
        ZLOGE(LABEL, "pid/uid is invalid, pid = {public}%d, uid = {public}%d", pid, uid);
        return IPC_STUB_INVALID_DATA_ERR;
    }
    if (!reply.WriteUint32(IRemoteObject::IF_PROT_DATABUS) || !reply.WriteString(sessionName)) {
        ZLOGE(LABEL, "write to parcel fail");
        return IPC_STUB_INVALID_DATA_ERR;
    }

    return ERR_NONE;
}

std::string IPCObjectStub::CreateDatabusName(int uid, int pid)
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
#endif
} // namespace OHOS
