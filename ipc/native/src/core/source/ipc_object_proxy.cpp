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

#include "ipc_object_proxy.h"

#include <cstdint>

#include "__mutex_base"
#include "algorithm"
#include "errors.h"
#include "hilog/log_c.h"
#include "hilog/log_cpp.h"
#include "iosfwd"
#include "ipc_debug.h"
#include "ipc_process_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "ipc_types.h"
#include "iremote_invoker.h"
#include "iremote_object.h"
#include "log_tags.h"
#include "message_option.h"
#include "message_parcel.h"
#include "mutex"
#include "refbase.h"
#include "string"
#include "string_ex.h"
#include "type_traits"
#include "unistd.h"
#include "vector"

#ifndef CONFIG_IPC_SINGLE
#include "access_token_adapter.h"
#include "dbinder_databus_invoker.h"
#endif

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
using namespace IPC_SINGLE;
#endif

static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "IPCObjectProxy" };

IPCObjectProxy::IPCObjectProxy(int handle, std::u16string descriptor, int proto)
    : IRemoteObject(std::move(descriptor)), handle_(handle), proto_(proto), isFinishInit_(false), isRemoteDead_(false)
{
    ExtendObjectLifetime();
}

IPCObjectProxy::~IPCObjectProxy()
{
}

int32_t IPCObjectProxy::GetObjectRefCount()
{
    MessageParcel data, reply;
    MessageOption option;
    if (SendRequestInner(false, SYNCHRONIZE_REFERENCE, data, reply, option) == ERR_NONE) {
        return reply.ReadInt32();
    }
    return 0;
}

int IPCObjectProxy::Dump(int fd, const std::vector<std::u16string> &args)
{
    MessageParcel data, reply;
    MessageOption option { MessageOption::TF_SYNC };
    data.WriteFileDescriptor(fd);
    data.WriteString16Vector(args);
    return SendRequestInner(false, DUMP_TRANSACTION, data, reply, option);
}

int IPCObjectProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (code != DUMP_TRANSACTION && code > MAX_TRANSACTION_ID) {
        return IPC_PROXY_INVALID_CODE_ERR;
    }

    return SendRequestInner(false, code, data, reply, option);
}

int IPCObjectProxy::SendLocalRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    return SendRequestInner(true, code, data, reply, option);
}

int IPCObjectProxy::SendRequestInner(bool isLocal, uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    if (IsObjectDead()) {
        return ERR_DEAD_OBJECT;
    }

    IRemoteInvoker *invoker = nullptr;
    if (isLocal) {
        invoker = IPCThreadSkeleton::GetDefaultInvoker();
    } else {
        invoker = IPCThreadSkeleton::GetRemoteInvoker(proto_);
    }
    if (invoker == nullptr) {
        ZLOGE(LABEL, "%{public}s: handle: %{public}u, proto: %{public}d, invoker is null", __func__, handle_, proto_);
        return ERR_NULL_OBJECT;
    }

    int status = invoker->SendRequest(handle_, code, data, reply, option);
    if (status == ERR_DEAD_OBJECT) {
        MarkObjectDied();
    }
    return status;
}

std::u16string IPCObjectProxy::GetInterfaceDescriptor()
{
    if (!remoteDescriptor_.empty()) {
        return remoteDescriptor_;
    }
    if (handle_ == 0) {
        ZLOGD(LABEL, "handle == 0, do nothing");
        return std::u16string();
    }

    MessageParcel data, reply;
    MessageOption option;

    int err = SendRequestInner(false, INTERFACE_TRANSACTION, data, reply, option);
    if (err != ERR_NONE) {
        ZLOGE(LABEL, "send INTERFACE_TRANSACTION cmd failed, error: %{public}d", err);
        return std::u16string();
    }
    remoteDescriptor_ = reply.ReadString16();

    return remoteDescriptor_;
}

std::string IPCObjectProxy::GetSessionName()
{
    MessageParcel data, reply;
    MessageOption option;

    int err = SendRequestInner(false, GET_SESSION_NAME, data, reply, option);
    if (err != ERR_NONE) {
        ZLOGE(LABEL, "send GET_SESSION_NAME failed, error: %{public}d", err);
        return std::string("");
    }
    return reply.ReadString();
}

std::string IPCObjectProxy::GetGrantedSessionName()
{
    MessageParcel data, reply;
    MessageOption option;

    int err = SendRequestInner(false, GET_GRANTED_SESSION_NAME, data, reply, option);
    if (err != ERR_NONE) {
        ZLOGE(LABEL, "send GET_GRANTED_SESSION_NAME failed, error: %{public}d", err);
        return std::string("");
    }

    if (reply.ReadUint32() != IRemoteObject::IF_PROT_DATABUS) {
        ZLOGE(LABEL, "GetDataBusName normal binder");
        return std::string("");
    }

    return reply.ReadString();
}

std::string IPCObjectProxy::GetSessionNameForPidUid(uint32_t uid, uint32_t pid)
{
    if (pid == static_cast<uint32_t>(getpid())) {
        ZLOGE(LABEL, "TransDataBusName can't write local pid. my/remotePid = %{public}u/%{public}u", getpid(), pid);
        return std::string("");
    }

    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteUint32(pid) || !data.WriteUint32(uid)) {
        ZLOGE(LABEL, "TransDataBusName write pid/uid = %{public}u/%{public}u failed", pid, uid);
        return std::string("");
    }
    int err = SendRequestInner(false, GET_SESSION_NAME_PID_UID, data, reply, option);
    if (err != ERR_NONE) {
        ZLOGE(LABEL, "TransDataBusName transact return error = %{public}d", err);
        return std::string("");
    }

    if (reply.ReadUint32() != IRemoteObject::IF_PROT_DATABUS) {
        ZLOGE(LABEL, "TransDataBusName normal binder");
        return std::string("");
    }

    return reply.ReadString();
}

int IPCObjectProxy::GetPidUid(MessageParcel &reply)
{
    MessageParcel data;
    MessageOption option;

    return SendRequestInner(true, GET_PID_UID, data, reply, option);
}

void IPCObjectProxy::OnFirstStrongRef(const void *objectId)
{
    // IPC proxy: AcquireHandle->AttachObject
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
    if (invoker != nullptr) {
        invoker->AcquireHandle(handle_);
    }
}

void IPCObjectProxy::WaitForInit()
{
    // RPC proxy: AcquireHandle->AttachObject->Open Session->IncRef to Remote Stub
    {
        std::lock_guard<std::mutex> lockGuard(initMutex_);
        // When remote stub is gone, handle is reclaimed. But mapping from this handle to
        // proxy may still exist before OnLastStrongRef called. If so, in FindOrNewObject
        // we may find the same proxy that has been marked as dead. Thus, we need to check again.
        if (IsObjectDead()) {
            ZLOGW(LABEL, "proxy is dead, init again");
            isRemoteDead_ = false;
            isFinishInit_ = false;
        }

        if (!isFinishInit_) {
#ifndef CONFIG_IPC_SINGLE
            if (UpdateProto() == IRemoteObject::IF_PROT_ERROR) {
                ZLOGE(LABEL, "UpdateProto get IF_PROT_ERROR");
                isRemoteDead_ = true;
            }
#endif
            isFinishInit_ = true;
        } else {
#ifndef CONFIG_IPC_SINGLE
            // Anoymous rpc proxy need to update proto anyway because ownership of session
            // corresponding to this handle has been marked as null in TranslateRemoteHandleType
            if (proto_ == IRemoteObject::IF_PROT_DATABUS) {
                if (!CheckHaveSession()) {
                    SetProto(IRemoteObject::IF_PROT_ERROR);
                    isRemoteDead_ = true;
                }
            }
#endif
        }

    }
#ifndef CONFIG_IPC_SINGLE
    if (proto_ == IRemoteObject::IF_PROT_DATABUS) {
        if (IncRefToRemote() != ERR_NONE) {
            SetProto(IRemoteObject::IF_PROT_ERROR);
            isRemoteDead_ = true;
        }
    }
#endif
}

void IPCObjectProxy::OnLastStrongRef(const void *objectId)
{
    // IPC proxy: DetachObject->ReleaseHandle
    // RPC proxy: DecRef to Remote Stub->Close Session->DetachObject->ReleaseHandle
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "OnLastStrongRef skeleton is null");
        return;
    }
#ifndef CONFIG_IPC_SINGLE
    ReleaseProto();
#endif
    ClearDeathRecipients();
    // This proxy is going to be destroyed, so we need to decrease refcount of binder_ref.
    // It may has been replace with a new proxy, thus we have no need to check result.
    current->DetachObject(this);
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
    if (invoker != nullptr) {
        invoker->ReleaseHandle(handle_);
    }
}

/* mutex_ should be called before set or get isRemoteDead_ status */
void IPCObjectProxy::MarkObjectDied()
{
    isRemoteDead_ = true;
}

bool IPCObjectProxy::IsObjectDead() const
{
    return isRemoteDead_;
}

bool IPCObjectProxy::AddDeathRecipient(const sptr<DeathRecipient> &recipient)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (IsObjectDead()) {
        ZLOGW(LABEL, "%{public}s: proxy is already dead", __func__);
        return false;
    }
    recipients_.push_back(recipient);
    if (recipients_.size() > 1 || handle_ >= IPCProcessSkeleton::DBINDER_HANDLE_BASE) {
        return true;
    }

    IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
    if (invoker == nullptr) {
        ZLOGE(LABEL, "%{public}s : invoker is null", __func__);
        return false;
    }

    if (!invoker->AddDeathRecipient(handle_, this)) {
        ZLOGE(LABEL, "%{public}s: fail to add binder death recipient", __func__);
#ifndef BUILD_PUBLIC_VERSION
        ReportDriverEvent(DbinderErrorCode::COMMON_DRIVER_ERROR, std::string(DbinderErrorCode::ERROR_TYPE),
            DbinderErrorCode::IPC_DRIVER, std::string(DbinderErrorCode::ERROR_CODE),
            DbinderErrorCode::SET_DEATH_RECIPIENT_FAILURE);
#endif
        return false;
    }
#ifndef CONFIG_IPC_SINGLE
    if (proto_ == IRemoteObject::IF_PROT_DATABUS) {
        if (!AddDbinderDeathRecipient()) {
            ZLOGE(LABEL, "%{public}s: failed to add dbinder death recipient", __func__);
#ifndef BUILD_PUBLIC_VERSION
            ReportDriverEvent(DbinderErrorCode::COMMON_DRIVER_ERROR, std::string(DbinderErrorCode::ERROR_TYPE),
                DbinderErrorCode::RPC_DRIVER, std::string(DbinderErrorCode::ERROR_CODE),
                DbinderErrorCode::SET_DEATH_RECIPIENT_FAILURE);
#endif
            return false;
        }
    }
#endif
    return true;
}

bool IPCObjectProxy::RemoveDeathRecipient(const sptr<DeathRecipient> &recipient)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    if (IsObjectDead()) {
        ZLOGW(LABEL, "%{public}s: proxy is already dead", __func__);
        return false;
    }
    bool recipientErased = false;
    auto it = find(recipients_.begin(), recipients_.end(), recipient);
    if (it != recipients_.end()) {
        recipients_.erase(it);
        recipientErased = true;
    }

    if (handle_ >= IPCProcessSkeleton::DBINDER_HANDLE_BASE && recipientErased == true) {
        ZLOGW(LABEL, "%{public}s: death recipient is already unregistered", __func__);
        return true;
    }

    if (recipientErased && recipients_.empty()) {
        IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
        if (invoker == nullptr) {
            ZLOGE(LABEL, "%{public}s: invoker is null", __func__);
            return false;
        }

        bool dbinderStatus = true;
        bool status = invoker->RemoveDeathRecipient(handle_, this);
#ifndef CONFIG_IPC_SINGLE
        if (proto_ == IRemoteObject::IF_PROT_DATABUS || proto_ == IRemoteObject::IF_PROT_ERROR) {
            dbinderStatus = RemoveDbinderDeathRecipient();
        }
#endif
        return status && dbinderStatus;
    }
    return recipientErased;
}

void IPCObjectProxy::SendObituary()
{
    ZLOGW(LABEL, "%{public}s: enter, handle: %{public}d", __func__, handle_);
#ifndef CONFIG_IPC_SINGLE
    if (handle_ < IPCProcessSkeleton::DBINDER_HANDLE_BASE) {
        if (proto_ == IRemoteObject::IF_PROT_DATABUS || proto_ == IRemoteObject::IF_PROT_ERROR) {
            RemoveDbinderDeathRecipient();
        }
    }
#endif
    std::vector<sptr<DeathRecipient>> toBeReport;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        MarkObjectDied();
        toBeReport = recipients_;
        recipients_.clear();
    }

    if (toBeReport.size() > 0 && handle_ < IPCProcessSkeleton::DBINDER_HANDLE_BASE) {
        IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
        if (invoker != nullptr) {
            invoker->RemoveDeathRecipient(handle_, this);
        } else {
            ZLOGE(LABEL, "%{public}s: invoker is null", __func__);
        }
    }
    const size_t size = toBeReport.size();
    for (size_t i = 0; i < size; i++) {
        sptr<DeathRecipient> recipient = toBeReport[i];
        ZLOGW(LABEL, "%{public}s: handle = %{public}u call OnRemoteDied", __func__, handle_);
        if (recipient != nullptr) {
            recipient->OnRemoteDied(this);
        }
    }
}

void IPCObjectProxy::ClearDeathRecipients()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (recipients_.empty()) {
        return;
    }
    recipients_.clear();
    if (handle_ >= IPCProcessSkeleton::DBINDER_HANDLE_BASE) {
        return;
    }
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
    if (invoker != nullptr) {
        invoker->RemoveDeathRecipient(handle_, this);
    }
#ifndef CONFIG_IPC_SINGLE
    if (proto_ == IRemoteObject::IF_PROT_DATABUS || proto_ == IRemoteObject::IF_PROT_ERROR) {
        RemoveDbinderDeathRecipient();
    }
#endif
}

int IPCObjectProxy::GetProto() const
{
    return proto_;
}

int32_t IPCObjectProxy::NoticeServiceDie()
{
    ZLOGW(LABEL, "%{public}s: handle: %{public}d", __func__, handle_);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    data.WriteInt32(IRemoteObject::DeathRecipient::NOTICE_DEATH_RECIPIENT);

    int status = SendLocalRequest(DBINDER_OBITUARY_TRANSACTION, data, reply, option);
    if (status != ERR_NONE || reply.ReadInt32() != ERR_NONE) {
        ZLOGE(LABEL, "%{public}s: send local request fail, status = %{public}d", __func__, status);
        return IPC_PROXY_TRANSACTION_ERR;
    }
    return ERR_NONE;
}

int IPCObjectProxy::InvokeListenThread(MessageParcel &data, MessageParcel &reply)
{
    MessageOption option;
    return SendRequestInner(false, INVOKE_LISTEN_THREAD, data, reply, option);
}

#ifndef CONFIG_IPC_SINGLE
int IPCObjectProxy::UpdateProto()
{
    int proto = GetProtoInfo();
    SetProto(proto);
    return proto;
}

int32_t IPCObjectProxy::IncRefToRemote()
{
    MessageParcel data, reply;
    MessageOption option;

    int32_t err = SendRequestInner(false, DBINDER_INCREFS_TRANSACTION, data, reply, option);
    if (err != ERR_NONE) {
        ZLOGE(LABEL, "DBINDER_INCREFS_TRANSACTION transact return error = %{public}d", err);
        // do nothing
    }
    return err;
}


void IPCObjectProxy::ReleaseProto()
{
    switch (GetProto()) {
        case IRemoteObject::IF_PROT_BINDER: {
            ReleaseBinderProto();
            break;
        }
        case IRemoteObject::IF_PROT_DATABUS:
        case IRemoteObject::IF_PROT_ERROR: {
            ReleaseDatabusProto();
            break;
        }
        default: {
            ZLOGE(LABEL, "release invalid proto %{public}d", proto_);
            break;
        }
    }
}

void IPCObjectProxy::SetProto(int proto)
{
    proto_ = proto;
}

int IPCObjectProxy::GetProtoInfo()
{
    if (CheckHaveSession()) {
        return IRemoteObject::IF_PROT_DATABUS;
    }
    if (handle_ >= IPCProcessSkeleton::DBINDER_HANDLE_BASE) {
        ZLOGE(LABEL, "cannot find session for handle:%{public}u", handle_);
        return IRemoteObject::IF_PROT_ERROR;
    }

    MessageParcel data, reply;
    MessageOption option;
    int err = SendRequestInner(true, GET_PROTO_INFO, data, reply, option);
    if (err != ERR_NONE) {
        ZLOGW(LABEL, "GET_PROTO_INFO transact return error = %{public}d", err);
        return IRemoteObject::IF_PROT_ERROR;
    }

    switch (reply.ReadUint32()) {
        case IRemoteObject::IF_PROT_BINDER: {
            break;
        }
        case IRemoteObject::IF_PROT_DATABUS: {
            if (UpdateDatabusClientSession(handle_, reply)) {
                ZLOGW(LABEL, "it is dbinder, not binder");
                return IRemoteObject::IF_PROT_DATABUS;
            } else {
                ZLOGE(LABEL, "UpdateDatabusClientSession failed");
                return IRemoteObject::IF_PROT_ERROR;
            }
            break;
        }
        default: {
            ZLOGE(LABEL, "get Invalid proto");
            return IRemoteObject::IF_PROT_ERROR;
            break;
        }
    }

    return IRemoteObject::IF_PROT_BINDER;
}

bool IPCObjectProxy::AddDbinderDeathRecipient()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "%{public}s: get current fail", __func__);
        return false;
    }

    if (current->QueryCallbackStub(this) != nullptr) {
        ZLOGW(LABEL, "%{public}s: already attach callback stub", __func__);
        return true;
    }

    //note that cannot use this proxy's descriptor
    sptr<IPCObjectStub> callbackStub = new (std::nothrow) IPCObjectStub(u"DbinderDeathRecipient" + descriptor_);
    if (callbackStub == nullptr) {
        ZLOGE(LABEL, "create IPCObjectStub object failed");
        return false;
    }
    if (!current->AttachCallbackStub(this, callbackStub)) {
        ZLOGW(LABEL, "%{public}s: already attach new callback stub", __func__);
        return false;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    data.WriteInt32(IRemoteObject::DeathRecipient::ADD_DEATH_RECIPIENT);
    data.WriteRemoteObject(callbackStub);

    int err = SendLocalRequest(DBINDER_OBITUARY_TRANSACTION, data, reply, option);
    if (err != ERR_NONE) {
        ZLOGE(LABEL, "AddDbinderDeathRecipient fail, err = %{public}d", err);
        current->DetachCallbackStub(this);
        return false;
    }

    return true;
}

bool IPCObjectProxy::RemoveDbinderDeathRecipient()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "%{public}s: get current fail", __func__);
        return false;
    }

    sptr<IPCObjectStub> callbackStub = current->DetachCallbackStub(this);
    if (callbackStub == nullptr) {
        ZLOGE(LABEL, "%{public}s: get callbackStub fail", __func__);
        return false;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    data.WriteInt32(IRemoteObject::DeathRecipient::REMOVE_DEATH_RECIPIENT);
    data.WriteRemoteObject(callbackStub);

    int err = SendLocalRequest(DBINDER_OBITUARY_TRANSACTION, data, reply, option);
    if (err != ERR_NONE) {
        ZLOGE(LABEL, "%{public}s: send local request fail, err = %{public}d", __func__, err);
        // do nothing, even send request failed
    }
    return err == ERR_NONE;
}

bool IPCObjectProxy::CheckHaveSession()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "IPCProcessSkeleton is null");
        return false;
    }

    return current->ProxyMoveDBinderSession(handle_, this);
}

bool IPCObjectProxy::UpdateDatabusClientSession(int handle, MessageParcel &reply)
{
    DBinderDatabusInvoker *invoker =
        reinterpret_cast<DBinderDatabusInvoker *>(IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS));
    if (invoker == nullptr) {
        ZLOGE(LABEL, "%{public}s: invoker is null", __func__);
        return false;
    }

    uint64_t stubIndex = reply.ReadUint64();
    std::string serviceName = reply.ReadString();
    std::string peerID = reply.ReadString();
    std::string localID = reply.ReadString();
    std::string localBusName = reply.ReadString();
    uint32_t peerTokenId = reply.ReadUint32();

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "%{public}s: skeleton is nullptr", __func__);
        return false;
    }

    std::shared_ptr<DBinderSessionObject> dbinderSession = std::make_shared<DBinderSessionObject>(
        nullptr, serviceName, peerID, stubIndex, this, peerTokenId);
    if (dbinderSession == nullptr) {
        ZLOGE(LABEL, "make DBinderSessionObject fail!");
        return false;
    }

    if (!current->CreateSoftbusServer(localBusName)) {
        ZLOGE(LABEL, "create softbus server fail, name = %{public}s, localID = %{public}s", localBusName.c_str(),
            IPCProcessSkeleton::ConvertToSecureString(localID).c_str());
        return false;
    }

    if (!invoker->UpdateClientSession(dbinderSession)) {
        // no need to remove softbus server
        ZLOGE(LABEL, "update server session object fail!");
        return false;
    }
    if (!current->ProxyAttachDBinderSession(handle, dbinderSession)) {
        // should not get here
        ZLOGE(LABEL, "fail to attach session, handle: %{public}d", handle);
        if (current->QuerySessionByInfo(serviceName, peerID) == nullptr) {
            dbinderSession->CloseDatabusSession();
        }
        return false;
    }
    return true;
}

void IPCObjectProxy::ReleaseDatabusProto()
{
    if (handle_ == 0) {
        ZLOGW(LABEL, "%{public}s: handle == 0, do nothing", __func__);
        return;
    }

    MessageParcel data, reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    int err = SendRequestInner(false, DBINDER_DECREFS_TRANSACTION, data, reply, option);
    if (err != ERR_NONE) {
        ZLOGE(LABEL, "send DBINDER_DECREFS_TRANSACTION cmd failed, error: %{public}d", err);
        // do nothing, if this cmd failed, stub's refcount will be decreased when OnSessionClosed called
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "release databus proto skeleton is null");
        return;
    }
    std::shared_ptr<DBinderSessionObject> toBeDelete = current->ProxyDetachDBinderSession(handle_, this);
    if (toBeDelete != nullptr &&
        // make sure session corresponding to this sessionName and deviceId is no longer used by other proxy
        current->QuerySessionByInfo(toBeDelete->GetServiceName(), toBeDelete->GetDeviceId()) == nullptr) {
        // close session in lock
        toBeDelete->CloseDatabusSession();
    }
}

void IPCObjectProxy::ReleaseBinderProto()
{
    // do nothing
}
#endif
} // namespace OHOS
