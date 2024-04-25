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
#include "process_skeleton.h"
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

#define PRINT_SEND_REQUEST_FAIL_INFO(handle, error, desc) \
    uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(   \
        std::chrono::steady_clock::now().time_since_epoch()).count());                               \
    ZLOGE(LABEL, "failed, handle:%{public}d error:%{public}d desc:%{public}s time:%{public}" PRIu64, \
        handle, error, (desc).c_str(), curTime)

static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC_PROXY, "IPCObjectProxy" };
static const long long int SEND_REQUEST_TIMEOUT = 2000;

IPCObjectProxy::IPCObjectProxy(int handle, std::u16string descriptor, int proto)
    : IRemoteObject(std::move(descriptor)), handle_(handle), proto_(proto), isFinishInit_(false), isRemoteDead_(false)
{
#ifdef CONFIG_ACTV_BINDER
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(proto_);
    if (invoker != nullptr) {
        invoker->LinkRemoteInvoker(&invokerData_);
    }
#endif
    ZLOGD(LABEL, "handle:%{public}u desc:%{public}s %{public}zu", handle_,
        ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(descriptor_)).c_str(), reinterpret_cast<uintptr_t>(this));
    ExtendObjectLifetime();
    ProcessSkeleton *current = ProcessSkeleton::GetInstance();
    if (current == nullptr) {
        ZLOGE(LABEL, "ProcessSkeleton is null");
        return;
    }
    current->DetachDeadObject(this);
}

IPCObjectProxy::~IPCObjectProxy()
{
#ifdef CONFIG_ACTV_BINDER
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(proto_);
    if (invoker != nullptr) {
        invoker->UnlinkRemoteInvoker(&invokerData_);
    }
#endif
    ZLOGD(LABEL, "handle:%{public}u desc:%{public}s %{public}zu", handle_,
        ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)).c_str(),
        reinterpret_cast<uintptr_t>(this));
    ProcessSkeleton *current = ProcessSkeleton::GetInstance();
    if (current == nullptr) {
        ZLOGE(LABEL, "ProcessSkeleton is null");
        return;
    }
    uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
    DeadObjectInfo obj = { handle_, curTime, curTime, remoteDescriptor_ };
    current->AttachDeadObject(this, obj);
}

int32_t IPCObjectProxy::GetObjectRefCount()
{
    MessageParcel data, reply;
    MessageOption option;
    int err = SendRequestInner(false, SYNCHRONIZE_REFERENCE, data, reply, option);
    if (err == ERR_NONE) {
        return reply.ReadInt32();
    }
    PRINT_SEND_REQUEST_FAIL_INFO(handle_, err,
        ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)));
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

    auto beginTime = std::chrono::steady_clock::now();
    int err = SendRequestInner(false, code, data, reply, option);
    auto endTime = std::chrono::steady_clock::now();
    auto timeInterval = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - beginTime).count();
    if (timeInterval > SEND_REQUEST_TIMEOUT) {
        ZLOGE(LABEL, "BlockMonitor IPC cost %{public}lld ms, interface code = %{public}u", timeInterval, code);
    }
    if (err != ERR_NONE) {
        if (ProcessSkeleton::IsPrint(err, lastErr_, lastErrCnt_)) {
            PRINT_SEND_REQUEST_FAIL_INFO(handle_, err,
                ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)));
        }
    }

    return err;
}

int IPCObjectProxy::SendLocalRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    return SendRequestInner(true, code, data, reply, option);
}

int IPCObjectProxy::SendRequestInner(bool isLocal, uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    if (IsObjectDead()) {
        ZLOGD(LABEL, "proxy is already dead, handle:%{public}d desc:%{public}s",
            handle_, ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)).c_str());
        return ERR_DEAD_OBJECT;
    }

    IRemoteInvoker *invoker = nullptr;
    if (isLocal) {
        invoker = IPCThreadSkeleton::GetDefaultInvoker();
    } else {
        invoker = IPCThreadSkeleton::GetRemoteInvoker(proto_);
    }
    if (invoker == nullptr) {
        ZLOGE(LABEL, "invoker is null, handle:%{public}u proto:%{public}d", handle_, proto_);
        return ERR_NULL_OBJECT;
    }

#ifdef CONFIG_ACTV_BINDER
    int status = invoker->SendRequest(handle_, code, data, reply, option, invokerData_);
#else
    int status = invoker->SendRequest(handle_, code, data, reply, option);
#endif
    if (status == ERR_DEAD_OBJECT) {
        MarkObjectDied();
    }
    return status;
}

std::u16string IPCObjectProxy::GetInterfaceDescriptor()
{
    if (!interfaceDesc_.empty()) {
        return interfaceDesc_;
    }
    if (handle_ == 0) {
        ZLOGD(LABEL, "handle == 0, do nothing");
        return std::u16string();
    }

    MessageParcel data, reply;
    MessageOption option;

    int err = SendRequestInner(false, INTERFACE_TRANSACTION, data, reply, option);
    if (err != ERR_NONE) {
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err,
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)));
        return std::u16string();
    }
    interfaceDesc_ = reply.ReadString16();

    return interfaceDesc_;
}

std::string IPCObjectProxy::GetSessionName()
{
    MessageParcel data, reply;
    MessageOption option;

    int err = SendRequestInner(false, GET_SESSION_NAME, data, reply, option);
    if (err != ERR_NONE) {
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err,
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)));
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
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err,
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)));
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
        ZLOGE(LABEL, "TransDataBusName can't write local pid. my/remotePid:%{public}u/%{public}u", getpid(), pid);
        return std::string("");
    }

    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteUint32(pid) || !data.WriteUint32(uid)) {
        ZLOGE(LABEL, "TransDataBusName write pid/uid:%{public}u/%{public}u failed", pid, uid);
        return std::string("");
    }
    int err = SendRequestInner(false, GET_SESSION_NAME_PID_UID, data, reply, option);
    if (err != ERR_NONE) {
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err,
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)));
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
            ZLOGW(LABEL, "proxy is dead, init again, handle:%{public}d desc:%{public}s",
                handle_, ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)).c_str());
            isRemoteDead_ = false;
            isFinishInit_ = false;
        }

        if (!isFinishInit_) {
#ifndef CONFIG_IPC_SINGLE
            if (UpdateProto() == IRemoteObject::IF_PROT_ERROR) {
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
    ZLOGD(LABEL, "handle:%{public}u proto:%{public}d", handle_, proto_);
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "skeleton is null");
        return;
    }
#ifndef CONFIG_IPC_SINGLE
    ReleaseProto();
#endif
    ClearDeathRecipients();
    // This proxy is going to be destroyed, so we need to decrease refcount of binder_ref.
    // It may has been replace with a new proxy, thus we have no need to check result.
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
    if (invoker != nullptr) {
        invoker->ReleaseHandle(handle_);
    }
    current->DetachObject(this);
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
        ZLOGE(LABEL, "proxy is already dead, handle:%{public}d desc:%{public}s",
            handle_, ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)).c_str());
        return false;
    }
    recipients_.push_back(recipient);
    if (recipients_.size() > 1 || handle_ >= IPCProcessSkeleton::DBINDER_HANDLE_BASE) {
        ZLOGD(LABEL, "death recipient is already registered, handle:%{public}d desc:%{public}s",
            handle_, ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)).c_str());
        return true;
    }

    IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
    if (invoker == nullptr) {
        ZLOGE(LABEL, "invoker is null");
        return false;
    }

    if (!invoker->AddDeathRecipient(handle_, this)) {
        ZLOGE(LABEL, "fail to add binder death recipient, handle:%{public}d desc:%{public}s",
            handle_, ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)).c_str());
        return false;
    }
#ifndef CONFIG_IPC_SINGLE
    if (proto_ == IRemoteObject::IF_PROT_DATABUS) {
        if (!AddDbinderDeathRecipient()) {
            ZLOGE(LABEL, "failed to add dbinder death recipient, handle:%{public}d desc:%{public}s",
                handle_, ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)).c_str());
            return false;
        }
    }
#endif
    ZLOGD(LABEL, "success, handle:%{public}d desc:%{public}s %{public}zu", handle_,
        ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)).c_str(),
        reinterpret_cast<uintptr_t>(this));
    return true;
}

bool IPCObjectProxy::RemoveDeathRecipient(const sptr<DeathRecipient> &recipient)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    if (IsObjectDead()) {
        ZLOGD(LABEL, "proxy is already dead, handle:%{public}d desc:%{public}s",
            handle_, ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)).c_str());
        return false;
    }
    bool recipientErased = false;
    auto it = find(recipients_.begin(), recipients_.end(), recipient);
    if (it != recipients_.end()) {
        recipients_.erase(it);
        recipientErased = true;
    }

    if (handle_ >= IPCProcessSkeleton::DBINDER_HANDLE_BASE && recipientErased == true) {
        ZLOGI(LABEL, "death recipient is already unregistered, handle:%{public}d desc:%{public}s",
            handle_, ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)).c_str());
        return true;
    }

    if (recipientErased && recipients_.empty()) {
        IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
        if (invoker == nullptr) {
            ZLOGE(LABEL, "invoker is null");
            return false;
        }

        bool dbinderStatus = true;
        bool status = invoker->RemoveDeathRecipient(handle_, this);
#ifndef CONFIG_IPC_SINGLE
        if (proto_ == IRemoteObject::IF_PROT_DATABUS || proto_ == IRemoteObject::IF_PROT_ERROR) {
            dbinderStatus = RemoveDbinderDeathRecipient();
        }
#endif
        ZLOGD(LABEL, "result:%{public}d handle:%{public}d desc:%{public}s %{public}zu", status && dbinderStatus,
            handle_, ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)).c_str(),
            reinterpret_cast<uintptr_t>(this));
        return status && dbinderStatus;
    }
    return recipientErased;
}

void IPCObjectProxy::SendObituary()
{
    ZLOGW(LABEL, "handle:%{public}d desc:%{public}s %{public}zu", handle_,
        ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)).c_str(),
        reinterpret_cast<uintptr_t>(this));
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
            ZLOGE(LABEL, "invoker is null");
        }
    }

    const size_t size = toBeReport.size();
    for (size_t i = 0; i < size; i++) {
        sptr<DeathRecipient> recipient = toBeReport[i];
        if (recipient != nullptr) {
            ZLOGD(LABEL, "handle:%{public}u call OnRemoteDied begin", handle_);
            recipient->OnRemoteDied(this);
            ZLOGD(LABEL, "handle:%{public}u call OnRemoteDied end", handle_);
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
    ZLOGW(LABEL, "handle:%{public}d desc:%{public}s", handle_,
        ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)).c_str());
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    data.WriteInt32(IRemoteObject::DeathRecipient::NOTICE_DEATH_RECIPIENT);

    int err = SendLocalRequest(DBINDER_OBITUARY_TRANSACTION, data, reply, option);
    if (err != ERR_NONE || reply.ReadInt32() != ERR_NONE) {
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err,
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)));
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
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err,
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)));
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
            ZLOGE(LABEL, "release invalid proto:%{public}d", proto_);
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
    if (err != ERR_NONE && err != -EBADMSG) {
        uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        ZLOGW(LABEL, "GET_PROTO_INFO transact return error:%{public}d handle:%{public}u time:%{public}" PRIu64,
            err, handle_, curTime);
        return IRemoteObject::IF_PROT_ERROR;
    }

    switch (reply.ReadUint32()) {
        case IRemoteObject::IF_PROT_BINDER: {
            remoteDescriptor_ = reply.ReadString16();
            ZLOGD(LABEL, "binder, handle:%{public}u desc:%{public}s",
                handle_, ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)).c_str());
            break;
        }
        case IRemoteObject::IF_PROT_DATABUS: {
            if (UpdateDatabusClientSession(handle_, reply)) {
                remoteDescriptor_ = reply.ReadString16();
                ZLOGD(LABEL, "dbinder, handle:%{public}u desc:%{public}s",
                    handle_, ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)).c_str());
                return IRemoteObject::IF_PROT_DATABUS;
            } else {
                ZLOGE(LABEL, "UpdateDatabusClientSession failed");
                return IRemoteObject::IF_PROT_ERROR;
            }
        }
        default: {
            ZLOGE(LABEL, "get Invalid proto");
            return IRemoteObject::IF_PROT_ERROR;
        }
    }

    return IRemoteObject::IF_PROT_BINDER;
}

bool IPCObjectProxy::AddDbinderDeathRecipient()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGW(LABEL, "get current fail, handle:%{public}d desc:%{public}s",
            handle_, ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)).c_str());
        return false;
    }

    if (current->QueryCallbackStub(this) != nullptr) {
        ZLOGW(LABEL, "already attach callback stub, handle:%{public}d desc:%{public}s",
            handle_, ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)).c_str());
        return true;
    }

    //note that cannot use this proxy's descriptor
    sptr<IPCObjectStub> callbackStub = new (std::nothrow) IPCObjectStub(u"DbinderDeathRecipient" + remoteDescriptor_);
    if (callbackStub == nullptr) {
        ZLOGE(LABEL, "create IPCObjectStub object failed, handle:%{public}d desc:%{public}s",
            handle_, ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)).c_str());
        return false;
    }
    if (!current->AttachCallbackStub(this, callbackStub)) {
        ZLOGW(LABEL, "already attach new callback stub, handle:%{public}d desc:%{public}s",
            handle_, ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)).c_str());
        return false;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    data.WriteInt32(IRemoteObject::DeathRecipient::ADD_DEATH_RECIPIENT);
    data.WriteRemoteObject(callbackStub);

    int err = SendLocalRequest(DBINDER_OBITUARY_TRANSACTION, data, reply, option);
    if (err != ERR_NONE) {
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err,
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)));
        current->DetachCallbackStub(this);
        return false;
    }

    return true;
}

bool IPCObjectProxy::RemoveDbinderDeathRecipient()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "get current fail");
        return false;
    }
    ZLOGW(LABEL, "handle:%{public}d desc:%{public}s", handle_,
        ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)).c_str());
    sptr<IPCObjectStub> callbackStub = current->DetachCallbackStub(this);
    if (callbackStub == nullptr) {
        ZLOGE(LABEL, "get callbackStub fail, handle:%{public}d desc:%{public}s",
            handle_, ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)).c_str());
        return false;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    data.WriteInt32(IRemoteObject::DeathRecipient::REMOVE_DEATH_RECIPIENT);
    data.WriteRemoteObject(callbackStub);

    int err = SendLocalRequest(DBINDER_OBITUARY_TRANSACTION, data, reply, option);
    if (err != ERR_NONE) {
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err,
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)));
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
        ZLOGE(LABEL, "invoker is null");
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
        ZLOGE(LABEL, "skeleton is nullptr");
        return false;
    }

    std::string str = serviceName.substr(DBINDER_SOCKET_NAME_PREFIX.length());
    std::string::size_type pos = str.find("_");
    std::string peerUid = str.substr(0, pos);
    std::string peerPid = str.substr(pos + 1);

    std::shared_ptr<DBinderSessionObject> dbinderSession = std::make_shared<DBinderSessionObject>(
        serviceName, peerID, stubIndex, this, peerTokenId);
    if (dbinderSession == nullptr) {
        ZLOGE(LABEL, "make DBinderSessionObject fail!");
        return false;
    }
    dbinderSession->SetPeerPid(std::stoi(peerPid));
    dbinderSession->SetPeerUid(std::stoi(peerUid));
    if (!current->CreateSoftbusServer(localBusName)) {
        ZLOGE(LABEL, "create softbus server fail, name:%{public}s localID:%{public}s", localBusName.c_str(),
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
        ZLOGW(LABEL, "fail to attach session for handle:%{public}d, maybe a concurrent scenarios", handle);
        if (current->QuerySessionByInfo(serviceName, peerID) == nullptr) {
            ZLOGE(LABEL, "session is not exist, service:%{public}s devId:%{public}s",
                serviceName.c_str(), IPCProcessSkeleton::ConvertToSecureString(peerID).c_str());
            dbinderSession->CloseDatabusSession();
            return false;
        }
    }
    return true;
}

void IPCObjectProxy::ReleaseDatabusProto()
{
    if (handle_ == 0) {
        ZLOGW(LABEL, "handle == 0, do nothing");
        return;
    }

    MessageParcel data, reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    int err = SendRequestInner(false, DBINDER_DECREFS_TRANSACTION, data, reply, option);
    if (err != ERR_NONE) {
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err,
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)));
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

uint32_t IPCObjectProxy::GetStrongRefCountForStub()
{
    BinderInvoker *invoker = reinterpret_cast<BinderInvoker *>(IPCThreadSkeleton::GetDefaultInvoker());
    if (invoker == nullptr) {
        ZLOGE(LABEL, "get default invoker failed");
        return 0;  // 0 means get failed
    }
    return invoker->GetStrongRefCountForStub(handle_);
}
#endif
} // namespace OHOS
