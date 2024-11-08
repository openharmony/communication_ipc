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
#include "backtrace_local.h"
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

#define PRINT_SEND_REQUEST_FAIL_INFO(handle, error, desc, proxy) \
    uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(   \
        std::chrono::steady_clock::now().time_since_epoch()).count());                               \
    ZLOGE(LABEL, "failed, handle:%{public}d error:%{public}d desc:%{public}s proxy:%{public}u time:%{public}" PRIu64, \
        handle, error, (desc).c_str(), proxy, curTime)

using namespace OHOS::HiviewDFX;
static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC_PROXY, "IPCObjectProxy" };
static constexpr int SEND_REQUEST_TIMEOUT = 2000;

IPCObjectProxy::IPCObjectProxy(int handle, std::u16string descriptor, int proto)
    : IRemoteObject(std::move(descriptor)), handle_(handle), proto_(proto), isFinishInit_(false), isRemoteDead_(false)
{
    ZLOGD(LABEL, "handle:%{public}u desc:%{public}s %{public}u", handle_,
        ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(descriptor_)).c_str(), ProcessSkeleton::ConvertAddr(this));
    ExtendObjectLifetime();
    ProcessSkeleton *current = ProcessSkeleton::GetInstance();
    if (current == nullptr) {
        ZLOGE(LABEL, "ProcessSkeleton is null");
        return;
    }
    std::u16string str(descriptor_);
    current->AttachValidObject(this, str);
}

IPCObjectProxy::~IPCObjectProxy()
{
    std::string desc;
    {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        ZLOGD(LABEL, "handle:%{public}u desc:%{public}s %{public}u", handle_,
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)).c_str(),
            ProcessSkeleton::ConvertAddr(this));
        desc = Str16ToStr8(remoteDescriptor_);
    }
    if (desc == "ohos.aafwk.AbilityToken" || desc == "ohos.aafwk.AbilityManager") {
        ZLOGI(LABEL, "destroy handle:%{public}u desc:%{public}s %{public}u", handle_,
            ProcessSkeleton::ConvertToSecureDesc(desc).c_str(), ProcessSkeleton::ConvertAddr(this));
    }
    auto pos = desc.find("IVpnStateCallback");
    if (pos != std::string::npos) {
        ZLOGI(LABEL, "handle:%{public}u desc:%{public}s %{public}u", handle_,
            ProcessSkeleton::ConvertToSecureDesc(desc).c_str(), ProcessSkeleton::ConvertAddr(this));
    }
    ProcessSkeleton *current = ProcessSkeleton::GetInstance();
    if (current == nullptr) {
        ZLOGE(LABEL, "ProcessSkeleton is null");
        return;
    }
    current->DetachValidObject(this);
    // for map clean
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (!recipients_.empty()) {
            recipients_.clear();
        }
    }
}

int32_t IPCObjectProxy::GetObjectRefCount()
{
    MessageParcel data, reply;
    MessageOption option;
    int err = SendRequestInner(false, SYNCHRONIZE_REFERENCE, data, reply, option);
    if (err == ERR_NONE) {
        return reply.ReadInt32();
    }
    {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err,
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)),
            ProcessSkeleton::ConvertAddr(this));
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
    std::string desc;
    {
        std::unique_lock<std::shared_mutex> lockGuard(descMutex_);
        if (remoteDescriptor_.empty()) {
            remoteDescriptor_ = data.GetInterfaceToken();
        }
        desc = Str16ToStr8(remoteDescriptor_);
    }
    if (desc == "ohos.aafwk.AbilityManager") {
        ZLOGI(LABEL, "handle:%{public}u desc:%{public}s refcnt:%{public}d %{public}u", handle_,
            ProcessSkeleton::ConvertToSecureDesc(desc).c_str(), GetSptrRefCount(), ProcessSkeleton::ConvertAddr(this));
    }

    auto beginTime = std::chrono::steady_clock::now();
    int err = SendRequestInner(false, code, data, reply, option);
    auto endTime = std::chrono::steady_clock::now();
    auto timeInterval = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - beginTime).count();
    if (timeInterval > SEND_REQUEST_TIMEOUT) {
        ZLOGW(LABEL, "DFX_BlockMonitor IPC cost %{public}lld ms, interface code:%{public}u, desc:%{public}s",
            timeInterval, code, ProcessSkeleton::ConvertToSecureDesc(desc).c_str());
    }
    if (err != ERR_NONE && ProcessSkeleton::IsPrint(err, lastErr_, lastErrCnt_)) {
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, ProcessSkeleton::ConvertToSecureDesc(desc),
            ProcessSkeleton::ConvertAddr(this));
        if (err == BR_FAILED_REPLY) {
            std::string backtrace;
            if (!GetBacktrace(backtrace, false)) {
                ZLOGE(LABEL, "GetBacktrace fail");
            } else {
                ZLOGW(LABEL, "backtrace info:\n%{public}s", backtrace.c_str());
            }
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
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
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

    IPCThreadSkeleton::UpdateSendRequestCount(1);
    int status = invoker->SendRequest(handle_, code, data, reply, option);
    if (status == ERR_DEAD_OBJECT) {
        SetObjectDied(true);
    }
    IPCThreadSkeleton::UpdateSendRequestCount(-1);
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
    std::string desc;
    {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        desc = Str16ToStr8(remoteDescriptor_);
    }
    if (desc == "ohos.aafwk.AbilityToken") {
        ZLOGI(LABEL, "handle:%{public}u desc:%{public}s refcnt:%{public}d %{public}u", handle_,
            ProcessSkeleton::ConvertToSecureDesc(desc).c_str(), GetSptrRefCount(), ProcessSkeleton::ConvertAddr(this));
    }

    int err = SendRequestInner(false, INTERFACE_TRANSACTION, data, reply, option);
    if (err != ERR_NONE) {
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, ProcessSkeleton::ConvertToSecureDesc(desc),
            ProcessSkeleton::ConvertAddr(this));
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
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err,
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)),
            ProcessSkeleton::ConvertAddr(this));
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
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err,
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)),
            ProcessSkeleton::ConvertAddr(this));
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
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err,
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)),
            ProcessSkeleton::ConvertAddr(this));
        return std::string("");
    }

    if (reply.ReadUint32() != IRemoteObject::IF_PROT_DATABUS) {
        ZLOGE(LABEL, "TransDataBusName normal binder");
        return std::string("");
    }

    return reply.ReadString();
}

int IPCObjectProxy::RemoveSessionName(const std::string &sessionName)
{
    MessageParcel data, reply;
    MessageOption option { MessageOption::TF_ASYNC };
    if (!data.WriteString(sessionName)) {
        ZLOGE(LABEL, "write parcel fail, sessionName:%{public}s", sessionName.c_str());
        return IPC_PROXY_WRITE_PARCEL_ERR;
    }
    int err = SendRequestInner(false, REMOVE_SESSION_NAME, data, reply, option);
    if (err != ERR_NONE) {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err,
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)),
            ProcessSkeleton::ConvertAddr(this));
    }
    return err;
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

void IPCObjectProxy::WaitForInit(const void *dbinderData)
{
    std::string desc;
    {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        desc = Str16ToStr8(remoteDescriptor_);
    }
    // RPC proxy: AcquireHandle->AttachObject->Open Session->IncRef to Remote Stub
    {
        std::lock_guard<std::mutex> lockGuard(initMutex_);
        // When remote stub is gone, handle is reclaimed. But mapping from this handle to
        // proxy may still exist before OnLastStrongRef called. If so, in FindOrNewObject
        // we may find the same proxy that has been marked as dead. Thus, we need to check again.
        if (IsObjectDead()) {
            ZLOGW(LABEL, "proxy is dead, init again, handle:%{public}d desc:%{public}s",
                handle_, ProcessSkeleton::ConvertToSecureDesc(desc).c_str());
            SetObjectDied(false);
            isFinishInit_ = false;
        }

        if (!isFinishInit_) {
#ifndef CONFIG_IPC_SINGLE
            if (!UpdateProto(dbinderData)) {
                return;
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
                    SetObjectDied(true);
                }
            }
#endif
        }
    }
#ifndef CONFIG_IPC_SINGLE
    if (proto_ == IRemoteObject::IF_PROT_DATABUS) {
        if (IncRefToRemote() != ERR_NONE) {
            SetProto(IRemoteObject::IF_PROT_ERROR);
            SetObjectDied(true);
        }
    }
#endif
}

void IPCObjectProxy::OnLastStrongRef(const void *objectId)
{
    // IPC proxy: DetachObject->ReleaseHandle
    // RPC proxy: DecRef to Remote Stub->Close Session->DetachObject->ReleaseHandle
    std::string desc;
    {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        desc = Str16ToStr8(remoteDescriptor_);
    }
    if (desc == "ohos.aafwk.AbilityToken" || desc == "ohos.aafwk.AbilityManager") {
        ZLOGI(LABEL, "handle:%{public}u desc:%{public}s %{public}u", handle_,
            ProcessSkeleton::ConvertToSecureDesc(desc).c_str(), ProcessSkeleton::ConvertAddr(this));
    }
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

void IPCObjectProxy::SetObjectDied(bool isDied)
{
    isRemoteDead_.store(isDied);
}

bool IPCObjectProxy::IsObjectDead() const
{
    return isRemoteDead_.load();
}

bool IPCObjectProxy::AddDeathRecipient(const sptr<DeathRecipient> &recipient)
{
    if (recipient == nullptr) {
        ZLOGE(LABEL, "recipient is null");
        return false;
    }
    std::string desc;
    {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        desc = Str16ToStr8(remoteDescriptor_);
    }
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (IsObjectDead()) {
        ZLOGE(LABEL, "proxy is already dead, handle:%{public}d desc:%{public}s",
            handle_, ProcessSkeleton::ConvertToSecureDesc(desc).c_str());
        return false;
    }
    sptr<DeathRecipientAddrInfo> info = new DeathRecipientAddrInfo(recipient);
    if (info == nullptr || info->soPath_.empty()) {
        ZLOGE(LABEL, "invalid object, info is nullptr:%{public}d", info == nullptr);
        return false;
    }
    recipients_.push_back(info);
    if (recipients_.size() > 1 || handle_ >= IPCProcessSkeleton::DBINDER_HANDLE_BASE) {
        ZLOGD(LABEL, "death recipient is already registered, handle:%{public}d desc:%{public}s",
            handle_, ProcessSkeleton::ConvertToSecureDesc(desc).c_str());
        return true;
    }
    if (!RegisterBinderDeathRecipient()) {
        ZLOGE(LABEL, "register failed, handle:%{public}d desc:%{public}s addr:%{public}u", handle_,
            ProcessSkeleton::ConvertToSecureDesc(desc).c_str(), ProcessSkeleton::ConvertAddr(this));
        recipients_.pop_back();
    }
    ZLOGD(LABEL, "success, handle:%{public}d desc:%{public}s %{public}u", handle_,
        ProcessSkeleton::ConvertToSecureDesc(desc).c_str(), ProcessSkeleton::ConvertAddr(this));
    return true;
}

bool IPCObjectProxy::RemoveDeathRecipient(const sptr<DeathRecipient> &recipient)
{
    if (recipient == nullptr) {
        ZLOGE(LABEL, "recipient is null");
        return false;
    }
    std::string desc;
    {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        desc = Str16ToStr8(remoteDescriptor_);
    }
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (IsObjectDead()) {
        ZLOGD(LABEL, "proxy is already dead, handle:%{public}d desc:%{public}s",
            handle_, ProcessSkeleton::ConvertToSecureDesc(desc).c_str());
        return false;
    }
    bool recipientErased = false;
    for (auto iter = recipients_.begin(); iter != recipients_.end(); iter++) {
        if ((*iter)->recipient_ == recipient) {
            recipients_.erase(iter);
            recipientErased = true;
            break;
        }
    }
    if (handle_ >= IPCProcessSkeleton::DBINDER_HANDLE_BASE && recipientErased == true) {
        ZLOGI(LABEL, "death recipient is already unregistered, handle:%{public}d desc:%{public}s",
            handle_, ProcessSkeleton::ConvertToSecureDesc(desc).c_str());
        return true;
    }

    if (recipientErased && recipients_.empty() && !UnRegisterBinderDeathRecipient()) {
        ZLOGE(LABEL, "unregister failed, handle:%{public}d desc:%{public}s addr:%{public}u",
            handle_, ProcessSkeleton::ConvertToSecureDesc(desc).c_str(), ProcessSkeleton::ConvertAddr(this));
    }

    ZLOGD(LABEL, "handle:%{public}d desc:%{public}s addr:%{public}u, result:%{public}d", handle_,
        ProcessSkeleton::ConvertToSecureDesc(desc).c_str(), ProcessSkeleton::ConvertAddr(this), recipientErased);
    return recipientErased;
}

void IPCObjectProxy::SendObituary()
{
    {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        ZLOGW(LABEL, "handle:%{public}d desc:%{public}s %{public}u", handle_,
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)).c_str(),
            ProcessSkeleton::ConvertAddr(this));
    }

#ifndef CONFIG_IPC_SINGLE
    if (handle_ < IPCProcessSkeleton::DBINDER_HANDLE_BASE) {
        if (proto_ == IRemoteObject::IF_PROT_DATABUS || proto_ == IRemoteObject::IF_PROT_ERROR) {
            RemoveDbinderDeathRecipient();
        }
    }
#endif
    SetObjectDied(true);
    std::vector<sptr<DeathRecipientAddrInfo>> toBeReport;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        toBeReport.swap(recipients_);
    }

    if (toBeReport.size() > 0 && handle_ < IPCProcessSkeleton::DBINDER_HANDLE_BASE) {
        IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
        if (invoker != nullptr) {
            invoker->RemoveDeathRecipient(handle_, this);
        } else {
            ZLOGE(LABEL, "invoker is null");
        }
    }
    for (auto iter = toBeReport.begin(); iter != toBeReport.end(); iter++) {
        if ((*iter)->IsDlclosed()) {
            ZLOGE(LABEL, "so has been dlclosed, sopath:%{public}s", (*iter)->soPath_.c_str());
            continue;
        }
        sptr<DeathRecipient> recipient = (*iter)->recipient_;
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
    std::string desc;
    {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        desc = Str16ToStr8(remoteDescriptor_);
    }
    ZLOGW(LABEL, "handle:%{public}d desc:%{public}s", handle_,
        ProcessSkeleton::ConvertToSecureDesc(desc).c_str());
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    data.WriteInt32(IRemoteObject::DeathRecipient::NOTICE_DEATH_RECIPIENT);

    int err = SendLocalRequest(DBINDER_OBITUARY_TRANSACTION, data, reply, option);
    if (err != ERR_NONE || reply.ReadInt32() != ERR_NONE) {
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, ProcessSkeleton::ConvertToSecureDesc(desc),
            ProcessSkeleton::ConvertAddr(this));
        return IPC_PROXY_TRANSACTION_ERR;
    }

    return ERR_NONE;
}

int IPCObjectProxy::InvokeListenThread(MessageParcel &data, MessageParcel &reply)
{
    MessageOption option;
    return SendRequestInner(false, INVOKE_LISTEN_THREAD, data, reply, option);
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

#ifndef EMULATOR_PLATFORM
bool IPCObjectProxy::CanPromote()
{
    return (GetSptrRefCount() > 0);
}
#endif

#ifndef CONFIG_IPC_SINGLE
int IPCObjectProxy::UpdateProto()
{
    int proto = GetProtoInfo();
    SetProto(proto);
    return proto;
}

bool IPCObjectProxy::UpdateProto(const void *dbinderData)
{
    auto data = reinterpret_cast<const dbinder_negotiation_data *>(dbinderData);
    if (data != nullptr && data->proto == IRemoteObject::IF_PROT_DATABUS) {
        dbinderData_ = std::make_unique<uint8_t[]>(sizeof(dbinder_negotiation_data));
        if (dbinderData_ == nullptr) {
            SetObjectDied(true);
            SetProto(IRemoteObject::IF_PROT_ERROR);
            ZLOGE(LABEL, "malloc dbinderData fail, handle:%{public}d", handle_);
            return false;
        }
        auto tmp = reinterpret_cast<dbinder_negotiation_data *>(dbinderData_.get());
        *tmp = *data;
        if (!UpdateDatabusClientSession()) {
            ZLOGE(LABEL, "UpdateDatabusClientSession fail, handle:%{public}d", handle_);
            SetObjectDied(true);
            SetProto(IRemoteObject::IF_PROT_ERROR);
            dbinderData_ = nullptr;
            return false;
        }
        SetProto(IRemoteObject::IF_PROT_DATABUS);
        {
            std::unique_lock<std::shared_mutex> lockGuard(descMutex_);
            remoteDescriptor_ = data->desc;
        }
    } else if (CheckHaveSession()) {
        SetProto(IRemoteObject::IF_PROT_DATABUS);
    }
    return true;
}

int32_t IPCObjectProxy::IncRefToRemote()
{
    MessageParcel data, reply;
    MessageOption option;

    int32_t err = SendRequestInner(false, DBINDER_INCREFS_TRANSACTION, data, reply, option);
    if (err != ERR_NONE) {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err,
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)),
            ProcessSkeleton::ConvertAddr(this));
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
            std::unique_lock<std::shared_mutex> lockGuard(descMutex_);
            remoteDescriptor_ = reply.ReadString16();
            ZLOGD(LABEL, "binder, handle:%{public}u desc:%{public}s",
                handle_, ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)).c_str());
            break;
        }
        case IRemoteObject::IF_PROT_DATABUS: {
            if (UpdateDatabusClientSession(handle_, reply)) {
                std::unique_lock<std::shared_mutex> lockGuard(descMutex_);
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
    std::string desc;
    std::u16string remoteDescriptorTmp;
    {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        remoteDescriptorTmp = remoteDescriptor_;
        desc = Str16ToStr8(remoteDescriptor_);
    }
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGW(LABEL, "get current fail, handle:%{public}d desc:%{public}s",
            handle_, ProcessSkeleton::ConvertToSecureDesc(desc).c_str());
        return false;
    }

    if (current->QueryCallbackStub(this) != nullptr) {
        ZLOGW(LABEL, "already attach callback stub, handle:%{public}d desc:%{public}s",
            handle_, ProcessSkeleton::ConvertToSecureDesc(desc).c_str());
        return true;
    }

    //note that cannot use this proxy's descriptor
    sptr<IPCObjectStub> callbackStub = new (std::nothrow) IPCObjectStub(u"DbinderDeathRecipient" + remoteDescriptorTmp);
    if (callbackStub == nullptr) {
        ZLOGE(LABEL, "create IPCObjectStub object failed, handle:%{public}d desc:%{public}s",
            handle_, ProcessSkeleton::ConvertToSecureDesc(desc).c_str());
        return false;
    }
    if (!current->AttachCallbackStub(this, callbackStub)) {
        ZLOGW(LABEL, "already attach new callback stub, handle:%{public}d desc:%{public}s",
            handle_, ProcessSkeleton::ConvertToSecureDesc(desc).c_str());
        return false;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    data.WriteInt32(IRemoteObject::DeathRecipient::ADD_DEATH_RECIPIENT);
    data.WriteRemoteObject(callbackStub);

    int err = SendLocalRequest(DBINDER_OBITUARY_TRANSACTION, data, reply, option);
    if (err != ERR_NONE) {
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, ProcessSkeleton::ConvertToSecureDesc(desc),
            ProcessSkeleton::ConvertAddr(this));
        current->DetachCallbackStub(this);
        return false;
    }

    return true;
}

bool IPCObjectProxy::RemoveDbinderDeathRecipient()
{
    std::string desc;
    {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        desc = Str16ToStr8(remoteDescriptor_);
    }
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "get current fail");
        return false;
    }
    ZLOGW(LABEL, "handle:%{public}d desc:%{public}s", handle_,
        ProcessSkeleton::ConvertToSecureDesc(desc).c_str());
    sptr<IPCObjectStub> callbackStub = current->DetachCallbackStub(this);
    if (callbackStub == nullptr) {
        ZLOGE(LABEL, "get callbackStub fail, handle:%{public}d desc:%{public}s",
            handle_, ProcessSkeleton::ConvertToSecureDesc(desc).c_str());
        return false;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    data.WriteInt32(IRemoteObject::DeathRecipient::REMOVE_DEATH_RECIPIENT);
    data.WriteRemoteObject(callbackStub);

    int err = SendLocalRequest(DBINDER_OBITUARY_TRANSACTION, data, reply, option);
    if (err != ERR_NONE) {
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, ProcessSkeleton::ConvertToSecureDesc(desc),
            ProcessSkeleton::ConvertAddr(this));
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

bool IPCObjectProxy::MakeDBinderTransSession(const DBinderNegotiationData &data)
{
    DBinderDatabusInvoker *invoker =
        reinterpret_cast<DBinderDatabusInvoker *>(IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS));
    if (invoker == nullptr) {
        ZLOGE(LABEL, "invoker is null");
        return false;
    }
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "skeleton is nullptr");
        return false;
    }
    if (data.peerServiceName.empty()) {
        ZLOGE(LABEL, "serviceName is empty");
        return false;
    }

    auto dbinderSession = std::make_shared<DBinderSessionObject>(
        data.peerServiceName, data.peerDeviceId, data.stubIndex, this, data.peerTokenId);
    if (dbinderSession == nullptr) {
        ZLOGE(LABEL, "make DBinderSessionObject fail!");
        return false;
    }
    dbinderSession->SetPeerPid(data.peerPid);
    dbinderSession->SetPeerUid(data.peerUid);

    if (!current->CreateSoftbusServer(data.localServiceName)) {
        ZLOGE(LABEL, "CreateSoftbusServer fail, name:%{public}s localID:%{public}s", data.localServiceName.c_str(),
            IPCProcessSkeleton::ConvertToSecureString(data.localDeviceId).c_str());
        return false;
    }
    if (!invoker->UpdateClientSession(dbinderSession)) {
        // no need to remove softbus server
        ZLOGE(LABEL, "UpdateClientSession fail!");
        return false;
    }
    if (!current->ProxyAttachDBinderSession(handle_, dbinderSession)) {
        // should not get here
        ZLOGW(LABEL, "ProxyAttachDBinderSession fail for handle:%{public}d, maybe a concurrent scenarios", handle_);
        if (current->QuerySessionByInfo(data.peerServiceName, data.peerDeviceId) == nullptr) {
            ZLOGE(LABEL, "session is not exist, service:%{public}s devId:%{public}s",
                data.peerServiceName.c_str(), IPCProcessSkeleton::ConvertToSecureString(data.peerDeviceId).c_str());
            dbinderSession->CloseDatabusSession();
            return false;
        }
    }
    ZLOGI(LABEL, "succ");
    return true;
}

int IPCObjectProxy::GetDBinderNegotiationData(int handle, MessageParcel &reply,
    DBinderNegotiationData &dbinderData)
{
    dbinderData.stubIndex = reply.ReadUint64();
    dbinderData.peerServiceName = reply.ReadString();
    dbinderData.peerDeviceId = reply.ReadString();
    dbinderData.localDeviceId = reply.ReadString();
    dbinderData.localServiceName = reply.ReadString();
    dbinderData.peerTokenId = reply.ReadUint32();
    if (dbinderData.peerServiceName.empty() || dbinderData.peerDeviceId.empty() ||
        dbinderData.localDeviceId.empty() || dbinderData.localServiceName.empty()) {
        ZLOGE(LABEL, "invalid param");
        return ERR_INVALID_DATA;
    }

    std::string str = dbinderData.peerServiceName.substr(DBINDER_SOCKET_NAME_PREFIX.length());
    std::string::size_type pos = str.find("_");
    if (pos == str.npos) {
        ZLOGE(LABEL, "ServiceName format error");
        return ERR_INVALID_DATA;
    }
    dbinderData.peerUid = std::stoi(str.substr(0, pos));
    dbinderData.peerPid = std::stoi(str.substr(pos + 1));
    return ERR_NONE;
}

bool IPCObjectProxy::UpdateDatabusClientSession(int handle, MessageParcel &reply)
{
    DBinderNegotiationData dbinderData;
    if (GetDBinderNegotiationData(handle, reply, dbinderData) != ERR_NONE) {
        return false;
    }
    return MakeDBinderTransSession(dbinderData);
}

int IPCObjectProxy::GetDBinderNegotiationData(DBinderNegotiationData &dbinderData)
{
    if (dbinderData_ == nullptr) {
        ZLOGE(LABEL, "dbinderData_ is null");
        return ERR_INVALID_DATA;
    }
    auto data = reinterpret_cast<const dbinder_negotiation_data *>(dbinderData_.get());
    dbinderData.stubIndex = data->stub_index;
    dbinderData.peerServiceName = data->target_name;
    dbinderData.peerDeviceId = data->target_device;
    dbinderData.localDeviceId = data->local_device;
    dbinderData.localServiceName = data->local_name;
    dbinderData.peerTokenId = data->tokenid;

    std::string str = dbinderData.peerServiceName.substr(DBINDER_SOCKET_NAME_PREFIX.length());
    std::string::size_type pos = str.find("_");
    if (pos == str.npos) {
        ZLOGW(LABEL, "ServiceName format error");
        return ERR_INVALID_DATA;
    }
    dbinderData.peerUid = std::stoi(str.substr(0, pos));
    dbinderData.peerPid = std::stoi(str.substr(pos + 1));
    return ERR_NONE;
}

bool IPCObjectProxy::UpdateDatabusClientSession()
{
    DBinderNegotiationData dbinderData;
    if (GetDBinderNegotiationData(dbinderData) != ERR_NONE) {
        return false;
    }
    return MakeDBinderTransSession(dbinderData);
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
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err,
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(remoteDescriptor_)),
            ProcessSkeleton::ConvertAddr(this));
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

bool IPCObjectProxy::RegisterBinderDeathRecipient()
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
    if (invoker == nullptr) {
        ZLOGE(LABEL, "invoker is null");
        return false;
    }
    if (!invoker->AddDeathRecipient(handle_, this)) {
        ZLOGE(LABEL, "add failed, handle:%{public}d", handle_);
        return false;
    }
#ifndef CONFIG_IPC_SINGLE
    if (proto_ == IRemoteObject::IF_PROT_DATABUS && !AddDbinderDeathRecipient()) {
        ZLOGE(LABEL, "add failed, handle:%{public}d", handle_);
        return false;
    }
#endif
    ZLOGD(LABEL, "success, handle:%{public}d", handle_);
    return true;
}

bool IPCObjectProxy::UnRegisterBinderDeathRecipient()
{
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
    ZLOGD(LABEL, "unregister result:%{public}d, handle:%{public}d",
        status && dbinderStatus, handle_);
    return status && dbinderStatus;
}

IPCObjectProxy::DeathRecipientAddrInfo::DeathRecipientAddrInfo(const sptr<DeathRecipient> &recipient)
    : recipient_(recipient), soFuncAddr_(nullptr), soPath_()
{
    if (recipient_ == nullptr) {
        ZLOGD(LABEL, "recipient is null");
        return;
    }
    soFuncAddr_ = reinterpret_cast<void *>(GET_FIRST_VIRTUAL_FUNC_ADDR(recipient_.GetRefPtr()));
    soPath_ = GetNewSoPath();
}

std::string IPCObjectProxy::DeathRecipientAddrInfo::GetNewSoPath()
{
    if (soFuncAddr_ == nullptr) {
        ZLOGE(LABEL, "empty function addr");
        return "";
    }

    Dl_info info;
    int32_t ret = dladdr(soFuncAddr_, &info);
    if ((ret == 0) || (info.dli_fname == nullptr)) {
        ZLOGE(LABEL, "dladdr failed ret:%{public}d", ret);
        return "";
    }
    return info.dli_fname;
}

bool IPCObjectProxy::DeathRecipientAddrInfo::IsDlclosed()
{
    std::string newSoPath = GetNewSoPath();
    if (newSoPath.empty() || (newSoPath != soPath_)) {
        return true;
    }
    return false;
}
} // namespace OHOS
