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

#include "dbinder_error_code.h"
#include "ipc_types.h"
#include "ipc_debug.h"
#include "ipc_thread_skeleton.h"
#include "ipc_process_skeleton.h"
#include "log_tags.h"
#include "securec.h"

#ifndef CONFIG_IPC_SINGLE
#include "dbinder_databus_invoker.h"
#endif

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
using namespace IPC_SINGLE;
#endif

static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "IPCObjectProxy" };
IPCObjectProxy::IPCObjectProxy(int handle, std::u16string descriptor, int proto)
    : IRemoteObject(std::move(descriptor)), handle_(handle), proto_(proto), isFinishInit_(false), isRemoteDead_(false)
{}

IPCObjectProxy::~IPCObjectProxy()
{
    ZLOGW(LABEL, "handle = %{public}u destroyed", handle_);
}

int32_t IPCObjectProxy::GetObjectRefCount()
{
    MessageParcel dummy, reply;
    MessageOption option;
    option.SetFlags(MessageOption::TF_SYNC);
    if (SendRequestInner(false, SYNCHRONIZE_REFERENCE, dummy, reply, option) == ERR_NONE) {
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
        ZLOGE(LABEL, "%s: null invoker, type = %d", __func__, proto_);
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
    std::lock_guard<std::mutex> lockGuard(initMutex_);
    if (!remoteDescriptor_.empty()) {
        return remoteDescriptor_;
    }
    if (handle_ == 0) {
        ZLOGI(LABEL, "handle == 0, do nothing");
        return std::u16string();
    }

    MessageParcel data, reply;
    MessageOption option;

    uint32_t err = SendRequestInner(false, INTERFACE_TRANSACTION, data, reply, option);
    if (err != ERR_NONE) {
        ZLOGE(LABEL, "INTERFACE_TRANSACTION transact return error = %{public}u", err);
        return std::u16string();
    }
    remoteDescriptor_ = reply.ReadString16();

    return remoteDescriptor_;
}

std::string IPCObjectProxy::GetPidAndUidInfo()
{
    MessageParcel data, reply;
    MessageOption option;

    uint32_t err = SendRequestInner(false, GET_UIDPID_INFO, data, reply, option);
    if (err != ERR_NONE) {
        ZLOGE(LABEL, "GetPidAndUidInfo SendRequestInner return error = %{public}u", err);
        return std::string("");
    }
    return reply.ReadString();
}

std::string IPCObjectProxy::GetDataBusName()
{
    MessageParcel data, reply;
    MessageOption option;

    uint32_t err = SendRequestInner(false, GRANT_DATABUS_NAME, data, reply, option);
    if (err != ERR_NONE) {
        ZLOGE(LABEL, "GetDataBusName transact return error = %{public}u", err);
        return std::string("");
    }

    if (reply.ReadUint32() != IRemoteObject::IF_PROT_DATABUS) {
        ZLOGE(LABEL, "GetDataBusName normal binder");
        return std::string("");
    }

    return reply.ReadString();
}

void IPCObjectProxy::OnFirstStrongRef(const void *objectId)
{
    return WaitForInit();
}

void IPCObjectProxy::WaitForInit()
{
#ifndef CONFIG_IPC_SINGLE
    int type = 0;
#endif

    {
        bool acquire = true;
        std::lock_guard<std::mutex> lockGuard(initMutex_);
        if (IsObjectDead()) {
            ZLOGI(LABEL, "check a dead proxy, init again");
            isRemoteDead_ = false;
            isFinishInit_ = false;
            acquire = false;
        }

        // check again is this object been initialized
        if (isFinishInit_) {
            return;
        }
        IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
        if (invoker != nullptr && acquire == true) {
            invoker->AcquireHandle(handle_);
        }
#ifndef CONFIG_IPC_SINGLE
        type = UpdateProto();
#endif
        isFinishInit_ = true;
    }
#ifndef CONFIG_IPC_SINGLE
    if (type == IRemoteObject::IF_PROT_DATABUS) {
        IncRefToRemote();
    }
#endif
}

void IPCObjectProxy::OnLastStrongRef(const void *objectId)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "OnLastStrongRef current is null");
        return;
    }

    if (current->DetachObject(this)) {
        IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
        if (invoker != nullptr) {
            invoker->ReleaseHandle(handle_);
        }
    }
#ifndef CONFIG_IPC_SINGLE
    ReleaseProto();
#endif
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
        ZLOGI(LABEL, "%s: proxy is already dead", __func__);
        return false;
    }

    bool registerRecipient = false;
    if (recipients_.empty()) {
        registerRecipient = true;
    }
    recipients_.push_back(recipient);

    if (!registerRecipient || handle_ >= IPCProcessSkeleton::DBINDER_HANDLE_BASE) {
        ZLOGI(LABEL, "%s: death recipient is already registered", __func__);
        return true;
    }

    IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
    if (invoker == nullptr) {
        ZLOGE(LABEL, "%s : invoker is null", __func__);
        return false;
    }

    /* 1. Subscribe to death notifications, whether the stub comes from kernel or remote;
     * 2. Subscribe to additional death notifications, if remote object.
     * If step 1 is failed, do not execute step 2 and return false directly.
     * If step 1 is successful but step 2 is failed, return false.
     */
    bool status = invoker->AddDeathRecipient(handle_, this);
    if (!status) {
        ZLOGE(LABEL, "%s: fail to add binder death recipient, status = %d", __func__, status);
#ifndef BUILD_PUBLIC_VERSION
        ReportDriverEvent(DbinderErrorCode::COMMON_DRIVER_ERROR, DbinderErrorCode::ERROR_TYPE,
            DbinderErrorCode::IPC_DRIVER, DbinderErrorCode::ERROR_CODE, DbinderErrorCode::SET_DEATH_RECIPIENT_FAILURE);
#endif
        return status;
    }
#ifndef CONFIG_IPC_SINGLE
    if (proto_ == IRemoteObject::IF_PROT_DATABUS) {
        status = AddDbinderDeathRecipient();
        ZLOGE(LABEL, "%s: fail to add dbinder death recipient, status = %d", __func__, status);
#ifndef BUILD_PUBLIC_VERSION
        if (!status) {
            ReportDriverEvent(DbinderErrorCode::COMMON_DRIVER_ERROR, DbinderErrorCode::ERROR_TYPE,
                DbinderErrorCode::RPC_DRIVER, DbinderErrorCode::ERROR_CODE,
                DbinderErrorCode::SET_DEATH_RECIPIENT_FAILURE);
        }
#endif
    }
#endif
    return status;
}

bool IPCObjectProxy::RemoveDeathRecipient(const sptr<DeathRecipient> &recipient)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    bool removeRecipient = false;

    if (!IsObjectDead()) {
        auto it = find(recipients_.begin(), recipients_.end(), recipient);
        if (it != recipients_.end()) {
            recipients_.erase(it);
            removeRecipient = true;
        }

        if (!recipients_.empty()) {
            removeRecipient = false;
        }
    }

    if ((handle_ >= IPCProcessSkeleton::DBINDER_HANDLE_BASE) && (removeRecipient == true)) {
        ZLOGI(LABEL, "%s: death recipient is already unregistered", __func__);
        return true;
    }

    if (removeRecipient) {
        IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
        if (invoker == nullptr) {
            ZLOGE(LABEL, "%s : invoker is null", __func__);
            return false;
        }

        bool dbinderStatus = true;
        bool binderStatus = invoker->RemoveDeathRecipient(handle_, this);
#ifndef CONFIG_IPC_SINGLE
        if (proto_ == IRemoteObject::IF_PROT_DATABUS) {
            dbinderStatus = RemoveDbinderDeathRecipient();
        }
#endif
        if (binderStatus && dbinderStatus) {
            return true;
        }
    }

    return false;
}

void IPCObjectProxy::SendObituary()
{
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        MarkObjectDied();
        int recipientCount = recipients_.size();
        for (int i = 0; i < recipientCount; i++) {
            sptr<DeathRecipient> recipient = recipients_[i];
            ZLOGW(LABEL, "%s: handle = %{public}u call OnRemoteDied", __func__, handle_);
            recipient->OnRemoteDied(this);
        }
        recipients_.clear();

        if (recipientCount > 0) {
            IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
            if (invoker != nullptr) {
                invoker->RemoveDeathRecipient(handle_, this);
            }
        }
    }
#ifndef CONFIG_IPC_SINGLE
    if (proto_ == IRemoteObject::IF_PROT_DATABUS) {
        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            ZLOGE(LABEL, "%s: get current fail", __func__);
            return;
        }

        current->DetachCallbackStubByProxy(this);
    }
#endif
}

int IPCObjectProxy::GetProto() const
{
    return proto_;
}

int32_t IPCObjectProxy::NoticeServiceDie()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    data.WriteInt32(IRemoteObject::DeathRecipient::NOTICE_DEATH_RECIPIENT);

    int status = SendLocalRequest(DBINDER_OBITUARY_TRANSACTION, data, reply, option);
    if (status != ERR_NONE || reply.ReadInt32() != ERR_NONE) {
        ZLOGE(LABEL, "%s: send local request fail, status = %d", __func__, status);
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
    int type = GetSessionFromDBinderService();
    SetProto(type);
    return type;
}

void IPCObjectProxy::IncRefToRemote()
{
    MessageParcel data, reply;
    MessageOption option;

    int32_t err = SendRequestInner(false, DBINDER_INCREFS_TRANSACTION, data, reply, option);
    if (err != ERR_NONE) {
        ZLOGE(LABEL, "DBINDER_INCREFS_TRANSACTION transact return error = %{public}d", err);
        // do nothing
    }
}


void IPCObjectProxy::ReleaseProto()
{
    switch (GetProto()) {
        case IRemoteObject::IF_PROT_BINDER: {
            ZLOGW(LABEL, "it is normal binder, try to delete handle to index");
            ReleaseBinderProto();
            break;
        }
        case IRemoteObject::IF_PROT_DATABUS: {
            ReleaseDatabusProto();
            break;
        }
        default: {
            ZLOGE(LABEL, "ReleaseProto Invalid Type");
            break;
        }
    }

    return;
}

void IPCObjectProxy::SetProto(int proto)
{
    proto_ = proto;
}

int IPCObjectProxy::GetSessionFromDBinderService()
{
    MessageParcel data, reply;
    MessageOption option;
    uint32_t type = IRemoteObject::IF_PROT_BINDER;

    if (CheckHaveSession(type)) {
        ZLOGE(LABEL, "GetSessionFromDBinderService type = %u", type);
        return type;
    }

    uint32_t err = SendRequestInner(true, GET_PROTO_INFO, data, reply, option);
    if (err != ERR_NONE) {
        ZLOGI(LABEL, "GET_PROTO_INFO transact return error = %{public}u", err);
        return IRemoteObject::IF_PROT_BINDER;
    }

    switch (reply.ReadUint32()) {
        case IRemoteObject::IF_PROT_BINDER: {
            ZLOGW(LABEL, "it is normal binder, not dbinder");
            break;
        }
        case IRemoteObject::IF_PROT_DATABUS: {
            if (UpdateDatabusClientSession(handle_, reply)) {
                ZLOGW(LABEL, "it is dbinder, not binder");
                return IRemoteObject::IF_PROT_DATABUS;
            }
            break;
        }
        default: {
            ZLOGE(LABEL, "GetSessionFromDBinderService Invalid Type");
            break;
        }
    }

    return IRemoteObject::IF_PROT_BINDER;
}

bool IPCObjectProxy::AddDbinderDeathRecipient()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "%s: get current fail", __func__);
        return false;
    }

    if (current->QueryCallbackStub(this) != nullptr) {
        ZLOGW(LABEL, "%s: already attach callback stub", __func__);
        return true;
    }

    sptr<IPCObjectStub> callbackStub = new IPCObjectStub(descriptor_);
    if (!current->AttachCallbackStub(this, callbackStub)) {
        ZLOGW(LABEL, "%s: already attach new callback stub", __func__);
        return false;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    data.WriteInt32(IRemoteObject::DeathRecipient::ADD_DEATH_RECIPIENT);
    data.WriteRemoteObject(callbackStub);

    int err = SendLocalRequest(DBINDER_OBITUARY_TRANSACTION, data, reply, option);
    if (err != ERR_NONE || reply.ReadInt32() != ERR_NONE) {
        ZLOGE(LABEL, "%s: send local request fail, err = %d", __func__, err);
        (void)current->DetachCallbackStubByProxy(this);
        return false;
    }

    return true;
}

bool IPCObjectProxy::RemoveDbinderDeathRecipient()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "%s: get current fail", __func__);
        return false;
    }

    sptr<IPCObjectStub> callbackStub = current->QueryCallbackStub(this);
    if (callbackStub == nullptr) {
        ZLOGE(LABEL, "%s: get callbackStub fail", __func__);
        return false;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    data.WriteInt32(IRemoteObject::DeathRecipient::REMOVE_DEATH_RECIPIENT);
    data.WriteRemoteObject(callbackStub);

    int err = SendLocalRequest(DBINDER_OBITUARY_TRANSACTION, data, reply, option);
    if (err != ERR_NONE || reply.ReadInt32() != ERR_NONE) {
        ZLOGE(LABEL, "%s: send local request fail, err = %d", __func__, err);
        // do nothing, even send request failed
    }

    return current->DetachCallbackStubByProxy(this);
}

bool IPCObjectProxy::CheckHaveSession(uint32_t &type)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "IPCProcessSkeleton is null, set type as binder");
        return false;
    }

    std::shared_ptr<DBinderSessionObject> session = current->ProxyQueryDBinderSession(handle_);
    if (session == nullptr) {
        ZLOGW(LABEL, "no databus session attach to this handle, maybe need update");
        return false;
    }
    type = IRemoteObject::IF_PROT_DATABUS;
    return true;
}

bool IPCObjectProxy::UpdateDatabusClientSession(int handle, MessageParcel &reply)
{
    DBinderDatabusInvoker *invoker =
        reinterpret_cast<DBinderDatabusInvoker *>(IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS));
    if (invoker == nullptr) {
        ZLOGE(LABEL, "%s: invoker null", __func__);
        return false;
    }

    uint64_t stubIndex = reply.ReadUint64();
    std::string serviceName = reply.ReadString();
    std::string peerID = reply.ReadString();
    std::string localID = reply.ReadString();
    std::string localBusName = reply.ReadString();

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "%s:current process skeleton is nullptr", __func__);
        return false;
    }

    std::shared_ptr<DBinderSessionObject> connectSession = current->QuerySessionByInfo(serviceName, peerID);
    if (connectSession == nullptr) {
        connectSession = std::make_shared<DBinderSessionObject>(nullptr, serviceName, peerID);
        if (connectSession == nullptr) {
            ZLOGE(LABEL, "new server session fail!");
            return false;
        }
    }

    if (!current->AttachHandleToIndex(handle, stubIndex)) {
        ZLOGE(LABEL, "add stub index err stubIndex = %" PRIu64 ", handle = %d", stubIndex, handle);
        return false;
    }

    if (!current->CreateSoftbusServer(localBusName)) {
        ZLOGE(LABEL, "create bus server fail name = %s, localID = %s", localBusName.c_str(), localID.c_str());
        return false;
    }

    bool result = invoker->UpdateClientSession(handle, connectSession);
    if (!result) {
        ZLOGE(LABEL, "update server session object fail!");
        return false;
    }

    return true;
}

void IPCObjectProxy::ReleaseDatabusProto()
{
    if (handle_ == 0) {
        ZLOGI(LABEL, "%s:handle == 0, do nothing", __func__);
        return;
    }

    if (GetProto() != IRemoteObject::IF_PROT_DATABUS) {
        ZLOGI(LABEL, "not databus dbinder, need do nothing");
        return;
    }

    MessageParcel data, reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    uint32_t err = SendRequestInner(false, DBINDER_DECREFS_TRANSACTION, data, reply, option);
    if (err != ERR_NONE) {
        ZLOGE(LABEL, "DBINDER_DECREFS_TRANSACTION transact return error = %{public}u", err);
        // do nothing
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "release proto current is null");
        return;
    }

    (void)current->ProxyDetachDBinderSession(handle_);
    (void)current->DetachHandleToIndex(handle_);
    return;
}

void IPCObjectProxy::ReleaseBinderProto()
{
    if (handle_ == 0) {
        ZLOGI(LABEL, "%s:handle == 0, do nothing", __func__);
        return;
    }

    if (GetProto() != IRemoteObject::IF_PROT_BINDER) {
        ZLOGI(LABEL, "not binder proxy, need do nothing");
        return;
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "release proto current is null");
        return;
    }

    (void)current->DetachHandleToIndex(handle_);
    return;
}
#endif
} // namespace OHOS
