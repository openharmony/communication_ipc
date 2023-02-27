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
#include "rpc_feature_set.h"
#endif

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
using namespace IPC_SINGLE;
#endif

static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "IPCObjectProxy" };

IPCObjectProxy::IPCObjectProxy(int handle, std::u16string descriptor, int proto)
    : IRemoteObject(std::move(descriptor)), handle_(handle), proto_(proto), isFinishInit_(false), isRemoteDead_(false)
{
}

IPCObjectProxy::~IPCObjectProxy()
{
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
    if (!remoteDescriptor_.empty()) {
        return remoteDescriptor_;
    }
    if (handle_ == 0) {
        ZLOGD(LABEL, "handle == 0, do nothing");
        return std::u16string();
    }

    MessageParcel data, reply;
    MessageOption option;

    int32_t err = SendRequestInner(false, INTERFACE_TRANSACTION, data, reply, option);
    if (err != ERR_NONE) {
        ZLOGE(LABEL, "INTERFACE_TRANSACTION transact return error = %{public}d", err);
        return std::u16string();
    }
    remoteDescriptor_ = reply.ReadString16();

    return remoteDescriptor_;
}

std::string IPCObjectProxy::GetPidAndUidInfo(int32_t systemAbilityId)
{
    MessageParcel data, reply;
    MessageOption option;

    data.WriteInt32(systemAbilityId);
    int32_t err = SendRequestInner(false, GET_UIDPID_INFO, data, reply, option);
    if (err != ERR_NONE) {
        ZLOGE(LABEL, "GetPidAndUidInfo SendRequestInner return error = %{public}d", err);
        return std::string("");
    }
    return reply.ReadString();
}

std::string IPCObjectProxy::GetDataBusName(int32_t systemAbilityId)
{
    MessageParcel data, reply;
    MessageOption option;

    data.WriteInt32(systemAbilityId);
    int32_t err = SendRequestInner(false, GRANT_DATABUS_NAME, data, reply, option);
    if (err != ERR_NONE) {
        ZLOGE(LABEL, "GetDataBusName transact return error = %{public}d", err);
        return std::string("");
    }

    if (reply.ReadUint32() != IRemoteObject::IF_PROT_DATABUS) {
        ZLOGE(LABEL, "GetDataBusName normal binder");
        return std::string("");
    }

    return reply.ReadString();
}

std::string IPCObjectProxy::TransDataBusName(uint32_t uid, uint32_t pid)
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
    int32_t err = SendRequestInner(false, TRANS_DATABUS_NAME, data, reply, option);
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

void IPCObjectProxy::OnFirstStrongRef(const void *objectId)
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
    if (invoker != nullptr) {
        invoker->AcquireHandle(handle_);
    }
}

void IPCObjectProxy::WaitForInit()
{
    {
        std::lock_guard<std::mutex> lockGuard(initMutex_);
        if (IsObjectDead()) {
            ZLOGW(LABEL, "check a dead proxy, init again");
            isRemoteDead_ = false;
            isFinishInit_ = false;
        }

        // check again is this object been initialized
        if (isFinishInit_) {
#ifndef CONFIG_IPC_SINGLE
            if (proto_ == IRemoteObject::IF_PROT_DATABUS) {
                if (!CheckHaveSession()) {
                    SetProto(IRemoteObject::IF_PROT_ERROR);
                    isRemoteDead_ = true;
                }
            }
#endif
            return;
        }
#ifndef CONFIG_IPC_SINGLE
        if (UpdateProto() == IRemoteObject::IF_PROT_ERROR) {
            ZLOGE(LABEL, "UpdateProto get IF_PROT_ERROR");
            isRemoteDead_ = true;
        }
#endif
        isFinishInit_ = true;
    }
#ifndef CONFIG_IPC_SINGLE
    if (proto_ == IRemoteObject::IF_PROT_DATABUS) {
        int32_t errcode = IncRefToRemote();
        if (errcode != ERR_NONE) {
            SetProto(IRemoteObject::IF_PROT_ERROR);
            isRemoteDead_ = true;
        }
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
    if (current->DetachObject(this) == false) { // if detach successfully, this proxy will be destroyed
        return;
    }
#ifndef CONFIG_IPC_SINGLE
    ReleaseProto();
    std::shared_ptr<DBinderSessionObject> session = nullptr;
    session = current->ProxyQueryDBinderSession(handle_);
    (void)current->ProxyDetachDBinderSession(handle_);
    (void)current->DetachHandleToIndex(handle_);
#endif
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
        ZLOGW(LABEL, "%s: proxy is already dead", __func__);
        return false;
    }

    bool registerRecipient = false;
    if (recipients_.empty()) {
        registerRecipient = true;
    }
    recipients_.push_back(recipient);

    if (!registerRecipient || handle_ >= IPCProcessSkeleton::DBINDER_HANDLE_BASE) {
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
#ifndef BUILD_PUBLIC_VERSION
        if (!status) {
            ZLOGE(LABEL, "failed to add dbinder death recipient");
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
        ZLOGD(LABEL, "%s: death recipient is already unregistered", __func__);
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
    std::vector<sptr<DeathRecipient>> deathCallback;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        ZLOGW(LABEL, "%{public}s: enter, handle: %{public}d", __func__, handle_);
        MarkObjectDied();
        deathCallback = recipients_;
        IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
        if (recipients_.size() > 0 && invoker != nullptr) {
            invoker->RemoveDeathRecipient(handle_, this);
        }
        recipients_.clear();
    }
    for (auto &deathRecipient : deathCallback) {
        ZLOGW(LABEL, "%{public}s: handle = %{public}u call OnRemoteDied", __func__, handle_);
        if (deathRecipient != nullptr) {
            deathRecipient->OnRemoteDied(this);
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
    ZLOGW(LABEL, "%{public}s: handle: %{public}d", __func__, handle_);
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

int32_t IPCObjectProxy::IncRefToRemote()
{
    MessageParcel data, reply;
    MessageOption option;

    int32_t err = SendRequestInner(false, DBINDER_INCREFS_TRANSACTION, data, reply, option);
    if (err != ERR_NONE) {
        ZLOGE(LABEL, "DBINDER_INCREFS_TRANSACTION transact return error = %{public}d", err);
    }
    return err;
}


void IPCObjectProxy::ReleaseProto()
{
    ReleaseDatabusProto();
}

void IPCObjectProxy::SetProto(int proto)
{
    proto_ = proto;
}

int IPCObjectProxy::GetSessionFromDBinderService()
{
    MessageParcel data, reply;
    MessageOption option;

    if (CheckHaveSession()) {
        ZLOGE(LABEL, "GetSessionFromDBinderService CheckHaveSession success");
        return IRemoteObject::IF_PROT_DATABUS;
    }
    if (handle_ >= IPCProcessSkeleton::DBINDER_HANDLE_BASE) {
        ZLOGE(LABEL, "cannot find session for handle:%{public}u", handle_);
        return IRemoteObject::IF_PROT_ERROR;
    }

    int32_t err = SendRequestInner(true, GET_PROTO_INFO, data, reply, option);
    if (err != ERR_NONE) {
        ZLOGE(LABEL, "GET_PROTO_INFO transact return error = %{public}d", err);
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
            ZLOGE(LABEL, "GetSessionFromDBinderService Invalid Type");
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
        ZLOGE(LABEL, "%s: get current fail", __func__);
        return false;
    }

    if (current->QueryCallbackStub(this) != nullptr) {
        ZLOGW(LABEL, "%s: already attach callback stub", __func__);
        return true;
    }

    sptr<IPCObjectStub> callbackStub = new (std::nothrow) IPCObjectStub(descriptor_);
    if (callbackStub == nullptr) {
        ZLOGE(LABEL, "create IPCObjectStub object failed");
        return false;
    }
    if (!current->AttachCallbackStub(this, callbackStub)) {
        ZLOGW(LABEL, "%s: already attach new callback stub", __func__);
        return false;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    data.WriteInt32(IRemoteObject::DeathRecipient::ADD_DEATH_RECIPIENT);
    data.WriteRemoteObject(callbackStub);
    data.WriteString(current->GetDatabusName());

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

bool IPCObjectProxy::CheckHaveSession()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "IPCProcessSkeleton is null, set type as binder");
        return false;
    }

    std::shared_ptr<DBinderSessionObject> session = current->ProxyQueryDBinderSession(handle_);
    if (session == nullptr) {
        return false;
    }

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
    uint32_t rpcFeatureSet = reply.ReadUint32();
    uint32_t tokenId = 0;
    if (IsATEnable(rpcFeatureSet) == true) {
        tokenId = RpcGetSelfTokenID();
    }
    std::shared_ptr<FeatureSetData> featureSet = nullptr;
    featureSet.reset(reinterpret_cast<FeatureSetData *>(::operator new(sizeof(FeatureSetData))));
    if (featureSet == nullptr) {
        ZLOGE(LABEL, "%s: featureSet null", __func__);
        return false;
    }
    featureSet->featureSet = rpcFeatureSet;
    featureSet->tokenId = tokenId;

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
    connectSession->SetFeatureSet(featureSet);

    if (!current->AttachHandleToIndex((uint32_t)handle, stubIndex)) {
        ZLOGE(LABEL, "add stub index err stubIndex = %" PRIu64 ", handle = %d", stubIndex, handle);
        return false;
    }

    if (!current->CreateSoftbusServer(localBusName)) {
        ZLOGE(LABEL, "create bus server fail name = %s, localID = %s", localBusName.c_str(), localID.c_str());
        return false;
    }

    bool result = invoker->UpdateClientSession(handle, connectSession);
    return result;
}

void IPCObjectProxy::ReleaseDatabusProto()
{
    if (handle_ == 0) {
        ZLOGD(LABEL, "%s:handle == 0, do nothing", __func__);
        return;
    }

    if (proto_ != IRemoteObject::IF_PROT_DATABUS) {
        return;
    }

    MessageParcel data, reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    int32_t err = SendRequestInner(false, DBINDER_DECREFS_TRANSACTION, data, reply, option);
    if (err != ERR_NONE) {
        ZLOGW(LABEL, "DBINDER_DECREFS_TRANSACTION transact return error = %{public}d", err);
        // do nothing
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "release proto current is null");
        return;
    }
    std::shared_ptr<DBinderSessionObject> toBeDelete = current->ProxyQueryDBinderSession(handle_);
    if (toBeDelete != nullptr &&
        current->QuerySessionByInfo(toBeDelete->GetServiceName(), toBeDelete->GetDeviceId()) != nullptr) {
            toBeDelete->CloseDatabusSession();
        }
}

void IPCObjectProxy::ReleaseBinderProto()
{
    // do nothing
}
#endif
} // namespace OHOS
