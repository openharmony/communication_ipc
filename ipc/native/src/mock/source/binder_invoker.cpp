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

#include "binder_invoker.h"

#include <chrono>
#include <csignal>
#include <securec.h>

#include "access_token_adapter.h"
#include "binder_debug.h"
#include "hilog/log.h"
#include "hitrace_invoker.h"
#include "ipc_object_proxy.h"
#include "ipc_object_stub.h"
#include "ipc_process_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "log_tags.h"
#include "string_ex.h"
#include "sys_binder.h"
#ifdef FFRT_IPC_ENABLE
#include "c/ffrt_ipc.h"
#endif

#if defined(__arm__) || defined(__aarch64__)
#define TLS_SLOT_MIGRATION_DISABLE_COUNT (-10)
class ThreadMigrationDisabler {
    unsigned long *GetTls()
    {
        unsigned long *tls = nullptr;
#ifdef __aarch64__
        asm("mrs %0, tpidr_el0" : "=r"(tls));
#else
        asm("mrc p15, 0, %0, c13, c0, 3" : "=r"(tls));
#endif
        return tls;
    }

public:
    ThreadMigrationDisabler()
    {
        GetTls()[TLS_SLOT_MIGRATION_DISABLE_COUNT]++;
    }
    ~ThreadMigrationDisabler()
    {
        GetTls()[TLS_SLOT_MIGRATION_DISABLE_COUNT]--;
    }
};
#else
class ThreadMigrationDisabler {};
#endif

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
namespace IPC_SINGLE {
#endif

#define PIDUID_OFFSET 2

using namespace OHOS::HiviewDFX;
static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC_BINDER_INVOKER, "BinderInvoker" };
enum {
    GET_SERVICE_TRANSACTION = 0x1,
    CHECK_SERVICE_TRANSACTION,
    ADD_SERVICE_TRANSACTION,
};

BinderInvoker::BinderInvoker()
    : isMainWorkThread(false), stopWorkThread(false), callerPid_(getpid()),
    callerRealPid_(getprocpid()), callerUid_(getuid()),
    callerTokenID_(0), firstTokenID_(0), callerSid_(""), status_(0)
{
    invokerInfo_ = { callerPid_, callerRealPid_, callerUid_, callerTokenID_, firstTokenID_, callerSid_,
        reinterpret_cast<uintptr_t>(this) };
    input_.SetDataCapacity(IPC_DEFAULT_PARCEL_SIZE);
    binderConnector_ = BinderConnector::GetInstance();
    ZLOGD(LABEL, "created %{public}zu", reinterpret_cast<uintptr_t>(this));
}

BinderInvoker::~BinderInvoker()
{
    ZLOGD(LABEL, "destroyed %{public}zu", reinterpret_cast<uintptr_t>(this));
    auto current = ProcessSkeleton::GetInstance();
    if (current != nullptr) {
        current->DetachInvokerProcInfo(true);
    }
}

bool BinderInvoker::AcquireHandle(int32_t handle)
{
    size_t rewindPos = output_.GetWritePosition();
    if (!output_.WriteUint32(BC_ACQUIRE)) {
        return false;
    }

    if (!output_.WriteInt32(handle)) {
        if (!output_.RewindWrite(rewindPos)) {
            output_.FlushBuffer();
        }
        return false;
    }
    /* invoke remote to receive acquire handle event, don't care ping result */
    if (handle != 0) {
        (void)FlushCommands(nullptr);
    }
    ZLOGD(LABEL, "handle:%{public}d", handle);
    return true;
}

bool BinderInvoker::ReleaseHandle(int32_t handle)
{
    size_t rewindPos = output_.GetWritePosition();
    if (!output_.WriteUint32(BC_RELEASE)) {
        return false;
    }

    if (!output_.WriteInt32(handle)) {
        if (!output_.RewindWrite(rewindPos)) {
            output_.FlushBuffer();
        }
        return false;
    }
    FlushCommands(nullptr);
    ZLOGD(LABEL, "handle:%{public}d", handle);
    return true;
}

int BinderInvoker::SendRequest(int handle, uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    int error = ERR_NONE;
    uint32_t flags = static_cast<uint32_t>(option.GetFlags());
    MessageParcel &newData = const_cast<MessageParcel &>(data);
    size_t oldWritePosition = newData.GetWritePosition();
    HiTraceId traceId = HiTraceChain::GetId();
    // set client send trace point if trace is enabled
    HiTraceId childId = HitraceInvoker::TraceClientSend(handle, code, newData, flags, traceId);

    if (!TranslateDBinderProxy(handle, data)) {
        return IPC_INVOKER_WRITE_TRANS_ERR;
    }
    if (!WriteTransaction(BC_TRANSACTION, flags, handle, code, data, nullptr)) {
        newData.RewindWrite(oldWritePosition);
        ZLOGE(LABEL, "WriteTransaction ERROR");
        return IPC_INVOKER_WRITE_TRANS_ERR;
    }

    if ((flags & TF_ONE_WAY) != 0) {
        error = WaitForCompletion(nullptr);
    } else {
#ifdef FFRT_IPC_ENABLE
        ffrt_this_task_set_legacy_mode(true);
#endif
        error = WaitForCompletion(&reply);
#ifdef FFRT_IPC_ENABLE
        ffrt_this_task_set_legacy_mode(false);
#endif
    }
    HitraceInvoker::TraceClientReceieve(handle, code, flags, traceId, childId);
    // restore Parcel data
    newData.RewindWrite(oldWritePosition);
    return error;
}

bool BinderInvoker::TranslateDBinderProxy(int handle, MessageParcel &parcel)
{
    uintptr_t dataOffset = parcel.GetData();
    binder_size_t *objOffset = reinterpret_cast<binder_size_t *>(parcel.GetObjectOffsets());
    for (size_t i = 0; i < parcel.GetOffsetsSize(); i++) {
        auto flat = reinterpret_cast<flat_binder_object *>(dataOffset + *(objOffset + i));
#ifdef CONFIG_IPC_SINGLE
        if (flat->hdr.type == BINDER_TYPE_HANDLE && flat->cookie != IRemoteObject::IF_PROT_BINDER) {
            ZLOGE(LABEL, "sending a dbinder proxy in ipc_single.z.so is not allowed");
            return false;
        }
#else
        if (flat->hdr.type == BINDER_TYPE_HANDLE && flat->cookie == IRemoteObject::IF_PROT_DATABUS
            && flat->handle < IPCProcessSkeleton::DBINDER_HANDLE_BASE) {
            if (!AddCommAuth(handle, flat)) {
                return false;
            }
        }
#endif
    }
    return true;
}

bool BinderInvoker::AddDeathRecipient(int32_t handle, void *cookie)
{
    ZLOGD(LABEL, "for handle:%{public}d", handle);
    size_t rewindPos = output_.GetWritePosition();
    if (!output_.WriteInt32(BC_REQUEST_DEATH_NOTIFICATION)) {
        ZLOGE(LABEL, "fail to write command field, handle:%{public}d", handle);
        return false;
    }

    if (!output_.WriteInt32(handle)) {
        if (!output_.RewindWrite(rewindPos)) {
            output_.FlushBuffer();
        }
        return false;
    }

    if (!output_.WritePointer((uintptr_t)cookie)) {
        /* rewind written size notification and handle. */
        if (!output_.RewindWrite(rewindPos)) {
            output_.FlushBuffer();
        }
        return false;
    }

    // pass in nullptr directly
    int error = FlushCommands(nullptr);
    if (error == ERR_NONE) {
        auto *proxy = reinterpret_cast<IPCObjectProxy *>(cookie);
        if (proxy != nullptr) {
            proxy->IncStrongRef(this);
        }
    }
    return error == ERR_NONE;
}

bool BinderInvoker::RemoveDeathRecipient(int32_t handle, void *cookie)
{
    size_t rewindPos = output_.GetWritePosition();
    if (!output_.WriteInt32(BC_CLEAR_DEATH_NOTIFICATION)) {
        return false;
    }

    if (!output_.WriteInt32(handle)) {
        if (!output_.RewindWrite(rewindPos)) {
            output_.FlushBuffer();
        }
        return false;
    }

    if (!output_.WritePointer((uintptr_t)cookie)) {
        if (!output_.RewindWrite(rewindPos)) {
            output_.FlushBuffer();
        }
        return false;
    }

    // pass in nullptr directly
    int error = FlushCommands(nullptr);
    if (error != ERR_NONE) {
        ZLOGE(LABEL, "failed, handle:%{public}d error:%{public}d", handle, error);
        return false;
    }

    return true;
}

#ifndef CONFIG_IPC_SINGLE
int BinderInvoker::TranslateIRemoteObject(int32_t cmd, const sptr<IRemoteObject> &obj)
{
    if ((binderConnector_ == nullptr) || (!binderConnector_->IsDriverAlive())) {
        return -IPC_INVOKER_CONNECT_ERR;
    }
    size_t rewindPos = output_.GetWritePosition();
    if (!output_.WriteInt32(cmd)) {
        if (!output_.RewindWrite(rewindPos)) {
            output_.FlushBuffer();
        }
        return -IPC_INVOKER_TRANSLATE_ERR;
    }
    if (!FlattenObject(output_, obj.GetRefPtr())) {
        if (!output_.RewindWrite(rewindPos)) {
            output_.FlushBuffer();
        }
        return -IPC_INVOKER_TRANSLATE_ERR;
    }
    MessageParcel reply;
    int error = WaitForCompletion(&reply);
    if (error == ERR_NONE) {
        uint32_t handle = reply.ReadUint32();
        if (handle > 0) {
            return handle;
        }
    }
    ZLOGE(LABEL, "failed to TranslateIRemoteObject");
    return -IPC_INVOKER_TRANSLATE_ERR;
}

sptr<IRemoteObject> BinderInvoker::GetSAMgrObject()
{
    ZLOGI(LABEL, "get samgr object!");
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current != nullptr) {
        return current->GetRegistryObject();
    }
    return nullptr;
}

bool BinderInvoker::AddCommAuth(int32_t handle, flat_binder_object *flat)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (SendRequest(handle, GET_PID_UID, data, reply, option) != ERR_NONE) {
        ZLOGE(LABEL, "get pid and uid failed");
        return false;
    }
    MessageParcel data2;
    MessageParcel reply2;
    MessageOption option2;
    data2.WriteUint32(reply.ReadUint32()); // pid
    data2.WriteUint32(reply.ReadUint32()); // uid
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "current is null");
        return false;
    }
    data2.WriteString(current->GetLocalDeviceID()); // deviceId
    std::shared_ptr<DBinderSessionObject> session = current->ProxyQueryDBinderSession(flat->handle);
    if (session == nullptr) {
        ZLOGE(LABEL, "no session found for handle:%{public}d", flat->handle);
        return false;
    }
    data2.WriteUint64(session->GetStubIndex()); // stubIndex
    data2.WriteUint32(session->GetTokenId()); // tokenId
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS);
    if (invoker == nullptr) {
        ZLOGE(LABEL, "invoker is null");
        return false;
    }
    if (invoker->SendRequest(flat->handle, DBINDER_ADD_COMMAUTH, data2, reply2, option2) != ERR_NONE) {
        ZLOGE(LABEL, "dbinder add auth info failed");
        return false;
    }
    return true;
}

#endif
bool BinderInvoker::SetMaxWorkThread(int maxThreadNum)
{
    if ((binderConnector_ == nullptr) || (!binderConnector_->IsDriverAlive())) {
        ZLOGE(LABEL, "driver died");
        return false;
    }

    int error = binderConnector_->WriteBinder(BINDER_SET_MAX_THREADS, &maxThreadNum);
    if (error != ERR_NONE) {
        ZLOGE(LABEL, "SetMaxWorkThread error:%{public}d", error);
        return false;
    }

    return true;
}

int BinderInvoker::FlushCommands(IRemoteObject *object)
{
    if ((binderConnector_ == nullptr) || (!binderConnector_->IsDriverAlive())) {
        ZLOGE(LABEL, "driver is died");
        return IPC_INVOKER_CONNECT_ERR;
    }
    int error = TransactWithDriver(false);
    if (error != ERR_NONE) {
        uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        ZLOGE(LABEL, "fail to flush commands with error:%{public}d time:%{public}" PRIu64, error, curTime);
    }

    if (output_.GetDataSize() > 0) {
        error = TransactWithDriver(false);
        ZLOGE(LABEL, "flush commands again with return value:%{public}d", error);
    }
    if (error != ERR_NONE || output_.GetDataSize() > 0) {
        ZLOGE(LABEL, "flush commands with error:%{public}d, left data size:%{public}zu", error,
            output_.GetDataSize());
    }

    return error;
}

void BinderInvoker::ExitCurrentThread()
{
    if ((binderConnector_ == nullptr) || (!binderConnector_->IsDriverAlive())) {
        ZLOGE(LABEL, "driver died when exit current thread");
        return;
    }
    binderConnector_->ExitCurrentThread(BINDER_THREAD_EXIT);
}

void BinderInvoker::StartWorkLoop()
{
    if ((binderConnector_ == nullptr) || (!binderConnector_->IsDriverAlive())) {
        ZLOGE(LABEL, "driver is died");
        return;
    }
    int error;
    do {
        error = TransactWithDriver();
        if (error < ERR_NONE && error != -ECONNREFUSED && error != -EBADF) {
            ZLOGE(LABEL, "returned unexpected error:%{public}d, aborting", error);
            break;
        }
        uint32_t cmd = input_.ReadUint32();
        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current != nullptr) {
            current->LockForNumExecuting();
        }
        int userError = HandleCommands(cmd);
        if (current != nullptr) {
            current->UnlockForNumExecuting();
        }
        if ((userError == -ERR_TIMED_OUT || userError == IPC_INVOKER_INVALID_DATA_ERR) && !isMainWorkThread) {
            ZLOGW(LABEL, "exit, userError:%{public}d", userError);
            break;
        }
    } while (error != -ECONNREFUSED && error != -EBADF && !stopWorkThread);
}

int BinderInvoker::SendReply(MessageParcel &reply, uint32_t flags, int32_t result)
{
    int error = WriteTransaction(BC_REPLY, flags, -1, 0, reply, &result);
    if (error < ERR_NONE) {
        return error;
    }

    return WaitForCompletion();
}

void BinderInvoker::OnBinderDied()
{
    ZLOGD(LABEL, "enter");
    uintptr_t cookie = input_.ReadPointer();
    auto *proxy = reinterpret_cast<IPCObjectProxy *>(cookie);
    if (proxy != nullptr) {
        ProcessSkeleton *current = ProcessSkeleton::GetInstance();
        DeadObjectInfo deadInfo;
        if ((current != nullptr) && current->IsDeadObject(proxy, deadInfo)) {
            ZLOGE(LABEL, "%{public}zu handle:%{public}d desc:%{public}s is deaded at time:%{public}" PRIu64,
                reinterpret_cast<uintptr_t>(proxy), deadInfo.handle,
                ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(deadInfo.desc)).c_str(), deadInfo.deadTime);
        } else {
            proxy->SendObituary();
        }
    }

    size_t rewindPos = output_.GetWritePosition();
    if (!output_.WriteInt32(BC_DEAD_BINDER_DONE)) {
        return;
    }

    if (!output_.WritePointer((uintptr_t)cookie)) {
        if (!output_.RewindWrite(rewindPos)) {
            output_.FlushBuffer();
        }
    }
}

void BinderInvoker::OnAcquireObject(uint32_t cmd)
{
    bool result = false;
    uintptr_t refsPointer = input_.ReadPointer();
    uintptr_t objectPointer = input_.ReadPointer();
    RefCounter *refs = reinterpret_cast<RefCounter *>(refsPointer);
    IRemoteObject *obj = reinterpret_cast<IRemoteObject *>(objectPointer);
    if ((obj == nullptr) || (refs == nullptr)) {
        ZLOGE(LABEL, "FAIL!");
        return;
    }
    ProcessSkeleton *current = ProcessSkeleton::GetInstance();
    DeadObjectInfo deadInfo;
    if ((current != nullptr) && current->IsDeadObject(obj, deadInfo)) {
        ZLOGE(LABEL, "%{public}zu desc:%{public}s is deaded at time:%{public}" PRIu64,
            reinterpret_cast<uintptr_t>(obj),
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(deadInfo.desc)).c_str(), deadInfo.deadTime);
        return;
    }

    size_t rewindPos = output_.GetWritePosition();
    if (cmd == BR_ACQUIRE) {
        obj->IncStrongRef(this);
        result = output_.WriteInt32(BC_ACQUIRE_DONE);
    } else {
        refs->IncWeakRefCount(this);
        result = output_.WriteInt32(BC_INCREFS_DONE);
    }

    if (!result || !output_.WritePointer(refsPointer)) {
        if (!output_.RewindWrite(rewindPos)) {
            output_.FlushBuffer();
        }
        return;
    }

    if (!output_.WritePointer(objectPointer)) {
        if (!output_.RewindWrite(rewindPos)) {
            output_.FlushBuffer();
        }
    }
}

void BinderInvoker::OnReleaseObject(uint32_t cmd)
{
    uintptr_t refsPointer = input_.ReadPointer();
    uintptr_t objectPointer = input_.ReadPointer();
    RefCounter *refs = reinterpret_cast<RefCounter *>(refsPointer);
    IRemoteObject *obj = reinterpret_cast<IRemoteObject *>(objectPointer);
    if ((refs == nullptr) || (obj == nullptr)) {
        ZLOGE(LABEL, "FAIL!");
        return;
    }

    ZLOGD(LABEL, "refcount:%{public}d refs:%{public}zu obj:%{public}zu", refs->GetStrongRefCount(),
        reinterpret_cast<uintptr_t>(refs), reinterpret_cast<uintptr_t>(obj));
    if (cmd == BR_RELEASE) {
        ProcessSkeleton *current = ProcessSkeleton::GetInstance();
        DeadObjectInfo deadInfo;
        if ((current != nullptr) && current->IsDeadObject(obj, deadInfo)) {
            ZLOGD(LABEL, "%{public}zu desc:%{public}s is deaded at time:%{public}" PRIu64,
                reinterpret_cast<uintptr_t>(obj),
                ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(deadInfo.desc)).c_str(), deadInfo.deadTime);
            return;
        }
        obj->DecStrongRef(this);
    } else {
        refs->DecWeakRefCount(this);
    }
}

void BinderInvoker::GetAccessToken(uint64_t &callerTokenID, uint64_t &firstTokenID)
{
    struct access_token token{};
    int error = binderConnector_->WriteBinder(BINDER_GET_ACCESS_TOKEN, &token);
    if (error != ERR_NONE) {
        token.sender_tokenid = 0;
        token.first_tokenid = 0;
    }
    callerTokenID = token.sender_tokenid;
    firstTokenID = token.first_tokenid;
}

void BinderInvoker::GetSenderInfo(uint64_t &callerTokenID, uint64_t &firstTokenID, pid_t &realPid)
{
    struct binder_sender_info sender{};
    int error = binderConnector_->WriteBinder(BINDER_GET_SENDER_INFO, &sender);
    if (error != ERR_NONE) {
        sender.tokens.sender_tokenid = 0;
        sender.tokens.first_tokenid = 0;
        sender.sender_pid_nr = 0;
    }
    callerTokenID = sender.tokens.sender_tokenid;
    firstTokenID = sender.tokens.first_tokenid;
    realPid = static_cast<pid_t>(sender.sender_pid_nr);
}

void BinderInvoker::RestoreInvokerProcInfo(const InvokerProcInfo &info)
{
    callerPid_ = info.pid;
    callerRealPid_ = info.realPid;
    callerUid_ = info.uid;
    callerTokenID_ = info.tokenId;
    firstTokenID_ = info.firstTokenId;
    callerSid_ = info.sid;
}

void BinderInvoker::AttachInvokerProcInfoWrapper()
{
    InvokerProcInfo invokerInfo = { callerPid_, callerRealPid_,
        callerUid_, callerTokenID_, firstTokenID_, callerSid_, reinterpret_cast<uintptr_t>(this) };
    auto current = ProcessSkeleton::GetInstance();
    if (current != nullptr) {
        current->AttachInvokerProcInfo(true, invokerInfo);
    }
}

int32_t BinderInvoker::SamgrServiceSendRequest(
    const binder_transaction_data &tr, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int error = ERR_DEAD_OBJECT;

    auto targetObject = IPCProcessSkeleton::GetCurrent()->GetRegistryObject();
    if (targetObject == nullptr) {
        ZLOGE(LABEL, "Invalid samgr stub object");
    } else {
        error = targetObject->SendRequest(tr.code, data, reply, option);
    }
    return error;
}

int32_t BinderInvoker::GeneralServiceSendRequest(
    const binder_transaction_data &tr, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int32_t error = ERR_DEAD_OBJECT;
    auto *refs = reinterpret_cast<RefCounter *>(tr.target.ptr);
    int count = 0;
    if ((refs != nullptr) && (tr.cookie) && (refs->AttemptIncStrongRef(this, count))) {
        auto *targetObject = reinterpret_cast<IPCObjectStub *>(tr.cookie);
        if (targetObject != nullptr) {
            DeadObjectInfo deadInfo;
            auto current = ProcessSkeleton::GetInstance();
            if ((current != nullptr) && current->IsDeadObject(targetObject, deadInfo)) {
                ZLOGE(LABEL, "%{public}zu desc:%{public}s is deaded at time:%{public}" PRIu64,
                    reinterpret_cast<uintptr_t>(targetObject),
                    ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(deadInfo.desc)).c_str(), deadInfo.deadTime);
            } else {
                error = targetObject->SendRequest(tr.code, data, reply, option);
                targetObject->DecStrongRef(this);
            }
        }
    }
    return error;
}

int32_t BinderInvoker::TargetStubSendRequest(const binder_transaction_data &tr,
    MessageParcel &data, MessageParcel &reply, MessageOption &option, uint32_t &flagValue)
{
#ifdef CONFIG_ACTV_BINDER
    bool oldActvBinder = GetUseActvBinder();
    SetUseActvBinder(false);
#endif

    int32_t error = ERR_DEAD_OBJECT;
    flagValue = static_cast<uint32_t>(tr.flags) & ~static_cast<uint32_t>(MessageOption::TF_ACCEPT_FDS);
    option.SetFlags(static_cast<int>(flagValue));
    if (tr.target.ptr != 0) {
        error = GeneralServiceSendRequest(tr, data, reply, option);
    } else {
        error = SamgrServiceSendRequest(tr, data, reply, option);
    }

#ifdef CONFIG_ACTV_BINDER
    SetUseActvBinder(oldActvBinder);
#endif
    return error;
}

void BinderInvoker::Transaction(binder_transaction_data_secctx& trSecctx)
{
    binder_transaction_data& tr = trSecctx.transaction_data;
    auto binderAllocator = new (std::nothrow) BinderAllocator();
    if (binderAllocator == nullptr) {
        ZLOGE(LABEL, "BinderAllocator Creation failed");
        return;
    }
    auto data = std::make_unique<MessageParcel>(binderAllocator);
    data->ParseFrom(tr.data.ptr.buffer, tr.data_size);
    if (tr.offsets_size > 0) {
        data->InjectOffsets(tr.data.ptr.offsets, tr.offsets_size / sizeof(binder_size_t));
    }
    uint32_t &newflags = const_cast<uint32_t &>(tr.flags);
    int isServerTraced = HitraceInvoker::TraceServerReceieve(static_cast<uint64_t>(tr.target.handle),
        tr.code, *data, newflags);
    InvokerProcInfo oldInvokerProcInfo = {
        callerPid_, callerRealPid_, callerUid_, callerTokenID_, firstTokenID_, callerSid_, 0 };
    uint32_t oldStatus = status_;

    callerSid_ = (trSecctx.secctx != 0) ? reinterpret_cast<char *>(trSecctx.secctx) : "";
    callerPid_ = tr.sender_pid;
    callerUid_ = tr.sender_euid;
    callerRealPid_ = callerPid_;
    if (binderConnector_ != nullptr && binderConnector_->IsRealPidSupported()) {
        GetSenderInfo(callerTokenID_, firstTokenID_, callerRealPid_);
    } else if (binderConnector_ != nullptr && binderConnector_->IsAccessTokenSupported()) {
        GetAccessToken(callerTokenID_, firstTokenID_);
    }
    // sync caller information to another binderinvoker
    AttachInvokerProcInfoWrapper();
    MessageParcel reply;
    MessageOption option;
    uint32_t flagValue;

    SetStatus(IRemoteInvoker::ACTIVE_INVOKER);
    int32_t error = TargetStubSendRequest(tr, *data, reply, option, flagValue);

    HitraceInvoker::TraceServerSend(static_cast<uint64_t>(tr.target.handle), tr.code, isServerTraced, newflags);
    if (!(flagValue & TF_ONE_WAY)) {
        SendReply(reply, 0, error);
    }

    RestoreInvokerProcInfo(oldInvokerProcInfo);
    // restore caller information to another binderinvoker
    AttachInvokerProcInfoWrapper();
    SetStatus(oldStatus);
}

void BinderInvoker::OnAttemptAcquire()
{
    bool success = false;
    uintptr_t refsPtr = input_.ReadPointer();
    uintptr_t objectPtr = input_.ReadPointer();
    auto *refs = reinterpret_cast<RefCounter *>(refsPtr);

    size_t rewindPos = output_.GetWritePosition();
    if ((refs != nullptr) && (!objectPtr)) {
        int count = 0;
        success = refs->AttemptIncStrongRef(this, count);
    }

    if (!output_.WriteUint32(BC_ACQUIRE_RESULT)) {
        return;
    }

    if (!output_.WriteUint32((uint32_t)success)) {
        if (!output_.RewindWrite(rewindPos)) {
            output_.FlushBuffer();
        }
    }
}

void BinderInvoker::OnRemoveRecipientDone()
{
    uintptr_t cookie = input_.ReadPointer();
    auto *proxy = reinterpret_cast<IPCObjectProxy *>(cookie);
    if (proxy != nullptr) {
        proxy->DecStrongRef(this);
    }
}

void BinderInvoker::OnSpawnThread()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current != nullptr) {
#ifdef CONFIG_ACTV_BINDER
        if (GetUseActvBinder()) {
            current->SpawnThread(IPCWorkThread::ACTV_PASSIVE);
        } else {
            current->SpawnThread();
        }
#else
        current->SpawnThread();
#endif
    }
}

void BinderInvoker::OnTransaction(int32_t cmd, int32_t &error)
{
    binder_transaction_data_secctx trSecctx = {
        .secctx = 0,
    };
    const uint8_t *buffer = nullptr;
    bool isSecctx = (cmd == static_cast<int32_t>(BR_TRANSACTION_SEC_CTX));
    uint32_t bufferSize = isSecctx ? sizeof(binder_transaction_data_secctx) : sizeof(binder_transaction_data);

    buffer = input_.ReadBuffer(bufferSize);
    if (buffer == nullptr) {
        error = IPC_INVOKER_INVALID_DATA_ERR;
        return;
    }

    if (isSecctx) {
        trSecctx = *(reinterpret_cast<const binder_transaction_data_secctx *>(buffer));
    } else {
        trSecctx.transaction_data = *(reinterpret_cast<const binder_transaction_data *>(buffer));
    }

    Transaction(trSecctx);
}

int BinderInvoker::HandleReply(MessageParcel *reply)
{
    const size_t readSize = sizeof(binder_transaction_data);
    const uint8_t *buffer = input_.ReadBuffer(readSize);
    if (buffer == nullptr) {
        ZLOGE(LABEL, "HandleReply read tr failed");
        return IPC_INVOKER_INVALID_DATA_ERR;
    }
    const binder_transaction_data *tr = reinterpret_cast<const binder_transaction_data *>(buffer);

    if (reply == nullptr) {
        ZLOGD(LABEL, "no need reply, free the buffer");
        FreeBuffer(reinterpret_cast<void *>(tr->data.ptr.buffer));
        return IPC_INVOKER_INVALID_REPLY_ERR;
    }

    if (tr->flags & TF_STATUS_CODE) {
        int32_t status = *reinterpret_cast<const int32_t *>(tr->data.ptr.buffer);
        ZLOGD(LABEL, "received status code:%{public}d, free the buffer", status);
        FreeBuffer(reinterpret_cast<void *>(tr->data.ptr.buffer));
        return status;
    }

    auto allocator = new (std::nothrow) BinderAllocator();
    if (allocator == nullptr) {
        ZLOGE(LABEL, "create BinderAllocator object failed");
        return IPC_INVOKER_INVALID_DATA_ERR;
    }
    if (!reply->SetAllocator(allocator)) {
        ZLOGD(LABEL, "SetAllocator failed");
        delete allocator;
        FreeBuffer(reinterpret_cast<void *>(tr->data.ptr.buffer));
        return IPC_INVOKER_INVALID_DATA_ERR;
    }
    reply->ParseFrom(tr->data.ptr.buffer, tr->data_size);

    if (tr->offsets_size > 0) {
        reply->InjectOffsets(tr->data.ptr.offsets, tr->offsets_size / sizeof(binder_size_t));
        reply->SetClearFdFlag();
    }

    return ERR_NONE;
}

int BinderInvoker::HandleCommandsInner(uint32_t cmd)
{
    int error = ERR_NONE;

    auto it = receiverCommandMap_.find(cmd);
    if (it != receiverCommandMap_.end()) {
        it->second(cmd, error);
    } else {
        error = IPC_INVOKER_ON_TRANSACT_ERR;
    }

    return error;
}

int BinderInvoker::HandleCommands(uint32_t cmd)
{
    auto start = std::chrono::steady_clock::now();
    bool isPrint = false;
    int error = HandleCommandsInner(cmd);
    if (error != ERR_NONE) {
        if (ProcessSkeleton::IsPrint(error, lastErr_, lastErrCnt_)) {
            ZLOGE(LABEL, "HandleCommands cmd:%{public}u error:%{public}d", cmd, error);
        }
    }
    if (cmd != BR_TRANSACTION) {
        auto finish = std::chrono::steady_clock::now();
        int duration = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
            finish - start).count());
        if (duration >= IPC_CMD_PROCESS_WARN_TIME) {
            ZLOGW(LABEL, "HandleCommands cmd:%{public}u cost time:%{public}dms", cmd, duration);
        }
    }
    return error;
}

void BinderInvoker::JoinThread(bool initiative)
{
    isMainWorkThread = initiative;
    output_.WriteUint32(initiative ? BC_ENTER_LOOPER : BC_REGISTER_LOOPER);
    StartWorkLoop();
    output_.WriteUint32(BC_EXIT_LOOPER);
    // pass in nullptr directly
    FlushCommands(nullptr);
    ZLOGE(LABEL, "Current Thread:%{public}d is leaving", getpid());
}

void BinderInvoker::JoinProcessThread(bool initiative) {}

int BinderInvoker::TransactWithDriver(bool doRead)
{
    if ((binderConnector_ == nullptr) || (!binderConnector_->IsDriverAlive())) {
        return IPC_INVOKER_CONNECT_ERR;
    }

    binder_write_read bwr;
    const bool readAvail = input_.GetReadableBytes() == 0;
    const size_t outAvail = (!doRead || readAvail) ? output_.GetDataSize() : 0;

    bwr.write_size = (binder_size_t)outAvail;
    bwr.write_buffer = output_.GetData();

    if (doRead && readAvail) {
        bwr.read_size = input_.GetDataCapacity();
        bwr.read_buffer = input_.GetData();
    } else {
        bwr.read_size = 0;
        bwr.read_buffer = 0;
    }
    if ((bwr.write_size == 0) && (bwr.read_size == 0)) {
        return ERR_NONE;
    }

    bwr.write_consumed = 0;
    bwr.read_consumed = 0;
#ifdef CONFIG_ACTV_BINDER
    int error = binderConnector_->WriteBinder(GetBWRCommand(), &bwr);
#else
    int error = binderConnector_->WriteBinder(BINDER_WRITE_READ, &bwr);
#endif
    if (bwr.write_consumed > 0) {
        if (bwr.write_consumed < output_.GetDataSize()) {
            // we still have some bytes not been handled.
            ZLOGF(LABEL, "still have some bytes not been handled result:%{public}d", error);
            int ret = raise(SIGABRT);
            if (ret != ERR_NONE) {
                ZLOGE(LABEL, "raise SIGABRT result:%{public}d", ret);
            }
            return error;
        } else {
            output_.FlushBuffer();
        }
    }
    if (bwr.read_consumed > 0) {
        input_.SetDataSize(bwr.read_consumed);
        input_.RewindRead(0);
    }
    if (error != ERR_NONE) {
        uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        ZLOGE(LABEL, "fail, result:%{public}d time:%{public}" PRIu64, error, curTime);
    }

    return error;
}

bool BinderInvoker::WriteTransaction(int cmd, uint32_t flags, int32_t handle, uint32_t code, const MessageParcel &data,
    const int32_t *status)
{
    binder_transaction_data tr {};
    tr.target.handle = (uint32_t)handle;
    tr.code = code;
    tr.flags = flags;
    tr.flags |= TF_ACCEPT_FDS;
    if (data.GetDataSize() > 0) {
        // Send this parcel's data through the binder.
        tr.data_size = data.GetDataSize();
        tr.data.ptr.buffer = (binder_uintptr_t)data.GetData();
        tr.offsets_size = data.GetOffsetsSize() * sizeof(binder_size_t);
        tr.data.ptr.offsets = data.GetObjectOffsets();
    } else if (status != nullptr) {
        // Send this parcel's status through the binder.
        tr.flags |= TF_STATUS_CODE;
        tr.data_size = sizeof(int32_t);
        tr.data.ptr.buffer = reinterpret_cast<uintptr_t>(status);
        tr.offsets_size = 0;
        tr.data.ptr.offsets = 0;
    }

    if (!output_.WriteInt32(cmd)) {
        ZLOGE(LABEL, "WriteTransaction Command failure");
        return false;
    }
    return output_.WriteBuffer(&tr, sizeof(binder_transaction_data));
}

void BinderInvoker::OnTransactionComplete(
    MessageParcel *reply, int32_t *acquireResult, bool &continueLoop, int32_t &error, uint32_t cmd)
{
    (void)continueLoop;
    (void)error;
    (void)cmd;

    if (reply == nullptr && acquireResult == nullptr) {
        continueLoop = false;
    }
}

void BinderInvoker::OnDeadOrFailedReply(
    MessageParcel *reply, int32_t *acquireResult, bool &continueLoop, int32_t &error, uint32_t cmd)
{
    (void)reply;

    error = static_cast<int32_t>(cmd);
    if (acquireResult != nullptr) {
        *acquireResult = cmd;
    }
    continueLoop = false;
}

void BinderInvoker::OnAcquireResult(
    MessageParcel *reply, int32_t *acquireResult, bool &continueLoop, int32_t &error, uint32_t cmd)
{
    (void)reply;
    (void)error;
    (void)cmd;

    int32_t result = input_.ReadInt32();
    if (acquireResult != nullptr) {
        *acquireResult = result ? ERR_NONE : ERR_INVALID_OPERATION;
        continueLoop = false;
    }
}

void BinderInvoker::OnReply(
    MessageParcel *reply, int32_t *acquireResult, bool &continueLoop, int32_t &error, uint32_t cmd)
{
    (void)reply;
    (void)acquireResult;
    (void)cmd;

    error = HandleReply(reply);
    if (error != IPC_INVOKER_INVALID_REPLY_ERR) {
        continueLoop = false;
        return;
    }
    error = ERR_NONE;
}

void BinderInvoker::OnTranslationComplete(
    MessageParcel *reply, int32_t *acquireResult, bool &continueLoop, int32_t &error, uint32_t cmd)
{
    (void)reply;
    (void)acquireResult;
    (void)error;
    (void)cmd;

    uint32_t handle = input_.ReadUint32();
    if (reply != nullptr) {
        reply->WriteUint32(handle);
    }
    continueLoop = false;
}

void BinderInvoker::DealWithCmd(
    MessageParcel *reply, int32_t *acquireResult, bool &continueLoop, int32_t &error, uint32_t cmd)
{
    switch (cmd) {
        case BR_TRANSACTION_COMPLETE:
            OnTransactionComplete(reply, acquireResult, continueLoop, error, cmd);
            break;
        case BR_DEAD_REPLY:
        case BR_FAILED_REPLY:
            OnDeadOrFailedReply(reply, acquireResult, continueLoop, error, cmd);
            break;
        case BR_ACQUIRE_RESULT:
            OnAcquireResult(reply, acquireResult, continueLoop, error, cmd);
            break;
        case BR_REPLY:
            OnReply(reply, acquireResult, continueLoop, error, cmd);
            break;
        case BR_TRANSLATION_COMPLETE:
            OnTranslationComplete(reply, acquireResult, continueLoop, error, cmd);
            break;
        default:
            error = HandleCommands(cmd);
            if (error != ERR_NONE) {
                continueLoop = false;
            }
            break;
    }
}

int BinderInvoker::WaitForCompletion(MessageParcel *reply, int32_t *acquireResult)
{
    if ((binderConnector_ == nullptr) || (!binderConnector_->IsDriverAlive())) {
        ZLOGE(LABEL, "driver is died");
        return IPC_INVOKER_CONNECT_ERR;
    }
    uint32_t cmd;
    bool continueLoop = true;
    int error = ERR_NONE;
    while (continueLoop) {
        if ((error = TransactWithDriver()) < ERR_NONE) {
            break;
        }
        if (input_.GetReadableBytes() == 0) {
            continue;
        }
        cmd = input_.ReadUint32();
        DealWithCmd(reply, acquireResult, continueLoop, error, cmd);
    }
    return error;
}

void BinderInvoker::StopWorkThread()
{
    stopWorkThread = true;
}

bool BinderInvoker::PingService(int32_t handle)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int result = SendRequest(handle, PING_TRANSACTION, data, reply, option);
    return (result == ERR_NONE);
}

bool BinderInvoker::SetRegistryObject(sptr<IRemoteObject> &object)
{
    if ((binderConnector_ == nullptr) || (!binderConnector_->IsDriverAlive())) {
        return false;
    }

    if (object->IsProxyObject()) {
        ZLOGE(LABEL, "set wrong object!");
        return false;
    }

#ifdef WITH_SELINUX
    flat_binder_object flat = {
        .flags = FLAT_BINDER_FLAG_TXN_SECURITY_CTX,
    };

    int result = binderConnector_->WriteBinder(BINDER_SET_CONTEXT_MGR_EXT, &flat);
    if (result == ERR_NONE) {
        return true;
    }
    ZLOGI(LABEL, "fail, error:%{public}d", result);
#endif

    int dummy = 0;
    int res = binderConnector_->WriteBinder(BINDER_SET_CONTEXT_MGR, &dummy);
    if (res != ERR_NONE) {
        ZLOGE(LABEL, "fail, error:%{public}d", res);
        return false;
    }

    return true;
}

void BinderInvoker::FreeBuffer(void *data)
{
    size_t rewindPos = output_.GetWritePosition();
    if (!output_.WriteUint32(BC_FREE_BUFFER)) {
        return;
    }

    if (!output_.WritePointer((uintptr_t)data)) {
        if (!output_.RewindWrite(rewindPos)) {
            output_.FlushBuffer();
        }
    }
}

void BinderInvoker::BinderAllocator::Dealloc(void *data)
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DEFAULT);
    if (invoker != nullptr) {
        invoker->FreeBuffer(data);
    }
}

pid_t BinderInvoker::GetCallerPid() const
{
    // when the current caller information is self, obtain another binderinvoker
    auto pid = getpid();
    if (!status_ && pid != invokerInfo_.pid) {
        return invokerInfo_.pid;
    }
    return callerPid_;
}

std::string BinderInvoker::GetCallerSid() const
{
    auto pid = getpid();
    if (!status_ && pid != invokerInfo_.pid) {
        return invokerInfo_.sid;
    }
    return callerSid_;
}

pid_t BinderInvoker::GetCallerRealPid() const
{
    auto pid = getpid();
    if (!status_ && pid != invokerInfo_.pid) {
        return invokerInfo_.realPid;
    }
    return callerRealPid_;
}

uid_t BinderInvoker::GetCallerUid() const
{
    auto pid = getpid();
    if (!status_ && pid != invokerInfo_.pid) {
        return invokerInfo_.uid;
    }
    return callerUid_;
}

uint64_t BinderInvoker::GetCallerTokenID() const
{
    // If a process does NOT have a tokenid, the UID should be returned accordingly.
    auto pid = getpid();
    if (!status_ && pid != invokerInfo_.pid) {
        return (invokerInfo_.tokenId == 0) ? invokerInfo_.uid : invokerInfo_.tokenId;
    }
    return (callerTokenID_ == 0) ? callerUid_ : callerTokenID_;
}

uint64_t BinderInvoker::GetFirstCallerTokenID() const
{
    auto pid = getpid();
    if (!status_ && pid != invokerInfo_.pid) {
        return invokerInfo_.firstTokenId;
    }
    return firstTokenID_;
}

uint64_t BinderInvoker::GetSelfTokenID() const
{
    if ((binderConnector_ == nullptr) || (!binderConnector_->IsDriverAlive())) {
        return 0;
    }
    uint64_t selfTokenId = binderConnector_->GetSelfTokenID();
    return (selfTokenId == 0) ? static_cast<uint64_t>(getuid()) : selfTokenId;
}

uint64_t BinderInvoker::GetSelfFirstCallerTokenID() const
{
    if ((binderConnector_ == nullptr) || (!binderConnector_->IsDriverAlive())) {
        return 0;
    }
    uint64_t selfFirstCallerTokenId = binderConnector_->GetSelfFirstCallerTokenID();
    return (selfFirstCallerTokenId == 0) ? static_cast<uint32_t>(getuid()) : selfFirstCallerTokenId;
}

uint32_t BinderInvoker::GetStatus()
{
    if (status_ != BinderInvoker::ACTIVE_INVOKER) {
        auto current = ProcessSkeleton::GetInstance();
        if (current != nullptr) {
            bool flag = current->QueryInvokerProcInfo(true, invokerInfo_) && (getpid() != invokerInfo_.pid);
            return flag ? BinderInvoker::ACTIVE_INVOKER : BinderInvoker::IDLE_INVOKER;
        }
    }
    return status_;
}

void BinderInvoker::SetStatus(uint32_t status)
{
    status_ = status;
}

std::string BinderInvoker::GetLocalDeviceID()
{
    return "";
}

std::string BinderInvoker::GetCallerDeviceID() const
{
    return "";
}

bool BinderInvoker::IsLocalCalling()
{
    return true;
}

bool BinderInvoker::FlattenObject(Parcel &parcel, const IRemoteObject *object) const
{
    if (object == nullptr) {
        return false;
    }
    flat_binder_object flat;
    flat.flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    if (object->IsProxyObject()) {
        const IPCObjectProxy *proxy = reinterpret_cast<const IPCObjectProxy *>(object);
        const int32_t handle = proxy ? static_cast<int32_t>(proxy->GetHandle()) : -1;
        flat.hdr.type = BINDER_TYPE_HANDLE;
        flat.binder = 0;
        flat.handle = (uint32_t)handle;
        flat.cookie = proxy ? static_cast<binder_uintptr_t>(proxy->GetProto()) : 0;
    } else {
        const IPCObjectStub *stub = reinterpret_cast<const IPCObjectStub *>(object);
        if (stub->GetRequestSidFlag()) {
            flat.flags |= FLAT_BINDER_FLAG_TXN_SECURITY_CTX;
        }
        flat.hdr.type = BINDER_TYPE_BINDER;
        flat.binder = reinterpret_cast<uintptr_t>(object->GetRefCounter());
        flat.cookie = reinterpret_cast<uintptr_t>(object);
    }

    bool status = parcel.WriteBuffer(&flat, sizeof(flat_binder_object));
    if (!status) {
        ZLOGE(LABEL, "Fail to flatten object");
    }
    return status;
}

sptr<IRemoteObject> BinderInvoker::UnflattenObject(Parcel &parcel)
{
    const uint8_t *buffer = parcel.ReadBuffer(sizeof(flat_binder_object));
    if (buffer == nullptr) {
        ZLOGE(LABEL, "null object buffer");
        return nullptr;
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject = nullptr;
    auto *flat = reinterpret_cast<const flat_binder_object *>(buffer);
    switch (flat->hdr.type) {
        case BINDER_TYPE_BINDER: {
            remoteObject = reinterpret_cast<IRemoteObject *>(flat->cookie);
            break;
        }
        case BINDER_TYPE_HANDLE: {
            remoteObject = current->FindOrNewObject(flat->handle);
            break;
        }
        default:
            ZLOGE(LABEL, "unknown binder type:%{public}u", flat->hdr.type);
            break;
    }

    if (!current->IsContainsObject(remoteObject)) {
                remoteObject = nullptr;
            }

    return remoteObject;
}

int BinderInvoker::ReadFileDescriptor(Parcel &parcel)
{
    int fd = -1;
    const uint8_t *buffer = parcel.ReadBuffer(sizeof(flat_binder_object));
    if (buffer == nullptr) {
        ZLOGE(LABEL, "UnflattenObject null object buffer");
        return fd;
    }

    auto *flat = reinterpret_cast<const flat_binder_object *>(buffer);
    if (flat->hdr.type == BINDER_TYPE_FD || flat->hdr.type == BINDER_TYPE_FDR) {
        fd = flat->handle;
        ZLOGD(LABEL, "fd:%{public}d", fd);
    } else {
        ZLOGE(LABEL, "unknown binder type:%{public}u", flat->hdr.type);
    }

    return fd;
}

bool BinderInvoker::WriteFileDescriptor(Parcel &parcel, int fd, bool takeOwnership)
{
    flat_binder_object flat;
    flat.hdr.type = BINDER_TYPE_FD;
    flat.flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    flat.binder = 0; // Don't pass uninitialized stack data to a remote process
    flat.handle = static_cast<__u32>(fd);
    flat.cookie = takeOwnership ? 1 : 0;

    return parcel.WriteBuffer(&flat, sizeof(flat_binder_object));
}

std::string BinderInvoker::ResetCallingIdentity()
{
    pid_t tempPid = callerPid_;
    pid_t tempRealPid = callerRealPid_;
    pid_t tempUid = callerUid_;
    uint64_t tempTokenId = callerTokenID_;
    std::string tempSid = callerSid_;

    auto pid = getpid();
    if (!status_ && pid != invokerInfo_.pid) {
        tempPid = invokerInfo_.pid;
        tempRealPid = invokerInfo_.realPid;
        tempUid = invokerInfo_.uid;
        tempTokenId = invokerInfo_.tokenId;
        tempSid = invokerInfo_.sid;
    }

    char buf[ACCESS_TOKEN_MAX_LEN + 1] = {0};
    int ret = sprintf_s(buf, ACCESS_TOKEN_MAX_LEN + 1, "%010" PRIu64, tempTokenId);
    if (ret < 0) {
        ZLOGE(LABEL, "sprintf callerTokenID:%{public}" PRIu64 " failed", tempTokenId);
        return "";
    }
    std::string accessToken(buf);
    ret = sprintf_s(buf, ACCESS_TOKEN_MAX_LEN + 1, "%010d", tempRealPid);
    if (ret < 0) {
        ZLOGE(LABEL, "sprintf callerRealPid_:%{public}d failed", tempRealPid);
        return "";
    }
    std::string realPid(buf);
    std::string pidUid = std::to_string(((static_cast<uint64_t>(tempUid) << PID_LEN)
        | static_cast<uint64_t>(tempPid)));
    callerUid_ = static_cast<pid_t>(getuid());
    callerPid_ = getpid();
    callerRealPid_ = getprocpid();
    callerTokenID_ = GetSelfTokenID();
    callerSid_ = "";
    return tempSid + "<" + accessToken + realPid + pidUid; // '<' is the separator character
}

bool BinderInvoker::SetCallingIdentity(std::string &identity)
{
    if (identity.empty() || identity.length() <= ACCESS_TOKEN_MAX_LEN) {
        return false;
    }

    auto pos = identity.find('<');
    if (pos == std::string::npos) {
        return false;
    }
    std::string callerSid_ = identity.substr(0, pos);
    callerTokenID_ = std::stoull(identity.substr(pos + 1, ACCESS_TOKEN_MAX_LEN).c_str());
    callerRealPid_ =
        static_cast<int>(std::stoull(identity.substr(pos + 1 + ACCESS_TOKEN_MAX_LEN, ACCESS_TOKEN_MAX_LEN).c_str()));
    uint64_t pidUid = std::stoull(identity.substr(pos + 1 + ACCESS_TOKEN_MAX_LEN * PIDUID_OFFSET,
        identity.length() - ACCESS_TOKEN_MAX_LEN * PIDUID_OFFSET).c_str());
    callerUid_ = static_cast<int>(pidUid >> PID_LEN);
    callerPid_ = static_cast<int>(pidUid);
    ZLOGD(LABEL, "callerSid:%{public}s, callerTokenID:%{public}" PRIu64 ", \
        callerRealPid:%{public}u, callerUid:%{public}u, callerPid:%{public}u",
        callerSid_.c_str(), callerTokenID_, callerRealPid_, callerUid_, callerPid_);
    return true;
}

uint32_t BinderInvoker::GetStrongRefCountForStub(uint32_t handle)
{
    if ((binderConnector_ == nullptr) || (!binderConnector_->IsDriverAlive())) {
        return 0;  // 0 means get failed
    }
    binder_node_info_for_ref info;
    memset_s(&info, sizeof(binder_node_info_for_ref), 0, sizeof(binder_node_info_for_ref));

    info.handle = handle;
    int32_t result = binderConnector_->WriteBinder(BINDER_GET_NODE_INFO_FOR_REF, &info);
    if (result != ERR_NONE) {
        ZLOGE(LABEL, "WriteBinder failed, Error code %{public}d", result);
        return 0;  // 0 means get failed
    }

    return info.strong_count;
}

#ifdef CONFIG_ACTV_BINDER
void BinderInvoker::JoinActvThread(bool initiative)
{
    IRemoteInvoker *remoteInvoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_BINDER);
    BinderInvoker *invoker = reinterpret_cast<BinderInvoker *>(remoteInvoker);

    if (invoker != nullptr) {
        invoker->SetUseActvBinder(true);
        invoker->JoinThread(initiative);
    }
}

bool BinderInvoker::IsActvBinderService()
{
    bool check = false;
    IRemoteInvoker *remoteInvoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_BINDER);
    BinderInvoker *invoker = reinterpret_cast<BinderInvoker *>(remoteInvoker);

    if ((invoker != nullptr) && (invoker->binderConnector_ != nullptr)) {
        check = invoker->binderConnector_->IsActvBinderService();
    }

    return check;
}
#endif // CONFIG_ACTV_BINDER

#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS
