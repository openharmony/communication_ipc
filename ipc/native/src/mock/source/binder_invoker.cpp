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
#include <securec.h>
#include "access_token_adapter.h"
#include "binder_debug.h"
#include "dbinder_error_code.h"
#include "hilog/log.h"
#include "hitrace_invoker.h"
#include "ipc_object_proxy.h"
#include "ipc_object_stub.h"
#include "ipc_process_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "log_tags.h"
#include "string_ex.h"
#include "sys_binder.h"

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
namespace IPC_SINGLE {
#endif

using namespace OHOS::HiviewDFX;
static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "BinderInvoker" };
enum {
    GET_SERVICE_TRANSACTION = 0x1,
    CHECK_SERVICE_TRANSACTION,
    ADD_SERVICE_TRANSACTION,
};

BinderInvoker::BinderInvoker()
    : isMainWorkThread(false), stopWorkThread(false), callerPid_(getpid()), callerUid_(getuid()),
    firstTokenID_(0), status_(0)
{
    callerTokenID_ = (uint32_t)RpcGetSelfTokenID();
    input_.SetDataCapacity(IPC_DEFAULT_PARCEL_SIZE);
    binderConnector_ = BinderConnector::GetInstance();
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
        (void)PingService(handle);
    }
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
    return true;
}

int BinderInvoker::SendRequest(int handle, uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    int error = ERR_NONE;
    uint32_t flags = (uint32_t)option.GetFlags();
    MessageParcel &newData = const_cast<MessageParcel &>(data);
    size_t oldWritePosition = newData.GetWritePosition();
    HiTraceId traceId = HiTraceChain::GetId();
    // set client send trace point if trace is enabled
    HiTraceId childId = HitraceInvoker::TraceClientSend(handle, code, newData, flags, traceId);
    if (!WriteTransaction(BC_TRANSACTION, flags, handle, code, data, nullptr)) {
        newData.RewindWrite(oldWritePosition);
        ZLOGE(LABEL, "WriteTransaction ERROR");
#ifndef BUILD_PUBLIC_VERSION
        ReportDriverEvent(DbinderErrorCode::COMMON_DRIVER_ERROR, DbinderErrorCode::ERROR_TYPE,
            DbinderErrorCode::IPC_DRIVER, DbinderErrorCode::ERROR_CODE, DbinderErrorCode::TRANSACT_DATA_FAILURE);
#endif
        return IPC_INVOKER_WRITE_TRANS_ERR;
    }

    if ((flags & TF_ONE_WAY) != 0) {
        error = WaitForCompletion(nullptr);
    } else {
        error = WaitForCompletion(&reply);
    }
    HitraceInvoker::TraceClientReceieve(handle, code, flags, traceId, childId);
    // restore Parcel data
    newData.RewindWrite(oldWritePosition);
    if (error != ERR_NONE) {
        ZLOGE(LABEL, "%{public}s: handle=%{public}d result = %{public}d", __func__, handle, error);
    }
    return error;
}

bool BinderInvoker::AddDeathRecipient(int32_t handle, void *cookie)
{
    size_t rewindPos = output_.GetWritePosition();
    if (!output_.WriteInt32(BC_REQUEST_DEATH_NOTIFICATION)) {
        ZLOGE(LABEL, "fail to write command field:%d", handle);
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
        ZLOGE(LABEL, "Remove Death Recipient handle =%{public}d result = %{public}d", handle, error);
        return false;
    }

    return true;
}

int BinderInvoker::GetObjectRefCount(const IRemoteObject *object)
{
    if ((binderConnector_ == nullptr) || (!binderConnector_->IsDriverAlive())) {
        return 0;
    }

    struct binder_ptr_count refs;
    refs.ptr = reinterpret_cast<uintptr_t>(object);

    int error = binderConnector_->WriteBinder(BINDER_GET_NODE_REFCOUNT, &refs);
    if (error != ERR_NONE) {
        ZLOGE(LABEL, "GetSRefCount error = %{public}d", error);
        return 0;
    }
    return refs.count;
}

#ifndef CONFIG_IPC_SINGLE
int BinderInvoker::TranslateProxy(uint32_t handle, uint32_t flag)
{
    binder_node_debug_info info {};
    if ((binderConnector_ == nullptr) || (!binderConnector_->IsDriverAlive())) {
        return -IPC_INVOKER_CONNECT_ERR;
    }
    info.has_strong_ref = handle;
    info.has_weak_ref = flag;
    ZLOGD(LABEL, "TranslateProxy input handle = %{public}u", info.has_strong_ref);
    int error = binderConnector_->WriteBinder(BINDER_TRANSLATE_HANDLE, &info);
    if (error == ERR_NONE && info.has_strong_ref > 0) {
        ZLOGD(LABEL, "TranslateProxy get new handle = %{public}u", info.has_strong_ref);
        return info.has_strong_ref;
    }
    ZLOGE(LABEL, "failed to translateProxy input handle = %{public}u", info.has_strong_ref);
    return -IPC_INVOKER_TRANSLATE_ERR;
}

int BinderInvoker::TranslateStub(binder_uintptr_t cookie, binder_uintptr_t ptr, uint32_t flag, int cmd)
{
    binder_node_debug_info info {};
    if ((binderConnector_ == nullptr) || (!binderConnector_->IsDriverAlive())) {
        return -IPC_INVOKER_CONNECT_ERR;
    }
    info.cookie = cookie;
    info.ptr = ptr;
    info.has_weak_ref = (uint32_t)cmd;
    info.has_strong_ref = flag;
    int error = binderConnector_->WriteBinder(BINDER_TRANSLATE_HANDLE, &info);
    if (error == ERR_NONE && info.has_strong_ref > 0) {
        ZLOGD(LABEL, "TranslateStub get new handle = %{public}u", info.has_strong_ref);
        return info.has_strong_ref;
    }
    ZLOGE(LABEL, "failed to TranslateStub");
    return -IPC_INVOKER_TRANSLATE_ERR;
}

sptr<IRemoteObject> BinderInvoker::GetSAMgrObject()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current != nullptr) {
        return current->GetRegistryObject();
    }
    return nullptr;
}

#endif
bool BinderInvoker::SetMaxWorkThread(int maxThreadNum)
{
    if ((binderConnector_ == nullptr) || (!binderConnector_->IsDriverAlive())) {
        ZLOGE(LABEL, "%{public}s driver died", __func__);
        return false;
    }

    int error = binderConnector_->WriteBinder(BINDER_SET_MAX_THREADS, &maxThreadNum);
    if (error != ERR_NONE) {
        ZLOGE(LABEL, "SetMaxWorkThread error = %{public}d", error);
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
        ZLOGE(LABEL, "fail to flush commands with error = %{public}d", error);
    }

    if (output_.GetDataSize() > 0) {
        error = TransactWithDriver(false);
        ZLOGE(LABEL, "flush commands again with return value = %{public}d", error);
    }
    if (error != ERR_NONE || output_.GetDataSize() > 0) {
        ZLOGE(LABEL, "flush commands with error = %{public}d, left data size = %{public}zu", error,
            output_.GetDataSize());
    }

    return error;
}

void BinderInvoker::ExitCurrentThread()
{
    if ((binderConnector_ == nullptr) || (!binderConnector_->IsDriverAlive())) {
        ZLOGE(LABEL, "%{public}s driver died when exit current thread", __func__);
        return;
    }
    binderConnector_->ExitCurrentThread(BINDER_THREAD_EXIT);
}

void BinderInvoker::StartWorkLoop()
{
    int error;
    do {
        error = TransactWithDriver();
        if (error < ERR_NONE && error != -ECONNREFUSED && error != -EBADF) {
            ZLOGE(LABEL, "returned unexpected error %d, aborting", error);
            break;
        }
        uint32_t cmd = input_.ReadUint32();
        int userError = HandleCommands(cmd);
        if ((userError == -ERR_TIMED_OUT || userError == IPC_INVOKER_INVALID_DATA_ERR) && !isMainWorkThread) {
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
    uintptr_t cookie = input_.ReadPointer();
    auto *proxy = reinterpret_cast<IPCObjectProxy *>(cookie);
    if (proxy != nullptr) {
        proxy->SendObituary();
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
    bool ParcelResult = false;
    uintptr_t refsPointer = input_.ReadPointer();
    uintptr_t objectPointer = input_.ReadPointer();
    RefBase *refs = reinterpret_cast<IRemoteObject *>(refsPointer);
    if ((refs == nullptr) || (!objectPointer)) {
        ZLOGE(LABEL, "OnAcquireObject FAIL!");
        return;
    }

    size_t rewindPos = output_.GetWritePosition();
    if (cmd == BR_ACQUIRE) {
        refs->IncStrongRef(this);
        ParcelResult = output_.WriteInt32(BC_ACQUIRE_DONE);
    } else {
        refs->IncWeakRef(this);
        ParcelResult = output_.WriteInt32(BC_INCREFS_DONE);
    }

    if (!ParcelResult || !output_.WritePointer(refsPointer)) {
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
    auto *refs = reinterpret_cast<IRemoteObject *>(refsPointer);
    auto *object = reinterpret_cast<IRemoteObject *>(objectPointer);
    if ((refs == nullptr) || (object == nullptr)) {
        ZLOGE(LABEL, "OnReleaseObject FAIL!");
        return;
    }

    if (cmd == BR_RELEASE) {
        refs->DecStrongRef(this);
    } else {
        refs->DecWeakRef(this);
    }
}

void BinderInvoker::OnTransaction(const uint8_t *buffer)
{
    const binder_transaction_data *tr = reinterpret_cast<const binder_transaction_data *>(buffer);
    auto binderAllocator = new (std::nothrow) BinderAllocator();
    if (binderAllocator == nullptr) {
        ZLOGE(LABEL, "BinderAllocator Creation failed");
        return;
    }
    auto data = std::make_unique<MessageParcel>(binderAllocator);
    data->ParseFrom(tr->data.ptr.buffer, tr->data_size);
    if (tr->offsets_size > 0) {
        data->InjectOffsets(tr->data.ptr.offsets, tr->offsets_size / sizeof(binder_size_t));
    }
    uint32_t &newflags = const_cast<uint32_t &>(tr->flags);
    int isServerTraced = HitraceInvoker::TraceServerReceieve(tr->target.handle, tr->code, *data, newflags);
    const pid_t oldPid = callerPid_;
    const auto oldUid = static_cast<const uid_t>(callerUid_);
    const uint32_t oldToken = callerTokenID_;
    const uint32_t oldFirstToken = firstTokenID_;
    uint32_t oldStatus = status_;
    callerPid_ = tr->sender_pid;
    callerUid_ = tr->sender_euid;
    if (binderConnector_->IsAccessTokenSupported()) {
        struct access_token tmp;
        int error = binderConnector_->WriteBinder(BINDER_GET_ACCESS_TOKEN, &tmp);
        if (error != ERR_NONE) {
            callerTokenID_ = 0;
            firstTokenID_ = 0;
        } else {
            callerTokenID_ = tmp.sender_tokenid;
            firstTokenID_ = tmp.first_tokenid;
        }
    } else {
        callerTokenID_ = 0;
        firstTokenID_ = 0;
    }
    SetStatus(IRemoteInvoker::ACTIVE_INVOKER);
    int error = ERR_DEAD_OBJECT;
    sptr<IRemoteObject> targetObject;
    if (tr->target.ptr != 0) {
        auto *refs = reinterpret_cast<IRemoteObject *>(tr->target.ptr);
        if ((refs != nullptr) && (tr->cookie) && (refs->AttemptIncStrongRef(this))) {
            targetObject = reinterpret_cast<IPCObjectStub *>(tr->cookie);
            if (targetObject != nullptr) {
                targetObject->DecStrongRef(this);
            }
        }
    } else {
        targetObject = IPCProcessSkeleton::GetCurrent()->GetRegistryObject();
        if (targetObject == nullptr) {
            ZLOGE(LABEL, "Invalid samgr stub object");
            abort();
        }
    }
    MessageParcel reply;
    MessageOption option;
    uint32_t flagValue = static_cast<uint32_t>(tr->flags) & ~static_cast<uint32_t>(MessageOption::TF_ACCEPT_FDS);
    if (targetObject != nullptr) {
        option.SetFlags(static_cast<int>(flagValue));
        auto start = std::chrono::steady_clock::now();
        error = targetObject->SendRequest(tr->code, *data, reply, option);
        auto finish = std::chrono::steady_clock::now();
        int duration = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
            finish - start).count());
        if (duration >= IPC_CMD_PROCESS_WARN_TIME) {
            ZLOGW(LABEL, "stub: %{public}s deal request code: %{public}u cost time: %{public}dms",
                Str16ToStr8(targetObject->descriptor_).c_str(), tr->code, duration);
        }
    }
    HitraceInvoker::TraceServerSend(tr->target.handle, tr->code, isServerTraced, newflags);
    if (!(flagValue & TF_ONE_WAY)) {
        SendReply(reply, 0, error);
    }
    callerPid_ = oldPid;
    callerUid_ = oldUid;
    callerTokenID_ = oldToken;
    firstTokenID_ = oldFirstToken;
    SetStatus(oldStatus);
}

void BinderInvoker::OnAttemptAcquire()
{
    bool success = false;
    uintptr_t refsPtr = input_.ReadPointer();
    uintptr_t objectPtr = input_.ReadPointer();
    auto *refs = reinterpret_cast<IRemoteObject *>(refsPtr);

    size_t rewindPos = output_.GetWritePosition();
    if ((refs != nullptr) && (!objectPtr)) {
        success = refs->AttemptIncStrongRef(this);
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
        FreeBuffer(reinterpret_cast<void *>(tr->data.ptr.buffer));
        return IPC_INVOKER_INVALID_REPLY_ERR;
    }

    if (tr->flags & TF_STATUS_CODE) {
        int32_t status = *reinterpret_cast<const int32_t *>(tr->data.ptr.buffer);
        FreeBuffer(reinterpret_cast<void *>(tr->data.ptr.buffer));
        return status;
    }

    if (tr->data_size > 0) {
        auto allocator = new (std::nothrow) BinderAllocator();
        if (allocator == nullptr) {
            ZLOGE(LABEL, "create BinderAllocator object failed");
            return IPC_INVOKER_INVALID_DATA_ERR;
        }
        if (!reply->SetAllocator(allocator)) {
            delete allocator;
            FreeBuffer(reinterpret_cast<void*>(tr->data.ptr.buffer));
            return IPC_INVOKER_INVALID_DATA_ERR;
        }
        reply->ParseFrom(tr->data.ptr.buffer, tr->data_size);
    }

    if (tr->offsets_size > 0) {
        reply->InjectOffsets(tr->data.ptr.offsets, tr->offsets_size / sizeof(binder_size_t));
        reply->SetClearFdFlag();
    }
    return ERR_NONE;
}

int BinderInvoker::HandleCommandsInner(uint32_t cmd)
{
    int error = ERR_NONE;
    switch (cmd) {
        case BR_ERROR:
            error = input_.ReadInt32();
            break;
        case BR_ACQUIRE:
        case BR_INCREFS:
            OnAcquireObject(cmd);
            break;
        case BR_RELEASE:
        case BR_DECREFS:
            OnReleaseObject(cmd);
            break;
        case BR_ATTEMPT_ACQUIRE:
            OnAttemptAcquire();
            break;
        case BR_TRANSACTION: {
            const uint8_t *buffer = input_.ReadBuffer(sizeof(binder_transaction_data));
            if (buffer == nullptr) {
                error = IPC_INVOKER_INVALID_DATA_ERR;
                break;
            }
            OnTransaction(buffer);
            break;
        }
        case BR_SPAWN_LOOPER: {
            IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
            if (current != nullptr) {
                current->SpawnThread();
            }
            break;
        }
        case BR_FINISHED:
            error = -ERR_TIMED_OUT;
            break;
        case BR_DEAD_BINDER:
            OnBinderDied();
            break;
        case BR_CLEAR_DEATH_NOTIFICATION_DONE:
            OnRemoveRecipientDone();
            break;
        case BR_OK:
        case BR_NOOP:
            break;
        default:
            error = IPC_INVOKER_ON_TRANSACT_ERR;
            break;
    }
    return error;
}

int BinderInvoker::HandleCommands(uint32_t cmd)
{
    auto start = std::chrono::steady_clock::now();
    int error = HandleCommandsInner(cmd);
    if (error != ERR_NONE) {
        ZLOGE(LABEL, "HandleCommands cmd = %{public}u, error = %{public}d", cmd, error);
    }
    if (cmd != BR_TRANSACTION) {
        auto finish = std::chrono::steady_clock::now();
        int duration = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
            finish - start).count());
        if (duration >= IPC_CMD_PROCESS_WARN_TIME) {
            ZLOGW(LABEL, "HandleCommands cmd: %{public}u cost time: %{public}dms", cmd, duration);
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
    ZLOGE(LABEL, "Current Thread %d is leaving", getpid());
}

void BinderInvoker::JoinProcessThread(bool initiative) {}

int BinderInvoker::TransactWithDriver(bool doRead)
{
    if ((binderConnector_ == nullptr) || (!binderConnector_->IsDriverAlive())) {
        ZLOGE(LABEL, "%{public}s: Binder Driver died", __func__);
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
    int error = binderConnector_->WriteBinder(BINDER_WRITE_READ, &bwr);
    if (bwr.write_consumed > 0) {
        if (bwr.write_consumed < output_.GetDataSize()) {
            // we still have some bytes not been handled.
        } else {
            output_.FlushBuffer();
        }
    }
    if (bwr.read_consumed > 0) {
        input_.SetDataSize(bwr.read_consumed);
        input_.RewindRead(0);
    }
    if (error != ERR_NONE) {
        ZLOGE(LABEL, "TransactWithDriver result = %{public}d", error);
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

int BinderInvoker::WaitForCompletion(MessageParcel *reply, int32_t *acquireResult)
{
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
        switch (cmd) {
            case BR_TRANSACTION_COMPLETE: {
                if (reply == nullptr && acquireResult == nullptr) {
                    continueLoop = false;
                }
                break;
            }
            case BR_DEAD_REPLY: // fall-through
            case BR_FAILED_REPLY: {
                error = (int)cmd;
                if (acquireResult != nullptr) {
                    *acquireResult = (int32_t)cmd;
                }
                continueLoop = false;
                break;
            }
            case BR_ACQUIRE_RESULT: {
                int32_t result = input_.ReadInt32();
                if (acquireResult != nullptr) {
                    *acquireResult = result ? ERR_NONE : ERR_INVALID_OPERATION;
                    continueLoop = false;
                }
                break;
            }
            case BR_REPLY: {
                error = HandleReply(reply);
                if (error != IPC_INVOKER_INVALID_REPLY_ERR) {
                    continueLoop = false;
                    break;
                }
                error = ERR_NONE;
                break;
            }
            default: {
                error = HandleCommands(cmd);
                if (error != ERR_NONE) {
                    continueLoop = false;
                }
                break;
            }
        }
    }
    return error;
}

void BinderInvoker::StopWorkThread()
{
    stopWorkThread = true;
}

bool BinderInvoker::PingService(int32_t handle)
{
    MessageParcel data, reply;
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
        ZLOGE(LABEL, "%{public}s: set wrong object!", __func__);
        return false;
    }

    Parcel dummy;
    int result = binderConnector_->WriteBinder(BINDER_SET_CONTEXT_MGR, &dummy);
    if (result != ERR_NONE) {
        ZLOGE(LABEL, "%{public}s:set registry fail, driver error %{public}d", __func__, result);
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
    return callerPid_;
}

uid_t BinderInvoker::GetCallerUid() const
{
    return callerUid_;
}

uint32_t BinderInvoker::GetCallerTokenID() const
{
    return callerTokenID_;
}

uint32_t BinderInvoker::GetFirstTokenID() const
{
    if (firstTokenID_ == 0) {
        return (uint32_t)RpcGetFirstCallerTokenID();
    }
    return firstTokenID_;
}

uint32_t BinderInvoker::GetStatus() const
{
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
    if (object->IsProxyObject()) {
        const IPCObjectProxy *proxy = reinterpret_cast<const IPCObjectProxy *>(object);
        const int32_t handle = proxy ? (int32_t)(proxy->GetHandle()) : -1;
        flat.hdr.type = BINDER_TYPE_HANDLE;
        flat.binder = 0;
        flat.handle = (uint32_t)handle;
        flat.cookie = proxy ? static_cast<binder_uintptr_t>(proxy->GetProto()) : 0;
    } else {
        flat.hdr.type = BINDER_TYPE_BINDER;
        flat.binder = reinterpret_cast<uintptr_t>(object);
        flat.cookie = flat.binder;
    }

    flat.flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    bool status = parcel.WriteBuffer(&flat, sizeof(flat_binder_object));
    if (!status) {
        ZLOGE(LABEL, "Fail to flatten object");
#ifndef BUILD_PUBLIC_VERSION
        ReportDriverEvent(DbinderErrorCode::COMMON_DRIVER_ERROR, DbinderErrorCode::ERROR_TYPE,
            DbinderErrorCode::IPC_DRIVER, DbinderErrorCode::ERROR_CODE, DbinderErrorCode::FLATTEN_OBJECT_FAILURE);
#endif
    }
    return status;
}

sptr<IRemoteObject> BinderInvoker::UnflattenObject(Parcel &parcel)
{
    const uint8_t *buffer = parcel.ReadBuffer(sizeof(flat_binder_object));
    if (buffer == nullptr) {
        ZLOGE(LABEL, "UnflattenObject null object buffer");
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
            if (!current->IsContainsObject(remoteObject)) {
                remoteObject = nullptr;
            }
            break;
        }
        case BINDER_TYPE_REMOTE_HANDLE:
        case BINDER_TYPE_HANDLE: {
            remoteObject = current->FindOrNewObject(flat->handle);
            break;
        }
        default:
            ZLOGE(LABEL, "%s: unknown binder type %u", __func__, flat->hdr.type);
            remoteObject = nullptr;
            break;
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
    } else {
        ZLOGE(LABEL, "%s: unknown binder type %u", __func__, flat->hdr.type);
    }

    return fd;
}

bool BinderInvoker::WriteFileDescriptor(Parcel &parcel, int fd, bool takeOwnership)
{
    flat_binder_object flat;
    flat.hdr.type = BINDER_TYPE_FD;
    flat.flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    flat.binder = 0; // Don't pass uninitialized stack data to a remote process
    flat.handle = (uint32_t)fd;
    flat.cookie = takeOwnership ? 1 : 0;

    return parcel.WriteBuffer(&flat, sizeof(flat_binder_object));
}

std::string BinderInvoker::ResetCallingIdentity()
{
    char buf[ACCESS_TOKEN_MAX_LEN + 1] = {0};
    int ret = sprintf_s(buf, ACCESS_TOKEN_MAX_LEN + 1, "%010u", callerTokenID_);
    if (ret < 0) {
        ZLOGE(LABEL, "%s: sprintf callerTokenID_ %u failed", __func__, callerTokenID_);
        return "";
    }
    std::string accessToken(buf);
    std::string pidUid = std::to_string(((static_cast<uint64_t>(callerUid_) << PID_LEN)
        | static_cast<uint64_t>(callerPid_)));
    callerUid_ = (pid_t)getuid();
    callerPid_ = getpid();
    callerTokenID_ = (uint32_t)RpcGetSelfTokenID();
    return accessToken + pidUid;
}

bool BinderInvoker::SetCallingIdentity(std::string &identity)
{
    if (identity.empty() || identity.length() <= ACCESS_TOKEN_MAX_LEN) {
        return false;
    }

    uint64_t pidUid =
        std::stoull(identity.substr(ACCESS_TOKEN_MAX_LEN, identity.length() - ACCESS_TOKEN_MAX_LEN).c_str());
    callerUid_ = static_cast<int>(pidUid >> PID_LEN);
    callerPid_ = static_cast<int>(pidUid);
    callerTokenID_ = static_cast<uint32_t>(std::atoi(identity.substr(0, ACCESS_TOKEN_MAX_LEN).c_str()));
    return true;
}
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS
