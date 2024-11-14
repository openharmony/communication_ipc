/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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
#include "backtrace_local.h"
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
#ifndef CONFIG_IPC_SINGLE
static constexpr pid_t INVALID_PID = -1;
static constexpr int32_t BINDER_ALIGN_BYTES = 8;
#endif

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
    ZLOGD(LABEL, ":%{public}u", ProcessSkeleton::ConvertAddr(this));
}

BinderInvoker::~BinderInvoker()
{
    ZLOGD(LABEL, ":%{public}u", ProcessSkeleton::ConvertAddr(this));
    auto current = ProcessSkeleton::GetInstance();
    if (current != nullptr) {
        current->DetachInvokerProcInfo(true);
    }
    ProcDeferredDecRefs();
    FlushCommands(nullptr);
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
    [[maybe_unused]] ThreadMigrationDisabler _d;

    if (!TranslateDBinderProxy(handle, data)) {
        return IPC_INVOKER_WRITE_TRANS_ERR;
    }

    size_t totalDBinderBufSize = 0;
#ifndef CONFIG_IPC_SINGLE
    if (!TranslateDBinderStub(handle, data, false, totalDBinderBufSize)) {
        return IPC_TRANSLATE_DBINDER_STUB_ERR;
    }
    auto dataSize = data.GetDataSize();
    if (totalDBinderBufSize > 0 && dataSize % BINDER_ALIGN_BYTES != 0) {
        ZLOGI(LABEL, "not 8 bytes aligned(%{public}zu), padding it", dataSize);
        data.WriteInt8(0);
    }
#endif
    MessageParcel &newData = const_cast<MessageParcel &>(data);
    size_t oldWritePosition = newData.GetWritePosition();
    HiTraceId traceId = HiTraceChain::GetId();
    // set client send trace point if trace is enabled
    HiTraceId childId = HitraceInvoker::TraceClientSend(handle, code, newData, flags, traceId);

    int cmd = (totalDBinderBufSize > 0) ? BC_TRANSACTION_SG : BC_TRANSACTION;
    if (!WriteTransaction(cmd, flags, handle, code, data, nullptr, totalDBinderBufSize)) {
        ZLOGE(LABEL, "WriteTransaction ERROR");
        newData.RewindWrite(oldWritePosition);
        return IPC_INVOKER_WRITE_TRANS_ERR;
    }

    ++sendRequestCount_;
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
    --sendRequestCount_;
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

bool BinderInvoker::GetDBinderCallingPidUid(int handle, bool isReply, pid_t &pid, uid_t &uid)
{
    if (pid == INVALID_PID) {
        if (!isReply) {
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            auto ret = SendRequest(handle, GET_PID_UID, data, reply, option);
            if (ret != ERR_NONE) {
                ZLOGE(LABEL, "GET_PID_UID failed, error:%{public}d", ret);
                return false;
            }
            uint32_t tempPid = reply.ReadUint32();
            if (tempPid > static_cast<uint32_t>(std::numeric_limits<pid_t>::max())) {
                ZLOGE(LABEL, "PID overflow: %{public}u", tempPid);
                return false;
            }
            pid = static_cast<pid_t>(tempPid);
            uid = reply.ReadUint32();
        } else {
            pid = GetCallerPid();
            uid = GetCallerUid();
        }
        ZLOGI(LABEL, "pid:%{public}d uid:%{public}d", pid, uid);
    }
    return true;
}

bool BinderInvoker::TranslateDBinderStub(int handle, MessageParcel &parcel, bool isReply, size_t &totalDBinderBufSize)
{
    pid_t pid = INVALID_PID;
    uid_t uid = INVALID_PID;
    uintptr_t dataBuf = parcel.GetData();
    size_t totalSize = parcel.GetDataSize();
    size_t objCount = parcel.GetOffsetsSize();
    binder_size_t *objOffset = reinterpret_cast<binder_size_t *>(parcel.GetObjectOffsets());
    size_t alignSize = 0;

    for (size_t i = 0; i < objCount; ++i) {
        auto obj = reinterpret_cast<binder_buffer_object *>(dataBuf + objOffset[i]);
        if ((obj->hdr.type == BINDER_TYPE_PTR) && (obj->length == sizeof(dbinder_negotiation_data))) {
            alignSize = (obj->length + (sizeof(uint64_t) - 1)) & ~(sizeof(uint64_t) - 1);
            if (alignSize != obj->length) {
                ZLOGW(LABEL, "alignSize(%{public}zu) != obj.length(%{public}llu)", alignSize, obj->length);
            }
            totalDBinderBufSize += alignSize;
            // skip to next object
            ++i;
            if ((i >= objCount) || (objOffset[i] + sizeof(flat_binder_object) > totalSize)) {
                ZLOGW(LABEL, "over length, i:%{public}zu count:%{public}zu offset:%{public}llu totalSize:%{public}zu",
                    i, objCount, objOffset[i], totalSize);
                break;
            }
            auto flat = reinterpret_cast<flat_binder_object *>(dataBuf + objOffset[i]);
            if (flat->hdr.type != BINDER_TYPE_BINDER) {
                ZLOGE(LABEL, "unexpected binder type:%{public}d", flat->hdr.type);
                return false;
            }
            if (!GetDBinderCallingPidUid(handle, isReply, pid, uid)) {
                ZLOGE(LABEL, "GetDBinderCallingPidUid fail, cookie:%{public}llu", flat->cookie);
                return false;
            }

            auto stub = reinterpret_cast<IPCObjectStub *>(flat->cookie);
            if (stub->GetAndSaveDBinderData(pid, uid) != ERR_NONE) {
                ZLOGE(LABEL, "GetAndSaveDBinderData fail, cookie:%{public}llu", flat->cookie);
                return false;
            }
            ZLOGI(LABEL, "succ, cookie:%{public}llu", flat->cookie);
        }
    }
    return true;
}

bool BinderInvoker::UnFlattenDBinderObject(Parcel &parcel, dbinder_negotiation_data &dbinderData)
{
    auto offset = parcel.GetReadPosition();
    auto *buffer = parcel.ReadBuffer(sizeof(binder_object_header), false);
    if (buffer == nullptr) {
        ZLOGE(LABEL, "null object buffer");
        return false;
    }
    auto *hdr = reinterpret_cast<const binder_object_header *>(buffer);
    if (hdr->type != BINDER_TYPE_PTR) {
        parcel.RewindRead(offset);
        return false;
    }
    ZLOGI(LABEL, "PTR");
    parcel.RewindRead(offset);
    buffer = parcel.ReadBuffer(sizeof(binder_buffer_object), false);
    if (buffer == nullptr) {
        ZLOGE(LABEL, "null object buffer");
        return false;
    }
    auto *obj = reinterpret_cast<const binder_buffer_object *>(buffer);
    if (((obj->flags & BINDER_BUFFER_FLAG_HAS_DBINDER) == 0) || (obj->length != sizeof(dbinder_negotiation_data))) {
        ZLOGW(LABEL, "no dbinder buffer flag");
        parcel.RewindRead(offset);
        return false;
    }
    dbinderData = *reinterpret_cast<dbinder_negotiation_data *>(obj->buffer);
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
        ZLOGE(LABEL, "failed, error:%{public}d time:%{public}" PRIu64, error, curTime);
    }

    if (output_.GetDataSize() > 0) {
        error = TransactWithDriver(false);
    }
    if (error != ERR_NONE || output_.GetDataSize() > 0) {
        ZLOGW(LABEL, "error:%{public}d, left data size:%{public}zu", error, output_.GetDataSize());
        PrintParcelData(input_, "input_");
        PrintParcelData(output_, "output_");
        std::string backtrace;
        if (!GetBacktrace(backtrace, false)) {
            ZLOGE(LABEL, "GetBacktrace fail");
        } else {
            ZLOGW(LABEL, "backtrace info:\n%{public}s", backtrace.c_str());
        }
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
        ProcessSkeleton *process = ProcessSkeleton::GetInstance();
        if (process == nullptr || process->GetThreadStopFlag()) {
            break;
        }
        error = TransactWithDriver();
        if (error < ERR_NONE && error != -ECONNREFUSED && error != -EBADF) {
            ZLOGE(LABEL, "returned unexpected error:%{public}d, aborting", error);
            break;
        }
        if (input_.GetReadableBytes() == 0) {
            continue;
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
        ProcDeferredDecRefs();
    } while (error != -ECONNREFUSED && error != -EBADF && !stopWorkThread);
}

int BinderInvoker::SendReply(MessageParcel &reply, uint32_t flags, int32_t result)
{
    size_t totalDBinderBufSize = 0;
#ifndef CONFIG_IPC_SINGLE
    if (!TranslateDBinderStub(-1, reply, true, totalDBinderBufSize)) {
        return IPC_TRANSLATE_DBINDER_STUB_ERR;
    }
    auto replySize = reply.GetDataSize();
    if (totalDBinderBufSize > 0 && replySize % BINDER_ALIGN_BYTES != 0) {
        ZLOGI(LABEL, "not 8 bytes aligned(%{public}zu), padding it", replySize);
        reply.WriteInt8(0);
    }
#endif

    int cmd = (totalDBinderBufSize > 0) ? BC_REPLY_SG : BC_REPLY;
    int error = WriteTransaction(cmd, flags, -1, 0, reply, &result, totalDBinderBufSize);
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
    if ((proxy == nullptr) || (proxy->GetSptrRefCount() <= 0)) {
        ZLOGE(LABEL, "Invalid proxy object %{public}u.", ProcessSkeleton::ConvertAddr(proxy));
        return;
    }
    ProcessSkeleton *current = ProcessSkeleton::GetInstance();
    std::u16string desc;
    if ((current != nullptr) && !current->IsValidObject(proxy, desc)) {
        ZLOGE(LABEL, "%{public}u is invalid", ProcessSkeleton::ConvertAddr(proxy));
    } else {
        std::string descTemp = Str16ToStr8(desc);
        CrashObjDumper dumper(descTemp.c_str());
        if (proxy->AttemptIncStrongRef(this)) {
            proxy->SendObituary();
            proxy->DecStrongRef(this);
        } else {
            ZLOGW(LABEL, "failed to increment strong reference count");
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
        ZLOGE(LABEL, "Invalid stub object %{public}u.", ProcessSkeleton::ConvertAddr(obj));
        return;
    }
    ProcessSkeleton *current = ProcessSkeleton::GetInstance();
    std::u16string desc;
    if ((current != nullptr) && !current->IsValidObject(obj, desc)) {
        ZLOGE(LABEL, "%{public}u is invalid", ProcessSkeleton::ConvertAddr(obj));
        return;
    }
    std::string descTemp = Str16ToStr8(desc);
    CrashObjDumper dumper(descTemp.c_str());
    if (obj->GetSptrRefCount() <= 0) {
        ZLOGE(LABEL, "Invalid stub object %{public}u.", ProcessSkeleton::ConvertAddr(obj));
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

    if (!result || !output_.WritePointer(refsPointer) || !output_.WritePointer(objectPointer)) {
        if (!output_.RewindWrite(rewindPos)) {
            output_.FlushBuffer();
        }
        return;
    }
}

void BinderInvoker::OnReleaseObject(uint32_t cmd)
{
    uintptr_t refsPointer = input_.ReadPointer();
    uintptr_t objectPointer = input_.ReadPointer();
    RefCounter *refs = reinterpret_cast<RefCounter *>(refsPointer);
    IRemoteObject *obj = reinterpret_cast<IRemoteObject *>(objectPointer);
    if ((refs == nullptr) || (obj == nullptr)) {
        ZLOGE(LABEL, "Invalid stub object %{public}u.", ProcessSkeleton::ConvertAddr(obj));
        return;
    }

    ZLOGD(LABEL, "refcount:%{public}d refs:%{public}u obj:%{public}u", refs->GetStrongRefCount(),
        ProcessSkeleton::ConvertAddr(refs), ProcessSkeleton::ConvertAddr(obj));
    if (cmd == BR_RELEASE) {
        std::lock_guard<std::mutex> lock(strongRefMutex_);
        decStrongRefs_.push_back(obj);
    } else {
        std::lock_guard<std::mutex> lock(weakRefMutex_);
        decWeakRefs_.push_back(refs);
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
        callerUid_, callerTokenID_, firstTokenID_, callerSid_, ProcessSkeleton::ConvertAddr(this) };
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
        if (targetObject == nullptr) {
            ZLOGE(LABEL, "Invalid stub object");
            return error;
        }
        auto current = ProcessSkeleton::GetInstance();
        std::u16string desc;
        if ((current != nullptr) && !current->IsValidObject(targetObject, desc)) {
            ZLOGE(LABEL, "%{public}u is invalid", ProcessSkeleton::ConvertAddr(targetObject));
        } else {
            std::string descTemp = Str16ToStr8(desc);
            CrashObjDumper dumper(descTemp.c_str());
            if (targetObject->GetSptrRefCount() > 0) {
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

    uint32_t &newFlags = const_cast<uint32_t&>(tr.flags);
    int isServerTraced = HitraceInvoker::TraceServerReceieve(static_cast<uint64_t>(tr.target.handle),
        tr.code, *data, newFlags);

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
    HitraceInvoker::TraceServerSend(static_cast<uint64_t>(tr.target.handle), tr.code, isServerTraced, newFlags);
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

void BinderInvoker::OnTransaction(uint32_t cmd, int32_t &error)
{
    binder_transaction_data_secctx trSecctx = {
        .secctx = 0,
    };
    const uint8_t *buffer = nullptr;
    bool isSecctx = (cmd == static_cast<uint32_t>(BR_TRANSACTION_SEC_CTX));
    uint32_t bufferSize = isSecctx ? sizeof(binder_transaction_data_secctx) : sizeof(binder_transaction_data);

    buffer = input_.ReadBuffer(bufferSize, false);
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

int BinderInvoker::HandleReply(MessageParcel *reply, bool &isStubRet)
{
    const size_t readSize = sizeof(binder_transaction_data);
    const uint8_t *buffer = input_.ReadBuffer(readSize, false);
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
        isStubRet = true;
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
        case BR_TRANSACTION_SEC_CTX:
        case BR_TRANSACTION:
            OnTransaction(cmd, error);
            break;
        case BR_SPAWN_LOOPER:
            OnSpawnThread();
            break;
        case BR_FINISHED:
            error = -ERR_TIMED_OUT;
            break;
        case BR_DEAD_BINDER:
            OnBinderDied();
            break;
        case BR_OK:
        case BR_NOOP:
            break;
        case BR_CLEAR_DEATH_NOTIFICATION_DONE:
            OnRemoveRecipientDone();
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
    if (error != ERR_NONE && error != -ERR_TIMED_OUT) {
        if (ProcessSkeleton::IsPrint(error, lastErr_, lastErrCnt_)) {
            ZLOGE(LABEL, "HandleCommands cmd:%{public}u error:%{public}d", cmd, error);
            PrintParcelData(input_, "input_");
            PrintParcelData(output_, "output_");
            std::string backtrace;
            if (!GetBacktrace(backtrace, false)) {
                ZLOGE(LABEL, "GetBacktrace fail");
            } else {
                ZLOGW(LABEL, "backtrace info:\n%{public}s", backtrace.c_str());
            }
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
    [[maybe_unused]] ThreadMigrationDisabler _d;
    isMainWorkThread = initiative;
    output_.WriteUint32(initiative ? BC_ENTER_LOOPER : BC_REGISTER_LOOPER);
    StartWorkLoop();
    output_.WriteUint32(BC_EXIT_LOOPER);
    // pass in nullptr directly
    FlushCommands(nullptr);
    ZLOGE(LABEL, "Current Thread:%{public}d is leaving", getpid());
}

void BinderInvoker::JoinProcessThread(bool initiative) {}

void BinderInvoker::UpdateConsumedData(const binder_write_read &bwr, const size_t outAvail)
{
    if (bwr.write_consumed > 0) {
        if (bwr.write_consumed < outAvail) {
            // we still have some bytes not been handled.
            PrintParcelData(input_, "input_");
            PrintParcelData(output_, "output_");
            ZLOGE(LABEL, "binder write_consumed:%{public}llu exception, "
                "outAvail:%{public}zu read_consumed:%{public}llu",
                bwr.write_consumed, outAvail, bwr.read_consumed);
        }

        // Moves the data that is not consumed by the binder to the output_ buffer header.
        if (bwr.write_consumed < output_.GetDataSize()) {
            ZLOGI(LABEL, "moves the data that is not consumed by the binder, "
                "write_consumed:%{public}llu outAvail:%{public}zu GetDataSize:%{public}zu",
                bwr.write_consumed, outAvail, output_.GetDataSize());
            Parcel temp;
            temp.WriteBuffer(reinterpret_cast<void *>(output_.GetData() + bwr.write_consumed),
                output_.GetDataSize() - bwr.write_consumed);
            output_.FlushBuffer();
            output_.WriteBuffer(reinterpret_cast<void *>(temp.GetData()), temp.GetDataSize());
        } else {
            --sendNestCount_;
            if (sendNestCount_ > 0) {
                ZLOGW(LABEL, "unexpected sendNestCount:%{public}d", sendNestCount_.load());
                PrintParcelData(input_, "input_");
                PrintParcelData(output_, "output_");
                sendNestCount_ = 0;
            }
            output_.FlushBuffer();
        }
    }
    if (bwr.read_consumed > 0) {
        input_.SetDataSize(bwr.read_consumed);
        input_.RewindRead(0);
    }
}

int BinderInvoker::TransactWithDriver(bool doRead)
{
    if ((binderConnector_ == nullptr) || (!binderConnector_->IsDriverAlive())) {
        return IPC_INVOKER_CONNECT_ERR;
    }

    binder_write_read bwr;
    const bool needRead = input_.GetReadableBytes() == 0;
    const size_t outAvail = (!doRead || needRead) ? output_.GetDataSize() : 0;

    bwr.write_size = (binder_size_t)outAvail;
    bwr.write_buffer = output_.GetData();

    if (doRead && needRead) {
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
    UpdateConsumedData(bwr, outAvail);
    if (error != ERR_NONE) {
        uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        ZLOGE(LABEL, "fail, result:%{public}d time:%{public}" PRIu64, error, curTime);
    }

    return error;
}

bool BinderInvoker::WriteTransaction(int cmd, uint32_t flags, int32_t handle, uint32_t code, const MessageParcel &data,
    const int32_t *status, size_t totalDBinderBufSize)
{
    binder_transaction_data_sg tr_sg {};
    auto &tr = tr_sg.transaction_data;
    bool isContainPtrType = totalDBinderBufSize > 0;

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
        tr_sg.buffers_size = isContainPtrType ? totalDBinderBufSize : 0;
    } else if (status != nullptr) {
        // Send this parcel's status through the binder.
        tr.flags |= TF_STATUS_CODE;
        tr.data_size = sizeof(int32_t);
        tr.data.ptr.buffer = reinterpret_cast<uintptr_t>(status);
        tr.offsets_size = 0;
        tr.data.ptr.offsets = 0;
    }

    if (!output_.WriteInt32(cmd)) {
        ZLOGE(LABEL, "write cmd fail");
        return false;
    }
    const void *buf = isContainPtrType ? static_cast<const void *>(&tr_sg) : static_cast<const void *>(&tr);
    size_t bufSize = isContainPtrType ? sizeof(tr_sg) : sizeof(tr);
    bool ret = output_.WriteBuffer(buf, bufSize);

    if (sendNestCount_ > 0) {
        ZLOGW(LABEL, "request nesting occurs, handle:%{public}d count:%{public}u", handle, sendNestCount_.load());
        PrintParcelData(input_, "input_");
        PrintParcelData(output_, "output_");
        std::string backtrace;
        if (!GetBacktrace(backtrace, false)) {
            ZLOGE(LABEL, "GetBacktrace fail");
        } else {
            ZLOGW(LABEL, "backtrace info:\n%{public}s", backtrace.c_str());
        }
    }
    ++sendNestCount_;
    return ret;
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

    bool isStubRet = false;
    error = HandleReply(reply, isStubRet);
    if (isStubRet || error != IPC_INVOKER_INVALID_REPLY_ERR) {
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
    if ((binderConnector_ == nullptr) || (!binderConnector_->IsDriverAlive()) || (object == nullptr)) {
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

    // Distribute data from output_ to the kernel for processing.
    int error = FlushCommands(nullptr);
    if (error != ERR_NONE) {
        ZLOGE(LABEL, "failed, error:%{public}d", error);
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
#ifndef CONFIG_IPC_SINGLE
    dbinder_negotiation_data dbinderData;
    bool isDBinderObj = UnFlattenDBinderObject(parcel, dbinderData);
#endif
    if (!parcel.CheckOffsets()) {
        ZLOGE(LABEL, "Parcel CheckOffsets fail");
        return nullptr;
    }
    const uint8_t *buffer = parcel.ReadBuffer(sizeof(flat_binder_object), false);
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
            auto stubObject = reinterpret_cast<IRemoteObject *>(flat->cookie);
            if (!current->IsContainsObject(stubObject)) {
                ZLOGE(LABEL, "invalid binder cookie:%{public}llu", flat->cookie);
                return nullptr;
            }
            remoteObject = stubObject;
            break;
        }
        case BINDER_TYPE_HANDLE: {
#ifndef CONFIG_IPC_SINGLE
            if (isDBinderObj) {
                ZLOGI(LABEL, "dbinder BINDER_TYPE_HANDLE");
            }
            remoteObject = current->FindOrNewObject(flat->handle, isDBinderObj ? &dbinderData : nullptr);
#else
            remoteObject = current->FindOrNewObject(flat->handle);
#endif
            break;
        }
        default:
            ZLOGE(LABEL, "unknown binder type:%{public}u", flat->hdr.type);
            break;
    }
    return remoteObject;
}

int BinderInvoker::ReadFileDescriptor(Parcel &parcel)
{
    int fd = -1;
    const uint8_t *buffer = parcel.ReadBuffer(sizeof(flat_binder_object), false);
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

void BinderInvoker::PrintIdentity(bool isPrint, bool isBefore)
{
    if (!isPrint) {
        return;
    }
    ZLOGI(LABEL, "%{public}s callingIdentity, callerSid:%{public}s, callerTokenID:%{public}" PRIu64 ", \
        callerRealPid:%{public}u, callerUid:%{public}u, callerPid:%{public}u",
        isBefore ? "Before" : "After", callerSid_.c_str(), callerTokenID_, callerRealPid_, callerUid_, callerPid_);
}

bool BinderInvoker::SetCallingIdentity(std::string &identity, bool flag)
{
    if (identity.empty() || identity.length() <= ACCESS_TOKEN_MAX_LEN) {
        return false;
    }
    auto pos = identity.find('<');
    if (pos == std::string::npos) {
        return false;
    }
    PrintIdentity(flag, true);
    std::string callerSid;
    if (!ProcessSkeleton::GetSubStr(identity, callerSid, 0, pos)) {
        ZLOGE(LABEL, "Identity param callerSid is invalid");
        return false;
    }
    std::string tokenIdStr;
    if (!ProcessSkeleton::GetSubStr(identity, tokenIdStr, pos + 1, ACCESS_TOKEN_MAX_LEN) ||
        !ProcessSkeleton::IsNumStr(tokenIdStr)) {
        ZLOGE(LABEL, "Identity param tokenId is invalid");
        return false;
    }
    std::string realPidStr;
    if (!ProcessSkeleton::GetSubStr(identity, realPidStr, pos + 1 + ACCESS_TOKEN_MAX_LEN, ACCESS_TOKEN_MAX_LEN) ||
        !ProcessSkeleton::IsNumStr(realPidStr)) {
        ZLOGE(LABEL, "Identity param realPid is invalid");
        return false;
    }
    std::string pidUidStr;
    size_t offset = pos + 1 + ACCESS_TOKEN_MAX_LEN * PIDUID_OFFSET;
    if (identity.length() <= offset) {
        ZLOGE(LABEL, "Identity param no pidUid, len:%{public}zu, offset:%{public}zu", identity.length(), offset);
        return false;
    }
    size_t subLen = identity.length() - offset;
    if (!ProcessSkeleton::GetSubStr(identity, pidUidStr, offset, subLen) || !ProcessSkeleton::IsNumStr(pidUidStr)) {
        ZLOGE(LABEL, "Identity param pidUid is invalid");
        return false;
    }
    callerSid_ = callerSid;
    callerTokenID_ = std::stoull(tokenIdStr.c_str());
    callerRealPid_ = static_cast<int>(std::stoull(realPidStr.c_str()));
    uint64_t pidUid = std::stoull(pidUidStr.c_str());
    callerUid_ = static_cast<int>(pidUid >> PID_LEN);
    callerPid_ = static_cast<int>(pidUid);
    PrintIdentity(flag, false);
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

void BinderInvoker::PrintParcelData(Parcel &parcel, const std::string &parcelName)
{
    std::string formatStr;
    size_t size = parcel.GetDataSize();
    auto data = reinterpret_cast<const uint8_t *>(parcel.GetData());
    size_t idex = 0;
    while (idex < size) {
        formatStr += std::to_string(data[idex]) + ',';
        ++idex;
    }
    ZLOGE(LABEL,
        "parcel name:%{public}s, size:%{public}zu, readpos:%{public}zu, writepos:%{public}zu, data:%{public}s",
        parcelName.c_str(), size, parcel.GetReadPosition(), parcel.GetWritePosition(), formatStr.c_str());
}

bool BinderInvoker::IsSendRequesting()
{
    return sendRequestCount_ > 0;
}

void BinderInvoker::ProcDeferredDecRefs()
{
    if (input_.GetReadableBytes() > 0) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(weakRefMutex_);
        for (size_t idx = 0; idx < decWeakRefs_.size(); ++idx) {
            auto &ref = decWeakRefs_[idx];
            ref->DecWeakRefCount(this);
        }
        decWeakRefs_.clear();
    }
    {
        ProcessSkeleton *current = ProcessSkeleton::GetInstance();
        if (current == nullptr) {
            ZLOGE(LABEL, "ProcessSkeleton is null");
            return;
        }
        std::lock_guard<std::mutex> lock(strongRefMutex_);
        for (size_t idx = 0; idx < decStrongRefs_.size(); ++idx) {
            auto &obj = decStrongRefs_[idx];
            std::u16string desc;
            if (!current->IsValidObject(obj, desc)) {
                ZLOGE(LABEL, "%{public}u is invalid", ProcessSkeleton::ConvertAddr(obj));
                continue;
            }
            std::string descTemp = Str16ToStr8(desc);
            CrashObjDumper dumper(descTemp.c_str());
            obj->DecStrongRef(this);
        }
        decStrongRefs_.clear();
    }
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
