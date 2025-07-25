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

#include "ipc_thread_skeleton.h"

#include <cinttypes>
#include <memory>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include "binder_invoker.h"
#include "ffrt.h"
#include "hilog/log_c.h"
#include "hilog/log_cpp.h"
#include "invoker_factory.h"
#include "ipc_debug.h"
#include "ipc_object_proxy.h"
#include "iremote_invoker.h"
#include "iremote_object.h"
#include "log_tags.h"
#include "new"
#include "process_skeleton.h"
#include "pthread.h"

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
namespace IPC_SINGLE {
#endif
using namespace OHOS::HiviewDFX;
pthread_key_t IPCThreadSkeleton::TLSKey_ = 0;
pthread_once_t IPCThreadSkeleton::TLSKeyOnce_ = PTHREAD_ONCE_INIT;

static constexpr uint32_t MAX_THREAD_NAME_LEN = 20;
static constexpr HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_THREAD_SKELETON, "IPCThreadSkeleton" };

extern "C" __attribute__((destructor)) void DeleteTlsKey()
{
    pthread_key_t key = IPCThreadSkeleton::GetTlsKey();
    pthread_key_delete(key);
}

void IPCThreadSkeleton::TlsDestructor(void *args)
{
    auto *current = static_cast<IPCThreadSkeleton *>(args);
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current is nullptr");
        return;
    }

    uint32_t ret = current->usingFlag_.load();
    if ((ret != INVOKER_USE_MAGIC) && (ret != INVOKER_IDLE_MAGIC)) {
        ZLOGF(LOG_LABEL, "memory may be damaged, ret:%{public}u", ret);
        return;
    }

    uint32_t itemIndex = static_cast<uint32_t>(IRemoteObject::IF_PROT_BINDER);
    if (itemIndex < IPCThreadSkeleton::INVOKER_MAX_COUNT && current->invokers_[itemIndex] != nullptr) {
        BinderInvoker *invoker = reinterpret_cast<BinderInvoker *>(current->invokers_[itemIndex]);
        invoker->FlushCommands(nullptr);
        invoker->ExitCurrentThread();
    }
    delete current;
}

// LCOV_EXCL_START
void IPCThreadSkeleton::MakeTlsKey()
{
    auto ret = pthread_key_create(&TLSKey_, IPCThreadSkeleton::TlsDestructor);
    if (ret != 0) {
        ZLOGE(LOG_LABEL, "pthread_key_create fail, ret:%{public}d", ret);
        return;
    }
    ZLOGD(LOG_LABEL, "key:%{public}d", TLSKey_);
}
// LCOV_EXCL_STOP

void IPCThreadSkeleton::GetVaildInstance(IPCThreadSkeleton *&instance)
{
    if (instance == nullptr) {
        ZLOGE(LOG_LABEL, "instance is null");
        return;
    }

    // 1. a FFRT task may be executed on multiple threads in different time periods.
    // 2. a thread can executed multiple FFRT tasks in different time periods.
    auto tid = gettid();
    auto taskId = ffrt_this_task_get_id();
    if (tid != instance->tid_ && taskId != instance->ffrtTaskId_) {
        ZLOGE(LOG_LABEL, "TLS mismatch, curTid:%{public}d tlsTid:%{public}d, curTaskId:%{public}" PRIu64
            " tlsTaskId:%{public}" PRIu64 ", key:%{public}u instance:%{public}u threadName:%{public}s",
            tid, instance->tid_, taskId, instance->ffrtTaskId_, TLSKey_, ProcessSkeleton::ConvertAddr(instance),
            instance->threadName_.c_str());
        pthread_setspecific(TLSKey_, nullptr);
        instance = new (std::nothrow) IPCThreadSkeleton();
    }
}

void IPCThreadSkeleton::SaveThreadName(const std::string &name)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    if (IsInstanceException(current->exitFlag_)) {
        return;
    }
    current->threadName_ = name;
}

// LCOV_EXCL_START
IPCThreadSkeleton *IPCThreadSkeleton::GetCurrent()
{
    pthread_once(&TLSKeyOnce_, IPCThreadSkeleton::MakeTlsKey);

    IPCThreadSkeleton *current = nullptr;
    void *curTLS = pthread_getspecific(TLSKey_);
    if (curTLS != nullptr) {
        current = reinterpret_cast<IPCThreadSkeleton *>(curTLS);
        if (IsInstanceException(current->exitFlag_)) {
            return nullptr;
        }
        GetVaildInstance(current);
    } else {
        current = new (std::nothrow) IPCThreadSkeleton();
    }
    return current;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
IPCThreadSkeleton::IPCThreadSkeleton() : tid_(gettid()), ffrtTaskId_(ffrt_this_task_get_id())
{
    pthread_setspecific(TLSKey_, this);
    char name[MAX_THREAD_NAME_LEN] = { 0 };
    auto ret = prctl(PR_GET_NAME, name);
    if (ret != 0) {
        ZLOGW(LOG_LABEL, "get thread name fail, tid:%{public}d ret:%{public}d", tid_, ret);
        return;
    }
    threadName_ = name;
    ZLOGD(LOG_LABEL, "instance:%{public}u name:%{public}s", ProcessSkeleton::ConvertAddr(this), threadName_.c_str());
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
IPCThreadSkeleton::~IPCThreadSkeleton()
{
    exitFlag_ = INVOKER_IDLE_MAGIC;
    pthread_setspecific(TLSKey_, nullptr);
    uint32_t ret = usingFlag_.load();
    while (ret == INVOKER_USE_MAGIC) {
        ZLOGI(LOG_LABEL, "%{public}u is using, wait a moment", ProcessSkeleton::ConvertAddr(this));
        usleep(1);
        ret = usingFlag_.load();
    }
    if ((ret != INVOKER_USE_MAGIC) && (ret != INVOKER_IDLE_MAGIC)) {
        ZLOGF(LOG_LABEL, "memory may be damaged, ret:%{public}u", ret);
        return;
    }

    for (auto &invoker : invokers_) {
        delete invoker;
        invoker = nullptr;
    }
    if (threadType_ == ThreadType::IPC_THREAD) {
        // subtract thread count when thread exiting
        auto process = ProcessSkeleton::GetInstance();
        if (process != nullptr) {
            process->DecreaseThreadCount();
        }
    }
    ZLOGD(LOG_LABEL, "thread exit, instance:%{public}u name:%{public}s threadType:%{public}d",
        ProcessSkeleton::ConvertAddr(this), threadName_.c_str(), threadType_);
}
// LCOV_EXCL_STOP

bool IPCThreadSkeleton::IsInstanceException(std::atomic<uint32_t> &flag)
{
    if (flag == INVOKER_USE_MAGIC) {
        return false;
    }

    if (flag == INVOKER_IDLE_MAGIC) {
        ZLOGE(LOG_LABEL, "Instance is exiting");
        return true;
    }

    ZLOGE(LOG_LABEL, "Memory may be damaged, flag:%{public}u", flag.load());
    return true;
}

IRemoteInvoker *IPCThreadSkeleton::GetRemoteInvoker(int proto)
{
    if (proto < 0 || static_cast<uint32_t>(proto) >= IPCThreadSkeleton::INVOKER_MAX_COUNT) {
        ZLOGE(LOG_LABEL, "invalid proto:%{public}d", proto);
        return nullptr;
    }

    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    if (current == nullptr) {
        return nullptr;
    }
    if (IsInstanceException(current->exitFlag_)) {
        return nullptr;
    }

    if ((current->usingFlag_ != INVOKER_USE_MAGIC) && (current->usingFlag_ != INVOKER_IDLE_MAGIC)) {
        ZLOGF(LOG_LABEL, "memory may be damaged, flag:%{public}u", current->usingFlag_.load());
        return nullptr;
    }
    current->usingFlag_ = INVOKER_USE_MAGIC;
    IRemoteInvoker *invoker = nullptr;
    auto it = current->invokers_[proto];
    if (it != nullptr) {
        invoker = it;
    } else {
        InvokerFactory &factory = InvokerFactory::Get();
        invoker = factory.newInstance(proto);
        if (invoker == nullptr) {
            current->usingFlag_ = INVOKER_IDLE_MAGIC;
            uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
            ZLOGE(LOG_LABEL, "invoker is NULL, proto:%{public}d time:%{public}" PRIu64, proto, curTime);
            return nullptr;
        }

        // non-thread safe, add lock to protect it.
        current->invokers_[proto] = invoker;
    }

    current->usingFlag_ = INVOKER_IDLE_MAGIC;
    return invoker;
}

// LCOV_EXCL_START
IRemoteInvoker *IPCThreadSkeleton::GetActiveInvoker()
{
    IRemoteInvoker *binderInvoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_BINDER);
    if ((binderInvoker != nullptr) && (binderInvoker->GetStatus() == IRemoteInvoker::ACTIVE_INVOKER)) {
        return binderInvoker;
    }
#ifndef CONFIG_IPC_SINGLE
    IRemoteInvoker *dbinderInvoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS);
    if ((dbinderInvoker != nullptr) && (dbinderInvoker->GetStatus() == IRemoteInvoker::ACTIVE_INVOKER)) {
        return dbinderInvoker;
    }
#endif
    return nullptr;
}
// LCOV_EXCL_STOP

IRemoteInvoker *IPCThreadSkeleton::GetProxyInvoker(IRemoteObject *object)
{
    if (object == nullptr) {
        ZLOGE(LOG_LABEL, "proxy is invalid");
        return nullptr;
    }
    if (!object->IsProxyObject()) {
        return nullptr;
    }

    IPCObjectProxy *proxy = reinterpret_cast<IPCObjectProxy *>(object);
    return IPCThreadSkeleton::GetRemoteInvoker(proxy->GetProto());
}

IRemoteInvoker *IPCThreadSkeleton::GetDefaultInvoker()
{
    return GetRemoteInvoker(IRemoteObject::IF_PROT_DEFAULT);
}

pthread_key_t IPCThreadSkeleton::GetTlsKey()
{
    return TLSKey_;
}

void IPCThreadSkeleton::JoinWorkThread(int proto)
{
    IRemoteInvoker *invoker = GetRemoteInvoker(proto);
    if (invoker != nullptr) {
        invoker->JoinThread(true);
    }
}

void IPCThreadSkeleton::StopWorkThread(int proto)
{
    IRemoteInvoker *invoker = GetRemoteInvoker(proto);
    if (invoker != nullptr) {
        invoker->StopWorkThread();
    }
}

bool IPCThreadSkeleton::UpdateSendRequestCount(int delta)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    if (IsInstanceException(current->exitFlag_)) {
        return false;
    }
    current->sendRequestCount_ += delta;
    return true;
}

// LCOV_EXCL_START
bool IPCThreadSkeleton::IsSendRequesting()
{
    return sendRequestCount_ > 0;
}
// LCOV_EXCL_STOP

bool IPCThreadSkeleton::SetThreadType(ThreadType type)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "IPCThreadSkeleton current get failed");
        return false;
    }

    current->threadType_ = type;
    return true;
}

// LCOV_EXCL_START
ThreadType IPCThreadSkeleton::GetThreadType()
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "IPCThreadSkeleton current get failed");
        return ThreadType::NORMAL_THREAD;
    }
    return current->threadType_;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
int32_t IPCThreadSkeleton::GetThreadInvocationState()
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_BINDER);
    if (invoker == nullptr) {
        ZLOGE(LOG_LABEL, "get remote invoker failed");
        return STATUS_UNKNOWN;
    }
    if(invoker->GetStatus() != IRemoteInvoker::ACTIVE_INVOKER) {
        ZLOGE(LOG_LABEL, "not ipc thread");
        return STATUS_NO_SUPPORT;
    }
    BinderInvoker *binder = reinterpret_cast<BinderInvoker *>(invoker);
    return binder->GetInvocationState();
}
// LCOV_EXCL_STOP
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS
