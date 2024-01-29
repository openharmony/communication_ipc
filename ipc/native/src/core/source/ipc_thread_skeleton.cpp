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

#include "ipc_thread_skeleton.h"

#include <memory>
#include <sys/syscall.h>

#include "binder_invoker.h"
#include "hilog/log_c.h"
#include "hilog/log_cpp.h"
#include "invoker_factory.h"
#include "ipc_debug.h"
#include "ipc_object_proxy.h"
#include "iremote_invoker.h"
#include "iremote_object.h"
#include "log_tags.h"
#include "new"
#include "pthread.h"

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
namespace IPC_SINGLE {
#endif
using namespace OHOS::HiviewDFX;
pthread_key_t IPCThreadSkeleton::TLSKey_ = 0;
pthread_once_t IPCThreadSkeleton::TLSKeyOnce_ = PTHREAD_ONCE_INIT;
std::recursive_mutex IPCThreadSkeleton::mutex_;

static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC_THREAD_SKELETON, "IPCThreadSkeleton" };
void IPCThreadSkeleton::TlsDestructor(void *args)
{
    std::lock_guard<std::recursive_mutex> lockGuard(mutex_);
    auto *current = static_cast<IPCThreadSkeleton *>(args);
    auto it = current->invokers_.find(IRemoteObject::IF_PROT_BINDER);
    if (it != current->invokers_.end()) {
        BinderInvoker *invoker = reinterpret_cast<BinderInvoker *>(it->second);
        invoker->FlushCommands(nullptr);
        invoker->ExitCurrentThread();
    }
    delete current;
}

void IPCThreadSkeleton::MakeTlsKey()
{
    pthread_key_create(&TLSKey_, IPCThreadSkeleton::TlsDestructor);
}

IPCThreadSkeleton *IPCThreadSkeleton::GetCurrent()
{
    IPCThreadSkeleton *current = nullptr;

    pthread_once(&TLSKeyOnce_, IPCThreadSkeleton::MakeTlsKey);

    void *curTLS = pthread_getspecific(TLSKey_);
    if (curTLS != nullptr) {
        current = reinterpret_cast<IPCThreadSkeleton *>(curTLS);
    } else {
        current = new (std::nothrow) IPCThreadSkeleton();
    }

    return current;
}

IPCThreadSkeleton::IPCThreadSkeleton()
{
    pthread_setspecific(TLSKey_, this);
}

IPCThreadSkeleton::~IPCThreadSkeleton()
{
    std::lock_guard<std::recursive_mutex> lockGuard(mutex_);
    ZLOGI(LABEL, "%{public}u_%{public}u", static_cast<uint32_t>(getpid()),
        static_cast<uint32_t>(syscall(SYS_gettid)));
    for (auto it = invokers_.begin(); it != invokers_.end();) {
        delete it->second;
        it = invokers_.erase(it);
    }
}

IRemoteInvoker *IPCThreadSkeleton::GetRemoteInvoker(int proto)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    IRemoteInvoker *invoker = nullptr;
    if (current == nullptr) {
        return nullptr;
    }
    std::lock_guard<std::recursive_mutex> lockGuard(mutex_);
    auto it = current->invokers_.find(proto);
    if (it != current->invokers_.end()) {
        invoker = it->second;
    } else {
        InvokerFactory &factory = InvokerFactory::Get();
        invoker = factory.newInstance(proto);
        if (invoker == nullptr) {
            uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
            ZLOGE(LABEL, "invoker is NULL, proto:%{public}d time:%{public}" PRIu64, proto, curTime);
            return nullptr;
        }

        // non-thread safe, add lock to protect it.
        current->invokers_.insert(std::make_pair(proto, invoker));
    }

    return invoker;
}

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

IRemoteInvoker *IPCThreadSkeleton::GetProxyInvoker(IRemoteObject *object)
{
    if (object == nullptr) {
        ZLOGE(LABEL, "proxy is invalid");
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
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS
