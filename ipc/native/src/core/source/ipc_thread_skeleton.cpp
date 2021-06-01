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
#include "ipc_debug.h"
#include "dbinder_error_code.h"
#include "log_tags.h"
#include "ipc_object_proxy.h"

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
namespace IPC_SINGLE {
#endif

using namespace OHOS::HiviewDFX;
pthread_key_t IPCThreadSkeleton::TLSKey_ = 0;
pthread_once_t IPCThreadSkeleton::TLSKeyOnce_ = PTHREAD_ONCE_INIT;

static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "IPCThreadSkeleton" };
void IPCThreadSkeleton::TlsDestructor(void *args)
{
    auto *current = static_cast<IPCThreadSkeleton *>(args);
    auto it = current->invokers_.find(IRemoteObject::IF_PROT_BINDER);
    if (it != current->invokers_.end()) {
        ZLOGW(LABEL, "thread exit, flush commands");
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
        current = new IPCThreadSkeleton();
    }

    return current;
}

IPCThreadSkeleton::IPCThreadSkeleton()
{
    pthread_setspecific(TLSKey_, this);
}

IPCThreadSkeleton::~IPCThreadSkeleton()
{
    ZLOGE(LABEL, "IPCThreadSkeleton delete");
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

    auto it = current->invokers_.find(proto);
    if (it != current->invokers_.end()) {
        invoker = it->second;
    } else {
        InvokerFactory &factory = InvokerFactory::Get();
        invoker = factory.newInstance(proto);
        if (invoker == nullptr) {
            ZLOGE(LABEL, "invoker is NULL proto = %d", proto);
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

void IPCThreadSkeleton::JoinWorkThread(int prot)
{
    IRemoteInvoker *invoker = GetRemoteInvoker(prot);
    if (invoker != nullptr) {
        invoker->JoinThread(true);
    }
}

void IPCThreadSkeleton::StopWorkThread(int prot)
{
    IRemoteInvoker *invoker = GetRemoteInvoker(prot);
    if (invoker != nullptr) {
        invoker->StopWorkThread();
    }
}
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS
