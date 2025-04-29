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

#include "ipc_thread_pool.h"

#include <dlfcn.h>
#include <sys/types.h>
#include <unistd.h>

#include "ipc_debug.h"
#include "log_tags.h"

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
namespace IPC_SINGLE {
#endif

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_COMMON, "IPCWorkThreadPool" };

static void *g_selfSoHandler = nullptr;

// this func is called when ipc_single and ipc_core before loading
extern "C" __attribute__((constructor)) void InitIpcSo()
{
    if (g_selfSoHandler == nullptr) {
        Dl_info info;
        // dladdr func return value description
        // On success, these functions return a nonzero value.
        // If the address specified in addr could not be matched to a shared object, then these functions return 0
        int ret = dladdr(reinterpret_cast<void *>(InitIpcSo), &info);
        if (ret == 0) {
            ZLOGE(LOG_LABEL, "dladdr func call failed");
            return;
        }
        g_selfSoHandler = dlopen(info.dli_fname, RTLD_LAZY);
        if (g_selfSoHandler == nullptr) {
            const char *error = dlerror();
            ZLOGE(LOG_LABEL, "dlopen failed, dlerror:%{public}s", error != nullptr ? error : "unknown");
        }
    }
}

IPCWorkThreadPool::IPCWorkThreadPool(int maxThreadNum)
    : threadSequence_(0), maxThreadNum_(maxThreadNum + maxThreadNum), idleThreadNum_(maxThreadNum),
      idleSocketThreadNum_(maxThreadNum)
{
}

IPCWorkThreadPool::~IPCWorkThreadPool()
{
    StopAllThreads();
}

void IPCWorkThreadPool::StopAllThreads()
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = spawnPassiveThreads_.begin(); it != spawnPassiveThreads_.end(); it++) {
        it->second->StopWorkThread();
    }
    spawnPassiveThreads_.clear();
}

bool IPCWorkThreadPool::SpawnThread(int policy, int proto)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (((proto == IRemoteObject::IF_PROT_DEFAULT) && (idleThreadNum_ <= 0)) ||
        ((proto == IRemoteObject::IF_PROT_DATABUS) && (idleSocketThreadNum_ <= 0))) {
        ZLOGE(LOG_LABEL, "Request thread exceeds online limit, proto:%{public}d", proto);
        return false;
    }
    int threadIndex = 0;
    std::string threadName = MakeThreadName(proto, threadIndex);
    ZLOGD(LOG_LABEL, "name:%{public}s", threadName.c_str());
    if (spawnPassiveThreads_.find(threadName) != spawnPassiveThreads_.end()) {
        ZLOGW(LOG_LABEL, "This thread already exists, threadName:%{public}s", threadName.c_str());
        return false;
    }

    sptr<IPCWorkThread> newThread = sptr<IPCWorkThread>::MakeSptr(threadName);
    if (newThread == nullptr) {
        ZLOGE(LOG_LABEL, "create IPCWorkThread object failed");
        return false;
    }

    if (proto == IRemoteObject::IF_PROT_DEFAULT) {
        if (policy == IPCWorkThread::SPAWN_ACTIVE) {
            spawnActiveThreads_ = newThread;
        }
        // IdleThreadNum_ variable manages SPAWN-PASSIVE type, does not manage SPAWN-ACTION.
        if (policy == IPCWorkThread::SPAWN_PASSIVE) {
            spawnPassiveThreads_[threadName] = newThread;
            idleThreadNum_--;
            ZLOGD(LOG_LABEL, "now idleThreadNum:%{public}d", idleThreadNum_);
        }
    }
    if (proto == IRemoteObject::IF_PROT_DATABUS) {
        idleSocketThreadNum_--;
        ZLOGD(LOG_LABEL, "now idleSocketThreadNum:%{public}d", idleSocketThreadNum_);
    }
    return newThread->Start(policy, proto, threadIndex);
}

std::string IPCWorkThreadPool::MakeThreadName(int proto, int &threadIndex)
{
    int sequence = threadSequence_.fetch_add(1, std::memory_order_relaxed);
    threadIndex = sequence;
    return IPCWorkThread::MakeBasicThreadName(proto, sequence);
}

bool IPCWorkThreadPool::RemoveThread(const std::string &threadName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = spawnPassiveThreads_.find(threadName);
    if (it != spawnPassiveThreads_.end()) {
        sptr<IPCWorkThread> workThread = it->second;
        if (workThread == nullptr) {
            return false;
        }
        if ((workThread->proto_ == IRemoteObject::IF_PROT_DEFAULT) &&
            (workThread->policy_ == IPCWorkThread::SPAWN_PASSIVE)) {
            idleThreadNum_++;
        } else if (workThread->proto_ == IRemoteObject::IF_PROT_DATABUS) {
            idleSocketThreadNum_++;
        }
        spawnPassiveThreads_.erase(it);
        ZLOGD(LOG_LABEL, "now idleThreadNum:%{public}d", idleSocketThreadNum_);
        return true;
    }
    return false;
}

int IPCWorkThreadPool::GetSocketIdleThreadNum() const
{
    return idleSocketThreadNum_;
}

int IPCWorkThreadPool::GetSocketTotalThreadNum() const
{
    return maxThreadNum_ / PROTO_NUM;
}

int IPCWorkThreadPool::GetMaxThreadNum() const
{
    return maxThreadNum_ / PROTO_NUM;
}

void IPCWorkThreadPool::UpdateMaxThreadNum(int maxThreadNum)
{
    /*
     * not support delete thread, because thread is in using
     */
    int totalNum = maxThreadNum + maxThreadNum;
    std::lock_guard<std::mutex> lock(mutex_);
    if (totalNum <= maxThreadNum_) {
        return;
    }
    int diff = totalNum - maxThreadNum_;
    maxThreadNum_ = totalNum;
    idleThreadNum_ += diff / PROTO_NUM;
    idleSocketThreadNum_ += diff / PROTO_NUM;
}
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS
