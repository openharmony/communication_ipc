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

#include "check_instance_exit.h"
#include "ipc_debug.h"
#include "log_tags.h"

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
namespace IPC_SINGLE {
#endif

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_COMMON, "IPCWorkThreadPool" };

static void *g_selfSoHandler = nullptr;
static constexpr int32_t IDLE_SPAWN_ACTIVE_NUM = 1;
std::atomic<bool> IPCWorkThreadPool::exitFlag_ = false;

// this func is called when ipc_single and ipc_core before loading
// LCOV_EXCL_START
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
// LCOV_EXCL_STOP

IPCWorkThreadPool::IPCWorkThreadPool(int maxThreadNum)
    : threadSequence_(0), maxThreadNum_(maxThreadNum + maxThreadNum),
      idleThreadNum_(maxThreadNum + IDLE_SPAWN_ACTIVE_NUM), idleSocketThreadNum_(maxThreadNum)
{
}

IPCWorkThreadPool::~IPCWorkThreadPool()
{
    exitFlag_ = true;
    StopAllThreads();
}

void IPCWorkThreadPool::StopAllThreads()
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = threads_.begin(); it != threads_.end(); it++) {
        it->second->StopWorkThread();
    }
    threads_.clear();
}

bool IPCWorkThreadPool::SpawnThread(int policy, int proto)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::lock_guard<std::mutex> lock(mutex_);
    if (((proto == IRemoteObject::IF_PROT_DEFAULT) && (idleThreadNum_ <= 0)) ||
        ((proto == IRemoteObject::IF_PROT_DATABUS) && (idleSocketThreadNum_ <= 0))) {
        ZLOGE(LOG_LABEL, "Request thread exceeds online limit, proto:%{public}d", proto);
        return false;
    }
    int threadIndex = 0;
    std::string threadName = MakeThreadName(proto, threadIndex);
    ZLOGD(LOG_LABEL, "name:%{public}s", threadName.c_str());
    if (threads_.find(threadName) != threads_.end()) {
        ZLOGW(LOG_LABEL, "This thread already exists, threadName:%{public}s", threadName.c_str());
        return false;
    }

    sptr<IPCWorkThread> newThread = sptr<IPCWorkThread>::MakeSptr(threadName);
    if (newThread == nullptr) {
        ZLOGE(LOG_LABEL, "create IPCWorkThread object failed");
        return false;
    }
    threads_[threadName] = newThread;
    if (proto == IRemoteObject::IF_PROT_DEFAULT) {
        idleThreadNum_--;
        ZLOGD(LOG_LABEL, "now idleThreadNum:%{public}d", idleThreadNum_);
    } else if (proto == IRemoteObject::IF_PROT_DATABUS) {
        idleSocketThreadNum_--;
        ZLOGD(LOG_LABEL, "now idleSocketThreadNum:%{public}d", idleSocketThreadNum_);
    } else {
        ZLOGE(LOG_LABEL, "Proto is incorrect:%{public}d", proto);
        return false;
    }
    return newThread->Start(policy, proto, threadIndex);
}

std::string IPCWorkThreadPool::MakeThreadName(int proto, int &threadIndex)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, "");
    int sequence = threadSequence_.fetch_add(1, std::memory_order_relaxed);
    threadIndex = sequence;
    return IPCWorkThread::MakeBasicThreadName(proto, sequence);
}

bool IPCWorkThreadPool::RemoveThread(const std::string &threadName)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = threads_.find(threadName);
    if (it != threads_.end()) {
        sptr<IPCWorkThread> workThread = it->second;
        if (workThread == nullptr) {
            return false;
        }
        if (workThread->proto_ == IRemoteObject::IF_PROT_DEFAULT) {
            idleThreadNum_++;
        } else if (workThread->proto_ == IRemoteObject::IF_PROT_DATABUS) {
            idleSocketThreadNum_++;
        }
        threads_.erase(it);
        ZLOGD(LOG_LABEL, "now idleThreadNum:%{public}d", idleSocketThreadNum_);
        return true;
    }
    return false;
}

int IPCWorkThreadPool::GetSocketIdleThreadNum() const
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, 0);
    return idleSocketThreadNum_;
}

int IPCWorkThreadPool::GetSocketTotalThreadNum() const
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, 0);
    return maxThreadNum_ / PROTO_NUM;
}

int IPCWorkThreadPool::GetMaxThreadNum() const
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, 0);
    return (maxThreadNum_ / PROTO_NUM) + IDLE_SPAWN_ACTIVE_NUM;
}

void IPCWorkThreadPool::UpdateMaxThreadNum(int maxThreadNum)
{
    /*
     * not support delete thread, because thread is in using
     */
    CHECK_INSTANCE_EXIT(exitFlag_);
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
