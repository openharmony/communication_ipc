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
#include <unistd.h>
#include <sys/types.h>
#include "ipc_debug.h"
#include "log_tags.h"

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
namespace IPC_SINGLE {
#endif

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC, "IPCWorkThreadPool" };

#define DBINDER_LOGI(fmt, args...) (void)OHOS::HiviewDFX::HiLog::Info(LOG_LABEL, "%{public}d: " fmt, __LINE__, ##args)

IPCWorkThreadPool::IPCWorkThreadPool(int maxThreadNum)
    : threadSequence_(0),
      maxThreadNum_(maxThreadNum + maxThreadNum),
      idleThreadNum_(maxThreadNum),
      idleSocketThreadNum_(maxThreadNum)
{}

IPCWorkThreadPool::~IPCWorkThreadPool()
{
    StopAllThreads();
    threads_.clear();
}

void IPCWorkThreadPool::StopAllThreads()
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = threads_.begin(); it != threads_.end(); it++) {
        it->second->StopWorkThread();
    }
}

bool IPCWorkThreadPool::SpawnThread(int policy, int proto)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!(proto == IRemoteObject::IF_PROT_DEFAULT && idleThreadNum_ > 0) &&
        !(proto == IRemoteObject::IF_PROT_DATABUS && idleSocketThreadNum_ > 0)) {
        return false;
    }
    std::string threadName = MakeThreadName(proto);
    DBINDER_LOGI("SpawnThread Name= %{public}s", threadName.c_str());

    if (threads_.find(threadName) == threads_.end()) {
        sptr<IPCWorkThread> newThread = sptr<IPCWorkThread>(new IPCWorkThread(threadName));
        threads_[threadName] = newThread;
        if (proto == IRemoteObject::IF_PROT_DEFAULT) {
            idleThreadNum_--;
            DBINDER_LOGI("SpawnThread, now idleThreadNum_ =%d", idleThreadNum_);
        }
        if (proto == IRemoteObject::IF_PROT_DATABUS) {
            idleSocketThreadNum_--;
            DBINDER_LOGI("SpawnThread, now idleSocketThreadNum_ =%d", idleSocketThreadNum_);
        }

        newThread->Start(policy, proto, threadName);
        return true;
    }
    return false;
}

std::string IPCWorkThreadPool::MakeThreadName(int proto)
{
    int sequence = threadSequence_.fetch_add(1, std::memory_order_relaxed);
    if (proto == IRemoteObject::IF_PROT_DATABUS) {
        std::string threadName = "DRPC";
        return std::to_string(sequence) + threadName;
    } else {
        std::string threadName = "IPC";
        return std::to_string(sequence) + threadName;
    }
}

bool IPCWorkThreadPool::RemoveThread(const std::string &threadName)
{
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
        DBINDER_LOGI("SpawnThread, now idleThreadNum_ =%d", idleSocketThreadNum_);
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
} // namesapce OHOS

