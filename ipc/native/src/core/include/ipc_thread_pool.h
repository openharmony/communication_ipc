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

#ifndef OHOS_IPC_IPC_WORK_THREAD_POOL_H
#define OHOS_IPC_IPC_WORK_THREAD_POOL_H

#include <functional>
#include <thread>
#include <map>
#include <atomic>
#include <mutex>
#include <ipc_workthread.h>
#include "hilog/log.h"
#include "log_tags.h"

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
namespace IPC_SINGLE {
#endif

class IPCWorkThreadPool {
public:
    IPCWorkThreadPool(const IPCWorkThreadPool &) = delete;

    IPCWorkThreadPool(IPCWorkThreadPool &&) = delete;

    ~IPCWorkThreadPool();

    IPCWorkThreadPool &operator = (const IPCWorkThreadPool &) = delete;

    IPCWorkThreadPool &operator = (IPCWorkThreadPool &&) = delete;

    bool SpawnThread(int policy = IPCWorkThread::SPAWN_PASSIVE, int proto = IRemoteObject::IF_PROT_DEFAULT);

    bool RemoveThread(const std::string &threadName);

    void StopAllThreads();

    explicit IPCWorkThreadPool(int maxThreadNum);

    int GetMaxThreadNum() const;

    void UpdateMaxThreadNum(int maxThreadNum);
    int GetSocketIdleThreadNum() const;
    int GetSocketTotalThreadNum() const;

private:
    static constexpr int PROTO_NUM = 2;
    std::string MakeThreadName(int proto);
    std::map<std::string, sptr<IPCWorkThread>> threads_;
    std::atomic<int> threadSequence_;
    int maxThreadNum_;
    int idleThreadNum_;
    int idleSocketThreadNum_;
    std::mutex mutex_;
    static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "IPCWorkThreadPool" };
};
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS
#endif // OHOS_IPC_IPC_WORK_THREAD_POOL_H
