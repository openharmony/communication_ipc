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

#include "ipc_workthread.h"

#include <cmath>
#include <cstddef>
#include <memory>
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "hilog/log_cpp.h"
#include "iosfwd"
#include "ipc_debug.h"
#include "ipc_process_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "iremote_invoker.h"
#include "string"
#include "type_traits"
#include "unistd.h"

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
namespace IPC_SINGLE {
#endif

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC, "IPCWorkThread" };

IPCWorkThread::IPCWorkThread(std::string threadName) : threadName_(std::move(threadName)) {}

IPCWorkThread::~IPCWorkThread()
{
    StopWorkThread();
}

void *IPCWorkThread::ThreadHandler(void *args)
{
    IPCWorkThread *threadObj = (IPCWorkThread *)args;
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(threadObj->proto_);
    threadObj->threadName_ += "_" + std::to_string(syscall(SYS_gettid));
    int32_t ret = prctl(PR_SET_NAME, threadObj->threadName_.c_str());
    if (ret != 0) {
        ZLOGE(LOG_LABEL, "set thread name: %{public}s fail, ret: %{public}d",
            threadObj->threadName_.c_str(), ret);
    }
    ZLOGD(LOG_LABEL, "proto_=%{public}d,policy_=%{public}d, name: %{public}s, ret: %{public}d",
        threadObj->proto_, threadObj->policy_, threadObj->threadName_.c_str(), ret);
    if (invoker != nullptr) {
        switch (threadObj->policy_) {
            case SPAWN_PASSIVE:
                invoker->JoinThread(false);
                break;
            case SPAWN_ACTIVE:
                invoker->JoinThread(true);
                break;
            case PROCESS_PASSIVE:
                invoker->JoinProcessThread(false);
                break;
            case PROCESS_ACTIVE:
                invoker->JoinProcessThread(true);
                break;
            default:
                ZLOGE(LOG_LABEL, "policy_ = %{public}d", threadObj->policy_);
                break;
        }
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current != nullptr) {
        current->OnThreadTerminated(threadObj->threadName_);
    }
    return nullptr;
}

void IPCWorkThread::StopWorkThread()
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(proto_);
    if (invoker != nullptr) {
        invoker->StopWorkThread();
    }
}

void IPCWorkThread::Start(int policy, int proto, std::string threadName)
{
    policy_ = policy;
    proto_ = proto;
    threadName_ = threadName;
    pthread_t threadId;
    int ret = pthread_create(&threadId, NULL, &IPCWorkThread::ThreadHandler, this);
    if (ret != 0) {
        ZLOGE(LOG_LABEL, "create thread failed");
    }
    ZLOGD(LOG_LABEL, "create thread, policy=%d, proto=%d", policy, proto);
    if (pthread_detach(threadId) != 0) {
        ZLOGE(LOG_LABEL, "detach error");
    }
}
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS
