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

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_COMMON, "IPCWorkThread" };

struct IPCWorkThreadParam {
    int proto;
    int policy;
    int index;
};

IPCWorkThread::IPCWorkThread(std::string threadName) : threadName_(std::move(threadName)) {}

IPCWorkThread::~IPCWorkThread()
{
    StopWorkThread();
}

std::string IPCWorkThread::MakeBasicThreadName(int proto, int threadIndex)
{
    if (proto == IRemoteObject::IF_PROT_DATABUS) {
        return "OS_RPC_" + std::to_string(threadIndex);
    } else {
        return "OS_IPC_" + std::to_string(threadIndex);
    }
}

void IPCWorkThread::JoinThread(int proto, int policy)
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(proto);
    if (invoker != nullptr) {
        switch (policy) {
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
#ifdef CONFIG_ACTV_BINDER
            case ACTV_PASSIVE:
                BinderInvoker::JoinActvThread(false);
                break;
            case ACTV_ACTIVE:
                BinderInvoker::JoinActvThread(true);
                break;
#endif
            default:
                ZLOGE(LOG_LABEL, "invalid policy:%{public}d", policy);
                break;
        }
    }
}

void *IPCWorkThread::ThreadHandler(void *args)
{
    (void)IPCThreadSkeleton::SetThreadType(ThreadType::IPC_THREAD);
    ProcessSkeleton *process = ProcessSkeleton::GetInstance();
    if (process == nullptr) {
        ZLOGE(LOG_LABEL, "get ProcessSkeleton object failed");
        return nullptr;
    }

    if (process->GetThreadStopFlag()) {
        ZLOGW(LOG_LABEL, "the stop flag is true, thread start exit");
        return nullptr;
    }

    auto param = (IPCWorkThreadParam *)args;
    if (param == nullptr) {
        return nullptr;
    }

    IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(param->proto);
    std::string basicName = MakeBasicThreadName(param->proto, param->index);
    std::string threadName = basicName + "_" + std::to_string(syscall(SYS_gettid));
    int32_t ret = prctl(PR_SET_NAME, threadName.c_str());
    if (ret != 0) {
        ZLOGE(LOG_LABEL, "set thread name:%{public}s fail, ret:%{public}d", threadName.c_str(), ret);
    } else {
        ZLOGI(LOG_LABEL, "proto:%{public}d policy:%{public}d name:%{public}s",
            param->proto, param->policy, threadName.c_str());
    }
    IPCThreadSkeleton::SaveThreadName(threadName);

    JoinThread(param->proto, param->policy);

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current != nullptr) {
        current->OnThreadTerminated(basicName);
    }
    ZLOGI(LOG_LABEL, "exit, proto:%{public}d policy:%{public}d name:%{public}s invoker:%{public}u",
        param->proto, param->policy, threadName.c_str(), ProcessSkeleton::ConvertAddr(invoker));
    delete param;
    return nullptr;
}

void IPCWorkThread::StopWorkThread()
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(proto_);
    if (invoker != nullptr) {
        invoker->StopWorkThread();
    }
}

void IPCWorkThread::Start(int policy, int proto, int threadIndex)
{
    ProcessSkeleton *process = ProcessSkeleton::GetInstance();
    if (process == nullptr) {
        ZLOGE(LOG_LABEL, "get ProcessSkeleton object failed");
        return;
    }

    if (process->GetThreadStopFlag()) {
        ZLOGW(LOG_LABEL, "the stop flag is true, can not create other thread");
        return;
    }

    auto param = new (std::nothrow) IPCWorkThreadParam();
    if (param == nullptr) {
        ZLOGE(LOG_LABEL, "create IPCWorkThreadParam failed");
        return;
    }

    policy_ = policy;
    proto_ = proto;
    param->policy = policy;
    param->proto = proto;
    param->index = threadIndex;
    pthread_t threadId;

    int ret = pthread_create(&threadId, NULL, &IPCWorkThread::ThreadHandler, param);
    if (ret != 0) {
        ZLOGE(LOG_LABEL, "create thread failed, ret:%{public}d", ret);
        return;
    }
    process->IncreaseThreadCount();
    ZLOGD(LOG_LABEL, "create thread, policy:%{public}d proto:%{public}d", policy, proto);
    if (pthread_detach(threadId) != 0) {
        ZLOGE(LOG_LABEL, "detach error");
    }
}
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS
