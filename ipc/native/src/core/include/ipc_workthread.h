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

#ifndef OHOS_IPC_IPC_WORK_THREAD_H
#define OHOS_IPC_IPC_WORK_THREAD_H

#include <string>
#include <thread>
#include "refbase.h"
#include "hilog/log.h"
#include "iremote_invoker.h"
#include "log_tags.h"

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
namespace IPC_SINGLE {
#endif

class IPCWorkThread : public virtual RefBase {
public:
    enum {
        SPAWN_PASSIVE,
        SPAWN_ACTIVE,
        PROCESS_PASSIVE,
        PROCESS_ACTIVE
    };
    explicit IPCWorkThread(std::string threadName);

    ~IPCWorkThread();

    void ThreadHandler();

    void Start(int policy, int proto, std::string threadName);

    void StopWorkThread();
    int proto_ = IRemoteObject::IF_PROT_DEFAULT;

private:
    int policy_ = SPAWN_PASSIVE;
    std::thread thread_;
    const std::string threadName_;
    static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "IPCWorkThread" };
};
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS
#endif // OHOS_IPC_IPC_WORK_THREAD_H
