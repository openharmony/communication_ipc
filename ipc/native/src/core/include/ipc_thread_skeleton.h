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

#ifndef OHOS_IPC_IPC_THREAD_SKELETON_H
#define OHOS_IPC_IPC_THREAD_SKELETON_H

#include <mutex>
#include <pthread.h>
#include <unordered_map>
#include "iremote_invoker.h"
#include "binder_invoker.h"

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
namespace IPC_SINGLE {
#endif

enum class ThreadType {
    NORMAL_THREAD = 0xB0B0B0B0,
    IPC_THREAD = 0xB1B1B1B1,
};

class IPCThreadSkeleton {
public:
    IPCThreadSkeleton();

    ~IPCThreadSkeleton();

    static void TlsDestructor(void *args);
    static void MakeTlsKey();

    static IPCThreadSkeleton *GetCurrent();

    static IRemoteInvoker *GetRemoteInvoker(int proto);

    static IRemoteInvoker *GetDefaultInvoker();

    static IRemoteInvoker *GetActiveInvoker();

    static IRemoteInvoker *GetProxyInvoker(IRemoteObject *object);

    static pthread_key_t GetTlsKey();

    static void GetVaildInstance(IPCThreadSkeleton *&instance);

    static void SaveThreadName(const std::string &name);

    static bool UpdateSendRequestCount(int delta);

    static bool CheckInstanceIsExiting(std::atomic<uint32_t> &flag);

    static bool SetThreadType(ThreadType type);

    bool IsSendRequesting();

    // Joint Current thread into IPC Work Group
    void JoinWorkThread(int proto);
    // Quit current thread from IPC work group.
    void StopWorkThread(int proto);

    static constexpr uint32_t INVOKER_USE_MAGIC = 0x5A5A5A5A;
    static constexpr uint32_t INVOKER_IDLE_MAGIC = 0xA5A5A5A5;

private:
    static pthread_key_t TLSKey_;
    static pthread_once_t TLSKeyOnce_;
    std::atomic<uint32_t> exitFlag_ = INVOKER_USE_MAGIC;
    std::atomic<uint32_t> usingFlag_ = INVOKER_IDLE_MAGIC;
    static constexpr uint32_t INVOKER_MAX_COUNT = 2;
    IRemoteInvoker *invokers_[INVOKER_MAX_COUNT] = {nullptr, nullptr};
    const pid_t tid_;
    std::atomic<int32_t> sendRequestCount_ = 0;
    std::string threadName_;
    ThreadType threadType_ = ThreadType::NORMAL_THREAD;
};
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS
#endif // OHOS_IPC_IPC_THREAD_SKELETON_H
