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

    // Joint Current thread into IPC Work Group
    void JoinWorkThread(int proto);
    // Quit current thread from IPC work group.
    void StopWorkThread(int proto);

private:
    static pthread_key_t TLSKey_;
    static pthread_once_t TLSKeyOnce_;
    std::unordered_map<int, IRemoteInvoker *> invokers_;
};
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS
#endif // OHOS_IPC_IPC_THREAD_SKELETON_H
