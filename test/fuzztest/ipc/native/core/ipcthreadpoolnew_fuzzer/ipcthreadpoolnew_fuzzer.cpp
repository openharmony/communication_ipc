/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "ipcthreadpoolnew_fuzzer.h"
#include "ipc_thread_pool.h"
#include "process_skeleton.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
void SpawnThreadFuzzTest(FuzzedDataProvider &provider)
{
    int policy = provider.ConsumeIntegral<int>();
    int proto = provider.ConsumeIntegral<int>();
    int32_t maxThreadNum = provider.ConsumeIntegral<int32_t>() % (INT_MAX >> 1);
    IPCWorkThreadPool threadPool(maxThreadNum);
    ProcessSkeleton *process = ProcessSkeleton::GetInstance();
    if (process == nullptr) {
        return;
    }
    process->NotifyChildThreadStop();
    threadPool.SpawnThread(policy, proto);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::SpawnThreadFuzzTest(provider);
    return 0;
}
