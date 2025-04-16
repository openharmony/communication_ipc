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

#include "ipcthreadpool_fuzzer.h"
#include "ipc_thread_pool.h"
#include "message_parcel.h"

namespace OHOS {
void RemoveThreadFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    size_t length = parcel.GetReadableBytes();
    if (length == 0) {
        return;
    }
    const char *bufData = reinterpret_cast<const char *>(parcel.ReadBuffer(length));
    if (bufData == nullptr) {
        return;
    }
    std::string threadName(bufData, length);
    const int threadPoolSize = 4;
    IPCWorkThreadPool threadPool(threadPoolSize);
    threadPool.RemoveThread(threadName);
}

void IPCWorkThreadPoolFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int32_t maxThreadNum = parcel.ReadInt32() % (INT_MAX >> 1);
    IPCWorkThreadPool threadPool(maxThreadNum);
}

void UpdateMaxThreadNumFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int32_t maxThreadNum = parcel.ReadInt32() % (INT_MAX >> 1);
    IPCWorkThreadPool threadPool(0);
    threadPool.UpdateMaxThreadNum(maxThreadNum);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::RemoveThreadFuzzTest(data, size);
    OHOS::IPCWorkThreadPoolFuzzTest(data, size);
    OHOS::UpdateMaxThreadNumFuzzTest(data, size);
    return 0;
}
