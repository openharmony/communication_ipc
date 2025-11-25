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

#include "dbinderdatabusinvoker_fuzzer.h"
#include "dbinder_base_invoker_process.h"
#include "dbinder_databus_invoker.h"
#include "securec.h"

using OHOS::DatabusSocketListener;

namespace OHOS {

void QueryHandleBySessionFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<DBinderSessionObject> session = CreateDBinderSessionObject(provider);
    if (session == nullptr) {
        return;
    }
    DBinderDatabusInvoker invoker;
    invoker.QueryHandleBySession(session);
}

void SetClientFdFuzzTest(FuzzedDataProvider &provider)
{
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    DBinderDatabusInvoker invoker;
    invoker.SetClientFd(fd);
}

void SetCallerDeviceIDFuzzTest(FuzzedDataProvider &provider)
{
    std::string deviceId = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    DBinderDatabusInvoker invoker;
    invoker.SetCallerDeviceID(deviceId);
}

void SetCallerTokenIDFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
    DBinderDatabusInvoker invoker;
    invoker.SetCallerTokenID(tokenId);
}

void CheckAndSetCallerInfoFuzzTest(FuzzedDataProvider &provider)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    uint32_t socketId = provider.ConsumeIntegral<uint32_t>();
    std::shared_ptr<DBinderSessionObject> object = CreateDBinderSessionObject(provider);
    if (object == nullptr) {
        return;
    }
    uint64_t stubIndex = object->GetStubIndex();
    DBinderDatabusInvoker invoker;
    invoker.CheckAndSetCallerInfo(socketId, stubIndex);
    current->StubAttachDBinderSession(socketId, object);
    uint32_t pid = provider.ConsumeIntegral<uint32_t>();
    uint32_t uid = provider.ConsumeIntegral<uint32_t>();
    uint32_t tokenId = object->GetTokenId();
    std::string deviceId = object->GetDeviceId();
    int32_t listenFd = provider.ConsumeIntegral<int32_t>();
    current->AttachAppInfoToStubIndex(pid, uid, tokenId, deviceId, stubIndex, listenFd);
    invoker.CheckAndSetCallerInfo(socketId, stubIndex);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::QueryHandleBySessionFuzzTest(provider);
    OHOS::SetClientFdFuzzTest(provider);
    OHOS::SetCallerDeviceIDFuzzTest(provider);
    OHOS::SetCallerTokenIDFuzzTest(provider);
    OHOS::CheckAndSetCallerInfoFuzzTest(provider);
    return 0;
}
