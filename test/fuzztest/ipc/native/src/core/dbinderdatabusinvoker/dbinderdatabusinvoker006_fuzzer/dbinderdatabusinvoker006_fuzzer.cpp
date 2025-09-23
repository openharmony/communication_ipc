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

void FlattenSessionFuzzTest(FuzzedDataProvider &provider)
{
    FlatDBinderSession flatSession;
    std::shared_ptr<DBinderSessionObject> connectSession = CreateDBinderSessionObject(provider);
    if (connectSession == nullptr) {
        return;
    }
    std::string deviceId = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    connectSession->SetDeviceId(deviceId);
    uint32_t binderVersion = provider.ConsumeIntegral<uint32_t>();
    DBinderDatabusInvoker invoker;
    invoker.FlattenSession(reinterpret_cast<unsigned char *>(&flatSession), connectSession, binderVersion);
}

void UnFlattenSessionFuzzTest(FuzzedDataProvider &provider)
{
    FlatDBinderSession flatSession;
    flatSession.stubIndex = provider.ConsumeIntegral<uint64_t>();
    flatSession.version = provider.ConsumeIntegral<uint16_t>();
    flatSession.magic = provider.ConsumeIntegral<uint32_t>();
    flatSession.tokenId = provider.ConsumeIntegral<uint32_t>();
    uint32_t binderVersion = provider.ConsumeIntegral<uint32_t>();
    DBinderDatabusInvoker invoker;
    invoker.UnFlattenSession(reinterpret_cast<unsigned char *>(&flatSession), binderVersion);
}

void UpdateClientSessionFuzzTest(FuzzedDataProvider &provider)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    current->sessionName_ = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    std::shared_ptr<DBinderSessionObject> sessionObject = CreateDBinderSessionObject(provider);
    if (sessionObject == nullptr) {
        return;
    }
    DBinderDatabusInvoker invoker;
    invoker.UpdateClientSession(sessionObject);
}

void OnDatabusSessionClientSideClosedFuzzTest(FuzzedDataProvider &provider)
{
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    DBinderDatabusInvoker invoker;
    invoker.OnDatabusSessionClientSideClosed(socketId);
}

void OnDatabusSessionServerSideClosedFuzzTest(FuzzedDataProvider &provider)
{
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    DBinderDatabusInvoker invoker;
    invoker.OnDatabusSessionServerSideClosed(socketId);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::FlattenSessionFuzzTest(provider);
    OHOS::UnFlattenSessionFuzzTest(provider);
    OHOS::UpdateClientSessionFuzzTest(provider);
    OHOS::OnDatabusSessionClientSideClosedFuzzTest(provider);
    OHOS::OnDatabusSessionServerSideClosedFuzzTest(provider);
    return 0;
}
