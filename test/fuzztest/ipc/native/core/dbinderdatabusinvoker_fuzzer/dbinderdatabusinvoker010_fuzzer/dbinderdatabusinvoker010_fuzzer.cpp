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
void CreateServerSessionObjectFuzzTest(FuzzedDataProvider &provider)
{
    std::string serviceName = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    std::string serverDeviceId = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
    std::shared_ptr<DBinderSessionObject> dbinderSession =
        std::make_shared<DBinderSessionObject>(serviceName, serverDeviceId, stubIndex, nullptr, tokenId);
    if (dbinderSession == nullptr) {
        return;
    }
    binder_uintptr_t binder = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
    DBinderDatabusInvoker invoker;
    invoker.CreateServerSessionObject(binder, dbinderSession);
}

void MakeStubIndexByRemoteObjectFuzzTest(FuzzedDataProvider &provider)
{
    int handle = provider.ConsumeIntegral<int>();
    int proto = provider.ConsumeIntegral<int>();
    sptr<IRemoteObject> obj = new (std::nothrow) IPCObjectProxy(handle, u"proxyTest", proto);
    if (obj == nullptr) {
        return;
    }
    DBinderDatabusInvoker invoker;
    invoker.MakeStubIndexByRemoteObject(obj.GetRefPtr());
}

void GetCallerInfoFuzzTest(FuzzedDataProvider &provider)
{
    DBinderDatabusInvoker::DBinderBaseInvoker::DBinderCallerInfo callerInfo;
    callerInfo.callerPid = provider.ConsumeIntegral<pid_t>();
    callerInfo.callerUid = provider.ConsumeIntegral<pid_t>();
    callerInfo.clientFd = provider.ConsumeIntegral<int32_t>();
    callerInfo.callerTokenID = provider.ConsumeIntegral<uint64_t>();
    callerInfo.firstTokenID = provider.ConsumeIntegral<uint64_t>();
    callerInfo.callerDeviceID = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    DBinderDatabusInvoker invoker;
    invoker.GetCallerInfo(callerInfo);
}

void SetCallerPidFuzzTest(FuzzedDataProvider &provider)
{
    pid_t pid = provider.ConsumeIntegral<pid_t>();
    DBinderDatabusInvoker invoker;
    invoker.SetCallerPid(pid);
}

void SetCallerUidFuzzTest(FuzzedDataProvider &provider)
{
    pid_t uid = provider.ConsumeIntegral<pid_t>();
    DBinderDatabusInvoker invoker;
    invoker.SetCallerUid(uid);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::CreateServerSessionObjectFuzzTest(provider);
    OHOS::MakeStubIndexByRemoteObjectFuzzTest(provider);
    OHOS::GetCallerInfoFuzzTest(provider);
    OHOS::SetCallerPidFuzzTest(provider);
    OHOS::SetCallerUidFuzzTest(provider);
    return 0;
}
