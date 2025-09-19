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

void HasCompletePackageFuzzTest001(FuzzedDataProvider &provider)
{
    dbinder_transaction_data data = CreateDbinderTransactionData(provider);
    uint32_t readCursor = 0;
    DBinderDatabusInvoker invoker;
    invoker.HasCompletePackage(reinterpret_cast<const char *>(&data), readCursor, sizeof(dbinder_transaction_data));
}

void HasCompletePackageFuzzTest002(FuzzedDataProvider &provider)
{
    dbinder_transaction_data data;
    data.magic = DBINDER_MAGICWORD;
    data.sizeOfSelf = provider.ConsumeIntegral<uint32_t>();
    data.buffer_size = provider.ConsumeIntegral<binder_size_t>();
    data.offsets = provider.ConsumeIntegral<binder_uintptr_t>();
    data.flags = provider.ConsumeIntegral<uint32_t>();
    data.offsets_size = provider.ConsumeIntegral<binder_size_t>();
    uint32_t readCursor = 0;
    ssize_t len = provider.ConsumeIntegral<ssize_t>();
    DBinderDatabusInvoker invoker;
    invoker.HasCompletePackage(reinterpret_cast<const char *>(&data), readCursor, len);

    data.sizeOfSelf = sizeof(dbinder_transaction_data);
    invoker.HasCompletePackage(reinterpret_cast<const char *>(&data), readCursor, sizeof(dbinder_transaction_data));
}

void NewSessionOfBinderProxyFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<DBinderSessionObject> session = CreateDBinderSessionObject(provider);
    if (session == nullptr) {
        return;
    }
    DBinderDatabusInvoker invoker;
    uint32_t handle = -1;
    invoker.NewSessionOfBinderProxy(handle, nullptr);
    invoker.NewSessionOfBinderProxy(handle, session);
}

void MakeDefaultServerSessionObjectFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<DBinderSessionObject> sessionObject = CreateDBinderSessionObject(provider);
    if (sessionObject == nullptr) {
        return;
    }
    uint64_t stubIndex = sessionObject->GetStubIndex();
    DBinderDatabusInvoker invoker;
    invoker.MakeDefaultServerSessionObject(stubIndex, sessionObject);
}

void SetCallingIdentityFuzzTest(FuzzedDataProvider &provider)
{
    std::string identity = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    bool flag = provider.ConsumeBool();
    DBinderDatabusInvoker invoker;
    invoker.SetCallingIdentity(identity, flag);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::HasCompletePackageFuzzTest001(provider);
    OHOS::HasCompletePackageFuzzTest002(provider);
    OHOS::NewSessionOfBinderProxyFuzzTest(provider);
    OHOS::MakeDefaultServerSessionObjectFuzzTest(provider);
    OHOS::SetCallingIdentityFuzzTest(provider);
    return 0;
}
