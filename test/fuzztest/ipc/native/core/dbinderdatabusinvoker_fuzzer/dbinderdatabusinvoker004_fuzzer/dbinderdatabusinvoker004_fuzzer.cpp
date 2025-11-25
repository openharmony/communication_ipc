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

static void ProcessTransactionFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    uint32_t listenFd = 0;
    if (!parcel.ReadUint32(listenFd)) {
        return;
    }

    dbinder_transaction_data *tr = new dbinder_transaction_data();
    if (tr == nullptr) {
        return;
    }
    DBinderDatabusInvoker invoker;
    invoker.ProcessTransaction(tr, listenFd);
    delete tr;
}

static void CheckTransactionDataFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    const uint8_t *buf = parcel.ReadBuffer(sizeof(dbinder_transaction_data));
    if (buf == nullptr) {
        return;
    }

    dbinder_transaction_data *tr = new dbinder_transaction_data();
    if (tr == nullptr) {
        return;
    }

    if (memcpy_s(tr, sizeof(dbinder_transaction_data), buf, sizeof(dbinder_transaction_data)) != EOK) {
        delete tr;
        return;
    }

    DBinderDatabusInvoker invoker;
    (void)invoker.CheckTransactionData(tr);
    delete tr;
}

void GetSessionForProxyFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    std::shared_ptr<DBinderSessionObject> session = CreateDBinderSessionObject(provider);
    sptr<IPCObjectProxy> ipcProxy = sptr<IPCObjectProxy>::MakeSptr(handle);
    if (session == nullptr || ipcProxy == nullptr) {
        return;
    }
    std::string localDeviceId = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    DBinderDatabusInvoker invoker;
    invoker.GetSessionForProxy(ipcProxy, session, localDeviceId);
}

void QueryClientSessionObjectFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t databusHandle = provider.ConsumeIntegral<uint32_t>();
    DBinderDatabusInvoker invoker;
    invoker.QueryClientSessionObject(databusHandle);
}

void QueryServerSessionObjectFuzzTest(FuzzedDataProvider &provider)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    std::shared_ptr<DBinderSessionObject> object = CreateDBinderSessionObject(provider);
    if (object == nullptr) {
        return;
    }
    current->ProxyAttachDBinderSession(handle, object);
    DBinderDatabusInvoker invoker;
    invoker.QueryServerSessionObject(handle);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::ProcessTransactionFuzzTest(data, size);
    OHOS::CheckTransactionDataFuzzTest(data, size);
    FuzzedDataProvider provider(data, size);
    OHOS::GetSessionForProxyFuzzTest(provider);
    OHOS::QueryClientSessionObjectFuzzTest(provider);
    OHOS::QueryServerSessionObjectFuzzTest(provider);
    return 0;
}
