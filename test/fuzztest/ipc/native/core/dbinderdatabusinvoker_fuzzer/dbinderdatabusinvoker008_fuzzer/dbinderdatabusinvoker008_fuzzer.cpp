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

void SetCallerInfoFuzzTest(FuzzedDataProvider &provider)
{
    DBinderDatabusInvoker::DBinderBaseInvoker::DBinderCallerInfo callerInfo;
    callerInfo.callerPid = provider.ConsumeIntegral<pid_t>();
    callerInfo.callerUid = provider.ConsumeIntegral<pid_t>();
    callerInfo.clientFd = provider.ConsumeIntegral<int32_t>();
    callerInfo.callerTokenID = provider.ConsumeIntegral<uint64_t>();
    callerInfo.firstTokenID = provider.ConsumeIntegral<uint64_t>();
    callerInfo.callerDeviceID = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    DBinderDatabusInvoker invoker;
    invoker.SetCallerInfo(callerInfo);
}

void ConnectRemoteObject2SessionFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    sptr<IPCObjectProxy> object = sptr<IPCObjectProxy>::MakeSptr(handle);
    if (object == nullptr) {
        return;
    }
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    std::shared_ptr<DBinderSessionObject> sessionObject = CreateDBinderSessionObject(provider);
    if (sessionObject == nullptr) {
        return;
    }
    DBinderDatabusInvoker invoker;
    invoker.ConnectRemoteObject2Session(object.GetRefPtr(), stubIndex, nullptr);
    invoker.ConnectRemoteObject2Session(object.GetRefPtr(), stubIndex, sessionObject);
}

void FlushCommandsFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    sptr<IPCObjectProxy> object = sptr<IPCObjectProxy>::MakeSptr(handle);
    if (object == nullptr) {
        return;
    }
    DBinderDatabusInvoker invoker;
    invoker.FlushCommands(nullptr);
    invoker.FlushCommands(object.GetRefPtr());
}

void HasRawDataPackageFuzzTest001(FuzzedDataProvider &provider)
{
    dbinder_transaction_data data = CreateDbinderTransactionData(provider);
    DBinderDatabusInvoker invoker;
    invoker.HasRawDataPackage(reinterpret_cast<const char *>(&data), sizeof(dbinder_transaction_data));
}

void HasRawDataPackageFuzzTest002(FuzzedDataProvider &provider)
{
    dbinder_transaction_data data;
    data.magic = DBINDER_MAGICWORD;
    data.cmd = BC_SEND_RAWDATA;
    data.sizeOfSelf = provider.ConsumeIntegral<uint32_t>();
    ssize_t len = provider.ConsumeIntegral<ssize_t>();
    DBinderDatabusInvoker invoker;
    invoker.HasRawDataPackage(reinterpret_cast<const char *>(&data), len);

    data.sizeOfSelf = sizeof(dbinder_transaction_data);
    invoker.HasRawDataPackage(reinterpret_cast<const char *>(&data), sizeof(dbinder_transaction_data));
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::SetCallerInfoFuzzTest(provider);
    OHOS::ConnectRemoteObject2SessionFuzzTest(provider);
    OHOS::FlushCommandsFuzzTest(provider);
    OHOS::HasRawDataPackageFuzzTest001(provider);
    OHOS::HasRawDataPackageFuzzTest002(provider);
    return 0;
}
