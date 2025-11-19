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

void SetStatusFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t status = provider.ConsumeIntegral<uint32_t>();
    DBinderDatabusInvoker invoker;
    invoker.SetStatus(status);
}

void WriteFileDescriptorFuzzTest(FuzzedDataProvider &provider)
{
    Parcel parcel;
    int fd = provider.ConsumeIntegral<int>();
    bool takeOwnership = provider.ConsumeBool();
    DBinderDatabusInvoker invoker;
    invoker.WriteFileDescriptor(parcel, fd, takeOwnership);
}

void AuthSession2ProxyFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t handle = 0;
    DBinderDatabusInvoker invoker;
    invoker.AuthSession2Proxy(handle, nullptr);
}

void OnMessageAvailableFuzzTest(FuzzedDataProvider &provider)
{
    dbinder_transaction_data data;
    data.magic = provider.ConsumeIntegral<uint32_t>();
    data.cmd = provider.ConsumeIntegral<int>();
    data.sizeOfSelf = sizeof(dbinder_transaction_data);
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    DBinderDatabusInvoker invoker;
    invoker.OnMessageAvailable(socketId, reinterpret_cast<const char *>(&data), sizeof(dbinder_transaction_data));
    invoker.OnMessageAvailable(socketId, nullptr, 0);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::SetStatusFuzzTest(provider);
    OHOS::WriteFileDescriptorFuzzTest(provider);
    OHOS::AuthSession2ProxyFuzzTest(provider);
    OHOS::OnMessageAvailableFuzzTest(provider);
    return 0;
}
