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

#include "binderinvoker_fuzzer.h"
#include "binder_invoker.h"
#include "ipc_object_stub.h"
#include "message_parcel.h"

#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
static constexpr size_t MAX_STR_LEN = 100;

void ReadFileDescriptorFuzzTest(FuzzedDataProvider &provider)
{
    Parcel parcel;
    flat_binder_object flat;
    flat.hdr.type = BINDER_TYPE_FD;
    flat.flags = provider.ConsumeIntegral<uint32_t>();
    flat.handle = provider.ConsumeIntegral<binder_uintptr_t>();
    parcel.WriteBuffer(&flat, sizeof(flat_binder_object));
    BinderInvoker invoker;
    invoker.ReadFileDescriptor(parcel);
}

void GetStrongRefCountForStubFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    BinderInvoker invoker;
    invoker.GetStrongRefCountForStub(handle);

    invoker.binderConnector_ = nullptr;
    invoker.GetStrongRefCountForStub(handle);

    bool enable = provider.ConsumeBool();
    invoker.binderConnector_ = nullptr;
    invoker.EnableIPCThreadReclaim(enable);
}

void GetCallerPidAndUidByStrFuzzTest(FuzzedDataProvider &provider)
{
    std::string str = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    size_t offset = str.length();
    pid_t pid = provider.ConsumeIntegral<pid_t>();
    pid_t uid = provider.ConsumeIntegral<pid_t>();
    BinderInvoker invoker;
    invoker.GetCallerPidAndUidByStr(str, offset, pid, uid);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::ReadFileDescriptorFuzzTest(provider);
    OHOS::GetStrongRefCountForStubFuzzTest(provider);
    OHOS::GetCallerPidAndUidByStrFuzzTest(provider);
    return 0;
}
