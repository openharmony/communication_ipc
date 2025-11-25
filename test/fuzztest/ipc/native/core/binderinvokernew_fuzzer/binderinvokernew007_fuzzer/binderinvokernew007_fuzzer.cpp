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

#include "binderinvokernew_fuzzer.h"
#include "binder_invoker.h"
#include "ipc_object_proxy.h"
#include "ipc_object_stub.h"
#include "message_parcel.h"
#include "string_ex.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
static const std::vector<uint32_t> binderTypeList = {
    BINDER_TYPE_BINDER,
    BINDER_TYPE_WEAK_BINDER,
    BINDER_TYPE_HANDLE,
    BINDER_TYPE_WEAK_HANDLE,
    BINDER_TYPE_FD,
    BINDER_TYPE_FDA,
    BINDER_TYPE_PTR,
};

void SetCallingIdentityFuzzTest(FuzzedDataProvider &provider)
{
    BinderInvoker invoker;
    std::string identity = invoker.ResetCallingIdentity();
    bool flag = provider.ConsumeBool();
    invoker.SetCallingIdentity(identity, flag);
}

void UnFlattenDBinderObjectFuzzTest001(FuzzedDataProvider &provider)
{
    MessageParcel dataParcel;
    binder_buffer_object obj;
    int index = provider.ConsumeIntegralInRange<int>(0, binderTypeList.size() - 1);
    obj.hdr.type = binderTypeList[index];
    obj.flags = provider.ConsumeIntegral<uint32_t>();
    obj.length = provider.ConsumeIntegral<binder_size_t>();
    obj.parent = provider.ConsumeIntegral<binder_size_t>();
    obj.buffer = 0;
    obj.parent_offset = provider.ConsumeIntegral<binder_size_t>();
    dataParcel.WriteBuffer(&obj, sizeof(binder_buffer_object));
    dbinder_negotiation_data dbinderData;

    BinderInvoker invoker;
    invoker.UnFlattenDBinderObject(dataParcel, dbinderData);
    dataParcel.FlushBuffer();
}

void UnFlattenDBinderObjectFuzzTest002(FuzzedDataProvider &provider)
{
    MessageParcel dataParcel;
    binder_buffer_object obj;
    obj.hdr.type = BINDER_TYPE_PTR;
    obj.flags = provider.ConsumeIntegral<uint32_t>() | BINDER_BUFFER_FLAG_HAS_DBINDER;
    obj.length = sizeof(dbinder_negotiation_data);
    obj.parent = provider.ConsumeIntegral<binder_size_t>();
    obj.parent_offset = provider.ConsumeIntegral<binder_size_t>();
    std::shared_ptr<dbinder_negotiation_data> buffer = std::make_shared<dbinder_negotiation_data>();
    if (buffer == nullptr) {
        return;
    }
    obj.buffer = reinterpret_cast<binder_uintptr_t>(buffer.get());
    dataParcel.WriteBuffer(&obj, sizeof(binder_buffer_object));
    dbinder_negotiation_data dbinderData;

    BinderInvoker invoker;
    invoker.UnFlattenDBinderObject(dataParcel, dbinderData);
    dataParcel.FlushBuffer();
}

void SetMaxWorkThreadFuzzTest(FuzzedDataProvider &provider)
{
    int32_t maxWorkThread = provider.ConsumeIntegral<int32_t>();

    BinderInvoker invoker;
    invoker.SetMaxWorkThread(maxWorkThread);
    invoker.binderConnector_ = nullptr;
    invoker.SetMaxWorkThread(maxWorkThread);
}

void WaitForCompletionFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel reply;

    BinderInvoker invoker;
    bool isDead = provider.ConsumeBool();
    uint32_t cmd = isDead ? BR_DEAD_REPLY : BR_FAILED_REPLY;
    invoker.input_.WriteUint32(cmd);
    invoker.WaitForCompletion(&reply);
    invoker.binderConnector_ = nullptr;
    invoker.WaitForCompletion(&reply);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::UnFlattenDBinderObjectFuzzTest001(provider);
    OHOS::UnFlattenDBinderObjectFuzzTest002(provider);
    OHOS::SetMaxWorkThreadFuzzTest(provider);
    OHOS::WaitForCompletionFuzzTest(provider);
    OHOS::SetCallingIdentityFuzzTest(provider);
    return 0;
}
} // namespace OHOS