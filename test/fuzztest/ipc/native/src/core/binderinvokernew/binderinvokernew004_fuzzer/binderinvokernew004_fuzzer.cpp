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
static constexpr size_t MAX_BYTES_SIZE = 50;
static const std::vector<uint32_t> cmdList = {
    binder_driver_return_protocol::BR_ERROR,
    binder_driver_return_protocol::BR_OK,
    binder_driver_return_protocol::BR_TRANSACTION_SEC_CTX,
    binder_driver_return_protocol::BR_TRANSACTION,
    binder_driver_return_protocol::BR_REPLY,
    binder_driver_return_protocol::BR_DEAD_REPLY,
    binder_driver_return_protocol::BR_TRANSACTION_COMPLETE,
    binder_driver_return_protocol::BR_INCREFS,
    binder_driver_return_protocol::BR_ACQUIRE,
    binder_driver_return_protocol::BR_RELEASE,
    binder_driver_return_protocol::BR_DECREFS,
    binder_driver_return_protocol::BR_ATTEMPT_ACQUIRE,
    binder_driver_return_protocol::BR_NOOP,
    binder_driver_return_protocol::BR_SPAWN_LOOPER,
    binder_driver_return_protocol::BR_FINISHED,
    binder_driver_return_protocol::BR_DEAD_BINDER,
    binder_driver_return_protocol::BR_CLEAR_DEATH_NOTIFICATION_DONE,
    binder_driver_return_protocol::BR_FAILED_REPLY,
    binder_driver_return_protocol::BR_RELEASE_NODE,
};

void HandleReplyFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel dataParcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    dataParcel.WriteBuffer(bytes.data(), bytes.size());
    bool isStubRet;

    BinderInvoker invoker;
    invoker.HandleReply(&dataParcel, isStubRet);
}

void HandleCommandsInnerFuzzTest001(FuzzedDataProvider &provider)
{
    uint32_t cmd = provider.ConsumeIntegral<uint32_t>();

    BinderInvoker invoker;
    invoker.HandleCommandsInner(cmd);

    for (auto cmd : cmdList) {
        BinderInvoker invoker;
        invoker.HandleCommandsInner(cmd);
    }
}

void HandleCommandsFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t cmd = provider.ConsumeIntegral<uint32_t>();

    BinderInvoker invoker;
    invoker.HandleCommands(cmd);
}

void UpdateConsumedDataFuzzTest(FuzzedDataProvider &provider)
{
    binder_write_read bwr;
    bwr.write_consumed = provider.ConsumeIntegral<uint32_t>();
    bwr.read_consumed = provider.ConsumeIntegral<uint32_t>();
    size_t outAvail = provider.ConsumeIntegral<size_t>();
    BinderInvoker invoker;
    invoker.UpdateConsumedData(bwr, outAvail);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::HandleReplyFuzzTest(provider);
    OHOS::HandleCommandsInnerFuzzTest001(provider);
    OHOS::HandleCommandsFuzzTest(provider);
    OHOS::UpdateConsumedDataFuzzTest(provider);
    return 0;
}
} // namespace OHOS