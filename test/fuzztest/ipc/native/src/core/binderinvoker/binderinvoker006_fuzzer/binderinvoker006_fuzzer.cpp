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

#ifndef __linux__
void GetDetailedErrorInfoFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t errorCode = provider.ConsumeIntegral<uint32_t>();
    std::string errDesc = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    BinderInvoker invoker;
    invoker.GetDetailedErrorInfo(errorCode, errDesc);
}
#endif

void GetAccessTokenFuzzTest(FuzzedDataProvider &provider)
{
    uint64_t callerTokenID = provider.ConsumeIntegral<uint64_t>();
    uint64_t firstTokenID = provider.ConsumeIntegral<uint64_t>();
    BinderInvoker invoker;
    invoker.binderConnector_->CloseDriverFd();
    invoker.GetAccessToken(callerTokenID, firstTokenID);
}

void GetSenderInfoFuzzTest(FuzzedDataProvider &provider)
{
    uint64_t callerTokenID = provider.ConsumeIntegral<uint64_t>();
    uint64_t firstTokenID = provider.ConsumeIntegral<uint64_t>();
    pid_t realPid = provider.ConsumeIntegral<pid_t>();
    BinderInvoker invoker;
    invoker.binderConnector_->CloseDriverFd();
    invoker.GetSenderInfo(callerTokenID, firstTokenID, realPid);
}

void SendRequestFuzzTest(FuzzedDataProvider &provider)
{
    int32_t handle = provider.ConsumeIntegral<int32_t>();
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    BinderInvoker invoker;
    invoker.SendRequest(handle, code, data, reply, option);
}

void UnflattenObjectFuzzTest(FuzzedDataProvider &provider)
{
    Parcel parcel;
    BinderInvoker invoker;
    invoker.UnflattenObject(parcel);

    flat_binder_object flat;
    flat.hdr.type = BINDER_TYPE_BINDER;
    flat.flags = provider.ConsumeIntegral<uint32_t>();
    flat.handle = provider.ConsumeIntegral<binder_uintptr_t>();
    flat.cookie = 0;
    parcel.WriteBuffer(&flat, sizeof(flat_binder_object));
    invoker.UnflattenObject(parcel);

    invoker.FlattenObject(parcel, nullptr);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
#ifndef __linux__
    OHOS::GetDetailedErrorInfoFuzzTest(provider);
#endif
    OHOS::GetAccessTokenFuzzTest(provider);
    OHOS::GetSenderInfoFuzzTest(provider);
    OHOS::SendRequestFuzzTest(provider);
    OHOS::UnflattenObjectFuzzTest(provider);
    return 0;
}
