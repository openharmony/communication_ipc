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
#include "message_parcel.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
void AcquireHandleFuzzTest(FuzzedDataProvider &provider)
{
    int32_t handle = provider.ConsumeIntegral<int32_t>();

    BinderInvoker invoker;
    invoker.AcquireHandle(handle);
}

void TranslateDBinderProxyFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel dataParcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    dataParcel.WriteBuffer(bytes.data(), bytes.size());
    int32_t handle = provider.ConsumeIntegral<int32_t>();

    BinderInvoker invoker;
    invoker.TranslateDBinderProxy(handle, dataParcel);
}

void AddCommAuthFuzzTest(FuzzedDataProvider &provider)
{
    int32_t handle = provider.ConsumeIntegral<int32_t>();
    flat_binder_object flat;
    flat.handle = provider.ConsumeIntegral<int32_t>();

    BinderInvoker invoker;
    invoker.AddCommAuth(handle, &flat);
}

void GetDBinderCallingPidUidFuzzTest(FuzzedDataProvider &provider)
{
    int32_t handle = provider.ConsumeIntegral<int32_t>();
    bool isReply = provider.ConsumeBool();
    pid_t pid = static_cast<pid_t>(provider.ConsumeIntegral<int32_t>());
    uid_t uid = static_cast<uid_t>(provider.ConsumeIntegral<int32_t>());

    BinderInvoker invoker;
    invoker.GetDBinderCallingPidUid(handle, isReply, pid, uid);
}

void TranslateDBinderStubFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel dataParcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    dataParcel.WriteBuffer(bytes.data(), bytes.size());
    int32_t handle = provider.ConsumeIntegral<int32_t>();
    bool isReply = provider.ConsumeBool();
    size_t totalDBinderBufSize;

    BinderInvoker invoker;
    invoker.TranslateDBinderStub(handle, dataParcel, isReply, totalDBinderBufSize);
}

void OnAcquireObjectFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t cmd = provider.ConsumeIntegral<uint32_t>();

    BinderInvoker invoker;
    invoker.OnAcquireObject(cmd);
}

void OnReleaseObjectFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t cmd = provider.ConsumeIntegral<uint32_t>();

    BinderInvoker invoker;
    invoker.OnReleaseObject(cmd);
}

void GetAccessTokenFuzzTest(FuzzedDataProvider &provider)
{
    uint64_t callerTokenID = provider.ConsumeIntegral<uint64_t>();
    uint64_t firstTokenID = provider.ConsumeIntegral<uint64_t>();

    BinderInvoker invoker;
    invoker.GetAccessToken(callerTokenID, firstTokenID);
}

void GetSenderInfoFuzzTest(FuzzedDataProvider &provider)
{
    uint64_t callerTokenID = provider.ConsumeIntegral<uint64_t>();
    uint64_t firstTokenID = provider.ConsumeIntegral<uint64_t>();
    pid_t realPid;

    BinderInvoker invoker;
    invoker.GetSenderInfo(callerTokenID, firstTokenID, realPid);
}

void SamgrServiceSendRequestFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel dataParcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    dataParcel.WriteBuffer(bytes.data(), bytes.size());
    binder_transaction_data transData;
    MessageParcel reply;
    MessageOption option;

    BinderInvoker invoker;
    invoker.SamgrServiceSendRequest(transData, dataParcel, reply, option);
}

void GeneralServiceSendRequestFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel dataParcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    dataParcel.WriteBuffer(bytes.data(), bytes.size());
    binder_transaction_data transData;
    transData.target.ptr = 0;
    transData.code = provider.ConsumeIntegral<uint32_t>();
    transData.cookie = provider.ConsumeIntegral<uint32_t>();
    MessageParcel reply;
    MessageOption option;

    BinderInvoker invoker;
    invoker.GeneralServiceSendRequest(transData, dataParcel, reply, option);
}

void TargetStubSendRequestFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel dataParcel;
    binder_transaction_data transData;
    transData.target.ptr = provider.ConsumeIntegral<uint64_t>();
    transData.flags = provider.ConsumeIntegral<uint32_t>();
    MessageParcel reply;
    MessageOption option;
    uint32_t flagValue;

    BinderInvoker invoker;
    invoker.TargetStubSendRequest(transData, dataParcel, reply, option, flagValue);
}

void OnTransactionFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t cmd = provider.ConsumeIntegral<uint32_t>();
    int32_t error;

    BinderInvoker invoker;
    invoker.OnTransaction(cmd, error);
}

void HandleReplyFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel dataParcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    dataParcel.WriteBuffer(bytes.data(), bytes.size());
    bool isStubRet;

    BinderInvoker invoker;
    invoker.HandleReply(&dataParcel, isStubRet);
}

void HandleCommandsInnerFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t cmd = provider.ConsumeIntegral<uint32_t>();

    BinderInvoker invoker;
    invoker.HandleCommandsInner(cmd);
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

void WriteTransactionFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel dataParcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    dataParcel.WriteBuffer(bytes.data(), bytes.size());
    int cmd = provider.ConsumeIntegral<int32_t>();
    uint32_t flags = provider.ConsumeIntegral<uint32_t>();
    int32_t handle = provider.ConsumeIntegral<int32_t>();
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    size_t statusSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> statusBytes = provider.ConsumeBytes<uint8_t>(statusSize);
    int32_t *status = reinterpret_cast<int32_t *>(statusBytes.data());
    size_t totalDBinderBufSize = provider.ConsumeIntegralInRange<size_t>(1, 50);

    BinderInvoker invoker;
    invoker.WriteTransaction(cmd, flags, handle, code, dataParcel, status, totalDBinderBufSize);
}

void OnReplyFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel reply;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    reply.WriteBuffer(bytes.data(), bytes.size());
    uint32_t cmd = provider.ConsumeIntegral<uint32_t>();
    bool continueLoop;
    int32_t error;

    BinderInvoker invoker;
    invoker.OnReply(&reply, continueLoop, error, cmd);
}

void DealWithCmdFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel reply;
    uint32_t cmd = provider.ConsumeIntegral<uint32_t>();
    bool continueLoop;
    int32_t error;

    BinderInvoker invoker;
    invoker.DealWithCmd(&reply, continueLoop, error, cmd);
}

void SetRegistryObjectFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel dataParcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    dataParcel.WriteBuffer(bytes.data(), bytes.size());
    sptr<OHOS::IRemoteObject> object = dataParcel.ReadRemoteObject();

    BinderInvoker invoker;
    invoker.SetRegistryObject(object);
}

void EnableIPCThreadReclaimFuzzTest(FuzzedDataProvider &provider)
{
    bool enable = provider.ConsumeBool();

    BinderInvoker invoker;
    invoker.EnableIPCThreadReclaim(enable);
}

void PrintParcelDataFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel dataParcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    dataParcel.WriteBuffer(bytes.data(), bytes.size());
    std::string parcelName = provider.ConsumeRandomLengthString();

    BinderInvoker invoker;
    invoker.PrintParcelData(dataParcel, parcelName);
}

void GetUint64ValueByStrSliceFuzzTest(FuzzedDataProvider &provider)
{
    std::string str = provider.ConsumeRandomLengthString();
    size_t offset = provider.ConsumeIntegral<size_t>();
    size_t length = provider.ConsumeIntegralInRange<size_t>(0, std::numeric_limits<size_t>::max() - offset);
    uint64_t value;

    BinderInvoker invoker;
    invoker.GetUint64ValueByStrSlice(str, offset, length, value);
}

void GetCallerRealPidByStrFuzzTest(FuzzedDataProvider &provider)
{
    std::string str = provider.ConsumeRandomLengthString();
    size_t offset = provider.ConsumeIntegral<size_t>();
    size_t length = provider.ConsumeIntegralInRange<size_t>(0, std::numeric_limits<size_t>::max() - offset);
    pid_t callerRealPid;

    BinderInvoker invoker;
    invoker.GetCallerRealPidByStr(str, offset, length, callerRealPid);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::AcquireHandleFuzzTest(provider);
    OHOS::TranslateDBinderProxyFuzzTest(provider);
    OHOS::AddCommAuthFuzzTest(provider);
    OHOS::GetDBinderCallingPidUidFuzzTest(provider);
    OHOS::TranslateDBinderStubFuzzTest(provider);
    OHOS::OnAcquireObjectFuzzTest(provider);
    OHOS::OnReleaseObjectFuzzTest(provider);
    OHOS::GetAccessTokenFuzzTest(provider);
    OHOS::GetSenderInfoFuzzTest(provider);
    OHOS::SamgrServiceSendRequestFuzzTest(provider);
    OHOS::GeneralServiceSendRequestFuzzTest(provider);
    OHOS::TargetStubSendRequestFuzzTest(provider);
    OHOS::OnTransactionFuzzTest(provider);
    OHOS::HandleReplyFuzzTest(provider);
    OHOS::HandleCommandsInnerFuzzTest(provider);
    OHOS::HandleCommandsFuzzTest(provider);
    OHOS::UpdateConsumedDataFuzzTest(provider);
    OHOS::WriteTransactionFuzzTest(provider);
    OHOS::OnReplyFuzzTest(provider);
    OHOS::DealWithCmdFuzzTest(provider);
    OHOS::SetRegistryObjectFuzzTest(provider);
    OHOS::EnableIPCThreadReclaimFuzzTest(provider);
    OHOS::PrintParcelDataFuzzTest(provider);
    OHOS::GetUint64ValueByStrSliceFuzzTest(provider);
    OHOS::GetCallerRealPidByStrFuzzTest(provider);
    return 0;
}
} // namespace OHOS