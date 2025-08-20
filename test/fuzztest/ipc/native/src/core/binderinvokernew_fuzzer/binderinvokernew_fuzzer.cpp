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

static constexpr size_t STR_MAX_LEN = 100;
static constexpr pid_t INVALID_PID = -1;
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
static const std::vector<uint32_t> binderTypeList = {
    BINDER_TYPE_BINDER,
    BINDER_TYPE_WEAK_BINDER,
    BINDER_TYPE_HANDLE,
    BINDER_TYPE_WEAK_HANDLE,
    BINDER_TYPE_FD,
    BINDER_TYPE_FDA,
    BINDER_TYPE_PTR,
};

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

void GetDBinderCallingPidUidFuzzTest001(FuzzedDataProvider &provider)
{
    int32_t handle = provider.ConsumeIntegral<int32_t>();
    bool isReply = provider.ConsumeBool();
    pid_t pid = static_cast<pid_t>(provider.ConsumeIntegral<int32_t>());
    uid_t uid = static_cast<uid_t>(provider.ConsumeIntegral<int32_t>());

    BinderInvoker invoker;
    invoker.GetDBinderCallingPidUid(handle, isReply, pid, uid);
}

void GetDBinderCallingPidUidFuzzTest002(FuzzedDataProvider &provider)
{
    int32_t handle = provider.ConsumeIntegral<int32_t>();
    bool isReply = provider.ConsumeBool();
    pid_t pid = INVALID_PID;
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

void OnTransactionFuzzTest001(FuzzedDataProvider &provider)
{
    uint32_t cmd = provider.ConsumeIntegral<uint32_t>();
    int32_t error;

    BinderInvoker invoker;
    invoker.OnTransaction(cmd, error);
}

void OnTransactionFuzzTest002(FuzzedDataProvider &provider)
{
    uint32_t cmd = provider.ConsumeIntegral<uint32_t>();
    int32_t error;
    MessageParcel dataParcel;

    BinderInvoker invoker;
    if (cmd == static_cast<uint32_t>(BR_TRANSACTION_SEC_CTX)) {
        binder_transaction_data_secctx trSecctx {};
        invoker.input_.WriteBuffer(&trSecctx, sizeof(binder_transaction_data_secctx));
    } else {
        binder_transaction_data tr {};
        invoker.input_.WriteBuffer(&tr, sizeof(binder_transaction_data));
    }
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

void HandleCommandsInnerFuzzTest001(FuzzedDataProvider &provider)
{
    uint32_t cmd = provider.ConsumeIntegral<uint32_t>();

    BinderInvoker invoker;
    invoker.HandleCommandsInner(cmd);
}

void HandleCommandsInnerFuzzTest002()
{
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
    std::string parcelName = provider.ConsumeRandomLengthString(STR_MAX_LEN);

    BinderInvoker invoker;
    invoker.PrintParcelData(dataParcel, parcelName);
}

void GetUint64ValueByStrSliceFuzzTest(FuzzedDataProvider &provider)
{
    std::string str = provider.ConsumeRandomLengthString(STR_MAX_LEN);
    size_t offset = provider.ConsumeIntegral<size_t>();
    size_t length = provider.ConsumeIntegralInRange<size_t>(0, std::numeric_limits<size_t>::max() - offset);
    uint64_t value;

    BinderInvoker invoker;
    invoker.GetUint64ValueByStrSlice(str, offset, length, value);
}

void GetCallerRealPidByStrFuzzTest001(FuzzedDataProvider &provider)
{
    std::string str = provider.ConsumeRandomLengthString(STR_MAX_LEN);
    size_t offset = provider.ConsumeIntegral<size_t>();
    size_t length = provider.ConsumeIntegralInRange<size_t>(0, std::numeric_limits<size_t>::max() - offset);
    pid_t callerRealPid;

    BinderInvoker invoker;
    invoker.GetCallerRealPidByStr(str, offset, length, callerRealPid);
}

void GetCallerRealPidByStrFuzzTest002(FuzzedDataProvider &provider)
{
    int32_t num = provider.ConsumeIntegral<int32_t>();
    std::string identity = "<" + std::to_string(num);
    size_t offset = provider.ConsumeIntegralInRange<size_t>(0, identity.length());
    size_t length = provider.ConsumeIntegralInRange<size_t>(0, identity.length());
    pid_t callerRealPid;

    BinderInvoker invoker;
    invoker.GetCallerRealPidByStr(identity, offset, length, callerRealPid);
}

void GetCallerPidAndUidByStrFuzzTest(FuzzedDataProvider &provider)
{
    int32_t num = provider.ConsumeIntegral<int32_t>();
    std::string str = "<" + std::to_string(num);
    size_t offset = provider.ConsumeIntegralInRange<size_t>(0, str.length());
    pid_t pid = 0;
    pid_t uid = 0;

    BinderInvoker binderInvoker;
    binderInvoker.GetCallerPidAndUidByStr(str, offset, pid, uid);
}

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
    obj.parent_offset = provider.ConsumeIntegral<binder_size_t>();
    dataParcel.WriteBuffer(&obj, sizeof(binder_buffer_object));
    dbinder_negotiation_data dbinderData;

    BinderInvoker invoker;
    invoker.UnFlattenDBinderObject(dataParcel, dbinderData);
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
    OHOS::AcquireHandleFuzzTest(provider);
    OHOS::TranslateDBinderProxyFuzzTest(provider);
    OHOS::AddCommAuthFuzzTest(provider);
    OHOS::GetDBinderCallingPidUidFuzzTest001(provider);
    OHOS::GetDBinderCallingPidUidFuzzTest002(provider);
    OHOS::TranslateDBinderStubFuzzTest(provider);
    OHOS::OnAcquireObjectFuzzTest(provider);
    OHOS::OnReleaseObjectFuzzTest(provider);
    OHOS::GetAccessTokenFuzzTest(provider);
    OHOS::GetSenderInfoFuzzTest(provider);
    OHOS::SamgrServiceSendRequestFuzzTest(provider);
    OHOS::GeneralServiceSendRequestFuzzTest(provider);
    OHOS::TargetStubSendRequestFuzzTest(provider);
    OHOS::OnTransactionFuzzTest001(provider);
    OHOS::OnTransactionFuzzTest002(provider);
    OHOS::HandleReplyFuzzTest(provider);
    OHOS::HandleCommandsInnerFuzzTest001(provider);
    OHOS::HandleCommandsInnerFuzzTest002();
    OHOS::HandleCommandsFuzzTest(provider);
    OHOS::UpdateConsumedDataFuzzTest(provider);
    OHOS::WriteTransactionFuzzTest(provider);
    OHOS::OnReplyFuzzTest(provider);
    OHOS::DealWithCmdFuzzTest(provider);
    OHOS::SetRegistryObjectFuzzTest(provider);
    OHOS::EnableIPCThreadReclaimFuzzTest(provider);
    OHOS::PrintParcelDataFuzzTest(provider);
    OHOS::GetUint64ValueByStrSliceFuzzTest(provider);
    OHOS::GetCallerRealPidByStrFuzzTest001(provider);
    OHOS::GetCallerRealPidByStrFuzzTest002(provider);
    OHOS::GetCallerPidAndUidByStrFuzzTest(provider);
    OHOS::UnFlattenDBinderObjectFuzzTest001(provider);
    OHOS::UnFlattenDBinderObjectFuzzTest002(provider);
    OHOS::SetMaxWorkThreadFuzzTest(provider);
    OHOS::WaitForCompletionFuzzTest(provider);
    OHOS::SetCallingIdentityFuzzTest(provider);
    return 0;
}
} // namespace OHOS