/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "dbinder_test_service_skeleton.h"

#include <cinttypes>

#include "dbinder_log.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "ipc_object_proxy.h"
#include "iremote_proxy.h"
#include "iservice_registry.h"
#include "string_ex.h"
#include "system_ability_definition.h"

namespace OHOS {
using namespace OHOS::HiviewDFX;

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_TEST, "DBinderTestServiceProxy" };

// set wait time for raw data
static constexpr int RAW_DATA_TIMEOUT = 300;

DBinderTestServiceProxy::DBinderTestServiceProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IDBinderTestService>(impl)
{}

int DBinderTestServiceProxy::ReverseInt(int data, int &rep)
{
    DBINDER_LOGE(LOG_LABEL, "data = %{public}d", data);
    int error;
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    if (!dataParcel.WriteInt32(data)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }
    error = Remote()->SendRequest(REVERSEINT, dataParcel, replyParcel, option);

    rep = replyParcel.ReadInt32();
    DBINDER_LOGE(LOG_LABEL, "rep = %{public}d, error = %{public}d", rep, error);
    return error;
}

int DBinderTestServiceProxy::GetChildId(uint64_t &rep)
{
    int error;
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    error = Remote()->SendRequest(TRANS_TRACE_ID, dataParcel, replyParcel, option);

    rep = replyParcel.ReadUint64();
    DBINDER_LOGE(LOG_LABEL, "rep = %{public}" PRIu64 ", error = %{public}d", rep, error);
    return error;
}

int DBinderTestServiceProxy::TransProxyObject(int data, sptr<IRemoteObject> &transObject, int operation, int &rep,
    int &withdrawRes)
{
    int error;
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    if (!dataParcel.WriteInt32(data) || !dataParcel.WriteInt32(operation) ||
        !dataParcel.WriteRemoteObject(transObject)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }
    error = Remote()->SendRequest(TRANS_PROXY_OBJECT, dataParcel, replyParcel, option);

    rep = replyParcel.ReadInt32();
    withdrawRes = replyParcel.ReadInt32();
    return error;
}

int DBinderTestServiceProxy::TransProxyObjectRefCount(sptr<IRemoteObject> &transObject, int operation)
{
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInt32(operation) || !data.WriteRemoteObject(transObject)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }
    int error = Remote()->SendRequest(TRANS_PROXY_OBJECT_REFCOUNT, data, reply, option);
    if (error != ERR_NONE) {
        DBINDER_LOGE(LOG_LABEL, "fail to send proxy object");
        return ERR_INVALID_STATE;
    }
    return error;
}

int DBinderTestServiceProxy::TransProxyObjectAgain(int data, sptr<IRemoteObject> &transObject, int operation, int &rep,
    int &withdrawRes)
{
    int error;
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    if (!dataParcel.WriteInt32(data) || !dataParcel.WriteInt32(operation) ||
        !dataParcel.WriteRemoteObject(transObject)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }
    error = Remote()->SendRequest(TRANS_OBJECT_OVER_DEVICE_OVER_PROCESS, dataParcel, replyParcel, option);

    rep = replyParcel.ReadInt32();
    withdrawRes = replyParcel.ReadInt32();
    return error;
}

int DBinderTestServiceProxy::TransStubObject(int data, sptr<IRemoteObject> &transObject, int &rep, int &stubRep)
{
    int error;
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    if (!dataParcel.WriteInt32(data) || !dataParcel.WriteRemoteObject(transObject)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }

    error = Remote()->SendRequest(TRANS_STUB_OBJECT, dataParcel, replyParcel, option);
    if (error != ERR_NONE) {
        DBINDER_LOGE(LOG_LABEL, "fail to send stub object");
        return ERR_INVALID_STATE;
    }

    rep = replyParcel.ReadInt32();

    sptr<IRemoteObject> proxy = replyParcel.ReadRemoteObject();
    if (proxy == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "fail to get remote stub object");
        return ERR_INVALID_STATE;
    }

    MessageParcel dataStubParcel, replyStubParcel;
    if (!dataStubParcel.WriteInt32(rep)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }

    error = proxy->SendRequest(REVERSEINT, dataStubParcel, replyStubParcel, option);
    if (error != ERR_NONE) {
        DBINDER_LOGE(LOG_LABEL, "fail to send data info");
        return ERR_INVALID_STATE;
    }

    stubRep = replyStubParcel.ReadInt32();
    return error;
}

int DBinderTestServiceProxy::TransStubObjectRefCount(sptr<IRemoteObject> &transObject, int operation)
{
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInt32(operation) || !data.WriteRemoteObject(transObject)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }
    int error = Remote()->SendRequest(TRANS_STUB_OBJECT_REFCOUNT, data, reply, option);
    if (error != ERR_NONE) {
        DBINDER_LOGE(LOG_LABEL, "fail to send stub object");
        return ERR_INVALID_STATE;
    }
    return error;
}

sptr<IRemoteObject> DBinderTestServiceProxy::GetRemoteObject(int type)
{
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    if (!dataParcel.WriteInt32(type)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return nullptr;
    }

    int error = Remote()->SendRequest(GET_REMOTE_STUB_OBJECT, dataParcel, replyParcel, option);
    if (error != ERR_NONE) {
        DBINDER_LOGE(LOG_LABEL, "fail to send data info");
        return nullptr;
    }

    sptr<IRemoteObject> proxy = replyParcel.ReadRemoteObject();
    if (proxy == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "fail to get remote stub object");
        return nullptr;
    }
    return proxy;
}

int DBinderTestServiceProxy::GetRemoteDecTimes()
{
    MessageOption option;
    MessageParcel dataParcel, replyParcel;

    int error = Remote()->SendRequest(GET_REMOTE_DES_TIMES, dataParcel, replyParcel, option);
    if (error != ERR_NONE) {
        DBINDER_LOGE(LOG_LABEL, "fail to send data info");
        return 0;
    }

    return replyParcel.ReadInt32();
}

void DBinderTestServiceProxy::ClearRemoteDecTimes()
{
    MessageOption option;
    MessageParcel dataParcel, replyParcel;

    int error = Remote()->SendRequest(CLEAR_REMOTE_DES_TIMES, dataParcel, replyParcel, option);
    if (error != ERR_NONE) {
        DBINDER_LOGE(LOG_LABEL, "fail to send data info");
    }
}

int DBinderTestServiceProxy::TransOversizedPkt(const std::string &dataStr, std::string &repStr)
{
    int error;
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    if (!dataParcel.WriteString(dataStr)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }
    error = Remote()->SendRequest(TRANS_OVERSIZED_PKT, dataParcel, replyParcel, option);

    repStr = replyParcel.ReadString();
    return error;
}

int DBinderTestServiceProxy::ProxyTransRawData(int length)
{
    MessageParcel dataParcel, replyParcel;

    MessageOption option;
    option.SetWaitTime(RAW_DATA_TIMEOUT);
    int waitTime = option.GetWaitTime();
    DBINDER_LOGE(LOG_LABEL, "data length = %{public}d, wait time = %{public}d", length, waitTime);

    if (length <= 1) {
        DBINDER_LOGE(LOG_LABEL, "length should > 1, length is %{public}d", length);
        return ERR_INVALID_STATE;
    }
    unsigned char *buffer = new (std::nothrow) unsigned char[length];
    if (buffer == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "new buffer failed of length = %{public}d", length);
        return ERR_INVALID_STATE;
    }
    buffer[0] = 'a';
    buffer[length - 1] = 'z';
    if (!dataParcel.WriteInt32(length) || !dataParcel.WriteRawData(buffer, length) || !dataParcel.WriteInt32(length)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        delete[] buffer;
        return ERR_INVALID_STATE;
    }
    delete[] buffer;
    int ret = Remote()->SendRequest(TRANS_RAW_DATA, dataParcel, replyParcel, option);
    if (ret != ERR_NONE) {
        DBINDER_LOGE(LOG_LABEL, "fail to send request, ret = %{public}d", ret);
        return ret;
    }
    if (length != replyParcel.ReadInt32()) {
        DBINDER_LOGE(LOG_LABEL, "reply wrong length");
        ret += ERR_TRANSACTION_FAILED;
    }
    return ret;
}

int DBinderTestServiceProxy::StubTransRawData(int length)
{
    MessageParcel dataParcel, replyParcel;

    MessageOption option;
    option.SetWaitTime(RAW_DATA_TIMEOUT);
    int waitTime = option.GetWaitTime();
    DBINDER_LOGE(LOG_LABEL, "data length = %{public}d, wait time = %{public}d", length, waitTime);

    if (length <= 1) {
        DBINDER_LOGE(LOG_LABEL, "length should > 1, length is %{public}d", length);
        return ERR_INVALID_STATE;
    }

    if (!dataParcel.WriteInt32(length)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }

    int ret = Remote()->SendRequest(RECEIVE_RAW_DATA, dataParcel, replyParcel, option);
    if (ret != ERR_NONE) {
        DBINDER_LOGE(LOG_LABEL, "fail to send request, ret = %{public}d", ret);
        return ret;
    }

    if (replyParcel.ReadInt32() != length) {
        DBINDER_LOGE(LOG_LABEL, "reply false data");
        return ERR_INVALID_DATA;
    }

    const char *buffer = nullptr;
    if ((buffer = reinterpret_cast<const char *>(replyParcel.ReadRawData(length))) == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "fail to read raw data, length = %{public}d", length);
        return ERR_INVALID_DATA;
    }
    if (buffer[0] != 'a' || buffer[length - 1] != 'z') {
        DBINDER_LOGE(LOG_LABEL, "received raw data is wrong, length = %{public}d", length);
        return ERR_INVALID_DATA;
    }

    if (replyParcel.ReadInt32() != length) {
        DBINDER_LOGE(LOG_LABEL, "fail to read length after raw data, length = %{public}d", length);
        return ERR_INVALID_DATA;
    }

    return ERR_NONE;
}

int DBinderTestServiceProxy::FlushAsyncCommands(int count, int length)
{
    int ret;
    MessageOption option = { MessageOption::TF_ASYNC };
    MessageParcel dataParcel, replyParcel;
    std::string dataStr(length, 'a');
    if (!dataParcel.WriteString(dataStr)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }
    for (int i = 0; i < count; i++) {
        ret = Remote()->SendRequest(TRANS_OVERSIZED_PKT, dataParcel, replyParcel, option);
        if (ret != ERR_NONE) {
            DBINDER_LOGE(LOG_LABEL, "fail to send request when count = %{public}d ret = %{public}d", i, ret);
            return ret;
        }
    }
    ret = IPCSkeleton::FlushCommands(this->AsObject());
    return ret;
}

int DBinderTestServiceProxy::ReverseIntNullReply(int data, int &rep)
{
    int error;
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    if (!dataParcel.WriteInt32(data)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }
    error = Remote()->SendRequest(REVERSEINT, dataParcel, replyParcel, option);

    rep = replyParcel.ReadInt32();
    return error;
}

int DBinderTestServiceProxy::ReverseIntVoidData(int data, int &rep)
{
    int error;
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    // do not write data to parcel;
    error = Remote()->SendRequest(REVERSEINT, dataParcel, replyParcel, option);

    rep = replyParcel.ReadInt32();
    return error;
}

int DBinderTestServiceProxy::ReverseIntDelay(int data, int &rep)
{
    int error;
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    if (!dataParcel.WriteInt32(data)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }
    error = Remote()->SendRequest(REVERSEINTDELAY, dataParcel, replyParcel, option);

    rep = replyParcel.ReadInt32();
    return error;
}

int DBinderTestServiceProxy::Delay(int data, int &rep)
{
    int error;
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    if (!dataParcel.WriteInt32(data)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }
    error = Remote()->SendRequest(ONLY_DELAY, dataParcel, replyParcel, option);

    rep = replyParcel.ReadInt32();
    return error;
}

int DBinderTestServiceProxy::ReverseIntDelayAsync(int data, int &rep)
{
    int error;
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    if (!dataParcel.WriteInt32(data) ||
        // 2:for data update check, only in test case
        !replyParcel.WriteInt32(data * 2)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }
    error = Remote()->SendRequest(REVERSEINTDELAY, dataParcel, replyParcel, option);

    rep = replyParcel.ReadInt32();
    return error;
}

int DBinderTestServiceProxy::PingService(std::u16string &serviceName)
{
    int error;
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    DBINDER_LOGE(LOG_LABEL, "TestServiceProxy:PingService");
    if (!dataParcel.WriteString16(serviceName.data())) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }
    error = Remote()->SendRequest(REVERSEINT, dataParcel, replyParcel, option);
    replyParcel.ReadInt32();
    return error;
}

pid_t DBinderTestServiceStub::g_lastCallingPid = 0;
pid_t DBinderTestServiceStub::g_lastCallinguid = 0;

pid_t DBinderTestServiceStub::GetLastCallingPid()
{
    return g_lastCallingPid;
}

uid_t DBinderTestServiceStub::GetLastCallingUid()
{
    return g_lastCallinguid;
}

int DBinderTestServiceStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    DBINDER_LOGE(LOG_LABEL, "TestServiceStub::OnReceived, cmd = %{public}d", code);
    g_lastCallingPid = IPCSkeleton::GetCallingPid();
    g_lastCallinguid = IPCSkeleton::GetCallingUid();
    auto it = codeFuncMap_.find(code);
    if (it != codeFuncMap_.end()) {
        auto itFunc = it->second;
        if (itFunc != nullptr) {
            return (this->*itFunc)(data, reply);
        }
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int DBinderTestServiceStub::ReverseIntDelayAsync(int data, int &rep)
{
    (void)data;
    HiLog::Error(LOG_LABEL, "%{public}s: not valid operate", __func__);
    return 0;
}

int DBinderTestServiceStub::OnReverseInt(MessageParcel &data, MessageParcel &reply)
{
    int result;
    int32_t reqData = data.ReadInt32();
    int ret = ReverseInt(reqData, result);
    DBINDER_LOGI(LOG_LABEL, "ReverseInt result = %{public}d", result);
    if (!reply.WriteInt32(result)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        ret = ERR_INVALID_STATE;
    }

    return ret;
}

int DBinderTestServiceStub::OnGetChildId(MessageParcel &data, MessageParcel &reply)
{
    uint64_t reqData = HiTraceChain::GetId().GetChainId();
    if (!reply.WriteUint64(reqData)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }

    DBINDER_LOGE(LOG_LABEL,
        "before reset uid = %{public}d, callerId = %{public}s, localId = %{public}s, islocal = %{public}d",
        IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingDeviceID().c_str(),
        IPCSkeleton::GetLocalDeviceID().c_str(), IPCSkeleton::IsLocalCalling());
    std::string token = IPCSkeleton::ResetCallingIdentity();

    DBINDER_LOGE(LOG_LABEL,
        "before set uid = %{public}d, callerId = %{public}s, localId = %{public}s, islocal = %{public}d",
        IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingDeviceID().c_str(),
        IPCSkeleton::GetLocalDeviceID().c_str(), IPCSkeleton::IsLocalCalling());
    if (!IPCSkeleton::SetCallingIdentity(token)) {
        DBINDER_LOGE(LOG_LABEL, "Set Calling Identity fail");
    }

    DBINDER_LOGE(LOG_LABEL,
        "after set uid = %{public}d, callerId = %{public}s, localId = %{public}s, islocal = %{public}d",
        IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingDeviceID().c_str(),
        IPCSkeleton::GetLocalDeviceID().c_str(), IPCSkeleton::IsLocalCalling());
    return ERR_NONE;
}

int DBinderTestServiceStub::OnReverseIntDelay(MessageParcel &data, MessageParcel &reply)
{
    int result;
    int32_t reqData = data.ReadInt32();
    int ret = ReverseIntDelay(reqData, result);
    if (!reply.WriteInt32(result)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        ret = ERR_INVALID_STATE;
    }

    return ret;
}

int DBinderTestServiceStub::OnPingService(MessageParcel &data, MessageParcel &reply)
{
    std::u16string serviceName = data.ReadString16();
    int ret = PingService(serviceName);
    DBINDER_LOGI(LOG_LABEL, "%s:PingService: ret=%d", __func__, ret);
    if (!reply.WriteInt32(ret)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        ret = ERR_INVALID_STATE;
    }

    return ret;
}

int DBinderTestServiceStub::OnDelay(MessageParcel &data, MessageParcel &reply)
{
    int result;
    int32_t reqData = data.ReadInt32();
    int ret = Delay(reqData, result);
    if (!reply.WriteInt32(result)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        ret = ERR_INVALID_STATE;
    }

    return ret;
}

int DBinderTestServiceStub::OnReceivedObject(MessageParcel &data, MessageParcel &reply)
{
    int32_t reqData = data.ReadInt32();
    int32_t operation = data.ReadInt32();
    sptr<IRemoteObject> proxy = data.ReadRemoteObject();
    if (proxy == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "null proxy");
        return ERR_INVALID_STATE;
    }

    // use the received proxy to communicate
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    if (!dataParcel.WriteInt32(reqData)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }
    DBINDER_LOGI(LOG_LABEL, "%{public}s:TRANSOBJECT: reqData=%{public}d", __func__, reqData);
    int ret = proxy->SendRequest(REVERSEINT, dataParcel, replyParcel, option);
    int reqResult = replyParcel.ReadInt32();
    DBINDER_LOGI(LOG_LABEL, "%{public}s:TRANSOBJECT: result=%{public}d", __func__, reqResult);

    if (!reply.WriteInt32(reqResult)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }

    if (operation == SAVE) {
        recvProxy_ = proxy;
    }

    // received proxy is different from that of last time
    if ((operation == WITHDRAW) && (recvProxy_ != proxy)) {
        if (!reply.WriteInt32(1)) {
            DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
            ret = ERR_INVALID_STATE;
        }
        return ret;
    }

    if (!reply.WriteInt32(0)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }
    return ret;
}

int DBinderTestServiceStub::OnReceivedProxyObjectRefCount(MessageParcel &data, MessageParcel &reply)
{
    int32_t operation = data.ReadInt32();
    sptr<IRemoteObject> proxy = data.ReadRemoteObject();
    if (proxy == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "fail to get proxy");
        return ERR_INVALID_STATE;
    }
    if (operation == IDBinderTestService::SAVE) {
        recvProxy_ = proxy;
    } else if (operation == IDBinderTestService::WITHDRAW) {
        recvProxy_ = nullptr;
    }
    return ERR_NONE;
}

int DBinderTestServiceStub::OnReceivedObjectTransAgain(MessageParcel &data, MessageParcel &reply)
{
    int32_t reqData = data.ReadInt32();
    int32_t operation = data.ReadInt32();
    sptr<IRemoteObject> proxy = data.ReadRemoteObject();
    if (proxy == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "null proxy");
        return ERR_INVALID_STATE;
    }
    sptr<ISystemAbilityManager> manager_ = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (manager_ == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "null manager_");
        return ERR_INVALID_STATE;
    }
    DBINDER_LOGI(LOG_LABEL, "%{public}s:OnReceivedObjectTransAgain-1: reqData=%{public}d", __func__, reqData);

    sptr<IRemoteObject> object = manager_->GetSystemAbility(RPC_TEST_SERVICE2);
    if (object == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "null object of RPC_TEST_SERVICE2");
        return ERR_INVALID_STATE;
    }

    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    if (!dataParcel.WriteInt32(reqData) || !dataParcel.WriteInt32(operation) ||
        !dataParcel.WriteRemoteObject(proxy)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }
    DBINDER_LOGI(LOG_LABEL, "%{public}s:OnReceivedObjectTransAgain-2: reqData=%{public}d", __func__, reqData);
    int ret = object->SendRequest(TRANS_RPC_OBJECT_TO_LOCAL, dataParcel, replyParcel, option);

    int reqResult = replyParcel.ReadInt32();
    DBINDER_LOGI(LOG_LABEL, "%{public}s:OnReceivedObjectTransAgain-3: result=%{public}d", __func__, reqResult);

    if (!reply.WriteInt32(reqResult)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }
    DBINDER_LOGI(LOG_LABEL, "%{public}s:OnReceivedObjectTransAgain-4: result=%{public}d", __func__, reqResult);
    if (!reply.WriteInt32(0)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }
    DBINDER_LOGI(LOG_LABEL, "%{public}s:OnReceivedObjectTransAgain-5: result=%{public}d", __func__, reqResult);
    return ret;
}

int DBinderTestServiceStub::OnReceivedStubObject(MessageParcel &data, MessageParcel &reply)
{
    int32_t reqData = data.ReadInt32();
    sptr<IRemoteObject> proxy = data.ReadRemoteObject();
    if (proxy == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "fail to get proxy");
        return ERR_INVALID_STATE;
    }

    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    if (!dataParcel.WriteInt32(reqData)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }

    int error = proxy->SendRequest(REVERSEINT, dataParcel, replyParcel, option);
    if (error != ERR_NONE) {
        DBINDER_LOGE(LOG_LABEL, "fail to send data info");
        return ERR_INVALID_STATE;
    }
    int reqResult = replyParcel.ReadInt32();
    if (!reply.WriteInt32(reqResult)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }

    if (!reply.WriteRemoteObject(this)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel stub");
        return ERR_INVALID_STATE;
    }

    return error;
}

int DBinderTestServiceStub::OnReceivedStubObjectRefCount(MessageParcel &data, MessageParcel &reply)
{
    int32_t operation = data.ReadInt32();
    sptr<IRemoteObject> proxy = data.ReadRemoteObject();
    if (proxy == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "fail to get proxy");
        return ERR_INVALID_STATE;
    }
    if (operation == IDBinderTestService::SAVE) {
        recvProxy_ = proxy;
    } else if (operation == IDBinderTestService::WITHDRAW) {
        recvProxy_ = nullptr;
    }
    return ERR_NONE;
}

int DBinderTestServiceStub::OnReceivedGetStubObject(MessageParcel &data, MessageParcel &reply)
{
    if (!reply.WriteRemoteObject(GetRemoteObject(data.ReadInt32()))) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }

    return ERR_NONE;
}

int DBinderTestServiceStub::OnReceivedGetDecTimes(MessageParcel &data, MessageParcel &reply)
{
    if (!reply.WriteInt32(GetRemoteDecTimes())) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }

    return ERR_NONE;
}

int DBinderTestServiceStub::OnReceivedClearDecTimes(MessageParcel &data, MessageParcel &reply)
{
    DBINDER_LOGE(LOG_LABEL, "OnReceivedClearDecTimes");

    ClearRemoteDecTimes();
    return ERR_NONE;
}

int DBinderTestServiceStub::OnReceivedOversizedPkt(MessageParcel &data, MessageParcel &reply)
{
    std::string reqStr = data.ReadString();
    std::string resultStr = reqStr;
    if (!reply.WriteString(resultStr)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }

    return ERR_NONE;
}

int DBinderTestServiceStub::OnReceivedRawData(MessageParcel &data, MessageParcel &reply)
{
    int length = data.ReadInt32();
    if (length <= 1) {
        DBINDER_LOGE(LOG_LABEL, "length should > 1, length is %{public}d", length);
        if (!reply.WriteInt32(length)) {
            DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        }
        return ERR_INVALID_DATA;
    }
    const char *buffer = nullptr;
    if ((buffer = reinterpret_cast<const char *>(data.ReadRawData(length))) == nullptr) {
        if (!reply.WriteInt32(0)) {
            DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        }
        DBINDER_LOGE(LOG_LABEL, "read raw data failed, length = %{public}d", length);
        return ERR_INVALID_DATA;
    }
    if (buffer[0] != 'a' || buffer[length - 1] != 'z') {
        if (!reply.WriteInt32(0)) {
            DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        }
        DBINDER_LOGE(LOG_LABEL, "buffer error, length = %{public}d", length);
        return ERR_INVALID_DATA;
    }
    if (data.ReadInt32() != length) {
        if (!reply.WriteInt32(0)) {
            DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        }
        DBINDER_LOGE(LOG_LABEL, "read raw data after failed, length = %{public}d", length);
        return ERR_INVALID_DATA;
    }
    if (!reply.WriteInt32(length)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }

    return ERR_NONE;
}

int DBinderTestServiceStub::OnSentRawData(MessageParcel &data, MessageParcel &reply)
{
    int length = data.ReadInt32();
    if (length <= 1) {
        DBINDER_LOGE(LOG_LABEL, "length should > 1, length is %{public}d", length);
        if (!reply.WriteInt32(length)) {
            DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        }
        return ERR_INVALID_DATA;
    }

    unsigned char *buffer = new (std::nothrow) unsigned char[length];
    if (buffer == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "new buffer failed of length = %{public}d", length);
        return ERR_INVALID_STATE;
    }
    buffer[0] = 'a';
    buffer[length - 1] = 'z';
    if (!reply.WriteInt32(length) || !reply.WriteRawData(buffer, length) || !reply.WriteInt32(length)) {
        DBINDER_LOGE(LOG_LABEL, "fail to write parcel");
        delete[] buffer;
        return ERR_INVALID_STATE;
    }
    delete[] buffer;
    return ERR_NONE;
}

bool DBinderTestDeathRecipient::g_gotDeathRecipient = false;
bool DBinderTestDeathRecipient::GotDeathRecipient()
{
    return g_gotDeathRecipient;
}

void DBinderTestDeathRecipient::ClearDeathRecipient()
{
    g_gotDeathRecipient = false;
}

void DBinderTestDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    g_gotDeathRecipient = true;
    printf("Succ! Remote Died!\n");
    DBINDER_LOGE(LOG_LABEL, "recv death notification");
}

DBinderTestDeathRecipient::DBinderTestDeathRecipient() {}

DBinderTestDeathRecipient::~DBinderTestDeathRecipient() {}
} // namespace OHOS
