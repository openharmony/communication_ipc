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
#include "iremote_proxy.h"
#include "ipc_skeleton.h"
#include "ipc_object_proxy.h"

namespace OHOS {
using namespace OHOS::HiviewDFX;

#ifndef TITLE
#define TITLE __PRETTY_FUNCTION__
#endif

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_RPC, "DBinderTestServiceProxy" };
#define DBINDER_LOGE(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Error(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)

// set wait time for raw data
static constexpr int RAW_DATA_TIMEOUT = 300;

DBinderTestServiceProxy::DBinderTestServiceProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IDBinderTestService>(impl)
{}

int DBinderTestServiceProxy::ReverseInt(int data, int &rep)
{
    DBINDER_LOGE("data = %{public}d", data);
    int error;
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    if (!dataParcel.WriteInt32(data)) {
        DBINDER_LOGE("fail to write parcel");
        return ERR_INVALID_STATE;
    }
    error = Remote()->SendRequest(REVERSEINT, dataParcel, replyParcel, option);

    rep = replyParcel.ReadInt32();
    DBINDER_LOGE("rep = %{public}d, error = %{public}d", rep, error);
    return error;
}

#ifndef CONFIG_STANDARD_SYSTEM
int DBinderTestServiceProxy::GetChildId(uint64_t &rep)
{
    int error;
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    error = Remote()->SendRequest(TRANS_TRACE_ID, dataParcel, replyParcel, option);

    rep = replyParcel.ReadUint64();
    DBINDER_LOGE("rep = %{public}" PRIu64 ", error = %{public}d", rep, error);
    return error;
}
#endif

int DBinderTestServiceProxy::TransProxyObject(int data, sptr<IRemoteObject> &transObject, int operation, int &rep,
    int &withdrawRes)
{
    int error;
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    if (!dataParcel.WriteInt32(data) || !dataParcel.WriteInt32(operation) ||
        !dataParcel.WriteRemoteObject(transObject)) {
        DBINDER_LOGE("fail to write parcel");
        return ERR_INVALID_STATE;
    }
    error = Remote()->SendRequest(TRANS_OBJECT, dataParcel, replyParcel, option);

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
        DBINDER_LOGE("fail to write parcel");
        return ERR_INVALID_STATE;
    }

    error = Remote()->SendRequest(TRANS_STUB_OBJECT, dataParcel, replyParcel, option);
    if (error != ERR_NONE) {
        DBINDER_LOGE("fail to send stub object");
        return ERR_INVALID_STATE;
    }

    rep = replyParcel.ReadInt32();

    sptr<IRemoteObject> proxy = replyParcel.ReadRemoteObject();
    if (proxy == nullptr) {
        DBINDER_LOGE("fail to get remote stub object");
        return ERR_INVALID_STATE;
    }

    MessageParcel dataStubParcel, replyStubParcel;
    if (!dataStubParcel.WriteInt32(rep)) {
        DBINDER_LOGE("fail to write parcel");
        return ERR_INVALID_STATE;
    }

    error = proxy->SendRequest(REVERSEINT, dataStubParcel, replyStubParcel, option);
    if (error != ERR_NONE) {
        DBINDER_LOGE("fail to send data info");
        return ERR_INVALID_STATE;
    }

    stubRep = replyStubParcel.ReadInt32();
    return error;
}

sptr<IRemoteObject> DBinderTestServiceProxy::GetRemoteObject(int type)
{
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    if (!dataParcel.WriteInt32(type)) {
        DBINDER_LOGE("fail to write parcel");
        return nullptr;
    }

    int error = Remote()->SendRequest(GET_REMOTE_STUB_OBJECT, dataParcel, replyParcel, option);
    if (error != ERR_NONE) {
        DBINDER_LOGE("fail to send data info");
        return nullptr;
    }

    sptr<IRemoteObject> proxy = replyParcel.ReadRemoteObject();
    if (proxy == nullptr) {
        DBINDER_LOGE("fail to get remote stub object");
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
        DBINDER_LOGE("fail to send data info");
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
        DBINDER_LOGE("fail to send data info");
    }
}

int DBinderTestServiceProxy::TransOversizedPkt(const std::string &dataStr, std::string &repStr)
{
    int error;
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    if (!dataParcel.WriteString(dataStr)) {
        DBINDER_LOGE("fail to write parcel");
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
    DBINDER_LOGE("data length = %{public}d, wait time = %{public}d", length, waitTime);

    if (length <= 1) {
        DBINDER_LOGE("length should > 1, length is %{public}d", length);
        return ERR_INVALID_STATE;
    }
    unsigned char *buffer = new (std::nothrow) unsigned char[length];
    if (buffer == nullptr) {
        DBINDER_LOGE("new buffer failed of length = %{public}d", length);
        return ERR_INVALID_STATE;
    }
    buffer[0] = 'a';
    buffer[length - 1] = 'z';
    if (!dataParcel.WriteInt32(length) || !dataParcel.WriteRawData(buffer, length) || !dataParcel.WriteInt32(length)) {
        DBINDER_LOGE("fail to write parcel");
        delete[] buffer;
        return ERR_INVALID_STATE;
    }
    delete[] buffer;
    int ret = Remote()->SendRequest(TRANS_RAW_DATA, dataParcel, replyParcel, option);
    if (ret != ERR_NONE) {
        DBINDER_LOGE("fail to send request, ret = %{public}d", ret);
        return ret;
    }
    if (length != replyParcel.ReadInt32()) {
        DBINDER_LOGE("reply wrong length");
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
    DBINDER_LOGE("data length = %{public}d, wait time = %{public}d", length, waitTime);

    if (length <= 1) {
        DBINDER_LOGE("length should > 1, length is %{public}d", length);
        return ERR_INVALID_STATE;
    }

    if (!dataParcel.WriteInt32(length)) {
        DBINDER_LOGE("fail to write parcel");
        return ERR_INVALID_STATE;
    }

    int ret = Remote()->SendRequest(RECEIVE_RAW_DATA, dataParcel, replyParcel, option);
    if (ret != ERR_NONE) {
        DBINDER_LOGE("fail to send request, ret = %{public}d", ret);
        return ret;
    }

    if (replyParcel.ReadInt32() != length) {
        DBINDER_LOGE("reply false data");
        return ERR_INVALID_DATA;
    }

    const char *buffer = nullptr;
    if ((buffer = reinterpret_cast<const char *>(replyParcel.ReadRawData(length))) == nullptr) {
        DBINDER_LOGE("fail to read raw data, length = %{public}d", length);
        return ERR_INVALID_DATA;
    }
    if (buffer[0] != 'a' || buffer[length - 1] != 'z') {
        DBINDER_LOGE("received raw data is wrong, length = %{public}d", length);
        return ERR_INVALID_DATA;
    }

    if (replyParcel.ReadInt32() != length) {
        DBINDER_LOGE("fail to read length after raw data, length = %{public}d", length);
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
        DBINDER_LOGE("fail to write parcel");
        return ERR_INVALID_STATE;
    }
    for (int i = 0; i < count; i++) {
        ret = Remote()->SendRequest(TRANS_OVERSIZED_PKT, dataParcel, replyParcel, option);
        if (ret != ERR_NONE) {
            DBINDER_LOGE("fail to send request when count = %{public}d ret = %{public}d", i, ret);
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
        DBINDER_LOGE("fail to write parcel");
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
        DBINDER_LOGE("fail to write parcel");
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
        DBINDER_LOGE("fail to write parcel");
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
        DBINDER_LOGE("fail to write parcel");
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
    DBINDER_LOGE("TestServiceProxy:PingService");
    if (!dataParcel.WriteString16(serviceName.data())) {
        DBINDER_LOGE("fail to write parcel");
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
    DBINDER_LOGE("TestServiceStub::OnReceived, cmd = %{public}d", code);
    g_lastCallingPid = IPCSkeleton::GetCallingPid();
    g_lastCallinguid = IPCSkeleton::GetCallingUid();
    switch (code) {
        case REVERSEINT: {
            return OnReverseInt(data, reply);
        }
        case REVERSEINTDELAY: {
            return OnReverseIntDelay(data, reply);
        }
        case PING_SERVICE: {
            return OnPingService(data, reply);
        }
        case ONLY_DELAY: {
            return OnDelay(data, reply);
        }
        case TRANS_OBJECT: {
            return OnReceivedObject(data, reply);
        }
        case TRANS_STUB_OBJECT: {
            return OnReceivedStubObject(data, reply);
        }
        case TRANS_OVERSIZED_PKT: {
            return OnReceivedOversizedPkt(data, reply);
        }
        case TRANS_RAW_DATA: {
            return OnReceivedRawData(data, reply);
        }
        case RECEIVE_RAW_DATA: {
            return OnSentRawData(data, reply);
        }
#ifndef CONFIG_STANDARD_SYSTEM
        case TRANS_TRACE_ID: {
            return OnGetChildId(data, reply);
        }
#endif
        case GET_REMOTE_STUB_OBJECT: {
            return OnReceivedGetStubObject(data, reply);
        }
        case GET_REMOTE_DES_TIMES: {
            return OnReceivedGetDecTimes(data, reply);
        }
        case CLEAR_REMOTE_DES_TIMES: {
            return OnReceivedClearDecTimes(data, reply);
        }
        default: {
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
}

int DBinderTestServiceStub::ReverseIntDelayAsync(int data, int &rep)
{
    HiLog::Error(LABEL, "%{public}s: not valid operate", __func__);
    return 0;
}

int DBinderTestServiceStub::OnReverseInt(MessageParcel &data, MessageParcel &reply)
{
    int result;
    int32_t reqData = data.ReadInt32();
    int ret = ReverseInt(reqData, result);
    HiLog::Info(LABEL, "ReverseInt result = %{public}d", result);
    if (!reply.WriteInt32(result)) {
        DBINDER_LOGE("fail to write parcel");
        ret = ERR_INVALID_STATE;
    }

    return ret;
}

#ifndef CONFIG_STANDARD_SYSTEM
int DBinderTestServiceStub::OnGetChildId(MessageParcel &data, MessageParcel &reply)
{
    uint64_t reqData = HiTrace::GetId().GetChainId();
    if (!reply.WriteUint64(reqData)) {
        DBINDER_LOGE("fail to write parcel");
        return ERR_INVALID_STATE;
    }

    DBINDER_LOGE("before reset uid = %{public}d, callerId = %{public}s, localId = %{public}s, islocal = %{public}d",
        IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingDeviceID().c_str(),
        IPCSkeleton::GetLocalDeviceID().c_str(), IPCSkeleton::IsLocalCalling());
    std::string token = IPCSkeleton::ResetCallingIdentity();

    DBINDER_LOGE("before set uid = %{public}d, callerId = %{public}s, localId = %{public}s, islocal = %{public}d",
        IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingDeviceID().c_str(),
        IPCSkeleton::GetLocalDeviceID().c_str(), IPCSkeleton::IsLocalCalling());
    if (!IPCSkeleton::SetCallingIdentity(token)) {
        DBINDER_LOGE("Set Calling Identity fail");
    }

    DBINDER_LOGE("after set uid = %{public}d, callerId = %{public}s, localId = %{public}s, islocal = %{public}d",
        IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingDeviceID().c_str(),
        IPCSkeleton::GetLocalDeviceID().c_str(), IPCSkeleton::IsLocalCalling());
    return ERR_NONE;
}
#endif

int DBinderTestServiceStub::OnReverseIntDelay(MessageParcel &data, MessageParcel &reply)
{
    int result;
    int32_t reqData = data.ReadInt32();
    int ret = ReverseIntDelay(reqData, result);
    if (!reply.WriteInt32(result)) {
        DBINDER_LOGE("fail to write parcel");
        ret = ERR_INVALID_STATE;
    }

    return ret;
}

int DBinderTestServiceStub::OnPingService(MessageParcel &data, MessageParcel &reply)
{
    std::u16string serviceName = data.ReadString16();
    int ret = PingService(serviceName);
    HiLog::Info(LABEL, "%s:PingService: ret=%d", __func__, ret);
    if (!reply.WriteInt32(ret)) {
        DBINDER_LOGE("fail to write parcel");
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
        DBINDER_LOGE("fail to write parcel");
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
        DBINDER_LOGE("null proxy");
        return ERR_INVALID_STATE;
    }

    // use the received proxy to communicate
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    if (!dataParcel.WriteInt32(reqData)) {
        DBINDER_LOGE("fail to write parcel");
        return ERR_INVALID_STATE;
    }
    HiLog::Info(LABEL, "%s:TRANSOBJECT: reqData=%d", __func__, reqData);
    int ret = proxy->SendRequest(REVERSEINT, dataParcel, replyParcel, option);
    int reqResult = replyParcel.ReadInt32();
    HiLog::Info(LABEL, "%s:TRANSOBJECT: result=%d", __func__, reqResult);

    if (!reply.WriteInt32(reqResult)) {
        DBINDER_LOGE("fail to write parcel");
        return ERR_INVALID_STATE;
    }

    if (operation == SAVE) {
        recvProxy_ = proxy;
    }

    // received proxy is different from that of last time
    if ((operation == WITHDRAW) && (recvProxy_ != proxy)) {
        if (!reply.WriteInt32(1)) {
            DBINDER_LOGE("fail to write parcel");
            ret = ERR_INVALID_STATE;
        }
        return ret;
    }

    if (!reply.WriteInt32(0)) {
        DBINDER_LOGE("fail to write parcel");
        return ERR_INVALID_STATE;
    }
    return ret;
}

int DBinderTestServiceStub::OnReceivedStubObject(MessageParcel &data, MessageParcel &reply)
{
    int32_t reqData = data.ReadInt32();
    sptr<IRemoteObject> proxy = data.ReadRemoteObject();
    if (proxy == nullptr) {
        DBINDER_LOGE("fail to get proxy");
        return ERR_INVALID_STATE;
    }

    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    if (!dataParcel.WriteInt32(reqData)) {
        DBINDER_LOGE("fail to write parcel");
        return ERR_INVALID_STATE;
    }

    int error = proxy->SendRequest(REVERSEINT, dataParcel, replyParcel, option);
    if (error != ERR_NONE) {
        DBINDER_LOGE("fail to send data info");
        return ERR_INVALID_STATE;
    }
    int reqResult = replyParcel.ReadInt32();
    if (!reply.WriteInt32(reqResult)) {
        DBINDER_LOGE("fail to write parcel");
        return ERR_INVALID_STATE;
    }

    if (!reply.WriteRemoteObject(this)) {
        DBINDER_LOGE("fail to write parcel stub");
        return ERR_INVALID_STATE;
    }

    return error;
}

int DBinderTestServiceStub::OnReceivedGetStubObject(MessageParcel &data, MessageParcel &reply)
{
    if (!reply.WriteRemoteObject(GetRemoteObject(data.ReadInt32()))) {
        DBINDER_LOGE("fail to write parcel");
        return ERR_INVALID_STATE;
    }

    return ERR_NONE;
}

int DBinderTestServiceStub::OnReceivedGetDecTimes(MessageParcel &data, MessageParcel &reply)
{
    if (!reply.WriteInt32(GetRemoteDecTimes())) {
        DBINDER_LOGE("fail to write parcel");
        return ERR_INVALID_STATE;
    }

    return ERR_NONE;
}

int DBinderTestServiceStub::OnReceivedClearDecTimes(MessageParcel &data, MessageParcel &reply)
{
    DBINDER_LOGE("OnReceivedClearDecTimes");

    ClearRemoteDecTimes();
    return ERR_NONE;
}

int DBinderTestServiceStub::OnReceivedOversizedPkt(MessageParcel &data, MessageParcel &reply)
{
    std::string reqStr = data.ReadString();
    std::string resultStr = reqStr;
    if (!reply.WriteString(resultStr)) {
        DBINDER_LOGE("fail to write parcel");
        return ERR_INVALID_STATE;
    }

    return ERR_NONE;
}

int DBinderTestServiceStub::OnReceivedRawData(MessageParcel &data, MessageParcel &reply)
{
    int length = data.ReadInt32();
    if (length <= 1) {
        DBINDER_LOGE("length should > 1, length is %{public}d", length);
        if (!reply.WriteInt32(length)) {
            DBINDER_LOGE("fail to write parcel");
        }
        return ERR_INVALID_DATA;
    }
    const char *buffer = nullptr;
    if ((buffer = reinterpret_cast<const char *>(data.ReadRawData(length))) == nullptr) {
        if (!reply.WriteInt32(0)) {
            DBINDER_LOGE("fail to write parcel");
        }
        DBINDER_LOGE("read raw data failed, length = %{public}d", length);
        return ERR_INVALID_DATA;
    }
    if (buffer[0] != 'a' || buffer[length - 1] != 'z') {
        if (!reply.WriteInt32(0)) {
            DBINDER_LOGE("fail to write parcel");
        }
        DBINDER_LOGE("buffer error, length = %{public}d", length);
        return ERR_INVALID_DATA;
    }
    if (data.ReadInt32() != length) {
        if (!reply.WriteInt32(0)) {
            DBINDER_LOGE("fail to write parcel");
        }
        DBINDER_LOGE("read raw data after failed, length = %{public}d", length);
        return ERR_INVALID_DATA;
    }
    if (!reply.WriteInt32(length)) {
        DBINDER_LOGE("fail to write parcel");
        return ERR_INVALID_STATE;
    }

    return ERR_NONE;
}

int DBinderTestServiceStub::OnSentRawData(MessageParcel &data, MessageParcel &reply)
{
    int length = data.ReadInt32();
    if (length <= 1) {
        DBINDER_LOGE("length should > 1, length is %{public}d", length);
        if (!reply.WriteInt32(length)) {
            DBINDER_LOGE("fail to write parcel");
        }
        return ERR_INVALID_DATA;
    }

    unsigned char *buffer = new (std::nothrow) unsigned char[length];
    if (buffer == nullptr) {
        DBINDER_LOGE("new buffer failed of length = %{public}d", length);
        return ERR_INVALID_STATE;
    }
    buffer[0] = 'a';
    buffer[length - 1] = 'z';
    if (!reply.WriteInt32(length) || !reply.WriteRawData(buffer, length) || !reply.WriteInt32(length)) {
        DBINDER_LOGE("fail to write parcel");
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
    DBINDER_LOGE("recv death notification");
}

DBinderTestDeathRecipient::DBinderTestDeathRecipient() {}

DBinderTestDeathRecipient::~DBinderTestDeathRecipient() {}
} // namespace OHOS
