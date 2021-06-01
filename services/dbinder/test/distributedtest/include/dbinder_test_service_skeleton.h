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

#ifndef OHOS_DBINDER_TEST_SERVICE_SKELETON_H
#define OHOS_DBINDER_TEST_SERVICE_SKELETON_H

#include "ipc_types.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_stub.h"
#include "iremote_proxy.h"
#include "hilog/log.h"
#include "log_tags.h"
#ifndef CONFIG_STANDARD_SYSTEM
#include "hitrace/trace.h"
#endif

namespace OHOS {
class IDBinderTestService : public IRemoteBroker {
public:
    enum {
        REVERSEINT = 0,
        REVERSEINTDELAY = 1,
        PING_SERVICE = 2,
        GET_FOO_SERVICE = 3,
        ONLY_DELAY = 4,
        TRANS_OBJECT = 5,
        TRANS_OVERSIZED_PKT = 6,
        TRANS_RAW_DATA = 7,
        RECEIVE_RAW_DATA = 8,
        TRANS_TRACE_ID = 9,
        TRANS_STUB_OBJECT = 10,
        GET_REMOTE_STUB_OBJECT = 11,
        GET_REMOTE_DES_TIMES = 12,
        CLEAR_REMOTE_DES_TIMES = 13,
    };

    enum {
        NOT_SAVE = 0,
        SAVE = 1,
        WITHDRAW = 2,
    };

    enum {
        FIRST_OBJECT = 0,  // Acquired once will be released automatically
        SECOND_OBJECT = 1, // Acquired twice will be released automatically
    };

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.rpc.IDBinderTestService");
    virtual int ReverseInt(int data, int &rep) = 0;
    virtual int ReverseIntDelay(int data, int &rep) = 0;
    virtual int Delay(int data, int &rep) = 0;
    virtual int PingService(std::u16string &serviceName) = 0;
    virtual int ReverseIntDelayAsync(int data, int &rep) = 0;
    virtual int TransProxyObject(int data, sptr<IRemoteObject> &transObject, int operation, int &rep,
        int &withdrawRes) = 0;
    virtual int TransStubObject(int data, sptr<IRemoteObject> &transObject, int &rep, int &stubRep) = 0;
    virtual int TransOversizedPkt(const std::string &dataStr, std::string &repStr) = 0;
    virtual int ProxyTransRawData(int lengths) = 0;
    virtual int StubTransRawData(int length) = 0;
#ifndef CONFIG_STANDARD_SYSTEM
    virtual int GetChildId(uint64_t &rep) = 0;
#endif
    virtual int FlushAsyncCommands(int count, int length) = 0;
    virtual sptr<IRemoteObject> GetRemoteObject(int type) = 0;
    virtual int GetRemoteDecTimes() = 0;
    virtual void ClearRemoteDecTimes() = 0;

private:
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_RPC, "IDBinderTestService" };
};

class DBinderTestServiceStub : public IRemoteStub<IDBinderTestService> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    int ReverseIntDelayAsync(int data, int &rep) override;
    static pid_t GetLastCallingPid();
    static uid_t GetLastCallingUid();

private:
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_RPC, "DBinderTestStub" };
    static pid_t g_lastCallingPid;
    static pid_t g_lastCallinguid;
    sptr<IRemoteObject> recvProxy_;

    int OnReverseInt(MessageParcel &data, MessageParcel &reply);
    int OnReverseIntDelay(MessageParcel &data, MessageParcel &reply);
    int OnPingService(MessageParcel &data, MessageParcel &reply);
    int OnDelay(MessageParcel &data, MessageParcel &reply);
    int OnReceivedObject(MessageParcel &data, MessageParcel &reply);
    int OnReceivedStubObject(MessageParcel &data, MessageParcel &reply);
    int OnReceivedOversizedPkt(MessageParcel &data, MessageParcel &reply);
    int OnReceivedRawData(MessageParcel &data, MessageParcel &reply);
#ifndef CONFIG_STANDARD_SYSTEM
    int OnGetChildId(MessageParcel &data, MessageParcel &reply);
#endif
    int OnSentRawData(MessageParcel &data, MessageParcel &reply);
    int OnReceivedGetStubObject(MessageParcel &data, MessageParcel &reply);
    int OnReceivedGetDecTimes(MessageParcel &data, MessageParcel &reply);
    int OnReceivedClearDecTimes(MessageParcel &data, MessageParcel &reply);
};


class DBinderTestServiceProxy : public IRemoteProxy<IDBinderTestService> {
public:
    explicit DBinderTestServiceProxy(const sptr<IRemoteObject> &impl);
    ~DBinderTestServiceProxy() = default;
    int ReverseInt(int data, int &rep) override;
    int ReverseIntNullReply(int data, int &rep);
    int ReverseIntVoidData(int data, int &rep);
    int ReverseIntDelay(int data, int &rep) override;
    int Delay(int data, int &rep) override;
    int ReverseIntDelayAsync(int data, int &rep) override;
    int PingService(std::u16string &serviceName) override;
    int TransProxyObject(int data, sptr<IRemoteObject> &transObject, int operation, int &rep,
        int &withdrawRes) override;
    int TransStubObject(int data, sptr<IRemoteObject> &transObject, int &rep, int &stubRep) override;
    int TransOversizedPkt(const std::string &dataStr, std::string &repStr) override;
    int ProxyTransRawData(int length) override;
    int StubTransRawData(int length) override;
#ifndef CONFIG_STANDARD_SYSTEM
    int GetChildId(uint64_t &rep) override;
#endif
    sptr<IRemoteObject> GetRemoteObject(int type) override;
    int GetRemoteDecTimes() override;
    void ClearRemoteDecTimes() override;
    int FlushAsyncCommands(int count, int length) override;

private:
    static inline BrokerDelegator<DBinderTestServiceProxy> delegator_;
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_RPC, "DBinderTestProxy" };
};


class DBinderTestDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    virtual void OnRemoteDied(const wptr<IRemoteObject> &remote);
    DBinderTestDeathRecipient();
    virtual ~DBinderTestDeathRecipient();
    static bool GotDeathRecipient();
    static void ClearDeathRecipient();
    static bool g_gotDeathRecipient;

private:
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_RPC, "DBinderTestDeathRecipient" };
};
} // namespace OHOS
#endif // OHOS_DBINDER_TEST_SERVICE_SKELETON_H
