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

#ifndef OHOS_TEST_SERVICE_SKELETON_H
#define OHOS_TEST_SERVICE_SKELETON_H

#include <map>
#include "ipc_debug.h"
#include "iremote_broker.h"
#include "iremote_stub.h"
#include "iremote_proxy.h"
#include "foo_service.h"
#include "ipc_file_descriptor.h"
#include "log_tags.h"

namespace OHOS {

class ITestService : public IRemoteBroker {
public:
    enum {
        TRANS_ID_SYNC_TRANSACTION = 1,
        TRANS_ID_ASYNC_TRANSACTION = 2,
        TRANS_ID_PING_SERVICE = 3,
        TRANS_ID_GET_FOO_SERVICE = 4,
        TRANS_ID_TRANSACT_FILE_DESC = 5,
        TRANS_ID_STRING_TRANSACTION = 6,
        TRANS_ID_ZTRACE_TRANSACTION = 7,
        TRANS_ID_LOOP_TRANSACTION = 8,
        TRANS_ID_DUMP_SERVICE = 9,
        TRANS_ID_RAWDATA_TRANSACTION = 10,
        TRANS_ID_RAWDATA_REPLY = 11,
        TRANS_ID_CALLING_UID_PID = 12,
        TRANS_ID_FLUSH_ASYNC_CALLS = 13,
        TRANS_ID_MULTIPLE_PROCESSES = 14,
        TRANS_ID_ASHMEM = 15,
        TRANS_ID_ASYNC_DUMP_SERVICE = 16,
        TRANS_ID_NESTING_SEND = 17,
        TRANS_ID_ACCESS_TOKENID = 18,
        TRANS_MESSAGE_PARCEL_ADDPED = 19,
        TRANS_MESSAGE_PARCEL_ADDPED_WITH_OBJECT = 20,
        TRANS_ID_ACCESS_TOKENID_64 = 21,
        TRANS_ENABLE_SERIAL_INVOKE_FLAG = 22,
        TRANS_ID_REGISTER_REMOTE_STUB_OBJECT = 23,
        TRANS_ID_UNREGISTER_REMOTE_STUB_OBJECT = 24,
        TRANS_ID_QUERY_REMOTE_PROXY_OBJECT = 25,
    };
public:
    virtual int TestSyncTransaction(int data, int &reply, int delayTime = 0) = 0;
    virtual int TestAsyncTransaction(int data, int timeout = 0) = 0;
    virtual int TestAsyncCallbackTrans(int data, int &reply, int timeout = 0) = 0;
    virtual int TestGetFileDescriptor() = 0;
    virtual int TestPingService(const std::u16string &serviceName) = 0;
    virtual int TestStringTransaction(const std::string &data) = 0;
    virtual int TestZtraceTransaction(std::string &send, std::string &reply, int len) = 0;
    virtual void TestDumpService() = 0;
    virtual int TestRawDataTransaction(int length, int &reply) = 0;
    virtual int TestRawDataReply(int length) = 0;
    virtual sptr<IFoo> TestGetFooService() = 0;
    virtual int TestCallingUidPid() = 0;
    virtual int TestFlushAsyncCalls(int count, int length) = 0;
    virtual int TestMultipleProcesses(int data, int &rep, int delayTime) = 0;
    virtual std::u16string TestAshmem(sptr<Ashmem> ashmem, int32_t contentSize) = 0;
    virtual void TestAsyncDumpService() = 0;
    virtual int TestNestingSend(int sendCode, int &replyCode) = 0;
    virtual int TestAccessTokenID(int32_t ftoken_expected) = 0;
    virtual int TestAccessTokenID64(uint64_t token_expected, uint64_t ftoken_expected) = 0;
    virtual int TestMessageParcelAppend(MessageParcel &dst, MessageParcel &src) = 0;
    virtual int TestMessageParcelAppendWithIpc(MessageParcel &dst, MessageParcel &src,
        MessageParcel &reply, bool withObject) = 0;
    virtual int TestEnableSerialInvokeFlag() = 0;

    virtual int TestRegisterRemoteStub(const char *descriptor, const sptr<IRemoteObject> object) = 0;
    virtual int TestUnRegisterRemoteStub(const char *descriptor) = 0;
    virtual sptr<IRemoteObject> TestQueryRemoteProxy(const char *descriptor) = 0;
    virtual int TestSendTooManyRequest(int data, int &reply) = 0;
    virtual int TestMultiThreadSendRequest(int data, int &reply) = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"test.ipc.ITestService");
};

class TestServiceStub : public IRemoteStub<ITestService> {
public:
    TestServiceStub(bool serialInvokeFlag = false);
    int OnRemoteRequest(uint32_t code,
        MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    bool serialInvokeFlag_ = { false };
private:
    static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_TEST, "TestServiceStub" };
    int32_t TransferRawData(MessageParcel &data, MessageParcel &reply);
    int32_t ReplyRawData(MessageParcel &data, MessageParcel &reply);
    int32_t TransferToNextProcess(MessageParcel &data, MessageParcel &reply);
    int32_t ReadAshmem(MessageParcel &data, MessageParcel &reply);
    int32_t ServerSyncTransaction(MessageParcel &data, MessageParcel &reply);
    int32_t ServerAsyncTransaction(MessageParcel &data, MessageParcel &reply);
    int32_t ServerPingService(MessageParcel &data, MessageParcel &reply);
    int32_t ServerGetFooService(MessageParcel &data, MessageParcel &reply);
    int32_t ServerTransactFileDesc(MessageParcel &data, MessageParcel &reply);
    int32_t ServerStringTransaction(MessageParcel &data, MessageParcel &reply);
    int32_t ServerZtraceTransaction(MessageParcel &data, MessageParcel &reply);
    int32_t ServerCallingUidAndPid(MessageParcel &data, MessageParcel &reply);
    int32_t ServerNestingSend(MessageParcel &data, MessageParcel &reply);
    int32_t ServerAccessTokenId(MessageParcel &data, MessageParcel &reply);
    int32_t ServerAccessTokenId64(MessageParcel &data, MessageParcel &reply);
    int32_t ServerMessageParcelAddped(MessageParcel &data, MessageParcel &reply);
    int32_t ServerMessageParcelAddpedWithObject(MessageParcel &data, MessageParcel &reply);
    int32_t ServerEnableSerialInvokeFlag(MessageParcel &data, MessageParcel &reply);
    int32_t RegisterRemoteStub(MessageParcel &data, MessageParcel &reply);
    int32_t UnRegisterRemoteStub(MessageParcel &data, MessageParcel &reply);
    int32_t QueryRemoteProxy(MessageParcel &data, MessageParcel &reply);
    int32_t ServerFlushAsyncCalls(MessageParcel &data, MessageParcel &reply);
    void InitMessageProcessMap();

    using TestServiceStubFunc = int32_t(TestServiceStub::*)(MessageParcel &data, MessageParcel &reply);
    std::map<uint32_t, TestServiceStubFunc> funcMap_;
};

class TestServiceProxy : public IRemoteProxy<ITestService> {
public:
    explicit TestServiceProxy(const sptr<IRemoteObject> &impl);
    ~TestServiceProxy() = default;
    int TestSyncTransaction(int data, int &reply, int delayTime = 0) override;
    int TestAsyncTransaction(int data, int timeout = 0) override;
    int TestAsyncCallbackTrans(int data, int &reply, int timeout = 0) override;
    int TestPingService(const std::u16string &serviceName) override;
    int TestGetFileDescriptor() override;
    int TestStringTransaction(const std::string &data) override;
    int TestZtraceTransaction(std::string &send, std::string &reply, int len) override;
    void TestDumpService() override;
    int TestRawDataTransaction(int length, int &reply) override;
    int TestRawDataReply(int length) override;
    sptr<IFoo> TestGetFooService() override;
    int TestCallingUidPid() override;
    int TestFlushAsyncCalls(int count, int length) override;
    int TestMultipleProcesses(int data, int &rep, int delayTime) override;
    std::u16string TestAshmem(sptr<Ashmem> ashmem, int32_t contentSize) override;
    void TestAsyncDumpService() override;
    int TestNestingSend(int sendCode, int &replyCode) override;
    int TestAccessTokenID(int32_t ftoken_expected) override;
    int TestAccessTokenID64(uint64_t token_expected, uint64_t ftoken_expected) override;
    int TestMessageParcelAppend(MessageParcel &dst, MessageParcel &src) override;
    int TestMessageParcelAppendWithIpc(MessageParcel &dst, MessageParcel &src,
        MessageParcel &reply, bool withObject) override;
    int TestEnableSerialInvokeFlag() override;

    int TestRegisterRemoteStub(const char *descriptor, const sptr<IRemoteObject> object) override;
    int TestUnRegisterRemoteStub(const char *descriptor) override;
    sptr<IRemoteObject> TestQueryRemoteProxy(const char *descriptor) override;
    int TestSendTooManyRequest(int data, int &reply) override;
    int TestMultiThreadSendRequest(int data, int &reply) override;

private:
    static inline BrokerDelegator<TestServiceProxy> delegator_;
    bool CheckTokenSelf(uint64_t token, uint64_t tokenSelf, uint64_t ftoken, uint64_t ftoken_expected);
    bool CheckSetFirstToken(uint64_t ftoken_expected);
    bool CheckSetSelfToken(uint64_t token_expected);
    static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_TEST, "TestServiceProxy" };
};

class TestDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    virtual void OnRemoteDied(const wptr<IRemoteObject> &remote);
    TestDeathRecipient();
    virtual ~TestDeathRecipient();
    static bool GotDeathRecipient();
    static bool gotDeathRecipient_;
private:
    static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_TEST, "TestDeathRecipient" };
};

} // namespace OHOS
#endif // OHOS_TEST_SERVICE_SKELETON_H
