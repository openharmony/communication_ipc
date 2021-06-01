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
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"test.ipc.ITestService");
};

class TestServiceStub : public IRemoteStub<ITestService> {
public:
    virtual int OnRemoteRequest(uint32_t code,
        MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
private:
    static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "TestServiceStub" };
    int TransferRawData(MessageParcel &data, MessageParcel &reply);
    int ReplyRawData(MessageParcel &data, MessageParcel &reply);
    void TransferToNextProcess(MessageParcel &data, MessageParcel &reply);
    void ReadAshmem(MessageParcel &data, MessageParcel &reply);
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
private:
    static inline BrokerDelegator<TestServiceProxy> delegator_;
    static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "TestServiceProxy" };
};

class TestDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    virtual void OnRemoteDied(const wptr<IRemoteObject> &remote);
    TestDeathRecipient();
    virtual ~TestDeathRecipient();
    static bool GotDeathRecipient();
    static bool gotDeathRecipient_;
private:
    static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "TestDeathRecipient" };
};

} // namespace OHOS
#endif // OHOS_TEST_SERVICE_SKELETON_H
