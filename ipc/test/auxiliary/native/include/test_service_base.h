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
        TRANS_ID_QUERY_THREAD_INVOCATION_STATE = 26,
#ifdef FREEZE_PROCESS_ENABLED
        TRANS_ID_TEST_FREEZE_PROCESS = 27,
#endif // FREEZE_PROCESS_ENABLED
    };
public:
    virtual int TestSyncTransaction(int value, int &reply, int delayTime = 0) = 0;
    virtual int TestAsyncTransaction(int data, int timeout = 0) = 0;
    virtual int TestAsyncCallbackTrans(int data, int &reply, int timeout = 0) = 0;
    virtual int TestGetFileDescriptor() = 0;
    virtual int TestPingService(const std::u16string &serviceName) = 0;
    virtual int TestStringTransaction(const std::string &data) = 0;
    virtual int TestZtraceTransaction(std::string &send, std::string &reply, int len) = 0;
    virtual int TestDumpService() = 0;
    virtual int TestRawDataTransaction(int length, int &reply) = 0;
    virtual int TestRawDataReply(int length) = 0;
    virtual sptr<IFoo> TestGetFooService() = 0;
    virtual int TestCallingUidPid() = 0;
    virtual int TestFlushAsyncCalls(int count, int length) = 0;
    virtual int TestMultipleProcesses(int data, int &rep, int delayTime) = 0;
    virtual std::u16string TestAshmem(sptr<Ashmem> ashmem, int32_t contentSize) = 0;
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
    virtual int TestQueryThreadInvocationState() = 0;
#ifdef FREEZE_PROCESS_ENABLED
    virtual int TestFreezeProcess() = 0;
#endif // FREEZE_PROCESS_ENABLED

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"test.ipc.ITestService");
};

} // namespace OHOS
#endif // OHOS_TEST_SERVICE_SKELETON_H
