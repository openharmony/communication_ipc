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

#ifndef OHOS_IPC_TEST_SERVICE_H
#define OHOS_IPC_TEST_SERVICE_H

#include "hilog/log.h"
#include "log_tags.h"
#include "test_service_skeleton.h"

namespace OHOS {

class TestService : public TestServiceStub {
public:
    TestService(bool serialInvokeFlag = false);
    ~TestService();
    static int Instantiate(bool isEnableSerialInvokeFlag);
    int TestSyncTransaction(int data, int &rep, int delayTime = 0) override;
    int TestAsyncTransaction(int data, int timeout = 0) override;
    int TestAsyncCallbackTrans(int data, int &reply, int timeout) override;
    int TestPingService(const std::u16string &serviceName) override;
    int TestGetFileDescriptor() override;
    int TestStringTransaction(const std::string& data) override;
    int TestZtraceTransaction(std::string& send, std::string& reply, int len) override;
    void TestDumpService() override;
    int TestRawDataTransaction(int length, int &reply) override;
    int TestRawDataReply(int length) override;
    sptr<IFoo> TestGetFooService() override;
    int Dump(int fd, const std::vector<std::u16string>& args) override;
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
    int testFd_;
    std::mutex remoteObjectsMutex_;
    std::map<std::string, sptr<IRemoteObject>> remoteObjects_;
    static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_TEST, "TestService" };
};
} // namespace OHOS
#endif // OHOS_IPC_TEST_SERVICE_H
