/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_TEST_SERVICE_PROXY_H
#define OHOS_TEST_SERVICE_PROXY_H

#include "test_service_base.h"

namespace OHOS {
class TestServiceProxy : public IRemoteProxy<ITestService> {
public:
    explicit TestServiceProxy(const sptr<IRemoteObject> &impl);
    ~TestServiceProxy() = default;
    int TestSyncTransaction(int value, int &reply, int delayTime = 0) override;
    int TestAsyncTransaction(int data, int timeout = 0) override;
    int TestAsyncCallbackTrans(int data, int &reply, int timeout = 0) override;
    int TestPingService(const std::u16string &serviceName) override;
    int TestGetFileDescriptor() override;
    int TestStringTransaction(const std::string &data) override;
    int TestZtraceTransaction(std::string &send, std::string &reply, int len) override;
    int TestDumpService() override;
    int TestRawDataTransaction(int length, int &reply) override;
    int TestRawDataReply(int length) override;
    sptr<IFoo> TestGetFooService() override;
    int TestCallingUidPid() override;
    int TestFlushAsyncCalls(int count, int length) override;
    int TestMultipleProcesses(int data, int &rep, int delayTime) override;
    std::u16string TestAshmem(sptr<Ashmem> ashmem, int32_t contentSize) override;
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

} // namespace OHOS
#endif // OHOS_TEST_SERVICE_PROXY_H
