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

#ifndef OHOS_TEST_SERVICE_STUB_H
#define OHOS_TEST_SERVICE_STUB_H

#include "test_service_base.h"

namespace OHOS {
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
    int32_t ServerThreadInvocationState(MessageParcel &data, MessageParcel &reply);
    void InitMessageProcessMap();

    using TestServiceStubFunc = int32_t(TestServiceStub::*)(MessageParcel &data, MessageParcel &reply);
    std::map<uint32_t, TestServiceStubFunc> funcMap_;
};

} // namespace OHOS
#endif // OHOS_TEST_SERVICE_STUB_H
