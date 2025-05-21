/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_IPC_TEST_SERVICE_CLIENT_H
#define OHOS_IPC_TEST_SERVICE_CLIENT_H

#include <string>
#include <vector>
#include "log_tags.h"
#include "test_service_proxy.h"
#include "test_capi_skeleton.h"

namespace OHOS {
struct TraceParam {
    int dataSize;
    int testTimes;
    int sleepUs;
};

class TestServiceClient {
public:
    bool ConnectService();
    bool StartSyncTransaction();
    bool StartPingService();
    bool StartGetFooService();
    bool StartLoopTest(int maxCount);
    bool StartDumpService();
    bool StartTestFileDescriptor();
    bool StartAsyncDumpService();
    bool TestEnableSerialInvokeFlag();
    bool TestNativeIPCSendRequests(int subCmd);
    bool TestRegisterRemoteStub();
    bool TestUnRegisterRemoteStub();
    bool TestSendTooManyRequest();
    bool TestMultiThreadSendRequest();
    bool TestQueryThreadInvocationState();

private:
    static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_TEST, "TestServiceClient" };
    sptr<ITestService> testService_;
    std::shared_ptr<NativeRemoteStubTest> remoteStub_{ nullptr };
};
} // namespace OHOS
#endif // OHOS_IPC_TEST_SERVICE_CLIENT_H
