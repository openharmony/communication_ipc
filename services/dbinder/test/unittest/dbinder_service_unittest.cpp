/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <string>
#include "securec.h"
#define private public
#include "dbinder_service.h"
#undef private
#include "dbinder_remote_listener.h"
#include "gtest/gtest.h"
#include "rpc_feature_set.h"
#include "rpc_log.h"
#include "log_tags.h"
#include "string_ex.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HiviewDFX;
using Communication::SoftBus::Session;

class DBinderServiceUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_RPC, "DBinderServiceUnitTest" };
};

void DBinderServiceUnitTest::SetUp() {}

void DBinderServiceUnitTest::TearDown() {}

void DBinderServiceUnitTest::SetUpTestCase() {}

void DBinderServiceUnitTest::TearDownTestCase() {}

HWTEST_F(DBinderServiceUnitTest, process_closesession_001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService_;
    std::shared_ptr<Session> session = nullptr;
    EXPECT_EQ(dBinderService_->ProcessOnSessionClosed(session), false);
}

/**
 * @tc.name: RegisterRemoteProxy001
 * @tc.desc: Verify the RegisterRemoteProxy function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, RegisterRemoteProxy001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    std::u16string serviceName;
    int32_t systemAbilityId = 1;
    EXPECT_EQ(dBinderService->RegisterRemoteProxy(serviceName, systemAbilityId), false);
    serviceName = u"testServer";
    systemAbilityId = 0;
    EXPECT_EQ(dBinderService->RegisterRemoteProxy(serviceName, systemAbilityId), false);
    systemAbilityId = 1;
    EXPECT_EQ(dBinderService->RegisterRemoteProxy(serviceName, systemAbilityId), true);
}

/**
 * @tc.name: RegisterRemoteProxy002
 * @tc.desc: Verify the RegisterRemoteProxy function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, RegisterRemoteProxy002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    std::u16string serviceName;
    sptr<IRemoteObject> binderObject = nullptr;
    EXPECT_EQ(dBinderService->RegisterRemoteProxy(serviceName, binderObject), false);
    serviceName = u"testServer";
    EXPECT_EQ(dBinderService->RegisterRemoteProxy(serviceName, binderObject), false);
    sptr<IRemoteObject> object = new IPCObjectProxy(16);
    EXPECT_EQ(dBinderService->RegisterRemoteProxy(serviceName, object), true);
}

/**
 * @tc.name: QuerySessionObject001
 * @tc.desc: Verify the QuerySessionObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, QuerySessionObject001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    binder_uintptr_t stub = 0;
    std::shared_ptr<struct SessionInfo> testSession = nullptr;
    testSession = dBinderService->QuerySessionObject(stub);
    EXPECT_EQ(testSession, nullptr);
}