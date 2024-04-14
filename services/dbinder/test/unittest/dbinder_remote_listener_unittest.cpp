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

#include "dbinder_service.h"
#include "gtest/gtest.h"
#include "rpc_log.h"
#include "log_tags.h"
#include "session_impl.h"
#define private public
#include "dbinder_remote_listener.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HiviewDFX;

class DBinderRemoteListenerUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_TEST, "DBinderRemoteListenerUnitTest" };
};

void DBinderRemoteListenerUnitTest::SetUp() {}

void DBinderRemoteListenerUnitTest::TearDown() {}

void DBinderRemoteListenerUnitTest::SetUpTestCase() {}

void DBinderRemoteListenerUnitTest::TearDownTestCase() {}

HWTEST_F(DBinderRemoteListenerUnitTest, CreateClientSocket_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    std::string networkId = "";
    EXPECT_EQ(dBinderRemoteListener.CreateClientSocket(networkId), SOCKET_ID_INVALID);
}
