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
using Communication::SoftBus::Session;
using Communication::SoftBus::SessionImpl;

class DBinderRemoteListenerUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_RPC, "DBinderRemoteListenerUnitTest" };
};

void DBinderRemoteListenerUnitTest::SetUp() {}

void DBinderRemoteListenerUnitTest::TearDown() {}

void DBinderRemoteListenerUnitTest::SetUpTestCase() {}

void DBinderRemoteListenerUnitTest::TearDownTestCase() {}

HWTEST_F(DBinderRemoteListenerUnitTest, onsessionopened_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener_(DBinderService::GetInstance());
    std::shared_ptr<Session> session = std::make_shared<SessionImpl>();
    EXPECT_EQ(dBinderRemoteListener_.OnSessionOpened(session), -DBINDER_SERVICE_WRONG_SESSION);
}

HWTEST_F(DBinderRemoteListenerUnitTest, onsessionopened_002, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener_(DBinderService::GetInstance());
    std::shared_ptr<Session> session = std::make_shared<SessionImpl>();
    const std::string name = "DBinderService";
    session->SetPeerSessionName(name);
    EXPECT_EQ(dBinderRemoteListener_.OnSessionOpened(session), 0);
}

HWTEST_F(DBinderRemoteListenerUnitTest, onsessionclosed_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener_(DBinderService::GetInstance());
    std::shared_ptr<Session> session = std::make_shared<SessionImpl>();
    session->SetIsServer(true);
    dBinderRemoteListener_.OnSessionClosed(session);
    EXPECT_EQ(session->IsServerSide(), true);
}

HWTEST_F(DBinderRemoteListenerUnitTest, onsessionclosed_002, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener_(DBinderService::GetInstance());
    std::shared_ptr<Session> session = std::make_shared<SessionImpl>();
    session->SetIsServer(false);
    dBinderRemoteListener_.OnSessionClosed(session);
    EXPECT_EQ(session->IsServerSide(), false);
}

HWTEST_F(DBinderRemoteListenerUnitTest, onbytesreceived_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener_(DBinderService::GetInstance());
    std::shared_ptr<Session> session = std::make_shared<SessionImpl>();
    const char* data = nullptr;
    auto len = sizeof(struct DHandleEntryTxRx);
    dBinderRemoteListener_.OnBytesReceived(session, data, len);
    EXPECT_EQ(data, nullptr);
}

HWTEST_F(DBinderRemoteListenerUnitTest, onbytesreceived_002, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener_(DBinderService::GetInstance());
    std::shared_ptr<Session> session = std::make_shared<SessionImpl>();
    const char *data = "testdatas";
    ssize_t len = 0;
    dBinderRemoteListener_.OnBytesReceived(session, data, len);
    EXPECT_EQ(len < static_cast<ssize_t>(sizeof(struct DHandleEntryTxRx)), true);
}

HWTEST_F(DBinderRemoteListenerUnitTest, onbytesreceived_003, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener_(DBinderService::GetInstance());
    const char *data = "testdatas";
    auto len = sizeof(struct DHandleEntryTxRx);
    dBinderRemoteListener_.dBinderService_ = nullptr;
    dBinderRemoteListener_.OnBytesReceived(nullptr, data, len);
    EXPECT_EQ(dBinderRemoteListener_.dBinderService_, nullptr);
}

HWTEST_F(DBinderRemoteListenerUnitTest, onbytesreceived_004, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener_(DBinderService::GetInstance());
    const char *data = "testdatas";
    auto len = sizeof(struct DHandleEntryTxRx);
    dBinderRemoteListener_.OnBytesReceived(nullptr, data, len);
    EXPECT_EQ(dBinderRemoteListener_.dBinderService_->OnRemoteMessageTask((struct DHandleEntryTxRx *)data), false);
}

HWTEST_F(DBinderRemoteListenerUnitTest, senddatatoremote_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener_(DBinderService::GetInstance());
    const std::string deviceId = "testdeviceid";
    EXPECT_EQ(dBinderRemoteListener_.SendDataToRemote(deviceId, nullptr), false);
}

HWTEST_F(DBinderRemoteListenerUnitTest, senddatatoremote_002, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener_(DBinderService::GetInstance());
    const std::string deviceId = "";
    DHandleEntryTxRx message;
    message.head.len = sizeof(DHandleEntryTxRx);
    message.head.version = VERSION_NUM;
    message.deviceIdInfo.afType = DATABBUS_TYPE;
    EXPECT_EQ(dBinderRemoteListener_.SendDataToRemote(deviceId, &message), false);
}

HWTEST_F(DBinderRemoteListenerUnitTest, startlistener_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener_(DBinderService::GetInstance());

    std::shared_ptr<DBinderRemoteListener> listener = nullptr;
    EXPECT_EQ(dBinderRemoteListener_.StartListener(listener), false);
}

HWTEST_F(DBinderRemoteListenerUnitTest, closedatabussession_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener_(DBinderService::GetInstance());
    const std::string deviceId = "";
    EXPECT_EQ(dBinderRemoteListener_.CloseDatabusSession(deviceId), false);
}
