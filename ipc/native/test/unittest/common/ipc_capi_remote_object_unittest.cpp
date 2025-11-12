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

#include <gtest/gtest.h>

#include <cstring>
#include <securec.h>
#include <mutex>
#include <condition_variable>

#include "if_system_ability_manager.h"
#include "ipc_inner_object.h"
#include "ipc_kit.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "ipc_debug.h"
#include "log_tags.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HiviewDFX;

namespace OHOS {
static constexpr uint32_t ON_CALLBACK_REPLIED_INT = 1598311760;

class IpcCApiRemoteObjectUnitTest : public testing::Test {
public:
    void SetUp();
    void TearDown() const;
    static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_TEST, "IpcCApiUnitTest" };

    void ResetCallbackReply();
    [[nodiscard]] int GetCallbackReply() const;

public:
    static void OnRemoteObjectDestroy(void *userData);
    static void OnDeathRecipientCallback(void *userData);
    static void OnDeathRecipientDestroyCallback(void *userData);
    static int OnRemoteRequestStub(uint32_t code, const OHIPCParcel *data, OHIPCParcel *reply, void *userData) const;

private:
    int callBackReply_{ 0 };
};

void IpcCApiRemoteObjectUnitTest::SetUp()
{
    callBackReply_ = 0;
}

void IpcCApiRemoteObjectUnitTest::TearDown() const
{}

void IpcCApiRemoteObjectUnitTest::ResetCallbackReply()
{
    callBackReply_ = 0;
}

int IpcCApiRemoteObjectUnitTest::GetCallbackReply() const
{
    return callBackReply_;
}

void IpcCApiRemoteObjectUnitTest::OnRemoteObjectDestroy(void *userData)
{
    if (userData != nullptr) {
        auto *test = static_cast<IpcCApiRemoteObjectUnitTest *>(userData);
        test->callBackReply_ = ON_CALLBACK_REPLIED_INT;
    }
}

void IpcCApiRemoteObjectUnitTest::OnDeathRecipientCallback(void *userData)
{
    ZLOGD(LABEL, "OnDeathRecipientCallback modify callBackReply_");
    if (userData != nullptr) {
        auto *test = static_cast<IpcCApiRemoteObjectUnitTest *>(userData);
        test->callBackReply_ = ON_CALLBACK_REPLIED_INT;
    }
}

void IpcCApiRemoteObjectUnitTest::OnDeathRecipientDestroyCallback(void *userData)
{
    if (userData != nullptr) {
        auto *test = static_cast<IpcCApiRemoteObjectUnitTest *>(userData);
        test->callBackReply_ = ON_CALLBACK_REPLIED_INT;
    }
}

int IpcCApiRemoteObjectUnitTest::OnRemoteRequestStub(uint32_t code, const OHIPCParcel *data, OHIPCParcel *reply,
    void *userData) const
{
    (void)userData;
    (void)code;
    (void)data;
    (void)reply;
    return 0;
}

HWTEST_F(IpcCApiRemoteObjectUnitTest, RemoteStub_Create_001, TestSize.Level1)
{
    OHIPCRemoteStub *remote = OH_IPCRemoteStub_Create(nullptr, OnRemoteRequestStub, OnRemoteObjectDestroy, this);
    EXPECT_EQ(remote, nullptr);

    remote = OH_IPCRemoteStub_Create("RemoteStub_Create_001", nullptr, OnRemoteObjectDestroy, this);
    EXPECT_EQ(remote, nullptr);

    remote = OH_IPCRemoteStub_Create("RemoteStub_Create_001", OnRemoteRequestStub, nullptr, this);
    EXPECT_NE(remote, nullptr);
    OH_IPCRemoteStub_Destroy(remote);

    remote = OH_IPCRemoteStub_Create("RemoteStub_Create_001", OnRemoteRequestStub, OnRemoteObjectDestroy, nullptr);
    EXPECT_NE(remote, nullptr);
    OH_IPCRemoteStub_Destroy(remote);
}

HWTEST_F(IpcCApiRemoteObjectUnitTest, RemoteStub_Destroy_001, TestSize.Level1)
{
    OHIPCRemoteStub *remote = OH_IPCRemoteStub_Create("RemoteStub_Destroy_001", OnRemoteRequestStub,
                                                      OnRemoteObjectDestroy, this);
    EXPECT_NE(remote, nullptr);

    ResetCallbackReply();
    OH_IPCRemoteStub_Destroy(remote);
    EXPECT_EQ(GetCallbackReply(), ON_CALLBACK_REPLIED_INT);
}

HWTEST_F(IpcCApiRemoteObjectUnitTest, DeathRecipient_Create_001, TestSize.Level1)
{
    auto deathRecipient = OH_IPCDeathRecipient_Create(nullptr, OnDeathRecipientDestroyCallback, this);
    EXPECT_EQ(deathRecipient, nullptr);
    deathRecipient = OH_IPCDeathRecipient_Create(OnDeathRecipientCallback, nullptr, nullptr);
    EXPECT_NE(deathRecipient, nullptr);
    OH_IPCDeathRecipient_Destroy(deathRecipient);
    deathRecipient = OH_IPCDeathRecipient_Create(OnDeathRecipientCallback, OnDeathRecipientDestroyCallback, this);
    EXPECT_NE(deathRecipient, nullptr);
    OH_IPCDeathRecipient_Destroy(deathRecipient);
}

HWTEST_F(IpcCApiRemoteObjectUnitTest, DeathRecipient_Destroy_001, TestSize.Level1)
{
    auto deathRecipient = OH_IPCDeathRecipient_Create(OnDeathRecipientCallback, OnDeathRecipientDestroyCallback, this);
    ASSERT_NE(deathRecipient, nullptr);
    ResetCallbackReply();
    OH_IPCDeathRecipient_Destroy(deathRecipient);
    EXPECT_EQ(GetCallbackReply(), ON_CALLBACK_REPLIED_INT);
}
} // namespace OHOS