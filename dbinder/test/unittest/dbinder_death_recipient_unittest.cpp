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
#define private public
#include "dbinder_death_recipient.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HiviewDFX;

class DbinderDeathRecipientUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_TEST, "DBinderRemoteListenerUnitTest" };
};

void DbinderDeathRecipientUnitTest::SetUp() {}

void DbinderDeathRecipientUnitTest::TearDown() {}

void DbinderDeathRecipientUnitTest::SetUpTestCase() {}

void DbinderDeathRecipientUnitTest::TearDownTestCase() {}

/**
 * @tc.name: OnRemoteDied001
 * @tc.desc: Verify the OnRemoteDied function when remote is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDeathRecipientUnitTest, OnRemoteDied001, TestSize.Level1)
{
    DbinderDeathRecipient dbinderDeathRecipient;
    wptr<IRemoteObject> remote = nullptr;
    dbinderDeathRecipient.OnRemoteDied(remote);
}

/**
 * @tc.name: OnRemoteDied002
 * @tc.desc: Verify the OnRemoteDied function when remote is a valid object
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDeathRecipientUnitTest, OnRemoteDied002, TestSize.Level1)
{
    DbinderDeathRecipient dbinderDeathRecipient;
    int handle = 1;
    sptr<IRemoteObject> result = nullptr;
    std::u16string descriptor = std::u16string();
    result = new (std::nothrow) IPCObjectProxy(handle, descriptor);
    ASSERT_TRUE(result != nullptr);
    IRemoteObject *object = result.GetRefPtr();
    wptr<IRemoteObject> remote = object;
    dbinderDeathRecipient.OnRemoteDied(remote);
}