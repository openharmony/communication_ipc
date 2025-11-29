/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "dbinder_death_recipient.h"
#include "dbinder_service.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
namespace OHOS {
class DbinderDeathRecipientTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void DbinderDeathRecipientTest::SetUpTestCase()
{
}

void DbinderDeathRecipientTest::TearDownTestCase()
{
}

void DbinderDeathRecipientTest::SetUp()
{
}

void DbinderDeathRecipientTest::TearDown()
{
}

/**
 * @tc.name: OnRemoteDiedTest001
 * @tc.desc: Verify the OnRemoteDied function when remote is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDeathRecipientTest, OnRemoteDiedTest001, TestSize.Level1)
{
    DbinderDeathRecipient dbinderDeathRecipient;
    wptr<IRemoteObject> remote = nullptr;
    ASSERT_NO_FATAL_FAILURE(dbinderDeathRecipient.OnRemoteDied(remote));
}

/**
 * @tc.name: OnRemoteDiedTest002
 * @tc.desc: Verify the OnRemoteDied function when remote is a valid object
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDeathRecipientTest, OnRemoteDiedTest002, TestSize.Level1)
{
    DbinderDeathRecipient dbinderDeathRecipient;
    int handle = 1;
    sptr<IRemoteObject> proxy = new (std::nothrow) IPCObjectProxy(handle, std::u16string());
    ASSERT_TRUE(proxy != nullptr);
    wptr<IRemoteObject> remote = proxy;
    dbinderDeathRecipient.OnRemoteDied(remote);
}
} // namespace OHOS