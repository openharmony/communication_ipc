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

#include "dbinder_sa_death_recipient.h"
#include "dbinder_service.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
namespace OHOS {
class DbinderSaDeathRecipientTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DbinderSaDeathRecipientTest::SetUpTestCase()
{
}

void DbinderSaDeathRecipientTest::TearDownTestCase()
{
}

void DbinderSaDeathRecipientTest::SetUp()
{
}

void DbinderSaDeathRecipientTest::TearDown()
{
}

/**
 * @tc.name: OnRemoteDiedTest001
 * @tc.desc: Verify the OnRemoteDied function
 * @tc.type: FUNC
 */
HWTEST_F(DbinderSaDeathRecipientTest, OnRemoteDiedTest001, TestSize.Level1)
{
    binder_uintptr_t ptr = 0;
    DbinderSaDeathRecipient dbinderSaDeathRecipient(ptr);
    dbinderSaDeathRecipient.OnRemoteDied(nullptr);
    int handle = 1;
    std::u16string descriptor = std::u16string();
    sptr<IPCObjectProxy> object = sptr<IPCObjectProxy>::MakeSptr(handle, descriptor);
    ASSERT_NE(object, nullptr);
    IRemoteObject *remoteObject = object.GetRefPtr();
    wptr<IRemoteObject> remote = remoteObject;
    dbinderSaDeathRecipient.OnRemoteDied(remote);
}
} // namespace OHOS