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
    void SetUp();
    void TearDown();
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
 * @tc.desc: Verify the OnRemoteDied function
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDeathRecipientTest, OnRemoteDiedTest001, TestSize.Level1)
{
    DbinderDeathRecipient dbinderDeathRecipient;
    int handle = 1;
    std::u16string descriptor = std::u16string();
    sptr<IPCObjectProxy> object = sptr<IPCObjectProxy>::MakeSptr(handle, descriptor);
    sptr<IRemoteObject::DeathRecipient> death = sptr<DbinderDeathRecipient>::MakeSptr();
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_NE(object, nullptr);
    ASSERT_NE(death, nullptr);
    ASSERT_NE(dBinderService, nullptr);
    dBinderService->AttachDeathRecipient(object, death);
    IRemoteObject *remoteObject = object.GetRefPtr();
    wptr<IRemoteObject> remote = remoteObject;
    dbinderDeathRecipient.OnRemoteDied(remote);
}
} // namespace OHOS