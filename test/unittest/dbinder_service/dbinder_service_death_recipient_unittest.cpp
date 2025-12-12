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

#include <gtest/gtest.h>

#include "dbinder_service_stub.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
namespace OHOS {

namespace {
    const binder_uintptr_t BINDER_OBJECT = 1ULL;
}
class DBinderServiceDeathRecipientTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void DBinderServiceDeathRecipientTest::SetUpTestCase()
{
}

void DBinderServiceDeathRecipientTest::TearDownTestCase()
{
}

void DBinderServiceDeathRecipientTest::SetUp()
{
}

void DBinderServiceDeathRecipientTest::TearDown()
{
}

/**
 * @tc.name: AddDbinderDeathRecipientTest001
 * @tc.desc: Verify the AddDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceDeathRecipientTest, AddDbinderDeathRecipientTest001, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    MessageParcel data;
    int32_t ret = dBinderServiceStub.AddDbinderDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_INVALID_DATA_ERR);
}

/**
 * @tc.name: AddDbinderDeathRecipientTest002
 * @tc.desc: Verify the AddDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceDeathRecipientTest, AddDbinderDeathRecipientTest002, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    sptr<IPCObjectStub> callbackStub = new (std::nothrow) IPCObjectStub(u"testStub");
    EXPECT_TRUE(callbackStub != nullptr);
    MessageParcel data;
    data.WriteRemoteObject(callbackStub);
    int32_t ret = dBinderServiceStub.AddDbinderDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_ADD_DEATH_ERR);
}

/**
 * @tc.name: RemoveDbinderDeathRecipientTest001
 * @tc.desc: Verify the RemoveDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceDeathRecipientTest, RemoveDbinderDeathRecipientTest001, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    MessageParcel data;
    int32_t ret = dBinderServiceStub.RemoveDbinderDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_REMOVE_DEATH_ERR);
}

/**
 * @tc.name: RemoveDbinderDeathRecipientTest002
 * @tc.desc: Verify the RemoveDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceDeathRecipientTest, RemoveDbinderDeathRecipientTest002, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    sptr<IPCObjectProxy> callbackProxy = new (std::nothrow) IPCObjectProxy(0);
    EXPECT_TRUE(callbackProxy != nullptr);
    MessageParcel data;
    data.WriteRemoteObject(callbackProxy);
    int32_t ret = dBinderServiceStub.AddDbinderDeathRecipient(data);
    EXPECT_EQ(ret, ERR_NONE);
    data.WriteRemoteObject(callbackProxy);
    ret = dBinderServiceStub.RemoveDbinderDeathRecipient(data);
    EXPECT_EQ(ret, ERR_NONE);
}

/**
 * @tc.name: RemoveDbinderDeathRecipientTest003
 * @tc.desc: Verify the RemoveDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceDeathRecipientTest, RemoveDbinderDeathRecipientTest003, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    sptr<IPCObjectProxy> callbackProxy = new (std::nothrow) IPCObjectProxy(0);
    EXPECT_TRUE(callbackProxy != nullptr);
    MessageParcel data;
    data.WriteRemoteObject(callbackProxy);
    int32_t ret = dBinderServiceStub.RemoveDbinderDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_REMOVE_DEATH_ERR);
}

/**
 * @tc.name: RemoveDbinderDeathRecipientTest004
 * @tc.desc: Verify the RemoveDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceDeathRecipientTest, RemoveDbinderDeathRecipientTest004, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    sptr<IPCObjectStub> callbackStub = new (std::nothrow) IPCObjectStub(u"testStub");
    EXPECT_TRUE(callbackStub != nullptr);
    MessageParcel data;
    data.WriteRemoteObject(callbackStub);
    int32_t ret = dBinderServiceStub.RemoveDbinderDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_REMOVE_DEATH_ERR);
}
} // namespace OHOS