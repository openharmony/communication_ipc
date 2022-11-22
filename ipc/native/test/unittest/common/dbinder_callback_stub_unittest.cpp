/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>

#include "dbinder_callback_stub.h"
#include "ipc_types.h"

using namespace testing::ext;
using namespace OHOS;

namespace {
const std::string SERVICE_TEST = "serviceTest";
const std::string DEVICE_TEST = "deviceTest";
const std::string LOCALDEVICE_TEST = "localDeviceTest";
constexpr uint64_t STUBINDEX_TEST = 1;
constexpr uint32_t HANDLE_TEST = 1;
}

class DBinderCallbackStubTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    sptr<DBinderCallbackStub> fakeStub_;
};

void DBinderCallbackStubTest::SetUpTestCase()
{
}

void DBinderCallbackStubTest::TearDownTestCase()
{
}

void DBinderCallbackStubTest::SetUp()
{
    std::shared_ptr<FeatureSetData> feature = std::make_shared<FeatureSetData>();
    fakeStub_ =  new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, feature);
}

void DBinderCallbackStubTest::TearDown()
{
}

/**
 * @tc.name: GetServiceNameTest001
 * @tc.desc: Verify the GetServiceName function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, GetServiceNameTest001, TestSize.Level1)
{
    ASSERT_TRUE(fakeStub_ != nullptr);
    std::string ret = fakeStub_->GetServiceName();

    EXPECT_STREQ(ret.c_str(), SERVICE_TEST.c_str());
}

/**
 * @tc.name:GetFeatureSetTest001
 * @tc.desc: Verify the GetFeatureSet function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, GetFeatureSetTest001, TestSize.Level1)
{
    ASSERT_TRUE(fakeStub_ != nullptr);
    std::shared_ptr<FeatureSetData> ret = fakeStub_->GetFeatureSet();

    EXPECT_NE(ret, nullptr);
}

/**
 * @tc.name:GetDeviceIDTest001
 * @tc.desc: Verify the GetDeviceID function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, GetDeviceIDTest001, TestSize.Level1)
{
    ASSERT_TRUE(fakeStub_ != nullptr);
    std::string ret = fakeStub_->GetDeviceID();

    EXPECT_STREQ(ret.c_str(), DEVICE_TEST.c_str());
}

/**
 * @tc.name:GetStubIndexTest001
 * @tc.desc: Verify the GetStubIndex function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, GetStubIndexTest001, TestSize.Level1)
{
    ASSERT_TRUE(fakeStub_ != nullptr);
    uint64_t ret = fakeStub_->GetStubIndex();

    EXPECT_EQ(ret, STUBINDEX_TEST);
}

/**
 * @tc.name: ProcessProtoTest001
 * @tc.desc: Verify the ProcessProto function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, ProcessProtoTest001, TestSize.Level1)
{
    ASSERT_TRUE(fakeStub_ != nullptr);
    uint32_t code = GET_PROTO_INFO;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = fakeStub_->ProcessProto(code, data, reply, option);

    EXPECT_EQ(ret, DBINDER_SERVICE_WRONG_SESSION);
}

/**
 * @tc.name: OnRemoteRequestTest001
 * @tc.desc: Verify the OnRemoteRequest function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, OnRemoteRequestTest001, TestSize.Level1)
{
    ASSERT_TRUE(fakeStub_ != nullptr);
    uint32_t code = GET_PROTO_INFO;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = fakeStub_->OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(ret, DBINDER_SERVICE_WRONG_SESSION);
}

/**
 * @tc.name: OnRemoteRequestTest002
 * @tc.desc: Verify the OnRemoteRequest function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, OnRemoteRequestTest002, TestSize.Level1)
{
    ASSERT_TRUE(fakeStub_ != nullptr);
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = fakeStub_->OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(ret, DBINDER_CALLBACK_ERR);
}