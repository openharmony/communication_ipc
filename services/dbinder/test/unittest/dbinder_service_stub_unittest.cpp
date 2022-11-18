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
#include "gtest/gtest.h"
#include "rpc_log.h"
#include "log_tags.h"
#include "message_parcel.h"
#define private public
#define protected public
#include "dbinder_service_stub.h"
#undef protected
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HiviewDFX;

typedef unsigned long long binder_uintptr_t;
class DBinderServiceStubUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DBinderServiceStubUnitTest::SetUp()
{}

void DBinderServiceStubUnitTest::TearDown()
{}

void DBinderServiceStubUnitTest::SetUpTestCase()
{}

void DBinderServiceStubUnitTest::TearDownTestCase()
{}

/**
 * @tc.name: DBinderServiceStub001
 * @tc.desc: Verify the DBinderServiceStub function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, DBinderServiceStub001, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = 11;
    DBinderServiceStub dBinderServiceStub(service, device, object);
}

/**
 * @tc.name: GetServiceName001
 * @tc.desc: Verify the GetServiceName function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, GetServiceName001, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = 11;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    std::string ret = dBinderServiceStub.GetServiceName();
    EXPECT_EQ(ret, "serviceTest");
}

/**
 * @tc.name: GetDeviceID001
 * @tc.desc: Verify the GetDeviceID function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, GetDeviceID001, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = 11;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    std::string ret = dBinderServiceStub.GetDeviceID();
    EXPECT_EQ(ret, "deviceTest");
}

/**
 * @tc.name: GetBinderObject001
 * @tc.desc: Verify the GetBinderObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, GetBinderObject001, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = 11;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    binder_uintptr_t ret = dBinderServiceStub.GetBinderObject();
    EXPECT_EQ(ret, 11);
}

/**
 * @tc.name: ProcessProto001
 * @tc.desc: Verify the ProcessProto function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, ProcessProto001, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = 11;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    uint32_t code = 11;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = dBinderServiceStub.ProcessProto(code, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
}
