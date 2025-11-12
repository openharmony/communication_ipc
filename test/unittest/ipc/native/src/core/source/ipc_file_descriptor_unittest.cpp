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

#include "ipc_file_descriptor.h"
#include "ipc_thread_skeleton.h"
#include "ipc_types.h"
#include "mock_iremote_invoker.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace {
    constexpr int VALID_FD_TEST = 1;
}
class IPCFileDescriptorInterface {
public:
    IPCFileDescriptorInterface() {};
    virtual ~IPCFileDescriptorInterface() {};

    virtual IRemoteInvoker *GetRemoteInvoker(int proto) = 0;
};
class IPCFileDescriptorInterfaceMock : public IPCFileDescriptorInterface {
public:
    IPCFileDescriptorInterfaceMock();
    ~IPCFileDescriptorInterfaceMock() override;
    
    MOCK_METHOD1(GetRemoteInvoker, IRemoteInvoker *(int));
};
static void *g_interface = nullptr;

IPCFileDescriptorInterfaceMock::IPCFileDescriptorInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

IPCFileDescriptorInterfaceMock::~IPCFileDescriptorInterfaceMock()
{
    g_interface = nullptr;
}

static IPCFileDescriptorInterface *GetIPCFileDescriptorInterface()
{
    return reinterpret_cast<IPCFileDescriptorInterface *>(g_interface);
}

extern "C" {
    IRemoteInvoker *IPCThreadSkeleton::GetRemoteInvoker(int proto)
    {
        if (GetIPCFileDescriptorInterface() == nullptr) {
            return nullptr;
        }
        return GetIPCFileDescriptorInterface()->GetRemoteInvoker(proto);
    }
}

class IPCFileDescriptorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() const;
    void TearDown() const;
};

void IPCFileDescriptorTest::SetUpTestCase()
{
}

void IPCFileDescriptorTest::TearDownTestCase()
{
}

void IPCFileDescriptorTest::SetUp() const
{
}

void IPCFileDescriptorTest::TearDown() const
{
}

/**
 * @tc.name: MarshallingTest001
 * @tc.desc: Verify the Marshalling function when ipcFileDescriptor.fd_ is -1
 * @tc.type: FUNC
 */
HWTEST_F(IPCFileDescriptorTest, MarshallingTest001, TestSize.Level1) {
    IPCFileDescriptor ipcFileDescriptor;
    ipcFileDescriptor.fd_ = INVALID_FD;
    Parcel parcel;

    auto result = ipcFileDescriptor.Marshalling(parcel);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MarshallingTest002
 * @tc.desc: Verify the Marshalling function when GetRemoteInvoker function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCFileDescriptorTest, MarshallingTest002, TestSize.Level1) {
    IPCFileDescriptor ipcFileDescriptor;
    ipcFileDescriptor.fd_ = VALID_FD_TEST;
    Parcel parcel;

    NiceMock<IPCFileDescriptorInterfaceMock> mock;
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(nullptr));

    auto result = ipcFileDescriptor.Marshalling(parcel);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MarshallingTest003
 * @tc.desc: Verify the Marshalling function when WriteFileDescriptor function return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCFileDescriptorTest, MarshallingTest003, TestSize.Level1) {
    IPCFileDescriptor ipcFileDescriptor;
    ipcFileDescriptor.fd_ = VALID_FD_TEST;
    Parcel parcel;

    NiceMock<IPCFileDescriptorInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(invoker));
    EXPECT_CALL(*invoker, WriteFileDescriptor(testing::_, testing::_, testing::_)).WillOnce(Return(false));

    auto result = ipcFileDescriptor.Marshalling(parcel);
    EXPECT_FALSE(result);
    delete invoker;
}

/**
 * @tc.name: MarshallingTest004
 * @tc.desc: Verify the Marshalling function when WriteFileDescriptor function return true
 * @tc.type: FUNC
 */
HWTEST_F(IPCFileDescriptorTest, MarshallingTest004, TestSize.Level1) {
    IPCFileDescriptor ipcFileDescriptor;
    ipcFileDescriptor.fd_ = VALID_FD_TEST;
    Parcel parcel;

    NiceMock<IPCFileDescriptorInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(invoker));
    EXPECT_CALL(*invoker, WriteFileDescriptor(testing::_, testing::_, testing::_)).WillOnce(Return(true));

    auto result = ipcFileDescriptor.Marshalling(parcel);
    EXPECT_TRUE(result);
    delete invoker;
}

/**
 * @tc.name: MarshallingTest005
 * @tc.desc: Verify the Marshalling function when object is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCFileDescriptorTest, MarshallingTest005, TestSize.Level1) {
    IPCFileDescriptor ipcFileDescriptor;
    Parcel parcel;
    sptr<IPCFileDescriptor> object;

    auto result = ipcFileDescriptor.Marshalling(parcel, object);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MarshallingTest006
 * @tc.desc: Verify the Marshalling function when GetRemoteInvoker function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCFileDescriptorTest, MarshallingTest006, TestSize.Level1) {
    IPCFileDescriptor ipcFileDescriptor;
    Parcel parcel;
    sptr<IPCFileDescriptor> object = new IPCFileDescriptor();
    NiceMock<IPCFileDescriptorInterfaceMock> mock;
    
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(nullptr));

    auto result = ipcFileDescriptor.Marshalling(parcel, object);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MarshallingTest007
 * @tc.desc: Verify the Marshalling function when WriteFileDescriptor function return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCFileDescriptorTest, MarshallingTest007, TestSize.Level1) {
    IPCFileDescriptor ipcFileDescriptor;
    Parcel parcel;
    sptr<IPCFileDescriptor> object = new IPCFileDescriptor();
    NiceMock<IPCFileDescriptorInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(invoker));
    EXPECT_CALL(*invoker, WriteFileDescriptor(testing::_, testing::_, testing::_)).WillOnce(Return(false));

    auto result = ipcFileDescriptor.Marshalling(parcel, object);
    EXPECT_FALSE(result);
    delete invoker;
}

/**
 * @tc.name: MarshallingTest008
 * @tc.desc: Verify the Marshalling function when WriteFileDescriptor function return true
 * @tc.type: FUNC
 */
HWTEST_F(IPCFileDescriptorTest, MarshallingTest008, TestSize.Level1) {
    IPCFileDescriptor ipcFileDescriptor;
    Parcel parcel;
    sptr<IPCFileDescriptor> object = new IPCFileDescriptor();
    NiceMock<IPCFileDescriptorInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(invoker));
    EXPECT_CALL(*invoker, WriteFileDescriptor(testing::_, testing::_, testing::_)).WillOnce(Return(true));

    auto result = ipcFileDescriptor.Marshalling(parcel, object);
    EXPECT_TRUE(result);
    delete invoker;
}

/**
 * @tc.name: UnmarshallingTest001
 * @tc.desc: Verify the Unmarshalling function when GetRemoteInvoker function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCFileDescriptorTest, UnmarshallingTest001, TestSize.Level1) {
    IPCFileDescriptor ipcFileDescriptor;
    Parcel parcel;
    NiceMock<IPCFileDescriptorInterfaceMock> mock;

    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(nullptr));

    auto result = ipcFileDescriptor.Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: UnmarshallingTest002
 * @tc.desc: Verify the Unmarshalling function when ReadFileDescriptor function return 1
 * @tc.type: FUNC
 */
HWTEST_F(IPCFileDescriptorTest, UnmarshallingTest002, TestSize.Level1) {
    IPCFileDescriptor ipcFileDescriptor;
    Parcel parcel;
    NiceMock<IPCFileDescriptorInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(invoker));
    EXPECT_CALL(*invoker, ReadFileDescriptor(testing::_)).WillOnce(Return(1));

    auto result = ipcFileDescriptor.Unmarshalling(parcel);
    EXPECT_NE(result, nullptr);
    delete invoker;
}
} // namespace OHOS