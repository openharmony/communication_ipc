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

#include "dbinder_databus_invoker.h"
#include "ipc_object_proxy.h"
#include "ipc_thread_skeleton.h"
#include "iremote_invoker.h"
#include "iremote_object.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
namespace OHOS {
    
namespace {
    const std::u16string DESCRIPTOR_TEST = u"test_descriptor";
    const std::string SO_PATH_TEST = "test_so_path";
}

class IremoteObjectInterface {
public:
    IremoteObjectInterface() {};
    virtual ~IremoteObjectInterface() {};

    virtual IRemoteInvoker *GetRemoteInvoker(int proto) = 0;
};
class IremoteObjectInterfaceMock : public IremoteObjectInterface {
public:
    IremoteObjectInterfaceMock();
    ~IremoteObjectInterfaceMock() override;

    MOCK_METHOD1(GetRemoteInvoker, IRemoteInvoker *(int));
};

static void *g_interface = nullptr;

IremoteObjectInterfaceMock::IremoteObjectInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

IremoteObjectInterfaceMock::~IremoteObjectInterfaceMock()
{
    g_interface = nullptr;
}

static IremoteObjectInterface *GetIremoteObjectInterface()
{
    return reinterpret_cast<IremoteObjectInterface *>(g_interface);
}

extern "C" {
    IRemoteInvoker *IPCThreadSkeleton::GetRemoteInvoker(int proto)
    {
        if (GetIremoteObjectInterface() == nullptr) {
            return nullptr;
        }
        return GetIremoteObjectInterface()->GetRemoteInvoker(proto);
    }
}

class IremoteObjectTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void IremoteObjectTest::SetUpTestCase()
{
}

void IremoteObjectTest::TearDownTestCase()
{
}

void IremoteObjectTest::SetUp()
{
}

void IremoteObjectTest::TearDown()
{
}

/**
 * @tc.name: CheckObjectLegalityTest001
 * @tc.desc: Verify the CheckObjectLegality function return false
 * @tc.type: FUNC
 */
HWTEST_F(IremoteObjectTest, CheckObjectLegalityTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);

    auto ret = object.CheckObjectLegality();
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: MarshallingTest001
 * @tc.desc: Verify the Marshalling function when GetRemoteInvoker function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IremoteObjectTest, MarshallingTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    Parcel parcel;
    NiceMock<IremoteObjectInterfaceMock> mock;

    EXPECT_CALL(mock, GetRemoteInvoker).WillOnce(Return(nullptr));

    auto ret = object.Marshalling(parcel);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: MarshallingTest002
 * @tc.desc: Verify the Marshalling function when GetRemoteInvoker function return valid value
 * @tc.type: FUNC
 */
HWTEST_F(IremoteObjectTest, MarshallingTest002, TestSize.Level1)
{
    IPCObjectProxy object(1);
    Parcel parcel;
    NiceMock<IremoteObjectInterfaceMock> mock;
    DBinderDatabusInvoker *invoker = new DBinderDatabusInvoker();

    EXPECT_CALL(mock, GetRemoteInvoker).WillOnce(Return(invoker));

    auto ret = object.Marshalling(parcel);
    ASSERT_TRUE(ret);
    if (invoker != nullptr) {
        delete invoker;
    }
}

/**
 * @tc.name: MarshallingTest003
 * @tc.desc: Verify the Marshalling function when GetRemoteInvoker function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IremoteObjectTest, MarshallingTest003, TestSize.Level1)
{
    IPCObjectProxy object(1);
    Parcel parcel;
    sptr<IRemoteObject> remoteOjbect = nullptr;
    NiceMock<IremoteObjectInterfaceMock> mock;

    EXPECT_CALL(mock, GetRemoteInvoker).WillOnce(Return(nullptr));

    auto ret = object.Marshalling(parcel, remoteOjbect);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: MarshallingTest004
 * @tc.desc: Verify the Marshalling function when GetRemoteInvoker function return valid value
 * @tc.type: FUNC
 */
HWTEST_F(IremoteObjectTest, MarshallingTest004, TestSize.Level1)
{
    IPCObjectProxy object(1);
    Parcel parcel;
    sptr<IRemoteObject> remoteOjbect = nullptr;
    NiceMock<IremoteObjectInterfaceMock> mock;
    DBinderDatabusInvoker *invoker = new DBinderDatabusInvoker();

    EXPECT_CALL(mock, GetRemoteInvoker).WillOnce(Return(invoker));

    auto ret = object.Marshalling(parcel, remoteOjbect);
    ASSERT_TRUE(ret);
    if (invoker != nullptr) {
        delete invoker;
    }
}

/**
 * @tc.name: UnmarshallingTest001
 * @tc.desc: Verify the Unmarshalling function when GetRemoteInvoker function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IremoteObjectTest, UnmarshallingTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    Parcel parcel;
    NiceMock<IremoteObjectInterfaceMock> mock;

    EXPECT_CALL(mock, GetRemoteInvoker).WillOnce(Return(nullptr));

    sptr<IRemoteObject> ret = object.Unmarshalling(parcel);
    EXPECT_EQ(ret.GetRefPtr(), nullptr);
}

/**
 * @tc.name: UnmarshallingTest002
 * @tc.desc: Verify the Unmarshalling function when GetRemoteInvoker function return valid value
 * @tc.type: FUNC
 */
HWTEST_F(IremoteObjectTest, UnmarshallingTest002, TestSize.Level1)
{
    IPCObjectProxy object(1);
    Parcel parcel;
    NiceMock<IremoteObjectInterfaceMock> mock;
    DBinderDatabusInvoker *invoker = new DBinderDatabusInvoker();

    EXPECT_CALL(mock, GetRemoteInvoker).WillRepeatedly(Return(invoker));
    sptr<IRemoteObject> ret = object.Unmarshalling(parcel);
    EXPECT_EQ(ret.GetRefPtr(), nullptr);
    if (invoker != nullptr) {
        delete invoker;
    }
}

/**
 * @tc.name: IsProxyObjectTest001
 * @tc.desc: Verify the IRemoteObject::IsProxyObject function return true
 * @tc.type: FUNC
 */
HWTEST_F(IremoteObjectTest, IsProxyObjectTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);

    auto ret = object.IsProxyObject();
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: IsObjectDeadTest001
 * @tc.desc: Verify the IRemoteObject::IsObjectDead function return false
 * @tc.type: FUNC
 */
HWTEST_F(IremoteObjectTest, IsObjectDeadTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);

    auto ret = object.IsObjectDead();
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: GetInterfaceDescriptorTest001
 * @tc.desc: Verify the IRemoteObject::GetInterfaceDescriptor function return valid value
 * @tc.type: FUNC
 */
HWTEST_F(IremoteObjectTest, GetInterfaceDescriptorTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);

    EXPECT_EQ(object.descriptor_, object.GetInterfaceDescriptor());
}
} // namespace OHOS