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
#include "mock_iremote_object.h"

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

/**
 * @tc.name: AddRefreshRecipientTest001
 * @tc.desc: Verify the IRemoteObject::AddRefreshRecipient function return false when recipient is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IremoteObjectTest, AddRefreshRecipientTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    bool ret = object.AddRefreshRecipient(nullptr);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: AddRefreshRecipientTest002
 * @tc.desc: Verify the IRemoteObject::AddRefreshRecipient function return false when recipients_.size() < 1
 * @tc.type: FUNC
 */
HWTEST_F(IremoteObjectTest, AddRefreshRecipientTest002, TestSize.Level1)
{
    IPCObjectProxy object(1);
    sptr<IRemoteObject::RefreshRecipient> recipient = new MockRefreshRecipient();
    bool ret = object.AddRefreshRecipient(recipient);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: RemoveRefreshRecipientTest001
 * @tc.desc: Verify the IRemoteObject::RemoveRefreshRecipient function return false when recipient is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IremoteObjectTest, RemoveRefreshRecipientTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    bool ret = object.RemoveRefreshRecipient(nullptr);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: RemoveRefreshRecipientTest002
 * @tc.desc: Verify the IRemoteObject::RemoveRefreshRecipient function return false when IsObjectDead return true
 * @tc.type: FUNC
 */
HWTEST_F(IremoteObjectTest, RemoveRefreshRecipientTest002, TestSize.Level1)
{
    IPCObjectProxy object(1);
    sptr<IRemoteObject::RefreshRecipient> recipient = new MockRefreshRecipient();
    object.SetObjectDied(true);
    bool ret = object.RemoveRefreshRecipient(recipient);
    object.SetObjectDied(false);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: Reserved1Test001
 * @tc.desc: Verify the IRemoteObject::reserved1 function
 * @tc.type: FUNC
 */
HWTEST_F(IremoteObjectTest, Reserved1Test001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    ASSERT_NO_FATAL_FAILURE(object.reserved1());
}

/**
 * @tc.name: Reserved2Test001
 * @tc.desc: Verify the IRemoteObject::reserved2 function
 * @tc.type: FUNC
 */
HWTEST_F(IremoteObjectTest, Reserved2Test001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    ASSERT_NO_FATAL_FAILURE(object.reserved2());
}

/**
 * @tc.name: Reserved3Test001
 * @tc.desc: Verify the IRemoteObject::reserved3 function
 * @tc.type: FUNC
 */
HWTEST_F(IremoteObjectTest, Reserved3Test001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    ASSERT_NO_FATAL_FAILURE(object.reserved3());
}

/**
 * @tc.name: Reserved4Test001
 * @tc.desc: Verify the IRemoteObject::reserved4 function
 * @tc.type: FUNC
 */
HWTEST_F(IremoteObjectTest, Reserved4Test001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    ASSERT_NO_FATAL_FAILURE(object.reserved4());
}

/**
 * @tc.name: Reserved5Test001
 * @tc.desc: Verify the IRemoteObject::reserved5 function
 * @tc.type: FUNC
 */
HWTEST_F(IremoteObjectTest, Reserved5Test001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    ASSERT_NO_FATAL_FAILURE(object.reserved5());
}

/**
 * @tc.name: Reserved6Test001
 * @tc.desc: Verify the IRemoteObject::reserved6 function
 * @tc.type: FUNC
 */
HWTEST_F(IremoteObjectTest, Reserved6Test001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    ASSERT_NO_FATAL_FAILURE(object.reserved6());
}

/**
 * @tc.name: Reserved7Test001
 * @tc.desc: Verify the IRemoteObject::reserved7 function
 * @tc.type: FUNC
 */
HWTEST_F(IremoteObjectTest, Reserved7Test001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    ASSERT_NO_FATAL_FAILURE(object.reserved7());
}

/**
 * @tc.name: Reserved8Test001
 * @tc.desc: Verify the IRemoteObject::reserved8 function
 * @tc.type: FUNC
 */
HWTEST_F(IremoteObjectTest, Reserved8Test001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    ASSERT_NO_FATAL_FAILURE(object.reserved8());
}

/**
 * @tc.name: Reserved9Test001
 * @tc.desc: Verify the IRemoteObject::reserved9 function
 * @tc.type: FUNC
 */
HWTEST_F(IremoteObjectTest, Reserved9Test001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    ASSERT_NO_FATAL_FAILURE(object.reserved9());
}

/**
 * @tc.name: Reserved10Test001
 * @tc.desc: Verify the IRemoteObject::reserved10 function
 * @tc.type: FUNC
 */
HWTEST_F(IremoteObjectTest, Reserved10Test001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    ASSERT_NO_FATAL_FAILURE(object.reserved10());
}
} // namespace OHOS