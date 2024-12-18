/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#define private public
#include "ipc_skeleton.h"
#include "message_parcel.h"
#include "message_parcel.cpp"
#undef private

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

class MockIPCProcessSkeleton : public IPCProcessSkeleton {
public:
    MockIPCProcessSkeleton();
    ~MockIPCProcessSkeleton();
};

MockIPCProcessSkeleton::MockIPCProcessSkeleton()
{
}

MockIPCProcessSkeleton::~MockIPCProcessSkeleton()
{
}

class MessageParcelInterface {
public:
    MessageParcelInterface() {};
    virtual ~MessageParcelInterface() {};

    virtual void IncStrongRef(const void *objectId) = 0;
    virtual IPCProcessSkeleton *GetCurrent() = 0;
    virtual sptr<IRemoteObject> QueryObject(
        const std::u16string &descriptor, bool lockFlag = true) = 0;
};

class MessageParcelInterfaceMock : public MessageParcelInterface {
public:
    MessageParcelInterfaceMock();
    ~MessageParcelInterfaceMock() override;

    MOCK_METHOD1(IncStrongRef, void(const void *));
    MOCK_METHOD0(GetCurrent, IPCProcessSkeleton *());
    MOCK_METHOD2(QueryObject, sptr<IRemoteObject>(const std::u16string &, bool));
};

static void *g_interface = nullptr;

MessageParcelInterfaceMock::MessageParcelInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

MessageParcelInterfaceMock::~MessageParcelInterfaceMock()
{
    g_interface = nullptr;
}

static MessageParcelInterface *GetMessageParcelInterface()
{
    return reinterpret_cast<MessageParcelInterface *>(g_interface);
}
extern "C" {
    void RefBase::IncStrongRef(const void *objectId)
    {
        return GetMessageParcelInterface()->IncStrongRef(objectId);
    }
    IPCProcessSkeleton *IPCProcessSkeleton::GetCurrent()
    {
        return GetMessageParcelInterface()->GetCurrent();
    }
    sptr<IRemoteObject> ProcessSkeleton::QueryObject(const std::u16string &descriptor, bool lockFlag)
    {
        return GetMessageParcelInterface()->QueryObject(descriptor, lockFlag);
    }
}

class MessageParcelTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void MessageParcelTest::SetUpTestCase()
{
}

void MessageParcelTest::TearDownTestCase()
{
}

void MessageParcelTest::SetUp()
{
}

void MessageParcelTest::TearDown()
{
}

/**
 * @tc.name: AcquireObjectTest001
 * @tc.desc: Verify the AcquireObject function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, AcquireObjectTest001, TestSize.Level1)
{
    flat_binder_object *flat = nullptr;
    AcquireObject(flat, nullptr);
    EXPECT_EQ(flat, nullptr);
}

/**
 * @tc.name: AcquireObjectTest002
 * @tc.desc: Verify the AcquireObject function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, AcquireObjectTest002, TestSize.Level1)
{
    flat_binder_object flat;
    flat.hdr.type = BINDER_TYPE_BINDER;
    flat.binder = 0;

    AcquireObject(&flat, nullptr);
    EXPECT_EQ(flat.binder, 0);
}

/**
 * @tc.name: AcquireObjectTest003
 * @tc.desc: Verify the AcquireObject function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, AcquireObjectTest003, TestSize.Level1)
{
    NiceMock<MessageParcelInterfaceMock> mock;
    flat_binder_object flat;
    flat.hdr.type = BINDER_TYPE_BINDER;
    sptr<IRemoteObject> remoteObj = IPCSkeleton::GetContextObject();
    ASSERT_TRUE(remoteObj != nullptr);

    flat.cookie = reinterpret_cast<binder_uintptr_t>(remoteObj.GetRefPtr());
    flat.binder = reinterpret_cast<binder_uintptr_t>(remoteObj.GetRefPtr());
    ASSERT_TRUE(flat.cookie != 0);

    EXPECT_CALL(mock, IncStrongRef).WillOnce(Return());
    AcquireObject(&flat, nullptr);
    EXPECT_EQ(flat.hdr.type, BINDER_TYPE_BINDER);
}

/**
 * @tc.name: AcquireObjectTest004
 * @tc.desc: Verify the AcquireObject function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, AcquireObjectTest004, TestSize.Level1)
{
    NiceMock<MessageParcelInterfaceMock> mock;
    flat_binder_object flat;
    flat.hdr.type = BINDER_TYPE_HANDLE;

    EXPECT_CALL(mock, GetCurrent).WillOnce(Return(nullptr));
    AcquireObject(&flat, nullptr);
    EXPECT_EQ(flat.hdr.type, BINDER_TYPE_HANDLE);
}

/**
 * @tc.name: AcquireObjectTest005
 * @tc.desc: Verify the AcquireObject function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, AcquireObjectTest005, TestSize.Level1)
{
    NiceMock<MessageParcelInterfaceMock> mock;
    flat_binder_object flat;
    flat.hdr.type = BINDER_TYPE_HANDLE;
    MockIPCProcessSkeleton *current = new MockIPCProcessSkeleton();
    sptr<IRemoteObject> remoteObj = IPCSkeleton::GetContextObject();
    ASSERT_TRUE(remoteObj != nullptr);

    IRemoteObject *object = remoteObj.GetRefPtr();
    ASSERT_TRUE(object != 0);
    EXPECT_CALL(mock, GetCurrent).WillOnce(Return(current));
    EXPECT_CALL(mock, QueryObject).WillOnce(Return(object));
    EXPECT_CALL(mock, IncStrongRef).WillOnce(Return());
    AcquireObject(&flat, nullptr);
    EXPECT_EQ(flat.hdr.type, BINDER_TYPE_HANDLE);
    if (current)
    {
        delete current;
    }
}

/**
 * @tc.name: AcquireObjectTest006
 * @tc.desc: Verify the AcquireObject function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, AcquireObjectTest006, TestSize.Level1)
{
    flat_binder_object flat;
    flat.hdr.type = BINDER_TYPE_PTR;

    AcquireObject(&flat, nullptr);
    EXPECT_EQ(flat.hdr.type, BINDER_TYPE_PTR);
}
