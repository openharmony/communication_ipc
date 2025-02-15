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

#include <algorithm>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>

#include "binder_connector.h"
#include "binder_invoker.h"
#include "ipc_process_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "message_parcel.h"
#include "sys_binder.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

static constexpr int EXECUTE_ONCE = 1;
static constexpr int EXECUTE_TWICE = 2;
static constexpr int32_t TEST_HANDLE = 1;
static constexpr int32_t TEST_HANDLE_INVALID = 0;

namespace OHOS {
class BinderInvokerInterface {
public:
    BinderInvokerInterface() {};
    virtual ~BinderInvokerInterface() {};

    virtual size_t GetWritePosition() = 0;
    virtual size_t GetReadPosition() = 0;
    virtual bool WriteUint32(uint32_t value) = 0;
    virtual bool WriteInt32(int32_t value) = 0;
    virtual bool RewindWrite(size_t position) = 0;
    virtual bool RewindRead(size_t position) = 0;
    virtual bool WritePointer(uintptr_t value) = 0;
    virtual uint32_t ReadUint32() = 0;
    virtual uintptr_t ReadPointer() = 0;
    virtual bool CheckOffsets() = 0;
    virtual uint8_t *ReadBuffer(size_t length, bool isValidate) = 0;
};
class BinderInvokerInterfaceMock : public BinderInvokerInterface {
public:
    BinderInvokerInterfaceMock();
    ~BinderInvokerInterfaceMock() override;

    MOCK_METHOD0(GetWritePosition, size_t());
    MOCK_METHOD0(GetReadPosition, size_t());
    MOCK_METHOD1(WriteUint32, bool(uint32_t value));
    MOCK_METHOD1(WriteInt32, bool(int32_t value));
    MOCK_METHOD1(RewindWrite, bool(size_t position));
    MOCK_METHOD1(RewindRead, bool(size_t position));
    MOCK_METHOD0(ReadUint32, uint32_t());
    MOCK_METHOD1(WritePointer, bool(uintptr_t value));
    MOCK_METHOD0(ReadPointer, uintptr_t());
    MOCK_METHOD0(CheckOffsets, bool());
    MOCK_METHOD2(ReadBuffer, uint8_t *(size_t length, bool isValidate));
};
static void *g_interface = nullptr;

BinderInvokerInterfaceMock::BinderInvokerInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

BinderInvokerInterfaceMock::~BinderInvokerInterfaceMock()
{
    g_interface = nullptr;
}

static BinderInvokerInterface *GetBinderInvokerInterface()
{
    return reinterpret_cast<BinderInvokerInterface *>(g_interface);
}

extern "C" {
    size_t Parcel::GetWritePosition()
    {
        return GetBinderInvokerInterface()->GetWritePosition();
    }
    size_t Parcel::GetReadPosition()
    {
        return GetBinderInvokerInterface()->GetReadPosition();
    }
    bool Parcel::WriteUint32(uint32_t value)
    {
        return GetBinderInvokerInterface()->WriteUint32(value);
    }
    bool Parcel::WriteInt32(int32_t value)
    {
        return GetBinderInvokerInterface()->WriteInt32(value);
    }
    bool Parcel::RewindWrite(size_t newPosition)
    {
        return GetBinderInvokerInterface()->RewindWrite(newPosition);
    }
    bool Parcel::RewindRead(size_t newPosition)
    {
        return GetBinderInvokerInterface()->RewindRead(newPosition);
    }
    bool Parcel::WritePointer(uintptr_t value)
    {
        return GetBinderInvokerInterface()->WritePointer(value);
    }
    uintptr_t Parcel::ReadPointer()
    {
        return GetBinderInvokerInterface()->ReadPointer();
    }
    const uint8_t *Parcel::ReadBuffer(size_t length, bool isValidate)
    {
        return GetBinderInvokerInterface()->ReadBuffer(length, isValidate);
    }
    uint32_t Parcel::ReadUint32()
    {
        return GetBinderInvokerInterface()->ReadUint32();
    }
    bool Parcel::CheckOffsets()
    {
        return GetBinderInvokerInterface()->CheckOffsets();
    }
}
} // namespace OHOS

class BinderInvokerTest : public ::testing::Test {
    public:
        static void SetUpTestCase(void);
        static void TearDownTestCase(void);
        void SetUp();
        void TearDown();
};

void BinderInvokerTest::SetUpTestCase()
{
}

void BinderInvokerTest::TearDownTestCase()
{
}

void BinderInvokerTest::SetUp()
{
}

void BinderInvokerTest::TearDown()
{
}

/**
 * @tc.name: AcquireHandleTest001
 * @tc.desc: Verify the AcquireHandle function, When WriteUint32 function return false
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, AcquireHandleTest001, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    int32_t handle = TEST_HANDLE;

    EXPECT_CALL(mock, GetWritePosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, WriteUint32).WillOnce(testing::Return(false));
    bool ret = binderInvoker.AcquireHandle(handle);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: AcquireHandleTest002
 * @tc.desc: Verify the AcquireHandle function
 * When WriteUint32 function return true, WriteInt32 function return false,
 * RewindWrite function return true
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, AcquireHandleTest002, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    int32_t handle = TEST_HANDLE;

    EXPECT_CALL(mock, GetWritePosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, WriteUint32).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, WriteInt32).WillOnce(testing::Return(false));
    EXPECT_CALL(mock, RewindWrite).WillOnce(testing::Return(true));
    bool ret = binderInvoker.AcquireHandle(handle);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: AcquireHandleTest003
 * @tc.desc: Verify the AcquireHandle function
 * When WriteUint32 function return true, WriteInt32 function return false,
 * RewindWrite function return false
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, AcquireHandleTest003, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    int32_t handle = TEST_HANDLE;

    EXPECT_CALL(mock, GetWritePosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, WriteUint32).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, WriteInt32).WillOnce(testing::Return(false));
    EXPECT_CALL(mock, RewindWrite).WillOnce(testing::Return(false));
    bool ret = binderInvoker.AcquireHandle(handle);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: AcquireHandleTest004
 * @tc.desc: Verify the AcquireHandle function
 * When WriteUint32 function return true, WriteInt32 function return true
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, AcquireHandleTest004, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    int32_t handle = TEST_HANDLE;

    EXPECT_CALL(mock, GetWritePosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, WriteUint32).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, WriteInt32).WillOnce(testing::Return(true));
    bool ret = binderInvoker.AcquireHandle(handle);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: AcquireHandleTest005
 * @tc.desc: Verify the AcquireHandle function when handle is 0
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, AcquireHandleTest005, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    int32_t handle = TEST_HANDLE_INVALID;

    EXPECT_CALL(mock, GetWritePosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, WriteUint32).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, WriteInt32).WillOnce(testing::Return(true));
    bool ret = binderInvoker.AcquireHandle(handle);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: ReleaseHandleTest001
 * @tc.desc: Verify the ReleaseHandle function when handle is 1
 * When WriteUint32 function return false
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, ReleaseHandleTest001, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    int32_t handle = TEST_HANDLE;

    EXPECT_CALL(mock, GetWritePosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, WriteUint32).WillOnce(testing::Return(false));
    bool ret = binderInvoker.ReleaseHandle(handle);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: ReleaseHandleTest002
 * @tc.desc: Verify the ReleaseHandle function
 * When WriteUint32 function return true, When WriteInt32 function return false
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, ReleaseHandleTest002, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    int32_t handle = TEST_HANDLE;

    EXPECT_CALL(mock, GetWritePosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, WriteUint32).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, WriteInt32).WillOnce(testing::Return(false));
    EXPECT_CALL(mock, RewindWrite).WillOnce(testing::Return(true));
    bool ret = binderInvoker.ReleaseHandle(handle);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: ReleaseHandleTest003
 * @tc.desc: Verify the ReleaseHandle function
 * When WriteUint32 function return true, When WriteInt32 function return true
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, ReleaseHandleTest003, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    int32_t handle = TEST_HANDLE;

    EXPECT_CALL(mock, GetWritePosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, WriteUint32).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, WriteInt32).WillOnce(testing::Return(true));
    bool ret = binderInvoker.ReleaseHandle(handle);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: AddDeathRecipientTest001
 * @tc.desc: Verify the AddDeathRecipient function When WriteInt32 function return false
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, AddDeathRecipientTest001, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    int32_t handle = TEST_HANDLE;
    void *cookie = nullptr;

    EXPECT_CALL(mock, GetWritePosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, WriteInt32).WillOnce(testing::Return(false));
    bool ret = binderInvoker.AddDeathRecipient(handle, cookie);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: AddDeathRecipientTest002
 * @tc.desc: Verify the AddDeathRecipient function When WriteInt32 function return true
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, AddDeathRecipientTest002, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    int32_t handle = TEST_HANDLE;
    void *cookie = nullptr;

    EXPECT_CALL(mock, GetWritePosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, WriteInt32).Times(EXECUTE_TWICE)
        .WillOnce(testing::Return(true))
        .WillOnce(testing::Return(false));
    bool ret = binderInvoker.AddDeathRecipient(handle, cookie);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: AddDeathRecipientTest003
 * @tc.desc: Verify the AddDeathRecipient function
 * When WriteInt32 function return true, When WritePointer function return false
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, AddDeathRecipientTest003, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    int32_t handle = TEST_HANDLE;
    void *cookie = nullptr;

    EXPECT_CALL(mock, GetWritePosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, WriteInt32).Times(EXECUTE_TWICE)
        .WillOnce(testing::Return(true))
        .WillOnce(testing::Return(true));
    EXPECT_CALL(mock, WritePointer).WillOnce(testing::Return(false));
    bool ret = binderInvoker.AddDeathRecipient(handle, cookie);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: AddDeathRecipientTest004
 * @tc.desc: Verify the AddDeathRecipient function
 * When WriteInt32 function return true, When WritePointer function return true
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, AddDeathRecipientTest004, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    int32_t handle = TEST_HANDLE;
    void *cookie = nullptr;

    EXPECT_CALL(mock, GetWritePosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, WriteInt32).Times(EXECUTE_TWICE)
        .WillOnce(testing::Return(true))
        .WillOnce(testing::Return(true));
    EXPECT_CALL(mock, WritePointer).WillOnce(testing::Return(true));
    bool ret = binderInvoker.AddDeathRecipient(handle, cookie);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: RemoveDeathRecipientTest001
 * @tc.desc: Verify the RemoveDeathRecipient function When WriteInt32 function return false
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, RemoveDeathRecipientTest001, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    int32_t handle = TEST_HANDLE;
    void *cookie = nullptr;

    EXPECT_CALL(mock, GetWritePosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, WriteInt32).WillOnce(testing::Return(false));
    bool ret = binderInvoker.RemoveDeathRecipient(handle, cookie);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: RemoveDeathRecipientTest002
 * @tc.desc: Verify the RemoveDeathRecipient function
 * When the WriteUint32 function returns true for the first time and false for the second time
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, RemoveDeathRecipientTest002, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    int32_t handle = TEST_HANDLE;
    void *cookie = nullptr;

    EXPECT_CALL(mock, GetWritePosition()).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, WriteInt32).Times(EXECUTE_TWICE)
        .WillOnce(testing::Return(true))
        .WillOnce(testing::Return(false));
    bool ret = binderInvoker.RemoveDeathRecipient(handle, cookie);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: RemoveDeathRecipientTest003
 * @tc.desc: Verify the RemoveDeathRecipient function
 * When the WriteUint32 function returns true for the first time and true for the second time
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, RemoveDeathRecipientTest003, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    int32_t handle = TEST_HANDLE;
    void *cookie = nullptr;

    EXPECT_CALL(mock, GetWritePosition()).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, WriteInt32).Times(EXECUTE_TWICE)
        .WillOnce(testing::Return(true))
        .WillOnce(testing::Return(true));
    EXPECT_CALL(mock, WritePointer).WillOnce(testing::Return(false));
    bool ret = binderInvoker.RemoveDeathRecipient(handle, cookie);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: RemoveDeathRecipientTest004
 * @tc.desc: Verify the RemoveDeathRecipient function When WritePointer function return true
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, RemoveDeathRecipientTest004, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    int32_t handle = TEST_HANDLE;
    void *cookie = nullptr;

    EXPECT_CALL(mock, GetWritePosition()).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, WriteInt32).Times(EXECUTE_TWICE)
        .WillOnce(testing::Return(true))
        .WillOnce(testing::Return(true));
    EXPECT_CALL(mock, WritePointer).WillOnce(testing::Return(true));
    bool ret = binderInvoker.RemoveDeathRecipient(handle, cookie);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: TranslateIRemoteObjectTest001
 * @tc.desc: Verify the TranslateIRemoteObject function When binderInvoker.binderConnector_ is nullptr
 * @tc.type: FUNC
 */
#ifndef CONFIG_IPC_SINGLE
HWTEST_F(BinderInvokerTest, TranslateIRemoteObjectTest001, TestSize.Level1) {
    BinderInvoker binderInvoker;
    int32_t cmd = TEST_HANDLE;
    const sptr<IRemoteObject> obj;
    binderInvoker.binderConnector_ = nullptr;
    int ret = binderInvoker.TranslateIRemoteObject(cmd, obj);
    EXPECT_EQ(ret, -IPC_INVOKER_CONNECT_ERR);
}
#endif

/**
 * @tc.name: TranslateIRemoteObjectTest002
 * @tc.desc: Verify the TranslateIRemoteObject function When WritePointer function return false
 * @tc.type: FUNC
 */
#ifndef CONFIG_IPC_SINGLE
HWTEST_F(BinderInvokerTest, TranslateIRemoteObjectTest002, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    int32_t cmd = TEST_HANDLE;
    const sptr<IRemoteObject> obj;

    EXPECT_CALL(mock, GetWritePosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, WriteInt32).WillOnce(testing::Return(false));
    int ret = binderInvoker.TranslateIRemoteObject(cmd, obj);
    EXPECT_EQ(ret, -IPC_INVOKER_TRANSLATE_ERR);
}
#endif

/**
 * @tc.name: TranslateIRemoteObjectTest003
 * @tc.desc: Verify the TranslateIRemoteObject function When WritePointer function return true
 * @tc.type: FUNC
 */
#ifndef CONFIG_IPC_SINGLE
HWTEST_F(BinderInvokerTest, TranslateIRemoteObjectTest003, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    int32_t cmd = TEST_HANDLE;
    const sptr<IRemoteObject> obj;

    EXPECT_CALL(mock, GetWritePosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, WriteInt32).WillOnce(testing::Return(true));
    int ret = binderInvoker.TranslateIRemoteObject(cmd, obj);
    EXPECT_EQ(ret, -IPC_INVOKER_TRANSLATE_ERR);
}
#endif

/**
 * @tc.name: GetDBinderCallingPidUidTest001
 * @tc.desc: Verify the GetDBinderCallingPidUid function When pid is -1 and uid is 0
 * @tc.type: FUNC
 */
#ifndef CONFIG_IPC_SINGLE
HWTEST_F(BinderInvokerTest, GetDBinderCallingPidUidTest001, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    pid_t pid = -1;
    uid_t uid = 0;
    int handle = TEST_HANDLE;
    bool isReply = false;

    bool ret = binderInvoker.GetDBinderCallingPidUid(handle, isReply, pid, uid);
    EXPECT_FALSE(ret);
}
#endif

/**
 * @tc.name: GetDBinderCallingPidUidTest003
 * @tc.desc: Verify the GetDBinderCallingPidUid function When pid is 1 and uid is 0
 * @tc.type: FUNC
 */
#ifndef CONFIG_IPC_SINGLE
HWTEST_F(BinderInvokerTest, GetDBinderCallingPidUidTest003, TestSize.Level1) {
    BinderInvoker binderInvoker;
    pid_t pid = 1;
    uid_t uid = 0;
    int handle = TEST_HANDLE;
    bool isReply = false;

    bool ret = binderInvoker.GetDBinderCallingPidUid(handle, isReply, pid, uid);
    EXPECT_TRUE(ret);
}
#endif

/**
 * @tc.name: UnFlattenDBinderObjectTest001
 * @tc.desc: Verify the UnFlattenDBinderObject function When ReadBuffer function return null
 * @tc.type: FUNC
 */
#ifndef CONFIG_IPC_SINGLE
HWTEST_F(BinderInvokerTest, UnFlattenDBinderObjectTest001, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    dbinder_negotiation_data dbinderData;
    Parcel parcel;

    EXPECT_CALL(mock, GetReadPosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, ReadBuffer).WillOnce(testing::Return(nullptr));
    bool ret = binderInvoker.UnFlattenDBinderObject(parcel, dbinderData);
    EXPECT_FALSE(ret);
}
#endif

/**
 * @tc.name: FlushCommandsTest001
 * @tc.desc: Verify the FlushCommands function
 * When binderInvoker.binderConnector_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, FlushCommandsTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.binderConnector_ = nullptr;
    EXPECT_EQ(binderInvoker.FlushCommands(nullptr), IPC_INVOKER_CONNECT_ERR);
}

/**
 * @tc.name: OnAcquireObjectTest001
 * @tc.desc: Verify the OnAcquireObject function
 * When the ReadPointer function returns 1 for the first time and 0 for the second time
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, OnAcquireObjectTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    uint32_t cmd = TEST_HANDLE;
    uintptr_t nullPtrValue = 0;
    uintptr_t validObjPtr = 1;

    EXPECT_CALL(mock, ReadPointer)
        .WillOnce(testing::Return(validObjPtr))
        .WillOnce(testing::Return(nullPtrValue));
    ASSERT_NO_FATAL_FAILURE(binderInvoker.OnAcquireObject(cmd));
}

/**
 * @tc.name: OnReleaseObjectTest001
 * @tc.desc: Verify the OnReleaseObject function
 * When the ReadPointer function returns 0 for the first time and 1 for the second time
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, OnReleaseObjectTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    uint32_t cmd = 1;
    uintptr_t nullPtrValue = 0;
    uintptr_t validObjPtr = 1;

    EXPECT_CALL(mock, ReadPointer())
        .WillOnce(testing::Return(nullPtrValue))
        .WillOnce(testing::Return(validObjPtr));

    ASSERT_NO_FATAL_FAILURE(binderInvoker.OnReleaseObject(cmd));
}

/**
 * @tc.name: GeneralServiceSendRequestTest001
 * @tc.desc: Verify the GeneralServiceSendRequest function when return ERR_DEAD_OBJECT
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GeneralServiceSendRequestTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binder_transaction_data tr;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    int32_t ret = binderInvoker.GeneralServiceSendRequest(tr, data, reply, option);
    EXPECT_EQ(ret, ERR_DEAD_OBJECT);
}

/**
 * @tc.name: SetCallingIdentityTest001
 * @tc.desc: Verify the SetCallingIdentityTest001 function when identity is ""
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, SetCallingIdentityTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    std::string identity = "";
    bool ret = binderInvoker.SetCallingIdentity(identity, false);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: SetCallingIdentityTest002
 * @tc.desc: Override SetCallingIdentity function when identity is valid value
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, SetCallingIdentityTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    std::string identity = "testIdentity";
    bool flag = true;
    bool result = binderInvoker.SetCallingIdentity(identity, flag);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: TriggerSystemIPCThreadReclaimTest001
 * @tc.desc: Override TriggerSystemIPCThreadReclaim function when binderConnector_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, TriggerSystemIPCThreadReclaimTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.binderConnector_ = nullptr;

    bool result = binderInvoker.TriggerSystemIPCThreadReclaim();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: EnableIPCThreadReclaimTest001
 * @tc.desc: Override EnableIPCThreadReclaim function when binderConnector_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, EnableIPCThreadReclaimTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    bool enable = true;
    binderInvoker.binderConnector_ = nullptr;

    bool result = binderInvoker.EnableIPCThreadReclaim(enable);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: GetStrongRefCountForStubTest001
 * @tc.desc: Override GetStrongRefCountForStub function when binderConnector_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetStrongRefCountForStubTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    uint32_t handle = 1;
    binderInvoker.binderConnector_ = nullptr;

    uint32_t result = binderInvoker.GetStrongRefCountForStub(handle);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: IsSendRequestingTest001
 * @tc.desc: Override IsSendRequesting function when sendRequestCount_ is 1
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, IsSendRequestingTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.sendRequestCount_ = 1;

    bool result = binderInvoker.IsSendRequesting();
    EXPECT_TRUE(result);
}

/**
 * @tc.name: IsSendRequestingTest002
 * @tc.desc: Override IsSendRequesting function when sendRequestCount_ is 0
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, IsSendRequestingTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.sendRequestCount_ = 0;

    bool result = binderInvoker.IsSendRequesting();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: GetUint64ValueByStrSliceTest001
 * @tc.desc: cover GetUint64ValueByStrSlice function
 * when str.length is less than offset + length
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetUint64ValueByStrSliceTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    std::string str = "<0671418004000000000023721104375808";
    size_t offset = str.length();
    size_t length = 1;
    uint64_t value = 0;
    bool ret = binderInvoker.GetUint64ValueByStrSlice(str, offset, length, value);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: GetUint64ValueByStrSliceTest002
 * @tc.desc: cover GetUint64ValueByStrSlice function when str is ""
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetUint64ValueByStrSliceTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    std::string str = "";
    size_t offset = 0;
    size_t length = 0;
    uint64_t value = 0;

    bool ret = binderInvoker.GetUint64ValueByStrSlice(str, offset, length, value);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: GetCallerRealPidByStrTest001
 * @tc.desc: cover GetCallerRealPidByStr function
 * when str.length is less than offset + length
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetCallerRealPidByStrTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    std::string str = "<0671418004000000000023721104375808";
    size_t offset = str.length();
    size_t length = 1;
    pid_t callerRealPid = 0;
    bool ret = binderInvoker.GetCallerRealPidByStr(str, offset, length, callerRealPid);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: GetCallerRealPidByStrTest002
 * @tc.desc: cover GetCallerRealPidByStr function when str is ""
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetCallerRealPidByStrTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    std::string str = "";
    size_t offset = 0;
    size_t length = 0;
    pid_t callerRealPid = 0;
    bool ret = binderInvoker.GetCallerRealPidByStr(str, offset, length, callerRealPid);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: GetCallerPidAndUidByStrTest001
 * @tc.desc: cover GetCallerPidAndUidByStr function
 * when str.length is less than offset + length
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetCallerPidAndUidByStrTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    std::string str = "<0671418004000000000023721104375808";
    size_t offset = str.length() + 1;
    pid_t pid = 0;
    pid_t uid = 0;
    bool ret = binderInvoker.GetCallerPidAndUidByStr(str, offset, pid, uid);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: UnflattenObjectTest001
 * @tc.desc: Verify the UnflattenObject function when str is ""
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, UnflattenObjectTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    Parcel parcel;
    NiceMock<BinderInvokerInterfaceMock> mock;

    EXPECT_CALL(mock, CheckOffsets).WillOnce(testing::Return(false));

    sptr<IRemoteObject> ret = binderInvoker.UnflattenObject(parcel);
    EXPECT_EQ(ret, nullptr);
}