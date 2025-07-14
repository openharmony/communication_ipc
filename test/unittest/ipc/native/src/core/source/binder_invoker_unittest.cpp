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

const std::u16string DESCRIPTOR_TEST = u"test_descriptor";
const std::string STR_TEST = "<000000000006714180040000000000000000000023721104375808";
const std::string STR_TEST_ONE = "000000000006714180040000000000000000000023721104375808<";
const std::string STR_TEST_TWO = "000000000006714180040000000000000000000023<721104375808";
const std::string STR_TEST_THREE = "<12345678901234567890";
const std::string IDENTITY_TEST = "testIdentity";
const std::string IDENTITY_TEST_INVALID = "identity";
const std::string CALLER_SID_TEST = "test_caller_id";
const std::string SID_TEST = "test_id";
static constexpr const char *DRIVER_NAME = "/dev/binder";
static constexpr const char *DRIVER_NAME_INVALID = "/dev/test/test";
static constexpr int EXECUTE_ONCE = 1;
static constexpr int EXECUTE_TWICE = 2;
static constexpr int32_t TEST_HANDLE = 1;
static constexpr int32_t TEST_HANDLE_INVALID = 0;
static constexpr uint64_t TOKEN_ID_TEST = 1;
static constexpr uint64_t TOKEN_ID_INVALID_TEST = 0;
static constexpr uint64_t FIRST_TOKEN_ID_TEST = 1;
static constexpr pid_t PID_TEST_INVALID = 0;
static constexpr pid_t PID_TEST = 1;
static constexpr pid_t UID_INVALID_TEST = 0;
static constexpr pid_t UID_TEST = 1;

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
    virtual sptr<IRemoteObject> GetRegistryObject() = 0;
    virtual bool IsValidObject(IRemoteObject *object, std::u16string &desc) = 0;
    virtual int GetSptrRefCount() = 0;
    virtual uint64_t GetSelfFirstCallerTokenID() = 0;
    virtual bool IsDriverAlive() = 0;
    virtual bool GetSubStr(const std::string &str, std::string &substr, size_t offset, size_t length) = 0;
    virtual bool StrToUint64(const std::string &str, uint64_t &value) = 0;
    virtual bool StrToInt32(const std::string &str, int32_t &value) = 0;
    virtual int WriteBinder(unsigned long request, void *value) = 0;
    virtual size_t GetDataSize() = 0;
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
    MOCK_METHOD0(GetRegistryObject, sptr<IRemoteObject>());
    MOCK_METHOD2(IsValidObject, bool(IRemoteObject *object, std::u16string &desc));
    MOCK_METHOD0(GetSptrRefCount, int());
    MOCK_METHOD0(GetSelfFirstCallerTokenID, uint64_t());
    MOCK_METHOD0(IsDriverAlive, bool());
    MOCK_METHOD4(GetSubStr, bool(const std::string &str, std::string &substr, size_t offset, size_t length));
    MOCK_METHOD2(StrToUint64, bool(const std::string &str, uint64_t &value));
    MOCK_METHOD2(StrToInt32, bool(const std::string &str, int32_t &value));
    MOCK_METHOD2(WriteBinder, int(unsigned long request, void *value));
    MOCK_METHOD0(GetDataSize, size_t());
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
        if (GetBinderInvokerInterface() == nullptr) {
            return 0;
        }
        return GetBinderInvokerInterface()->GetWritePosition();
    }
    size_t Parcel::GetReadPosition()
    {
        if (GetBinderInvokerInterface() == nullptr) {
            return 0;
        }
        return GetBinderInvokerInterface()->GetReadPosition();
    }
    bool Parcel::WriteUint32(uint32_t value)
    {
        if (GetBinderInvokerInterface() == nullptr) {
            return false;
        }
        return GetBinderInvokerInterface()->WriteUint32(value);
    }
    bool Parcel::WriteInt32(int32_t value)
    {
        if (GetBinderInvokerInterface() == nullptr) {
            return false;
        }
        return GetBinderInvokerInterface()->WriteInt32(value);
    }
    bool Parcel::RewindWrite(size_t newPosition)
    {
        if (GetBinderInvokerInterface() == nullptr) {
            return false;
        }
        return GetBinderInvokerInterface()->RewindWrite(newPosition);
    }
    bool Parcel::RewindRead(size_t newPosition)
    {
        if (GetBinderInvokerInterface() == nullptr) {
            return false;
        }
        return GetBinderInvokerInterface()->RewindRead(newPosition);
    }
    bool Parcel::WritePointer(uintptr_t value)
    {
        if (GetBinderInvokerInterface() == nullptr) {
            return false;
        }
        return GetBinderInvokerInterface()->WritePointer(value);
    }
    uintptr_t Parcel::ReadPointer()
    {
        if (GetBinderInvokerInterface() == nullptr) {
            return 0;
        }
        return GetBinderInvokerInterface()->ReadPointer();
    }
    const uint8_t *Parcel::ReadBuffer(size_t length, bool isValidate)
    {
        if (GetBinderInvokerInterface() == nullptr) {
            return nullptr;
        }
        return GetBinderInvokerInterface()->ReadBuffer(length, isValidate);
    }
    uint32_t Parcel::ReadUint32()
    {
        if (GetBinderInvokerInterface() == nullptr) {
            return 0;
        }
        return GetBinderInvokerInterface()->ReadUint32();
    }
    bool Parcel::CheckOffsets()
    {
        if (GetBinderInvokerInterface() == nullptr) {
            return false;
        }
        return GetBinderInvokerInterface()->CheckOffsets();
    }
    size_t Parcel::GetDataSize() const
    {
        if (GetBinderInvokerInterface() == nullptr) {
            return 0;
        }
        return GetBinderInvokerInterface()->GetDataSize();
    }
    sptr<IRemoteObject> IPCProcessSkeleton::GetRegistryObject()
    {
        if (GetBinderInvokerInterface() == nullptr) {
            return nullptr;
        }
        return GetBinderInvokerInterface()->GetRegistryObject();
    }
    bool ProcessSkeleton::IsValidObject(IRemoteObject *object, std::u16string &desc)
    {
        if (GetBinderInvokerInterface() == nullptr) {
            return false;
        }
        return GetBinderInvokerInterface()->IsValidObject(object, desc);
    }
    int RefBase::GetSptrRefCount()
    {
        if (GetBinderInvokerInterface() == nullptr) {
            return 0;
        }
        return GetBinderInvokerInterface()->GetSptrRefCount();
    }
    uint64_t BinderConnector::GetSelfFirstCallerTokenID()
    {
        if (GetBinderInvokerInterface() == nullptr) {
            return 0;
        }
        return GetBinderInvokerInterface()->GetSelfFirstCallerTokenID();
    }
    bool BinderConnector::IsDriverAlive()
    {
        if (GetBinderInvokerInterface() == nullptr) {
            return false;
        }
        return GetBinderInvokerInterface()->IsDriverAlive();
    }
    bool ProcessSkeleton::GetSubStr(const std::string &str, std::string &substr, size_t offset, size_t length)
    {
        if (GetBinderInvokerInterface() == nullptr) {
            return false;
        }
        return GetBinderInvokerInterface()->GetSubStr(str, substr, offset, length);
    }
    bool ProcessSkeleton::StrToUint64(const std::string &str, uint64_t &value)
    {
        if (GetBinderInvokerInterface() == nullptr) {
            return false;
        }
        return GetBinderInvokerInterface()->StrToUint64(str, value);
    }
    bool ProcessSkeleton::StrToInt32(const std::string &str, int32_t &value)
    {
        if (GetBinderInvokerInterface() == nullptr) {
            return false;
        }
        return GetBinderInvokerInterface()->StrToInt32(str, value);
    }
    int BinderConnector::WriteBinder(unsigned long request, void *value)
    {
        if (GetBinderInvokerInterface() == nullptr) {
            return 0;
        }
        return GetBinderInvokerInterface()->WriteBinder(request, value);
    }
}

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
    EXPECT_CALL(mock, RewindWrite).WillOnce(testing::Return(false));
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
 * @tc.name: ReleaseHandleTest004
 * @tc.desc: Verify the ReleaseHandle function
 * When WriteUint32 function return true, When RewindWrite function return true
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, ReleaseHandleTest004, TestSize.Level1) {
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
    EXPECT_CALL(mock, RewindWrite).WillOnce(testing::Return(false));
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
    EXPECT_CALL(mock, RewindWrite).WillOnce(testing::Return(false));
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
    EXPECT_CALL(mock, IsDriverAlive).WillRepeatedly(testing::Return(true));
    bool ret = binderInvoker.AddDeathRecipient(handle, cookie);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: AddDeathRecipientTest005
 * @tc.desc: Verify the AddDeathRecipient function
 * When WriteInt32 function return true, When WritePointer function return true
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, AddDeathRecipientTest005, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    int32_t handle = TEST_HANDLE;
    void *cookie = nullptr;

    EXPECT_CALL(mock, GetWritePosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, WriteInt32).Times(EXECUTE_TWICE)
        .WillOnce(testing::Return(true))
        .WillOnce(testing::Return(true));
    EXPECT_CALL(mock, WritePointer).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, IsDriverAlive).WillRepeatedly(testing::Return(false));
    bool ret = binderInvoker.AddDeathRecipient(handle, cookie);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: AddDeathRecipientTest006
 * @tc.desc: Verify the AddDeathRecipient function When RewindWrite function return true
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, AddDeathRecipientTest006, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    int32_t handle = TEST_HANDLE;
    void *cookie = nullptr;

    EXPECT_CALL(mock, GetWritePosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, WriteInt32)
        .Times(EXECUTE_TWICE)
        .WillOnce(testing::Return(true))
        .WillOnce(testing::Return(false));
    EXPECT_CALL(mock, RewindWrite).WillOnce(testing::Return(true));
    bool ret = binderInvoker.AddDeathRecipient(handle, cookie);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: AddDeathRecipientTest007
 * @tc.desc: Verify the AddDeathRecipient function when WritePointer function return false
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, AddDeathRecipientTest007, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    int32_t handle = TEST_HANDLE;
    void *cookie = nullptr;

    EXPECT_CALL(mock, GetWritePosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, WriteInt32)
        .Times(EXECUTE_TWICE)
        .WillOnce(testing::Return(true))
        .WillOnce(testing::Return(true));
    EXPECT_CALL(mock, WritePointer).WillOnce(testing::Return(false));
    EXPECT_CALL(mock, RewindWrite).WillOnce(testing::Return(true));
    bool ret = binderInvoker.AddDeathRecipient(handle, cookie);
    EXPECT_FALSE(ret);
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
    EXPECT_CALL(mock, RewindWrite).WillOnce(testing::Return(false));
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
    EXPECT_CALL(mock, RewindWrite).WillOnce(testing::Return(false));
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
    EXPECT_CALL(mock, IsDriverAlive).WillRepeatedly(testing::Return(true));
    bool ret = binderInvoker.RemoveDeathRecipient(handle, cookie);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: RemoveDeathRecipientTest005
 * @tc.desc: Verify the RemoveDeathRecipient function When WritePointer function return true
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, RemoveDeathRecipientTest005, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    int32_t handle = TEST_HANDLE;
    void *cookie = nullptr;

    EXPECT_CALL(mock, GetWritePosition()).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, WriteInt32).Times(EXECUTE_TWICE)
        .WillOnce(testing::Return(true))
        .WillOnce(testing::Return(true));
    EXPECT_CALL(mock, WritePointer).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, IsDriverAlive).WillRepeatedly(testing::Return(false));
    bool ret = binderInvoker.RemoveDeathRecipient(handle, cookie);
    EXPECT_FALSE(ret);
}

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
 * @tc.name: UnFlattenDBinderObjectTest002
 * @tc.desc: Verify the UnFlattenDBinderObject function When RewindRead function return false
 * @tc.type: FUNC
 */
#ifndef CONFIG_IPC_SINGLE
HWTEST_F(BinderInvokerTest, UnFlattenDBinderObjectTest002, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    dbinder_negotiation_data dbinderData;
    Parcel parcel;

    binder_object_header hdr{};
    hdr.type = BINDER_TYPE_BINDER;
    uint8_t *buffer = (uint8_t *)&hdr;

    EXPECT_CALL(mock, GetReadPosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, ReadBuffer).WillOnce(testing::Return(buffer));
    EXPECT_CALL(mock, RewindRead).WillOnce(testing::Return(false));
    bool ret = binderInvoker.UnFlattenDBinderObject(parcel, dbinderData);
    EXPECT_FALSE(ret);
}
#endif

/**
 * @tc.name: UnFlattenDBinderObjectTest003
 * @tc.desc: Verify the UnFlattenDBinderObject function When ReadBuffer function return null
 * @tc.type: FUNC
 */
#ifndef CONFIG_IPC_SINGLE
HWTEST_F(BinderInvokerTest, UnFlattenDBinderObjectTest003, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    dbinder_negotiation_data dbinderData;
    Parcel parcel;

    binder_object_header hdr{};
    hdr.type = BINDER_TYPE_PTR;
    uint8_t *buffer = (uint8_t *)&hdr;

    EXPECT_CALL(mock, GetReadPosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, ReadBuffer)
        .WillOnce(testing::Return(buffer))
        .WillOnce(testing::Return(nullptr));
    EXPECT_CALL(mock, RewindRead).WillOnce(testing::Return(false));
    bool ret = binderInvoker.UnFlattenDBinderObject(parcel, dbinderData);
    EXPECT_FALSE(ret);
}
#endif

/**
 * @tc.name: UnFlattenDBinderObjectTest004
 * @tc.desc: Verify the UnFlattenDBinderObject function When flags is BINDER_BUFFER_FLAG_HAS_PARENT
 * @tc.type: FUNC
 */
#ifndef CONFIG_IPC_SINGLE
HWTEST_F(BinderInvokerTest, UnFlattenDBinderObjectTest004, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    dbinder_negotiation_data dbinderData;
    Parcel parcel;

    binder_object_header hdr{};
    hdr.type = BINDER_TYPE_PTR;
    uint8_t *buffer = (uint8_t *)&hdr;

    binder_buffer_object obj{};
    obj.flags = BINDER_BUFFER_FLAG_HAS_PARENT;
    obj.length = sizeof(dbinder_negotiation_data);
    uint8_t *buffer2 = (uint8_t *)&obj;

    EXPECT_CALL(mock, GetReadPosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, ReadBuffer)
        .WillOnce(testing::Return(buffer))
        .WillOnce(testing::Return(buffer2));
    EXPECT_CALL(mock, RewindRead).WillRepeatedly(testing::Return(0));
    bool ret = binderInvoker.UnFlattenDBinderObject(parcel, dbinderData);
    EXPECT_FALSE(ret);
}
#endif

/**
 * @tc.name: UnFlattenDBinderObjectTest005
 * @tc.desc: Verify the UnFlattenDBinderObject function When flags is BINDER_BUFFER_FLAG_HAS_DBINDER
 * @tc.type: FUNC
 */
#ifndef CONFIG_IPC_SINGLE
HWTEST_F(BinderInvokerTest, UnFlattenDBinderObjectTest005, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    dbinder_negotiation_data dbinderData;
    Parcel parcel;

    binder_object_header hdr{};
    hdr.type = BINDER_TYPE_PTR;
    uint8_t *buffer = (uint8_t *)&hdr;

    binder_buffer_object obj{};
    obj.flags = BINDER_BUFFER_FLAG_HAS_DBINDER;
    obj.length = sizeof(dbinder_negotiation_data) + 1;
    uint8_t *buffer2 = (uint8_t *)&obj;

    EXPECT_CALL(mock, GetReadPosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, ReadBuffer)
        .WillOnce(testing::Return(buffer))
        .WillOnce(testing::Return(buffer2));
    EXPECT_CALL(mock, RewindRead).WillRepeatedly(testing::Return(0));
    bool ret = binderInvoker.UnFlattenDBinderObject(parcel, dbinderData);
    EXPECT_FALSE(ret);
}
#endif

/**
 * @tc.name: UnFlattenDBinderObjectTest006
 * @tc.desc: Verify the UnFlattenDBinderObject function return true
 * @tc.type: FUNC
 */
#ifndef CONFIG_IPC_SINGLE
HWTEST_F(BinderInvokerTest, UnFlattenDBinderObjectTest006, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    dbinder_negotiation_data dbinderData;
    dbinder_negotiation_data validDbinderData_;
    Parcel parcel;

    binder_object_header hdr{};
    hdr.type = BINDER_TYPE_PTR;
    uint8_t *buffer = (uint8_t *)&hdr;

    binder_buffer_object obj{};
    obj.flags = BINDER_BUFFER_FLAG_HAS_DBINDER;
    obj.length = sizeof(dbinder_negotiation_data);
    obj.buffer = reinterpret_cast<binder_uintptr_t>(&validDbinderData_);
    uint8_t *buffer2 = (uint8_t *)&obj;

    EXPECT_CALL(mock, GetReadPosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, ReadBuffer)
        .WillOnce(testing::Return(buffer))
        .WillOnce(testing::Return(buffer2));
    EXPECT_CALL(mock, RewindRead).WillRepeatedly(testing::Return(false));
    bool ret = binderInvoker.UnFlattenDBinderObject(parcel, dbinderData);
    EXPECT_TRUE(ret);
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
 * @tc.name: OnAcquireObjectTest002
 * @tc.desc: Verify the OnAcquireObject function
 * When the ReadPointer function returns 0 for the first time and 1 for the second time
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, OnAcquireObjectTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    uint32_t cmd = TEST_HANDLE;

    EXPECT_CALL(mock, ReadPointer)
        .WillOnce(testing::Return(0))
        .WillOnce(testing::Return(1));
    ASSERT_NO_FATAL_FAILURE(binderInvoker.OnAcquireObject(cmd));
}

/**
 * @tc.name: OnAcquireObjectTest003
 * @tc.desc: Verify the OnAcquireObject function when current->validObjectRecord_ is empty
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, OnAcquireObjectTest003, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    uint32_t cmd = TEST_HANDLE;

    ProcessSkeleton *current = ProcessSkeleton::GetInstance();
    current->validObjectRecord_.clear();

    EXPECT_CALL(mock, ReadPointer)
        .WillOnce(testing::Return(1))
        .WillOnce(testing::Return(1));
    ASSERT_NO_FATAL_FAILURE(binderInvoker.OnAcquireObject(cmd));
}

/**
 * @tc.name: OnAcquireObjectTest004
 * @tc.desc: Verify the OnAcquireObject function when GetSptrRefCount function return 0
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, OnAcquireObjectTest004, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    uint32_t cmd = TEST_HANDLE;

    ProcessSkeleton *current = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(current != nullptr);
    std::u16string str(DESCRIPTOR_TEST);
    RefCounter refs;
    IPCObjectStub object;
    uintptr_t refsPointer = reinterpret_cast<uintptr_t>(&refs);
    uintptr_t objectPointer = reinterpret_cast<uintptr_t>(&object);
    current->AttachValidObject(&object, str);

    EXPECT_CALL(mock, ReadPointer)
        .WillOnce(testing::Return(refsPointer))
        .WillOnce(testing::Return(objectPointer));
    EXPECT_CALL(mock, IsValidObject).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, GetSptrRefCount).WillRepeatedly(testing::Return(0));

    ASSERT_NO_FATAL_FAILURE(binderInvoker.OnAcquireObject(cmd));
    current->validObjectRecord_.clear();
}

/**
 * @tc.name: OnAcquireObjectTest005
 * @tc.desc: Verify the OnAcquireObject function WriteInt32 function return false
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, OnAcquireObjectTest005, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    uint32_t cmd = TEST_HANDLE;
    ProcessSkeleton *current = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(current != nullptr);
    std::u16string str(DESCRIPTOR_TEST);
    RefCounter refs;
    IPCObjectStub object;
    uintptr_t refsPointer = reinterpret_cast<uintptr_t>(&refs);
    uintptr_t objectPointer = reinterpret_cast<uintptr_t>(&object);
    current->AttachValidObject(&object, str);

    EXPECT_CALL(mock, ReadPointer)
        .WillOnce(testing::Return(refsPointer))
        .WillOnce(testing::Return(objectPointer));
    EXPECT_CALL(mock, IsValidObject).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, GetSptrRefCount).WillRepeatedly(testing::Return(1));
    EXPECT_CALL(mock, WriteInt32).WillRepeatedly(testing::Return(false));
    ASSERT_NO_FATAL_FAILURE(binderInvoker.OnAcquireObject(cmd));
    current->validObjectRecord_.clear();
}

/**
 * @tc.name: OnAcquireObjectTest006 When WriteInt32 function return true
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, OnAcquireObjectTest006, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    uint32_t cmd = BR_ACQUIRE;

    ProcessSkeleton *current = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(current != nullptr);
    std::u16string str(DESCRIPTOR_TEST);
    RefCounter refs;
    IPCObjectStub object;
    uintptr_t refsPointer = reinterpret_cast<uintptr_t>(&refs);
    uintptr_t objectPointer = reinterpret_cast<uintptr_t>(&object);
    current->AttachValidObject(&object, str);

    EXPECT_CALL(mock, ReadPointer)
        .WillOnce(testing::Return(refsPointer))
        .WillOnce(testing::Return(objectPointer));
    EXPECT_CALL(mock, IsValidObject).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, GetSptrRefCount).WillRepeatedly(testing::Return(1));
    EXPECT_CALL(mock, WriteInt32).WillRepeatedly(testing::Return(true));
    ASSERT_NO_FATAL_FAILURE(binderInvoker.OnAcquireObject(cmd));
    current->validObjectRecord_.clear();
}

/**
 * @tc.name: OnAcquireObjectTest007
 * @tc.desc: Verify the OnAcquireObject function When RewindWrite function return false
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, OnAcquireObjectTest007, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    uint32_t cmd = BR_ACQUIRE;

    ProcessSkeleton *current = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(current != nullptr);
    std::u16string str(DESCRIPTOR_TEST);
    RefCounter refs;
    IPCObjectStub object;
    uintptr_t refsPointer = reinterpret_cast<uintptr_t>(&refs);
    uintptr_t objectPointer = reinterpret_cast<uintptr_t>(&object);
    current->AttachValidObject(&object, str);

    EXPECT_CALL(mock, ReadPointer)
        .WillOnce(testing::Return(refsPointer))
        .WillOnce(testing::Return(objectPointer));
    EXPECT_CALL(mock, IsValidObject).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, GetSptrRefCount).WillRepeatedly(testing::Return(1));
    EXPECT_CALL(mock, WriteInt32).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, WritePointer).WillRepeatedly(testing::Return(false));
    EXPECT_CALL(mock, RewindWrite).WillRepeatedly(testing::Return(false));
    ASSERT_NO_FATAL_FAILURE(binderInvoker.OnAcquireObject(cmd));
    current->validObjectRecord_.clear();
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
 * @tc.desc: Override SetCallingIdentity function when identity is invalid value
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, SetCallingIdentityTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    std::string identity = IDENTITY_TEST_INVALID;
    bool result = binderInvoker.SetCallingIdentity(identity, true);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SetCallingIdentityTest003
 * @tc.desc: Override SetCallingIdentity function when identity is valid value
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, SetCallingIdentityTest003, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    std::string identity = IDENTITY_TEST;
    bool result = binderInvoker.SetCallingIdentity(identity, true);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SetCallingIdentityTest004
 * @tc.desc: Override SetCallingIdentity function when GetSubStr function return false
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, SetCallingIdentityTest004, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    std::string identity = STR_TEST;
    NiceMock<BinderInvokerInterfaceMock> mock;

    EXPECT_CALL(mock, GetSubStr).WillRepeatedly(testing::Return(false));
    bool result = binderInvoker.SetCallingIdentity(identity, true);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SetCallingIdentityTest005
 * @tc.desc: Override SetCallingIdentity function when GetUint64ValueByStrSlice function return false
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, SetCallingIdentityTest005, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    std::string identity = STR_TEST_ONE;
    NiceMock<BinderInvokerInterfaceMock> mock;

    EXPECT_CALL(mock, GetSubStr).WillRepeatedly(testing::Return(true));
    bool result = binderInvoker.SetCallingIdentity(identity, true);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SetCallingIdentityTest006
 * @tc.desc: Override SetCallingIdentity function when GetCallerRealPidByStr function return false
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, SetCallingIdentityTest006, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    std::string identity = STR_TEST_TWO;
    NiceMock<BinderInvokerInterfaceMock> mock;

    EXPECT_CALL(mock, GetSubStr).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, StrToUint64).WillRepeatedly(testing::Return(true));
    bool result = binderInvoker.SetCallingIdentity(identity, true);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SetCallingIdentityTest007
 * @tc.desc: Override SetCallingIdentity function when GetCallerPidAndUidByStr function return false
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, SetCallingIdentityTest007, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    std::string identity = STR_TEST_THREE;
    NiceMock<BinderInvokerInterfaceMock> mock;

    EXPECT_CALL(mock, GetSubStr).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, StrToUint64).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, StrToInt32).WillRepeatedly(testing::Return(true));
    bool result = binderInvoker.SetCallingIdentity(identity, true);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SetCallingIdentityTest008
 * @tc.desc: Override SetCallingIdentity function when true
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, SetCallingIdentityTest008, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    std::string identity = STR_TEST;
    NiceMock<BinderInvokerInterfaceMock> mock;

    EXPECT_CALL(mock, GetSubStr).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, StrToUint64).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, StrToInt32).WillRepeatedly(testing::Return(true));
    bool result = binderInvoker.SetCallingIdentity(identity, true);
    EXPECT_TRUE(result);
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
 * @tc.name: TriggerSystemIPCThreadReclaimTest002
 * @tc.desc: Verify the TriggerSystemIPCThreadReclaim function When IsDriverAlive is false
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, TriggerSystemIPCThreadReclaimTest002, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;

    EXPECT_CALL(mock, IsDriverAlive).WillRepeatedly(testing::Return(false));

    bool result = binderInvoker.TriggerSystemIPCThreadReclaim();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: TriggerSystemIPCThreadReclaimTest003
 * @tc.desc: Verify the TriggerSystemIPCThreadReclaim function When WriteBinder return ERR_INVALID_DATA
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, TriggerSystemIPCThreadReclaimTest003, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;

    EXPECT_CALL(mock, IsDriverAlive).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, WriteBinder).WillRepeatedly(testing::Return(ERR_INVALID_DATA));

    bool result = binderInvoker.TriggerSystemIPCThreadReclaim();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: TriggerSystemIPCThreadReclaimTest004
 * @tc.desc: Verify the TriggerSystemIPCThreadReclaim function When WriteBinder return ERR_NONE
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, TriggerSystemIPCThreadReclaimTest004, TestSize.Level1) {
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;

    EXPECT_CALL(mock, IsDriverAlive).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, WriteBinder).WillRepeatedly(testing::Return(ERR_NONE));

    bool result = binderInvoker.TriggerSystemIPCThreadReclaim();
    EXPECT_TRUE(result);
}

/**
 * @tc.name: EnableIPCThreadReclaimTest001
 * @tc.desc: Override EnableIPCThreadReclaim function when binderConnector_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, EnableIPCThreadReclaimTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.binderConnector_ = nullptr;

    bool result = binderInvoker.EnableIPCThreadReclaim(true);
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
    std::string str = STR_TEST;
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
 * @tc.name: GetUint64ValueByStrSliceTest003
 * @tc.desc: cover GetUint64ValueByStrSlice function when StrToUint64 function return false
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetUint64ValueByStrSliceTest003, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    std::string str = STR_TEST;
    size_t offset = 2;
    size_t length = 1;
    uint64_t value = 0;
    NiceMock<BinderInvokerInterfaceMock> mock;

    EXPECT_CALL(mock, GetSubStr).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, StrToUint64).WillRepeatedly(testing::Return(false));
    bool ret = binderInvoker.GetUint64ValueByStrSlice(str, offset, length, value);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: GetUint64ValueByStrSliceTest004
 * @tc.desc: cover GetUint64ValueByStrSlice function when StrToUint64 function return true
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetUint64ValueByStrSliceTest004, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    std::string str = STR_TEST;
    size_t offset = 2;
    size_t length = 1;
    uint64_t value = 0;
    NiceMock<BinderInvokerInterfaceMock> mock;

    EXPECT_CALL(mock, GetSubStr).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, StrToUint64).WillRepeatedly(testing::Return(true));
    bool ret = binderInvoker.GetUint64ValueByStrSlice(str, offset, length, value);
    EXPECT_TRUE(ret);
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
    std::string str = STR_TEST;
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
    std::string str = STR_TEST;
    size_t offset = str.length() + 1;
    pid_t pid = 0;
    pid_t uid = 0;
    bool ret = binderInvoker.GetCallerPidAndUidByStr(str, offset, pid, uid);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: UnflattenObjectTest001
 * @tc.desc: Verify the UnflattenObject function when CheckOffsets function return false
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

/**
 * @tc.name: UnflattenObjectTest002
 * @tc.desc: Verify the UnflattenObject function when ReadBuffer function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, UnflattenObjectTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    Parcel parcel;
    NiceMock<BinderInvokerInterfaceMock> mock;

    EXPECT_CALL(mock, CheckOffsets).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, ReadBuffer).WillRepeatedly(testing::Return(nullptr));

    sptr<IRemoteObject> ret = binderInvoker.UnflattenObject(parcel);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: UnflattenObjectTest003
 * @tc.desc: Verify the UnflattenObject function when current->instance_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, UnflattenObjectTest003, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    Parcel parcel;
    parcel.SetDataSize(100);
    NiceMock<BinderInvokerInterfaceMock> mock;
    flat_binder_object tr {};
    tr.flags = 1;
    tr.hdr.type = -1;
    uint8_t *buffer = (uint8_t *)&tr;

    EXPECT_CALL(mock, CheckOffsets).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, ReadBuffer).WillRepeatedly(testing::Return(buffer));

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->instance_ = nullptr;
    current->exitFlag_ = true;

    sptr<IRemoteObject> ret = binderInvoker.UnflattenObject(parcel);
    EXPECT_EQ(ret, nullptr);
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: GetSAMgrObjectTest001
 * @tc.desc: Verify the GetSAMgrObject function when current->instance_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetSAMgrObjectTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->instance_ = nullptr;
    current->exitFlag_ = true;

    auto ret = binderInvoker.GetSAMgrObject();
    EXPECT_EQ(ret, nullptr);
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: GetSAMgrObjectTest002
 * @tc.desc: Verify the GetSAMgrObject function when GetRegistryObject function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetSAMgrObjectTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;

    EXPECT_CALL(mock, GetRegistryObject).WillOnce(testing::Return(nullptr));

    auto ret = binderInvoker.GetSAMgrObject();
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: GetSAMgrObjectTest003
 * @tc.desc: Verify the GetSAMgrObject function when GetRegistryObject function return valid value
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetSAMgrObjectTest003, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    sptr<IRemoteObject> testStub = new IPCObjectStub(DESCRIPTOR_TEST);

    EXPECT_CALL(mock, GetRegistryObject).WillOnce(testing::Return(testStub));

    auto ret = binderInvoker.GetSAMgrObject();
    EXPECT_EQ(ret, testStub);
}

/**
 * @tc.name: WriteTransactionTest001
 * @tc.desc: Verify the WriteTransaction function when WriteInt32 function return true
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, WriteTransactionTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    int cmd = 1;
    uint32_t flags = 0;
    int32_t handle = TEST_HANDLE;
    uint32_t code = 456;
    const int32_t* status = nullptr;
    size_t totalDBinderBufSize = 1024;
    MessageParcel data;
    data.SetDataSize(100);
    data.objectCursor_ = 10;

    NiceMock<BinderInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, WriteInt32).WillRepeatedly(testing::Return(true));

    bool result = binderInvoker.WriteTransaction(cmd, flags, handle, code, data, status, totalDBinderBufSize);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: WriteTransactionTest002
 * @tc.desc: Verify the WriteTransaction function when WriteInt32 function return false
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, WriteTransactionTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    int cmd = 1;
    uint32_t flags = 0;
    int32_t handle = TEST_HANDLE;
    uint32_t code = 456;
    const int32_t* status = nullptr;
    size_t totalDBinderBufSize = 1024;
    MessageParcel data;
    data.SetDataSize(100);
    data.objectCursor_ = 10;

    NiceMock<BinderInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, WriteInt32).WillRepeatedly(testing::Return(false));

    bool result = binderInvoker.WriteTransaction(cmd, flags, handle, code, data, status, totalDBinderBufSize);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SamgrServiceSendRequestTest001
 * @tc.desc: Verify the SamgrServiceSendRequest function when GetRegistryObject function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, SamgrServiceSendRequestTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binder_transaction_data tr;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<BinderInvokerInterfaceMock> mock;

    EXPECT_CALL(mock, GetRegistryObject).WillRepeatedly(testing::Return(nullptr));

    int32_t result = binderInvoker.SamgrServiceSendRequest(tr, data, reply, option);
    EXPECT_EQ(result, ERR_DEAD_OBJECT);
}

/**
 * @tc.name: SamgrServiceSendRequestTest002
 * @tc.desc: Verify the SamgrServiceSendRequest function when GetRegistryObject function return not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, SamgrServiceSendRequestTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binder_transaction_data tr;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<BinderInvokerInterfaceMock> mock;
    sptr<IRemoteObject> testStub = new IPCObjectStub(DESCRIPTOR_TEST);

    EXPECT_CALL(mock, GetRegistryObject).WillRepeatedly(testing::Return(testStub));

    int32_t result = binderInvoker.SamgrServiceSendRequest(tr, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: FreeBufferTest001
 * @tc.desc: Verify the FreeBuffer function when WriteUint32 function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, FreeBufferTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    void* data = nullptr;
    NiceMock<BinderInvokerInterfaceMock> mock;

    EXPECT_CALL(mock, GetWritePosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, WriteUint32).WillOnce(testing::Return(false));

    ASSERT_NO_FATAL_FAILURE(binderInvoker.FreeBuffer(data));
}

/**
 * @tc.name: FreeBufferTest002
 * @tc.desc: Verify the FreeBuffer function when RewindWrite function return false
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, FreeBufferTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    void* data = nullptr;
    NiceMock<BinderInvokerInterfaceMock> mock;

    EXPECT_CALL(mock, GetWritePosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, WriteUint32).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, WritePointer).WillOnce(testing::Return(false));
    EXPECT_CALL(mock, RewindWrite).WillOnce(testing::Return(false));

    ASSERT_NO_FATAL_FAILURE(binderInvoker.FreeBuffer(data));
}

/**
 * @tc.name: FreeBufferTest003
 * @tc.desc: Verify the FreeBuffer function when RewindWrite function return true and binderConnector_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, FreeBufferTest003, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.binderConnector_ = nullptr;
    void *data = nullptr;
    NiceMock<BinderInvokerInterfaceMock> mock;

    EXPECT_CALL(mock, GetWritePosition).Times(EXECUTE_ONCE);
    EXPECT_CALL(mock, WriteUint32).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, WritePointer).WillOnce(testing::Return(false));
    EXPECT_CALL(mock, RewindWrite).WillOnce(testing::Return(true));

    ASSERT_NO_FATAL_FAILURE(binderInvoker.FreeBuffer(data));
}

/**
 * @tc.name: GetCallerPidTest001
 * @tc.desc: Verify the FreeBuffer function when callerPid_ is 1
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetCallerPidTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.callerPid_ = PID_TEST;
    binderInvoker.status_ = true;
    EXPECT_EQ(binderInvoker.GetCallerPid(), PID_TEST);
}

/**
 * @tc.name: GetCallerPidTest002
 * @tc.desc: Verify the FreeBuffer function when status_ is true and invokerInfo_.pid is 0
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetCallerPidTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.callerPid_ = PID_TEST;
    binderInvoker.status_ = true;
    binderInvoker.invokerInfo_.pid = PID_TEST_INVALID;
    EXPECT_EQ(binderInvoker.GetCallerPid(), PID_TEST);
}

/**
 * @tc.name: GetCallerPidTest003
 * @tc.desc: Verify the FreeBuffer function when status_ is false and invokerInfo_.pid is 0
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetCallerPidTest003, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.callerPid_ = PID_TEST;
    binderInvoker.status_ = false;
    binderInvoker.invokerInfo_.pid = PID_TEST_INVALID;
    EXPECT_EQ(binderInvoker.GetCallerPid(), PID_TEST_INVALID);
}

/**
 * @tc.name: GetCallerSidTest001
 * @tc.desc: Verify the GetCallerSid function when callerPid_ is 1
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetCallerSidTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.callerSid_ = CALLER_SID_TEST;
    EXPECT_EQ(binderInvoker.GetCallerSid(), CALLER_SID_TEST);
}

/**
 * @tc.name: GetCallerSidTest002
 * @tc.desc: Verify the GetCallerSid function when status_ is true and invokerInfo_.pid is 0
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetCallerSidTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.callerSid_ = CALLER_SID_TEST;
    binderInvoker.status_ = true;
    binderInvoker.invokerInfo_.pid = PID_TEST_INVALID;
    binderInvoker.invokerInfo_.sid = SID_TEST;
    EXPECT_EQ(binderInvoker.GetCallerSid(), CALLER_SID_TEST);
}

/**
 * @tc.name: GetCallerSidTest003
 * @tc.desc: Verify the GetCallerSid function when status_ is false and invokerInfo_.sid is SID_TEST
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetCallerSidTest003, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.callerSid_ = CALLER_SID_TEST;
    binderInvoker.status_ = false;
    binderInvoker.invokerInfo_.pid = PID_TEST_INVALID;
    binderInvoker.invokerInfo_.sid = SID_TEST;
    EXPECT_EQ(binderInvoker.GetCallerSid(), SID_TEST);
}

/**
 * @tc.name: GetCallerRealPidTest001
 * @tc.desc: Verify the GetCallerRealPid function when callerRealPid_ is 1
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetCallerRealPidTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.callerRealPid_ = PID_TEST;
    binderInvoker.status_ = true;
    EXPECT_EQ(binderInvoker.GetCallerRealPid(), PID_TEST);
}

/**
 * @tc.name: GetCallerRealPidTest002
 * @tc.desc: Verify the GetCallerRealPid function when status_ is true and invokerInfo_.pid is 0
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetCallerRealPidTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.callerRealPid_ = PID_TEST;
    binderInvoker.status_ = true;
    binderInvoker.invokerInfo_.pid = PID_TEST_INVALID;
    binderInvoker.invokerInfo_.realPid = PID_TEST_INVALID;
    EXPECT_EQ(binderInvoker.GetCallerRealPid(), 1);
}

/**
 * @tc.name: GetCallerRealPidTest003
 * @tc.desc: Verify the GetCallerRealPid function when status_ is false and invokerInfo_.realPid is 0
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetCallerRealPidTest003, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.callerRealPid_ = PID_TEST;
    binderInvoker.status_ = false;
    binderInvoker.invokerInfo_.pid = PID_TEST_INVALID;
    binderInvoker.invokerInfo_.realPid = PID_TEST_INVALID;
    EXPECT_EQ(binderInvoker.GetCallerRealPid(), PID_TEST_INVALID);
}

/**
 * @tc.name: GetCallerUidTest001
 * @tc.desc: Verify the GetCallerUid function when callerUid_ is 1
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetCallerUidTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.callerUid_ = UID_TEST;
    binderInvoker.status_ = true;
    EXPECT_EQ(binderInvoker.GetCallerUid(), 1);
}

/**
 * @tc.name: GetCallerUidTest002
 * @tc.desc: Verify the GetCallerUid function when status_ is true and invokerInfo_.pid is 0
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetCallerUidTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.callerUid_ = UID_TEST;
    binderInvoker.status_ = true;
    binderInvoker.invokerInfo_.pid = PID_TEST_INVALID;
    binderInvoker.invokerInfo_.uid = UID_INVALID_TEST;
    EXPECT_EQ(binderInvoker.GetCallerUid(), 1);
}

/**
 * @tc.name: GetCallerUidTest003
 * @tc.desc: Verify the GetCallerRealPid function when status_ is false and invokerInfo_.realPid is 0
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetCallerUidTest003, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.callerUid_ = UID_TEST;
    binderInvoker.status_ = false;
    binderInvoker.invokerInfo_.pid = PID_TEST_INVALID;
    binderInvoker.invokerInfo_.uid = UID_INVALID_TEST;
    EXPECT_EQ(binderInvoker.GetCallerUid(), PID_TEST_INVALID);
}

/**
 * @tc.name: GetCallerTokenIDTest001
 * @tc.desc: Verify the GetCallerTokenID function when callerUid_ is 1 and callerTokenID_ is 0
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetCallerTokenIDTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.callerUid_ = UID_TEST;
    binderInvoker.callerTokenID_ = TOKEN_ID_INVALID_TEST;
    binderInvoker.status_ = true;
    EXPECT_EQ(binderInvoker.GetCallerTokenID(), 1);
}

/**
 * @tc.name: GetCallerTokenIDTest002
 * @tc.desc: Verify the GetCallerTokenID function when callerUid_ is 0 and callerTokenID_ is 1
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetCallerTokenIDTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.callerUid_ = UID_INVALID_TEST;
    binderInvoker.callerTokenID_ = TOKEN_ID_TEST;
    binderInvoker.status_ = true;
    EXPECT_EQ(binderInvoker.GetCallerTokenID(), TOKEN_ID_TEST);
}

/**
 * @tc.name: GetCallerTokenIDTest003
 * @tc.desc: Verify the GetCallerTokenID function when status_ is false and tokenId is 0
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetCallerTokenIDTest003, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.callerUid_ = UID_INVALID_TEST;
    binderInvoker.callerTokenID_ = TOKEN_ID_TEST;
    binderInvoker.status_ = false;
    binderInvoker.invokerInfo_.uid = UID_TEST;
    binderInvoker.invokerInfo_.tokenId = TOKEN_ID_INVALID_TEST;
    binderInvoker.invokerInfo_.pid = PID_TEST_INVALID;
    EXPECT_EQ(binderInvoker.GetCallerTokenID(), TOKEN_ID_TEST);
}

/**
 * @tc.name: GetCallerTokenIDTest004
 * @tc.desc: Verify the GetCallerTokenID function when status_ is false and tokenId is 1
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetCallerTokenIDTest004, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.callerUid_ = UID_INVALID_TEST;
    binderInvoker.callerTokenID_ = TOKEN_ID_TEST;
    binderInvoker.status_ = false;
    binderInvoker.invokerInfo_.uid = UID_TEST;
    binderInvoker.invokerInfo_.tokenId = TOKEN_ID_TEST;
    binderInvoker.invokerInfo_.pid = PID_TEST_INVALID;
    EXPECT_EQ(binderInvoker.GetCallerTokenID(), TOKEN_ID_TEST);
}

/**
 * @tc.name: GetFirstCallerTokenIDTest001
 * @tc.desc: Verify the GetFirstCallerTokenID function when firstTokenID_ is 1
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetFirstCallerTokenIDTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.firstTokenID_ = TOKEN_ID_TEST;
    binderInvoker.status_ = true;
    EXPECT_EQ(binderInvoker.GetFirstCallerTokenID(), TOKEN_ID_TEST);
}

/**
 * @tc.name: GetFirstCallerTokenIDTest002
 * @tc.desc: Verify the GetFirstCallerTokenID function when status_ is false and pid is 0
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetFirstCallerTokenIDTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.firstTokenID_ = TOKEN_ID_TEST;
    binderInvoker.status_ = false;
    binderInvoker.invokerInfo_.pid = PID_TEST_INVALID;
    binderInvoker.invokerInfo_.firstTokenId = FIRST_TOKEN_ID_TEST;
    EXPECT_EQ(binderInvoker.GetFirstCallerTokenID(), FIRST_TOKEN_ID_TEST);
}

/**
 * @tc.name: GetFirstCallerTokenIDTest003
 * @tc.desc: Verify the GetFirstCallerTokenID function when status_ is true and pid is 0
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, GetFirstCallerTokenIDTest003, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.firstTokenID_ = TOKEN_ID_TEST;
    binderInvoker.status_ = true;
    binderInvoker.invokerInfo_.pid = PID_TEST_INVALID;
    EXPECT_EQ(binderInvoker.GetFirstCallerTokenID(), TOKEN_ID_TEST);
}

/**
 * @tc.name: UpdateConsumedDataTest001
 * @tc.desc: Verify the UpdateConsumedData function when bwr.write_consumed > output_.GetDataSize()
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, UpdateConsumedDataTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.sendNestCount_ = 3;
    binder_write_read bwr = {};
    bwr.write_consumed = 1;
    bwr.read_consumed = 1;
    size_t outAvail = 3;
    NiceMock<BinderInvokerInterfaceMock> mock;

    EXPECT_CALL(mock, GetDataSize).WillRepeatedly(testing::Return(0));

    ASSERT_NO_FATAL_FAILURE(binderInvoker.UpdateConsumedData(bwr, outAvail));
}

/**
 * @tc.name: UpdateConsumedDataTest002
 * @tc.desc: Verify the UpdateConsumedData function when bwr.write_consumed is 0
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerTest, UpdateConsumedDataTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.sendNestCount_ = 3;
    binder_write_read bwr = {};
    bwr.write_consumed = 0;
    bwr.read_consumed = 1;
    size_t outAvail = 3;
    NiceMock<BinderInvokerInterfaceMock> mock;

    EXPECT_CALL(mock, RewindRead).WillRepeatedly(testing::Return(0));

    ASSERT_NO_FATAL_FAILURE(binderInvoker.UpdateConsumedData(bwr, outAvail));
}

#ifndef __linux__
/**
 * @tc.name: GetDetailedErrorInfoTest001
 * @tc.desc: Verify the GetDetailedErrorInfo function when WriteBinder return ERR_NONE
 * @tc.type: FUNCw
 */
HWTEST_F(BinderInvokerTest, GetDetailedErrorInfoTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    uint32_t errorCode = BR_FAILED_REPLY;
    std::string errDesc = "errDesc";

    EXPECT_CALL(mock, WriteBinder).WillOnce(testing::Return(ERR_NONE));

    bool result = binderInvoker.GetDetailedErrorInfo(errorCode, errDesc);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: GetDetailedErrorInfoTest002
 * @tc.desc: Verify the GetDetailedErrorInfo function when WriteBinder return ERR_INVALID_DATA
 */
HWTEST_F(BinderInvokerTest, GetDetailedErrorInfoTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    uint32_t errorCode = BR_FAILED_REPLY;
    std::string errDesc = "errDesc";

    EXPECT_CALL(mock, WriteBinder).WillOnce(testing::Return(ERR_INVALID_DATA));

    bool result = binderInvoker.GetDetailedErrorInfo(errorCode, errDesc);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: GetDetailedErrorInfoTest003
 * @tc.desc: Verify the GetDetailedErrorInfo function when str is not end with '\0'
 * @tc.type: FUNCw
 */
HWTEST_F(BinderInvokerTest, GetDetailedErrorInfoTest003, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    uint32_t errorCode = BR_FAILED_REPLY;
    std::string errDesc = "errDesc";

    auto mockFunc = [](unsigned long request, void* data) -> bool {
        auto* errInfo = static_cast<hmb_detailed_err*>(data);
        errInfo->err_code = BR_FAILED_REPLY;
        memset_s(errInfo->err_str, sizeof(errInfo->err_str), 'x', sizeof(errInfo->err_str));
        return ERR_NONE;
    };
    EXPECT_CALL(mock, WriteBinder(::testing::_, ::testing::_)).WillOnce(Invoke(mockFunc));

    bool result = binderInvoker.GetDetailedErrorInfo(errorCode, errDesc);
    EXPECT_FALSE(result);
}
#endif

} // namespace OHOS