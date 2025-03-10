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

#include <algorithm>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#define private public
#include "ipc_cparcel.h"
#include "ipc_inner_object.h"
#include "ipc_error_code.h"
#include "message_parcel.h"
#undef private

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
namespace OHOS {
class IPCCparcelTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void IPCCparcelTest::SetUpTestCase()
{
}

void IPCCparcelTest::TearDownTestCase()
{
}

void IPCCparcelTest::SetUp()
{
}

void IPCCparcelTest::TearDown()
{
}

class IpcCparcelInterface {
public:
    IpcCparcelInterface() {};
    virtual ~IpcCparcelInterface() {};
    virtual bool IsIPCParcelValid(const OHIPCParcel *parcel, const char *promot) = 0;
    virtual bool WriteBuffer(const void *data, size_t size) = 0;
    virtual size_t GetReadableBytes() = 0;
    virtual const uint8_t* ReadBuffer(int32_t len) = 0;
    virtual bool WriteRemoteObject(const void* remote) = 0;
    virtual sptr<IRemoteObject> ReadRemoteObject() = 0;
    virtual int ReadFileDescriptor() = 0;
    virtual size_t GetWritePosition() = 0;
};

class IpcCparcelInterfaceMock : public IpcCparcelInterface {
public:
    IpcCparcelInterfaceMock();
    ~IpcCparcelInterfaceMock() override;
    MOCK_METHOD2(IsIPCParcelValid, bool(const OHIPCParcel *parcel, const char *promot));
    MOCK_METHOD2(WriteBuffer, bool(const void *, size_t));
    MOCK_METHOD0(GetReadableBytes, size_t());
    MOCK_METHOD1(ReadBuffer, const uint8_t*(int32_t));
    MOCK_METHOD1(WriteRemoteObject, bool(const void* remote));
    MOCK_METHOD0(ReadRemoteObject, sptr<IRemoteObject>());
    MOCK_METHOD0(ReadFileDescriptor, int());
    MOCK_METHOD0(GetWritePosition, size_t());
};

static void *g_interface = nullptr;

IpcCparcelInterfaceMock::IpcCparcelInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

IpcCparcelInterfaceMock::~IpcCparcelInterfaceMock()
{
    g_interface = nullptr;
}

static IpcCparcelInterface *GetIpcCparcelInterface()
{
    return reinterpret_cast<IpcCparcelInterface*>(g_interface);
}

extern "C" {
    bool IsIPCParcelValid(const OHIPCParcel *parcel, const char *promot)
    {
        IpcCparcelInterface* interface = GetIpcCparcelInterface();
        if (interface == nullptr) {
            return false;
        }
        return interface->IsIPCParcelValid(parcel, promot);
    }

    bool Parcel::WriteBuffer(const void *data, size_t size)
    {
        IpcCparcelInterface* interface = GetIpcCparcelInterface();
        if (interface == nullptr) {
            return false;
        }
        return interface->WriteBuffer(data, size);
    }

    size_t GetReadableBytes()
    {
        IpcCparcelInterface* interface = GetIpcCparcelInterface();
        if (interface == nullptr) {
            return 0;
        }
        return interface->GetReadableBytes();
    }

    const uint8_t* ReadBuffer(int32_t len)
    {
        IpcCparcelInterface* interface = GetIpcCparcelInterface();
        if (interface == nullptr) {
            return nullptr;
        }
        return interface->ReadBuffer(len);
    }

    bool WriteRemoteObject(const void* remote)
    {
        IpcCparcelInterface* interface = GetIpcCparcelInterface();
        if (interface == nullptr) {
            return false;
        }
        return interface->WriteRemoteObject(remote);
    }

    sptr<IRemoteObject> MessageParcel::ReadRemoteObject()
    {
        IpcCparcelInterface* interface = GetIpcCparcelInterface();
        if (interface == nullptr) {
            return nullptr;
        }
        return interface->ReadRemoteObject();
    }

    int MessageParcel::ReadFileDescriptor()
    {
        IpcCparcelInterface* interface = GetIpcCparcelInterface();
        if (interface == nullptr) {
            return 0;
        }
        return interface->ReadFileDescriptor();
    }

    size_t Parcel::GetWritePosition()
    {
        IpcCparcelInterface* interface = GetIpcCparcelInterface();
        if (interface == nullptr) {
            return 0;
        }
        return interface->GetWritePosition();
    }
}

template <typename T>
struct MockObject {
    const void* remote;
};

template <typename T>
struct MockRemoteObject {
    OHOS::sptr<OHOS::IRemoteObject> remote;
};

/**
 * @tc.name: WriteIPCRemoteObject001
 * @tc.desc: Test WriteIPCRemoteObject when IsIPCParcelValid return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCCparcelTest, WriteIPCRemoteObject001, TestSize.Level1)
{
    OHIPCRemoteProxy object;
    int result = OH_IPCParcel_WriteRemoteProxy(nullptr, &object);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);
}

/**
 * @tc.name: WriteIPCRemoteObject002
 * @tc.desc: Test WriteIPCRemoteObject when object is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCCparcelTest, WriteIPCRemoteObject002, TestSize.Level1)
{
    OHIPCParcel parcel;
    int result = OH_IPCParcel_WriteRemoteProxy(&parcel, nullptr);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);
}

/**
 * @tc.name: ReadIPCRemoteObject001
 * @tc.desc: Test ReadIPCRemoteObject when IsIPCParcelValid return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCCparcelTest, ReadIPCRemoteObject001, TestSize.Level1)
{
    auto result = OH_IPCParcel_ReadRemoteProxy(nullptr);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: ReadIPCRemoteObject002
 * @tc.desc: Test ReadIPCRemoteObject when ReadRemoteObject return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCCparcelTest, ReadIPCRemoteObject002, TestSize.Level1)
{
    OHIPCParcel parcel;
    NiceMock<IpcCparcelInterfaceMock> mock;
    EXPECT_CALL(mock, IsIPCParcelValid(testing::_, testing::_))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mock, ReadRemoteObject())
        .WillOnce(Return(nullptr));
    auto result = OH_IPCParcel_ReadRemoteProxy(&parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: OH_IPCParcel_ReadFileDescriptor001
 * @tc.desc: Test OH_IPCParcel_ReadFileDescriptor when IsIPCParcelValid return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCCparcelTest, OH_IPCParcel_ReadFileDescriptor001, TestSize.Level1)
{
    int32_t fd = 0;
    auto result = OH_IPCParcel_ReadFileDescriptor(nullptr, &fd);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);
}

/**
 * @tc.name: OH_IPCParcel_ReadFileDescriptor002
 * @tc.desc: Test OH_IPCParcel_ReadFileDescriptor when fd is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCCparcelTest, OH_IPCParcel_ReadFileDescriptor002, TestSize.Level1)
{
    OHIPCParcel parcel;
    int32_t* fd = nullptr;
    int result = OH_IPCParcel_ReadFileDescriptor(&parcel, fd);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);
}

/**
 * @tc.name: OH_IPCParcel_ReadFileDescriptor003
 * @tc.desc: Test OH_IPCParcel_ReadFileDescriptor when fd is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCCparcelTest, OH_IPCParcel_ReadFileDescriptor003, TestSize.Level1)
{
    OHIPCParcel parcel;
    int32_t* fd = nullptr;
    int result = OH_IPCParcel_ReadFileDescriptor(&parcel, fd);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);
}

/**
 * @tc.name: OH_IPCParcel_WriteInterfaceToken001
 * @tc.desc: Test OH_IPCParcel_WriteInterfaceToken when IsIPCParcelValid return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCCparcelTest, OH_IPCParcel_WriteInterfaceToken001, TestSize.Level1)
{
    const char token[] = "valid_token";
    auto result = OH_IPCParcel_WriteInterfaceToken(nullptr, token);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);
}

/**
 * @tc.name: OH_IPCParcel_WriteInterfaceToken002
 * @tc.desc: Test OH_IPCParcel_WriteInterfaceToken when fd is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCCparcelTest, OH_IPCParcel_WriteInterfaceToken002, TestSize.Level1)
{
    OHIPCParcel parcel;
    const char* token = nullptr;
    int result = OH_IPCParcel_WriteInterfaceToken(&parcel, token);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);
}

/**
 * @tc.name: OH_IPCParcel_WriteInterfaceToken003
 * @tc.desc: Test OH_IPCParcel_WriteInterfaceToken when IsIPCParcelValid return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCCparcelTest, OH_IPCParcel_WriteInterfaceToken003, TestSize.Level1)
{
    OHIPCParcel parcel;
    const char token[] = "";
    auto result = OH_IPCParcel_WriteInterfaceToken(&parcel, token);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);
}

/**
 * @tc.name: OH_IPCParcel_WriteInterfaceToken004
 * @tc.desc: Test OH_IPCParcel_WriteInterfaceToken when IsIPCParcelValid return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCCparcelTest, OH_IPCParcel_WriteInterfaceToken004, TestSize.Level1)
{
    OHIPCParcel parcel;
    std::string longToken(MAX_PARCEL_LEN + 1, 'a');
    auto result = OH_IPCParcel_WriteInterfaceToken(&parcel, longToken.c_str());
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);
}
}// namespace OHOS