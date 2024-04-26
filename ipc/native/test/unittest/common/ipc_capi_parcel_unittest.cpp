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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstring>
#include <securec.h>
#include "ipc_cparcel.h"
#include "ipc_test_helper.h"
#include "test_service_command.h"
#include "ipc_error_code.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "ipc_inner_object.h"
#include <vector>

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HiviewDFX;
using namespace std;

static constexpr int NUMBER_CONSTANT = 100;
static constexpr float FLOAT_CONSTANT = 1.1;
static const char *STRING_CONSTANT = "HELLO";
static constexpr int DEFAULT_CAPACITY = 0;
static constexpr int MAX_MEMORY_SIZE = 204800;

class IpcCApiParcelUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static constexpr HiLogLabel LABEL = {LOG_CORE, LOG_ID_TEST, "IpcCApiUnitTest"};
};

void IpcCApiParcelUnitTest::SetUpTestCase() {}

void IpcCApiParcelUnitTest::TearDownTestCase() {}

void IpcCApiParcelUnitTest::SetUp() {}

void IpcCApiParcelUnitTest::TearDown() {}

static void* LocalMemAllocator(int32_t len)
{
    if (len < 0 || len > MAX_MEMORY_SIZE) {
        return nullptr;
    }
    void *buffer = malloc(len);
    if (buffer != nullptr) {
        (void)memset_s(buffer, len, 0, len);
    }
    
    return buffer;
}

static void* LocalMemAllocatorErr(int32_t len)
{
    return nullptr;
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_Create_001, TestSize.Level1)
{
    OHIPCParcel *parcel = OH_IPCParcel_Create();
    EXPECT_NE(parcel, nullptr);
    OH_IPCParcel_Destroy(parcel);
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_Destroy_001, TestSize.Level1)
{
    OHIPCParcel *parcel = OH_IPCParcel_Create();
    EXPECT_NE(parcel, nullptr);
    OH_IPCParcel_Destroy(parcel);
    EXPECT_DEATH(OH_IPCParcel_Destroy(parcel), "");
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_GetDataSize_001, TestSize.Level1)
{
    OHIPCParcel *parcel = OH_IPCParcel_Create();
    EXPECT_NE(parcel, nullptr);
    EXPECT_EQ(OH_IPCParcel_GetDataSize(nullptr), -1);
    EXPECT_EQ(OH_IPCParcel_GetDataSize(parcel), 0);
    int32_t vals[] = {1, 2, 3, 4, 5, 1};
    for (auto i : vals) {
        ASSERT_EQ(OH_IPCParcel_WriteInt32(parcel, i), OH_IPC_SUCCESS);
    }
    // test get data size
    uint32_t dataSize = OH_IPCParcel_GetDataSize(parcel);
    EXPECT_EQ(dataSize, sizeof(vals));
    OH_IPCParcel_Destroy(parcel);
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_GetWritableBytes_001, TestSize.Level1)
{
    OHIPCParcel *parcel = OH_IPCParcel_Create();
    EXPECT_NE(parcel, nullptr);
    EXPECT_EQ(OH_IPCParcel_GetWritableBytes(nullptr), -1);
    EXPECT_EQ(OH_IPCParcel_GetWritableBytes(parcel), DEFAULT_CAPACITY);

    // function test, default capacity is zero, write some data to resize
    ASSERT_EQ(OH_IPCParcel_WriteInt32(parcel, 0), OH_IPC_SUCCESS);
    auto before_bytes = OH_IPCParcel_GetWritableBytes(parcel);
    int32_t data[10] = {1, 2, 3, 4, 5, 1, 3, 5, 7, 9};
    for (auto i : data) {
        ASSERT_EQ(OH_IPCParcel_WriteInt32(parcel, i), OH_IPC_SUCCESS);
    }
    auto after_bytes = OH_IPCParcel_GetWritableBytes(parcel);
    EXPECT_EQ(before_bytes, after_bytes + sizeof(data));
    OH_IPCParcel_Destroy(parcel);
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_GetReadableBytes_001, TestSize.Level1)
{
    OHIPCParcel *parcel = OH_IPCParcel_Create();
    EXPECT_NE(parcel, nullptr);
    EXPECT_EQ(OH_IPCParcel_GetReadableBytes(nullptr), -1);
    // function test
    EXPECT_EQ(OH_IPCParcel_GetReadableBytes(parcel), 0);
    int total = 10;
    for (int32_t i = 0; i < total; ++i) {
        ASSERT_EQ(OH_IPCParcel_WriteInt32(parcel, i), OH_IPC_SUCCESS);
    }
    auto bytes = OH_IPCParcel_GetReadableBytes(parcel);
    EXPECT_EQ(bytes, total * sizeof(int32_t));
    OH_IPCParcel_Destroy(parcel);
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_GetReadPosition_001, TestSize.Level1)
{
    OHIPCParcel *parcel = OH_IPCParcel_Create();
    EXPECT_NE(parcel, nullptr);
    EXPECT_EQ(OH_IPCParcel_GetReadPosition(nullptr), -1);
    // function test
    EXPECT_EQ(OH_IPCParcel_GetReadPosition(parcel), 0);
    int total = 10;
    for (int32_t i = 0; i < total; ++i) {
        ASSERT_EQ(OH_IPCParcel_WriteInt32(parcel, i), OH_IPC_SUCCESS);
    }
    int totalRead = 5;
    for (int32_t i = 0; i < totalRead; ++i) {
        int32_t value;
        ASSERT_EQ(OH_IPCParcel_ReadInt32(parcel, &value), OH_IPC_SUCCESS);
    }
    EXPECT_EQ(OH_IPCParcel_GetReadPosition(parcel), totalRead * sizeof(int32_t));
    OH_IPCParcel_Destroy(parcel);
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_GetWritePosition_001, TestSize.Level1)
{
    OHIPCParcel *parcel = OH_IPCParcel_Create();
    EXPECT_NE(parcel, nullptr);
    EXPECT_EQ(OH_IPCParcel_GetWritePosition(nullptr), -1);
    // function test
    EXPECT_EQ(OH_IPCParcel_GetWritePosition(parcel), 0);
    int total = 10;
    for (int32_t i = 0; i < total; ++i) {
        ASSERT_EQ(OH_IPCParcel_WriteInt32(parcel, i * 2), OH_IPC_SUCCESS);
    }
    auto pos = OH_IPCParcel_GetWritePosition(parcel);
    EXPECT_EQ(pos, total * sizeof(int32_t));
    OH_IPCParcel_Destroy(parcel);
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_RewindReadPosition_001, TestSize.Level1)
{
    OHIPCParcel *parcel = OH_IPCParcel_Create();
    EXPECT_NE(parcel, nullptr);
    int total = 10;
    for (int32_t i = 0; i < total; ++i) {
        ASSERT_EQ(OH_IPCParcel_WriteInt32(parcel, i * 2), OH_IPC_SUCCESS);
    }
    int totalRead = 5;
    for (int32_t i = 0; i < totalRead; ++i) {
        int32_t value;
        ASSERT_EQ(OH_IPCParcel_ReadInt32(parcel, &value), OH_IPC_SUCCESS);
    }
    auto pos = OH_IPCParcel_GetReadPosition(parcel);
    EXPECT_EQ(pos, totalRead * sizeof(int32_t));
    int32_t newPos = sizeof(int32_t) * 3;
    EXPECT_EQ(OH_IPCParcel_RewindReadPosition(nullptr, 0), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_RewindReadPosition(parcel, -1), OH_IPC_INNER_ERROR);
    EXPECT_EQ(OH_IPCParcel_RewindReadPosition(parcel, newPos), OH_IPC_SUCCESS);
    // real pos should be the same as we rewinded
    EXPECT_EQ(OH_IPCParcel_GetReadPosition(parcel), newPos);
    OH_IPCParcel_Destroy(parcel);
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_RewindWritePosition_001, TestSize.Level1)
{
    OHIPCParcel *parcel = OH_IPCParcel_Create();
    EXPECT_NE(parcel, nullptr);
    auto pos = OH_IPCParcel_GetWritePosition(parcel);
    EXPECT_EQ(pos, 0);
    int total = 30;
    for (int32_t i = 0; i < total; ++i) {
        ASSERT_EQ(OH_IPCParcel_WriteInt32(parcel, i * 3), OH_IPC_SUCCESS);
    }
    pos = OH_IPCParcel_GetWritePosition(parcel);
    EXPECT_EQ(pos, total * sizeof(int32_t));
    EXPECT_EQ(OH_IPCParcel_RewindWritePosition(nullptr, 0), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_RewindWritePosition(parcel, -1), OH_IPC_INNER_ERROR);
    int32_t newPos = sizeof(int32_t) * 5;
    EXPECT_EQ(OH_IPCParcel_RewindWritePosition(parcel, newPos), OH_IPC_SUCCESS);
    // real pos should be the same as we rewinded
    EXPECT_EQ(OH_IPCParcel_GetWritePosition(parcel), newPos);
    OH_IPCParcel_Destroy(parcel);
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_TestDataInfo_001, TestSize.Level1)
{
    OHIPCParcel *parcel = OH_IPCParcel_Create();
    EXPECT_NE(parcel, nullptr);
    
    EXPECT_EQ(OH_IPCParcel_GetDataSize(parcel), 0);
    EXPECT_EQ(OH_IPCParcel_GetWritableBytes(parcel), DEFAULT_CAPACITY);
    EXPECT_EQ(OH_IPCParcel_GetReadableBytes(parcel), 0);
    EXPECT_EQ(OH_IPCParcel_GetReadPosition(parcel), 0);
    EXPECT_EQ(OH_IPCParcel_GetWritePosition(parcel), 0);

    EXPECT_EQ(OH_IPCParcel_WriteInt32(parcel, 0x010203), OH_IPC_SUCCESS);
    EXPECT_EQ(OH_IPCParcel_GetDataSize(parcel), sizeof(int32_t));
    EXPECT_GT(OH_IPCParcel_GetWritableBytes(parcel), 0);
    EXPECT_EQ(OH_IPCParcel_GetReadableBytes(parcel), sizeof(int32_t));
    EXPECT_EQ(OH_IPCParcel_GetReadPosition(parcel), 0);
    EXPECT_EQ(OH_IPCParcel_GetWritePosition(parcel), sizeof(int32_t));

    int32_t value;
    ASSERT_EQ(OH_IPCParcel_ReadInt32(parcel, &value), OH_IPC_SUCCESS);
    EXPECT_EQ(OH_IPCParcel_GetReadableBytes(parcel), 0);
    EXPECT_EQ(OH_IPCParcel_GetReadPosition(parcel), sizeof(int32_t));

    EXPECT_EQ(OH_IPCParcel_RewindReadPosition(parcel, 0), OH_IPC_SUCCESS);
    EXPECT_EQ(OH_IPCParcel_RewindWritePosition(parcel, 0), OH_IPC_SUCCESS);
    EXPECT_EQ(OH_IPCParcel_GetDataSize(parcel), 0);

    EXPECT_EQ(OH_IPCParcel_GetReadableBytes(parcel), 0);
    EXPECT_EQ(OH_IPCParcel_GetReadPosition(parcel), 0);
    EXPECT_EQ(OH_IPCParcel_GetWritePosition(parcel), 0);

    OH_IPCParcel_Destroy(parcel);
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_TestReadWriteInt8_001, TestSize.Level1)
{
    OHIPCParcel *parcel = OH_IPCParcel_Create();
    EXPECT_NE(parcel, nullptr);
    int8_t value = static_cast<int8_t>(NUMBER_CONSTANT);
    EXPECT_EQ(OH_IPCParcel_WriteInt8(nullptr, value), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_WriteInt8(parcel, value), OH_IPC_SUCCESS);
    int8_t readValue = 0;
    EXPECT_EQ(OH_IPCParcel_ReadInt8(nullptr, &readValue), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadInt8(parcel, nullptr), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadInt8(parcel, &readValue), OH_IPC_SUCCESS);
    EXPECT_EQ(readValue, static_cast<int8_t>(NUMBER_CONSTANT));
    OH_IPCParcel_Destroy(parcel);
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_TestReadWriteInt16_001, TestSize.Level1)
{
    OHIPCParcel *parcel = OH_IPCParcel_Create();
    EXPECT_NE(parcel, nullptr);
    int16_t value = static_cast<int16_t>(NUMBER_CONSTANT);
    EXPECT_EQ(OH_IPCParcel_WriteInt16(nullptr, value), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_WriteInt16(parcel, value), OH_IPC_SUCCESS);
    int16_t readValue = 0;
    EXPECT_EQ(OH_IPCParcel_ReadInt16(nullptr, &readValue), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadInt16(parcel, nullptr), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadInt16(parcel, &readValue), OH_IPC_SUCCESS);
    EXPECT_EQ(readValue, static_cast<int16_t>(NUMBER_CONSTANT));
    OH_IPCParcel_Destroy(parcel);
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_TestReadWriteInt32_001, TestSize.Level1)
{
    OHIPCParcel *parcel = OH_IPCParcel_Create();
    EXPECT_NE(parcel, nullptr);
    int32_t value = static_cast<int32_t>(NUMBER_CONSTANT);
    EXPECT_EQ(OH_IPCParcel_WriteInt32(nullptr, value), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_WriteInt32(parcel, value), OH_IPC_SUCCESS);
    int32_t readValue = 0;
    EXPECT_EQ(OH_IPCParcel_ReadInt32(nullptr, &readValue), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadInt32(parcel, nullptr), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadInt32(parcel, &readValue), OH_IPC_SUCCESS);
    EXPECT_EQ(readValue, static_cast<int32_t>(NUMBER_CONSTANT));
    OH_IPCParcel_Destroy(parcel);
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_TestReadWriteInt64_001, TestSize.Level1)
{
    OHIPCParcel *parcel = OH_IPCParcel_Create();
    EXPECT_NE(parcel, nullptr);
    int64_t value = static_cast<int64_t>(NUMBER_CONSTANT);
    EXPECT_EQ(OH_IPCParcel_WriteInt64(nullptr, value), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_WriteInt64(parcel, value), OH_IPC_SUCCESS);
    int64_t readValue = 0;
    EXPECT_EQ(OH_IPCParcel_ReadInt64(nullptr, &readValue), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadInt64(parcel, nullptr), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadInt64(parcel, &readValue), OH_IPC_SUCCESS);
    EXPECT_EQ(readValue, static_cast<int64_t>(NUMBER_CONSTANT));
    OH_IPCParcel_Destroy(parcel);
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_TestReadWriteFloat_001, TestSize.Level1)
{
    OHIPCParcel *parcel = OH_IPCParcel_Create();
    EXPECT_NE(parcel, nullptr);
    float value = static_cast<float>(FLOAT_CONSTANT);
    EXPECT_EQ(OH_IPCParcel_WriteFloat(nullptr, value), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_WriteFloat(parcel, value), OH_IPC_SUCCESS);
    float readValue = 0.0;
    EXPECT_EQ(OH_IPCParcel_ReadFloat(nullptr, &readValue), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadFloat(parcel, nullptr), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadFloat(parcel, &readValue), OH_IPC_SUCCESS);
    EXPECT_TRUE(abs(readValue - static_cast<float>(FLOAT_CONSTANT)) < 0.000001);
    OH_IPCParcel_Destroy(parcel);
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_TestReadWriteDouble_001, TestSize.Level1)
{
    OHIPCParcel *parcel = OH_IPCParcel_Create();
    EXPECT_NE(parcel, nullptr);
    double value = static_cast<double>(FLOAT_CONSTANT);
    EXPECT_EQ(OH_IPCParcel_WriteDouble(nullptr, value), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_WriteDouble(parcel, value), OH_IPC_SUCCESS);
    double readValue = 0.0;
    EXPECT_EQ(OH_IPCParcel_ReadDouble(nullptr, &readValue), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadDouble(parcel, nullptr), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadDouble(parcel, &readValue), OH_IPC_SUCCESS);
    EXPECT_TRUE(abs(readValue - static_cast<double>(FLOAT_CONSTANT)) < 0.000001);
    OH_IPCParcel_Destroy(parcel);
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_TestReadWriteString_001, TestSize.Level1)
{
    OHIPCParcel *parcel = OH_IPCParcel_Create();
    EXPECT_NE(parcel, nullptr);

    void *data = nullptr;
    int32_t len = 0;
    // read without writing data
    EXPECT_EQ(OH_IPCParcel_ReadString(parcel, reinterpret_cast<char **>(&data), &len, LocalMemAllocator),
        OH_IPC_PARCEL_READ_ERROR);
    // write string
    EXPECT_EQ(OH_IPCParcel_WriteString(nullptr, STRING_CONSTANT), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_WriteString(parcel, nullptr), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_WriteString(parcel, STRING_CONSTANT), OH_IPC_SUCCESS);
    // read after write
    EXPECT_EQ(OH_IPCParcel_ReadString(nullptr, reinterpret_cast<char **>(&data), &len, LocalMemAllocator),
        OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadString(parcel, nullptr, &len, LocalMemAllocator), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadString(parcel, reinterpret_cast<char **>(&data), nullptr, LocalMemAllocator),
        OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadString(parcel, reinterpret_cast<char **>(&data), &len, nullptr),
        OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadString(parcel, reinterpret_cast<char **>(&data), &len, LocalMemAllocator),
        OH_IPC_SUCCESS);
    EXPECT_EQ(strncmp((reinterpret_cast<char *>(data)), STRING_CONSTANT, strlen(STRING_CONSTANT)), 0);
    if (data != nullptr) {
        free(data);
    }
    OH_IPCParcel_Destroy(parcel);
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_TestReadWriteString_002, TestSize.Level1)
{
    OHIPCParcel *parcel = OH_IPCParcel_Create();
    EXPECT_NE(parcel, nullptr);
    void *data = nullptr;
    int32_t len = 0;
    EXPECT_EQ(OH_IPCParcel_WriteString(parcel, STRING_CONSTANT), OH_IPC_SUCCESS);
    EXPECT_EQ(OH_IPCParcel_ReadString(parcel, reinterpret_cast<char **>(&data), &len, LocalMemAllocatorErr),
        OH_IPC_MEM_ALLOCATOR_ERROR);
    OH_IPCParcel_Destroy(parcel);
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_TestReadWriteFileDescriptor_001, TestSize.Level1)
{
    OHIPCParcel *parcel = OH_IPCParcel_Create();
    EXPECT_NE(parcel, nullptr);

    int32_t fd = open("/dev/null", O_RDONLY);
    EXPECT_TRUE(fd >= 0);
    EXPECT_EQ(OH_IPCParcel_WriteFileDescriptor(nullptr, fd), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_WriteFileDescriptor(parcel, fd), OH_IPC_SUCCESS);

    int32_t readFd = 0;
    EXPECT_EQ(OH_IPCParcel_ReadFileDescriptor(nullptr, &readFd), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadFileDescriptor(parcel, nullptr), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadFileDescriptor(parcel, &readFd), OH_IPC_SUCCESS);
    EXPECT_TRUE(readFd > 0);
    close(fd);
    close(readFd);
    OH_IPCParcel_Destroy(parcel);
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_Append_001, TestSize.Level1)
{
    OHIPCParcel *parcel1 = OH_IPCParcel_Create();
    EXPECT_NE(parcel1, nullptr);
    OHIPCParcel *parcel2 = OH_IPCParcel_Create();
    EXPECT_NE(parcel2, nullptr);
    vector<int16_t> v1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    vector<int16_t> v2 = {11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23};
    for (int16_t i = 0; i < v1.size(); ++i) {
        ASSERT_EQ(OH_IPCParcel_WriteInt16(parcel1, v1[i]), OH_IPC_SUCCESS);
    }
    for (int16_t i = 0; i < v2.size(); ++i) {
        ASSERT_EQ(OH_IPCParcel_WriteInt16(parcel2, v2[i]), OH_IPC_SUCCESS);
    }
    auto size1 = OH_IPCParcel_GetDataSize(parcel1);
    auto size2 = OH_IPCParcel_GetDataSize(parcel2);
    // parameters test
    EXPECT_EQ(OH_IPCParcel_Append(nullptr, parcel2), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_Append(parcel1, nullptr), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_Append(parcel1, parcel2), OH_IPC_SUCCESS);
    // function test
    EXPECT_EQ(OH_IPCParcel_GetDataSize(parcel1), size1 + size2);
    v1.insert(v1.end(), v2.begin(), v2.end());
    for (size_t i = 0; i < v1.size(); ++i) {
        int16_t readValue = 0;
        ASSERT_EQ(OH_IPCParcel_ReadInt16(parcel1, &readValue), OH_IPC_SUCCESS);
        EXPECT_EQ(v1[i], readValue);
    }
    OH_IPCParcel_Destroy(parcel1);
    OH_IPCParcel_Destroy(parcel2);
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_TestReadWriteBuffer_001, TestSize.Level1)
{
    OHIPCParcel *parcel = OH_IPCParcel_Create();
    EXPECT_NE(parcel, nullptr);
    uint8_t buffer[] = {0, 2, 5, 88, 9, 6, 4, 7, 100};
    int32_t len = sizeof(buffer);
    EXPECT_EQ(OH_IPCParcel_WriteBuffer(nullptr, buffer, len), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_WriteBuffer(parcel, nullptr, len), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_WriteBuffer(parcel, buffer, -1), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_WriteBuffer(parcel, buffer, len), OH_IPC_SUCCESS);

    uint8_t *data = nullptr;
    // abnormal parameters
    EXPECT_EQ(OH_IPCParcel_ReadBuffer(nullptr, reinterpret_cast<uint8_t **>(&data), &len, LocalMemAllocator),
        OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadBuffer(parcel, nullptr, &len, LocalMemAllocator), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadBuffer(parcel, reinterpret_cast<uint8_t **>(&data), nullptr,
        LocalMemAllocator), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadBuffer(parcel, reinterpret_cast<uint8_t **>(&data), &len,
        nullptr), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadBuffer(parcel, reinterpret_cast<uint8_t **>(&data), &len,
        LocalMemAllocatorErr), OH_IPC_MEM_ALLOCATOR_ERROR);
    // normal scenes
    EXPECT_EQ(OH_IPCParcel_ReadBuffer(parcel, reinterpret_cast<uint8_t **>(&data), &len,
        LocalMemAllocator), OH_IPC_SUCCESS);
    EXPECT_EQ(len, sizeof(buffer));
    EXPECT_EQ(memcmp(buffer, data, len), 0);
    if (data) {
        delete data;
    }
    OH_IPCParcel_Destroy(parcel);
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_TestReadWriteInterfaceToken_001, TestSize.Level1)
{
    OHIPCParcel *parcel = OH_IPCParcel_Create();
    EXPECT_NE(parcel, nullptr);
    const char *buffer = "hello, world!";
    EXPECT_EQ(OH_IPCParcel_WriteInterfaceToken(nullptr, buffer), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_WriteInterfaceToken(parcel, nullptr), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_WriteInterfaceToken(parcel, buffer), OH_IPC_SUCCESS);
    char *data = nullptr;
    int32_t realLen = 0;
    // abnormal parameters
    EXPECT_EQ(OH_IPCParcel_ReadInterfaceToken(nullptr, reinterpret_cast<char **>(&data), &realLen, LocalMemAllocator),
        OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadInterfaceToken(parcel, nullptr, &realLen, LocalMemAllocator), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadInterfaceToken(parcel, reinterpret_cast<char **>(&data), nullptr, LocalMemAllocator),
        OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadInterfaceToken(parcel, reinterpret_cast<char **>(&data), &realLen,
        nullptr), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_ReadInterfaceToken(parcel, reinterpret_cast<char **>(&data), &realLen,
        LocalMemAllocatorErr), OH_IPC_MEM_ALLOCATOR_ERROR);
    // normal scenes
    EXPECT_EQ(OH_IPCParcel_ReadInterfaceToken(parcel, reinterpret_cast<char **>(&data), &realLen,
        LocalMemAllocator), OH_IPC_SUCCESS);
    EXPECT_EQ(strcmp(buffer, data), 0);
    // destroy object
    if (data) {
        delete data;
    }
    OH_IPCParcel_Destroy(parcel);
}
