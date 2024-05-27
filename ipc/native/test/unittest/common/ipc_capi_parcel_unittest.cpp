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
#include <thread>
#include <chrono>
#include "parcel.h"
#include "refbase.h"
#include "ipc_cparcel.h"
#include "ipc_cremote_object.h"
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
static constexpr int MAX_INTERFACE_TOKEN_LEN = 100;
static constexpr int TEST_PARCEL_SIZE = MAX_MEMORY_SIZE - 10;
static constexpr int TEST_PERFORMANCE_OPERATOR_COUNT = 2000;
static constexpr int TEST_PERFORMANCE_OPERATOR_GROUP = 50;

struct PerformanceResult {
    uint32_t min{ 100 };
    uint32_t max{ 0 };
    uint32_t average{ 0 };
};

using TimePoint = std::chrono::time_point<std::chrono::steady_clock>;

class IpcCApiParcelUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    uint32_t CalcSpendTime(TimePoint &start, TimePoint &end);
    void ReadWriteString(const char *str, uint32_t &writeDuration, uint32_t &readDuration);
    void ReadWriteStringCpp(const char *str, uint32_t &writeDuration, uint32_t &readDuration);
    void ReadWriteStringPerformance(PerformanceResult &writeResult, PerformanceResult &readResult,
        PerformanceResult &writeCppResult, PerformanceResult &readCppResult);
    void ReadWriteBuffer(const uint8_t *buf, int32_t bufLength, uint32_t &writeDuration, uint32_t &readDuration);
    void ReadWriteBufferCpp(const uint8_t *buf, int32_t bufLength, uint32_t &writeDuration, uint32_t &readDuration);
    void ReadWriteBufferPerformance(PerformanceResult &writeResult, PerformanceResult &readResult,
        PerformanceResult &writeCppResult, PerformanceResult &readCppResult);
    void ReadWriteInterfaceToken(const char *token, uint32_t &writeDuration, uint32_t &readDuration);
    void ReadWriteInterfaceTokenCpp(const char *token, uint32_t &writeDuration, uint32_t &readDuration);
    void ReadWriteInterfaceTokenPerformance(PerformanceResult &writeResult, PerformanceResult &readResult,
        PerformanceResult &writeCppResult, PerformanceResult &readCppResult);

    void PerformanceStatistic(uint32_t writeAvg, uint32_t readAvg, uint32_t writeCppAvg, uint32_t readCppAvg);

    static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_TEST, "IpcCApiUnitTest" };
};

static void* LocalMemAllocator(int32_t len)
{
    if (len < 0 || len > MAX_MEMORY_SIZE) {
        return nullptr;
    }
    void *buffer = malloc(len);
    if (buffer != nullptr) {
        if (memset_s(buffer, len, 0, len) != EOK) {
            ZLOGE(IpcCApiParcelUnitTest::LABEL, "memset_s failed!");
        }
    }

    return buffer;
}

static void* LocalMemAllocatorErr(int32_t len)
{
    return nullptr;
}

static int OnRemoteRequestStub(uint32_t code, const OHIPCParcel *data, OHIPCParcel *reply,
    void *userData)
{
    (void)userData;
    (void)code;
    (void)data;
    (void)reply;
    return 0;
}

void IpcCApiParcelUnitTest::SetUpTestCase() {}

void IpcCApiParcelUnitTest::TearDownTestCase() {}

void IpcCApiParcelUnitTest::SetUp() {}

void IpcCApiParcelUnitTest::TearDown() {}

uint32_t IpcCApiParcelUnitTest::CalcSpendTime(TimePoint& start, TimePoint& end)
{
    auto duration = end - start;
    return static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count());
}

void IpcCApiParcelUnitTest::PerformanceStatistic(uint32_t writeAvg, uint32_t readAvg,
    uint32_t writeCppAvg, uint32_t readCppAvg)
{
    std::cout << "OHIPCParcel writeAvg:" << writeAvg << "ns, readAvg:" << readAvg << "ns" << std::endl;
    std::cout << "MessageParcel writeAvg:" << writeCppAvg << "ns, readAvg:" << readCppAvg << "ns" << std::endl;
}

void IpcCApiParcelUnitTest::ReadWriteString(const char *str, uint32_t &writeDuration, uint32_t &readDuration)
{
    auto dataCParcel = OH_IPCParcel_Create();
    int ret = OH_IPC_SUCCESS;
    auto startPoint = std::chrono::steady_clock::now();
    ret = OH_IPCParcel_WriteString(dataCParcel, str);
    auto endPoint = std::chrono::steady_clock::now();
    ASSERT_EQ(ret, OH_IPC_SUCCESS);
    writeDuration = CalcSpendTime(startPoint, endPoint);

    startPoint = std::chrono::steady_clock::now();
    const char *readStr = OH_IPCParcel_ReadString(dataCParcel);
    endPoint = std::chrono::steady_clock::now();
    ASSERT_NE(readStr, nullptr);
    EXPECT_EQ(strlen(readStr), strlen(str));
    OH_IPCParcel_Destroy(dataCParcel);
    readDuration = CalcSpendTime(startPoint, endPoint);
}

void IpcCApiParcelUnitTest::ReadWriteStringCpp(const char *str, uint32_t &writeDuration, uint32_t &readDuration)
{
    MessageParcel dataCpp;
    auto startPoint = std::chrono::steady_clock::now();
    dataCpp.WriteCString(str);
    auto endPoint = std::chrono::steady_clock::now();
    writeDuration = CalcSpendTime(startPoint, endPoint);

    startPoint = std::chrono::steady_clock::now();
    const char *readStr = dataCpp.ReadCString();
    endPoint = std::chrono::steady_clock::now();
    ASSERT_NE(readStr, nullptr);
    EXPECT_EQ(strlen(readStr), strlen(str));
    readDuration = CalcSpendTime(startPoint, endPoint);
}

void IpcCApiParcelUnitTest::ReadWriteStringPerformance(PerformanceResult &writeResult,
    PerformanceResult &readResult, PerformanceResult &writeCppResult, PerformanceResult &readCppResult)
{
    char str[TEST_PARCEL_SIZE] = {0};
    ASSERT_EQ(memset_s(str, sizeof(str) - 1, '1', sizeof(str) - 1), EOK);
    for (int i = 0; i < TEST_PERFORMANCE_OPERATOR_COUNT; ++i) {
        uint32_t writeDuration = 0;
        uint32_t readDuration = 0;
        ReadWriteString(str, writeDuration, readDuration);
        writeResult.min = (writeDuration > writeResult.min) ? writeResult.min : writeDuration;
        writeResult.max = (writeDuration < writeResult.max) ? writeResult.max : writeDuration;
        writeResult.average += writeDuration;
        readResult.min = (readDuration > readResult.min) ? readResult.min : readDuration;
        readResult.max = (readDuration < readResult.max) ? readResult.max : readDuration;
        readResult.average += readDuration;

        uint32_t writeCppDuration = 0;
        uint32_t readCppDuration = 0;
        ReadWriteStringCpp(str, writeCppDuration, readCppDuration);
        writeCppResult.min = (writeCppDuration > writeCppResult.min) ? writeCppResult.min : writeCppDuration;
        writeCppResult.max = (writeCppDuration < writeCppResult.max) ? writeCppResult.max : writeCppDuration;
        writeCppResult.average += writeCppDuration;
        readCppResult.min = (readCppDuration > readCppResult.min) ? readCppResult.min : readCppDuration;
        readCppResult.max = (readCppDuration < readCppResult.max) ? readCppResult.max : readCppDuration;
        readCppResult.average += readCppDuration;
    }
    writeResult.average /= TEST_PERFORMANCE_OPERATOR_COUNT;
    readResult.average /= TEST_PERFORMANCE_OPERATOR_COUNT;
    writeCppResult.average /= TEST_PERFORMANCE_OPERATOR_COUNT;
    readCppResult.average /= TEST_PERFORMANCE_OPERATOR_COUNT;
}

void IpcCApiParcelUnitTest::ReadWriteBuffer(const uint8_t *buf, int32_t bufLength,
    uint32_t &writeDuration, uint32_t &readDuration)
{
    auto dataCParcel = OH_IPCParcel_Create();
    int ret = OH_IPC_SUCCESS;
    auto startPoint = std::chrono::steady_clock::now();
    ret = OH_IPCParcel_WriteBuffer(dataCParcel, buf, bufLength);
    auto endPoint = std::chrono::steady_clock::now();
    ASSERT_EQ(ret, OH_IPC_SUCCESS);
    writeDuration = CalcSpendTime(startPoint, endPoint);

    startPoint = std::chrono::steady_clock::now();
    const uint8_t *readBuffer = OH_IPCParcel_ReadBuffer(dataCParcel, bufLength);
    endPoint = std::chrono::steady_clock::now();
    ASSERT_NE(readBuffer, nullptr);
    EXPECT_EQ(memcmp(readBuffer, buf, bufLength), 0);
    OH_IPCParcel_Destroy(dataCParcel);
    readDuration = CalcSpendTime(startPoint, endPoint);
}

void IpcCApiParcelUnitTest::ReadWriteBufferCpp(const uint8_t *buf, int32_t bufLength,
    uint32_t &writeDuration, uint32_t &readDuration)
{
    MessageParcel dataCpp;
    auto startPoint = std::chrono::steady_clock::now();
    dataCpp.WriteBuffer(buf, TEST_PARCEL_SIZE);
    auto endPoint = std::chrono::steady_clock::now();
    writeDuration = CalcSpendTime(startPoint, endPoint);

    startPoint = std::chrono::steady_clock::now();
    const uint8_t *readBuf = dataCpp.ReadBuffer(TEST_PARCEL_SIZE);
    endPoint = std::chrono::steady_clock::now();
    ASSERT_NE(readBuf, nullptr);
    EXPECT_EQ(memcmp(readBuf, buf, bufLength), 0);
    readDuration = CalcSpendTime(startPoint, endPoint);
}

void IpcCApiParcelUnitTest::ReadWriteBufferPerformance(PerformanceResult &writeResult,
    PerformanceResult &readResult, PerformanceResult &writeCppResult, PerformanceResult &readCppResult)
{
    uint8_t buf[TEST_PARCEL_SIZE] = {0};
    ASSERT_EQ(memset_s(buf, sizeof(buf), '2', sizeof(buf)), EOK);
    for (int i = 0; i < TEST_PERFORMANCE_OPERATOR_COUNT; ++i) {
        uint32_t writeDuration = 0;
        uint32_t readDuration = 0;
        ReadWriteBuffer(buf, TEST_PARCEL_SIZE, writeDuration, readDuration);
        writeResult.min = (writeDuration > writeResult.min) ? writeResult.min : writeDuration;
        writeResult.max = (writeDuration < writeResult.max) ? writeResult.max : writeDuration;
        writeResult.average += writeDuration;
        readResult.min = (readDuration > readResult.min) ? readResult.min : readDuration;
        readResult.max = (readDuration < readResult.max) ? readResult.max : readDuration;
        readResult.average += readDuration;

        uint32_t writeCppDuration = 0;
        uint32_t readCppDuration = 0;
        ReadWriteBufferCpp(buf, TEST_PARCEL_SIZE, writeCppDuration, readCppDuration);
        writeCppResult.min = (writeCppDuration > writeCppResult.min) ? writeCppResult.min : writeCppDuration;
        writeCppResult.max = (writeCppDuration < writeCppResult.max) ? writeCppResult.max : writeCppDuration;
        writeCppResult.average += writeCppDuration;
        readCppResult.min = (readCppDuration > readCppResult.min) ? readCppResult.min : readCppDuration;
        readCppResult.max = (readCppDuration < readCppResult.max) ? readCppResult.max : readCppDuration;
        readCppResult.average += readCppDuration;
    }
    writeResult.average /= TEST_PERFORMANCE_OPERATOR_COUNT;
    readResult.average /= TEST_PERFORMANCE_OPERATOR_COUNT;
    writeCppResult.average /= TEST_PERFORMANCE_OPERATOR_COUNT;
    readCppResult.average /= TEST_PERFORMANCE_OPERATOR_COUNT;
}

void IpcCApiParcelUnitTest::ReadWriteInterfaceToken(const char *token,
    uint32_t &writeDuration, uint32_t &readDuration)
{
    auto dataCParcel = OH_IPCParcel_Create();
    int ret = OH_IPC_SUCCESS;
    auto startPoint = std::chrono::steady_clock::now();
    ret = OH_IPCParcel_WriteInterfaceToken(dataCParcel, token);
    auto endPoint = std::chrono::steady_clock::now();
    ASSERT_EQ(ret, OH_IPC_SUCCESS);
    writeDuration = CalcSpendTime(startPoint, endPoint);

    int readLen = 0;
    char *readInterfaceToken = nullptr;
    startPoint = std::chrono::steady_clock::now();
    ret = OH_IPCParcel_ReadInterfaceToken(dataCParcel, &readInterfaceToken, &readLen, LocalMemAllocator);
    endPoint = std::chrono::steady_clock::now();
    EXPECT_EQ(strcmp(token, readInterfaceToken), 0);
    EXPECT_EQ(readLen, strlen(token) + 1);
    free(readInterfaceToken);
    OH_IPCParcel_Destroy(dataCParcel);
    readDuration = CalcSpendTime(startPoint, endPoint);
}

void IpcCApiParcelUnitTest::ReadWriteInterfaceTokenCpp(const char *token,
    uint32_t &writeDuration, uint32_t &readDuration)
{
    MessageParcel dataCpp;
    auto startPoint = std::chrono::steady_clock::now();
    auto u16Token = OHOS::Str8ToStr16(token);
    dataCpp.WriteInterfaceToken(u16Token.c_str());
    auto endPoint = std::chrono::steady_clock::now();
    writeDuration = CalcSpendTime(startPoint, endPoint);

    startPoint = std::chrono::steady_clock::now();
    auto u16TokenRead = dataCpp.ReadInterfaceToken();
    std::string strTokenRead = OHOS::Str16ToStr8(u16TokenRead);
    endPoint = std::chrono::steady_clock::now();
    EXPECT_EQ(strTokenRead.length(), strlen(token));
    EXPECT_EQ(strTokenRead.compare(token), 0);
    readDuration = CalcSpendTime(startPoint, endPoint);
}

void IpcCApiParcelUnitTest::ReadWriteInterfaceTokenPerformance(PerformanceResult &writeResult,
    PerformanceResult &readResult, PerformanceResult &writeCppResult, PerformanceResult &readCppResult)
{
    char token[MAX_INTERFACE_TOKEN_LEN] = {0};
    ASSERT_EQ(memset_s(token, sizeof(token) - 1, '1', sizeof(token) - 1), EOK);
    for (int i = 0; i < TEST_PERFORMANCE_OPERATOR_COUNT; ++i) {
        uint32_t writeDuration = 0;
        uint32_t readDuration = 0;
        ReadWriteInterfaceToken(token, writeDuration, readDuration);
        writeResult.min = (writeDuration > writeResult.min) ? writeResult.min : writeDuration;
        writeResult.max = (writeDuration < writeResult.max) ? writeResult.max : writeDuration;
        writeResult.average += writeDuration;
        readResult.min = (readDuration > readResult.min) ? readResult.min : readDuration;
        readResult.max = (readDuration < readResult.max) ? readResult.max : readDuration;
        readResult.average += readDuration;

        uint32_t writeCppDuration = 0;
        uint32_t readCppDuration = 0;
        ReadWriteInterfaceTokenCpp(token, writeCppDuration, readCppDuration);
        writeCppResult.min = (writeCppDuration > writeCppResult.min) ? writeCppResult.min : writeCppDuration;
        writeCppResult.max = (writeCppDuration < writeCppResult.max) ? writeCppResult.max : writeCppDuration;
        writeCppResult.average += writeCppDuration;
        readCppResult.min = (readCppDuration > readCppResult.min) ? readCppResult.min : readCppDuration;
        readCppResult.max = (readCppDuration < readCppResult.max) ? readCppResult.max : readCppDuration;
        readCppResult.average += readCppDuration;
    }
    writeResult.average /= TEST_PERFORMANCE_OPERATOR_COUNT;
    readResult.average /= TEST_PERFORMANCE_OPERATOR_COUNT;
    writeCppResult.average /= TEST_PERFORMANCE_OPERATOR_COUNT;
    readCppResult.average /= TEST_PERFORMANCE_OPERATOR_COUNT;
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

    // read without writing data
    EXPECT_EQ(OH_IPCParcel_ReadString(nullptr), nullptr);
    // write string
    EXPECT_EQ(OH_IPCParcel_WriteString(nullptr, STRING_CONSTANT), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_WriteString(parcel, nullptr), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_WriteString(parcel, STRING_CONSTANT), OH_IPC_SUCCESS);
    // read after write
    const char* str = OH_IPCParcel_ReadString(parcel);
    EXPECT_EQ(strncmp(str, STRING_CONSTANT, strlen(STRING_CONSTANT)), 0);
    EXPECT_EQ(strlen(STRING_CONSTANT), strlen(str));
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

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_TestReadWriteRemoteStub_001, TestSize.Level1)
{
    OHIPCParcel *parcel = OH_IPCParcel_Create();
    EXPECT_NE(parcel, nullptr);
    const char *descriptor = "test descriptor";
    OHIPCRemoteStub *stub = OH_IPCRemoteStub_Create(descriptor, OnRemoteRequestStub,
                                                    nullptr, nullptr);
    EXPECT_NE(stub, nullptr);
    EXPECT_EQ(OH_IPCParcel_WriteRemoteStub(parcel, nullptr), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_WriteRemoteStub(nullptr, stub), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_WriteRemoteStub(parcel, stub), OH_IPC_SUCCESS);
    // read after write
    EXPECT_EQ(OH_IPCParcel_ReadRemoteStub(nullptr), nullptr);
    auto obj = OH_IPCParcel_ReadRemoteStub(parcel);
    EXPECT_NE(obj, nullptr);
    // destroy the objects
    OH_IPCParcel_Destroy(parcel);
    OH_IPCRemoteStub_Destroy(obj);
    OH_IPCRemoteStub_Destroy(stub);
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_TestReadWriteRemoteProxy_001, TestSize.Level1)
{
    OHIPCParcel *parcel = OH_IPCParcel_Create();
    EXPECT_NE(parcel, nullptr);
    OHIPCRemoteProxy *remoteProxy = OH_IPCParcel_ReadRemoteProxy(nullptr);
    EXPECT_EQ(remoteProxy, nullptr);

    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saMgr, nullptr);
    sptr<IRemoteObject> object = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    OHIPCRemoteProxy *proxy = CreateIPCRemoteProxy(object);
    ASSERT_NE(proxy, nullptr);
    EXPECT_EQ(OH_IPCParcel_WriteRemoteProxy(nullptr, proxy), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_WriteRemoteProxy(parcel, nullptr), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_WriteRemoteProxy(parcel, proxy), OH_IPC_SUCCESS);
    remoteProxy = OH_IPCParcel_ReadRemoteProxy(parcel);
    EXPECT_NE(remoteProxy, nullptr);
    // destroy the objects
    OH_IPCParcel_Destroy(parcel);
    OH_IPCRemoteProxy_Destroy(proxy);
    OH_IPCRemoteProxy_Destroy(remoteProxy);
    res = helper.StopTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);
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

    EXPECT_EQ(OH_IPCParcel_ReadBuffer(nullptr, len), nullptr);
    // normal scenes
    const uint8_t* readBuffer = OH_IPCParcel_ReadBuffer(parcel, len);
    EXPECT_NE(readBuffer, nullptr);
    EXPECT_EQ(memcmp(buffer, readBuffer, len), 0);
    OH_IPCParcel_Destroy(parcel);
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_TestReadWriteInterfaceToken_001, TestSize.Level1)
{
    OHIPCParcel *parcel = OH_IPCParcel_Create();
    EXPECT_NE(parcel, nullptr);
    const char *token = "hello, world!";
    EXPECT_EQ(OH_IPCParcel_WriteInterfaceToken(nullptr, token), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_WriteInterfaceToken(parcel, nullptr), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_WriteInterfaceToken(parcel, token), OH_IPC_SUCCESS);
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
    EXPECT_EQ(strcmp(token, data), 0);
    EXPECT_EQ(realLen, strlen(token) + 1);
    // destroy object
    if (data) {
        delete data;
    }
    OH_IPCParcel_Destroy(parcel);
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_TestReadWriteStringPerformance_001, TestSize.Level1)
{
    uint32_t writeAvg = 0;
    uint32_t readAvg = 0;
    uint32_t writeCppAvg = 0;
    uint32_t readCppAvg = 0;
    for (int i = 0; i < TEST_PERFORMANCE_OPERATOR_GROUP; ++i) {
        PerformanceResult writeResult;
        PerformanceResult readResult;
        PerformanceResult writeCppResult;
        PerformanceResult readCppResult;
        ReadWriteStringPerformance(writeResult, readResult, writeCppResult, readCppResult);

        writeAvg += writeResult.average;
        readAvg += readResult.average;
        writeCppAvg += writeCppResult.average;
        readCppAvg += readCppResult.average;

        std::cout << "Test String len:" << TEST_PARCEL_SIZE << ", count:"
            << TEST_PERFORMANCE_OPERATOR_COUNT << std::endl;
        std::cout << "OHIPCParcel WriteCString spend:[min:" << writeResult.min << ", max:" << writeResult.max
            << ", avg:" << writeResult.average << "]ns" << std::endl;
        std::cout << "MessageParcel WriteCString spend:[min:" << writeCppResult.min << ", max:" << writeCppResult.max
            << ", avg:" << writeCppResult.average << "]ns" << std::endl;
        std::cout << "OHIPCParcel ReadCString spend:[min:" << readResult.min << ", max:" << readResult.max
            << ", avg:" << readResult.average << "]ns" << std::endl;
        std::cout << "MessageParcel ReadCString spend:[min:" << readCppResult.min << ", max:" << readCppResult.max
            << ", avg:" << readCppResult.average << "]ns" << std::endl;
    }
    writeAvg /= TEST_PERFORMANCE_OPERATOR_GROUP;
    readAvg /= TEST_PERFORMANCE_OPERATOR_GROUP;
    writeCppAvg /= TEST_PERFORMANCE_OPERATOR_GROUP;
    readCppAvg /= TEST_PERFORMANCE_OPERATOR_GROUP;
    PerformanceStatistic(writeAvg, readAvg, writeCppAvg, readCppAvg);
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_TestReadWriteBufferPerformance_001, TestSize.Level1)
{
    uint32_t writeAvg = 0;
    uint32_t readAvg = 0;
    uint32_t writeCppAvg = 0;
    uint32_t readCppAvg = 0;
    for (int i = 0; i < TEST_PERFORMANCE_OPERATOR_GROUP; ++i) {
        PerformanceResult writeResult;
        PerformanceResult readResult;
        PerformanceResult writeCppResult;
        PerformanceResult readCppResult;
        ReadWriteBufferPerformance(writeResult, readResult, writeCppResult, readCppResult);

        writeAvg += writeResult.average;
        readAvg += readResult.average;
        writeCppAvg += writeCppResult.average;
        readCppAvg += readCppResult.average;

        std::cout << "Test Buffer len:" << TEST_PARCEL_SIZE << ", count:"
            << TEST_PERFORMANCE_OPERATOR_COUNT << std::endl;
        std::cout << "OHIPCParcel WriteBuffer spend:[min:" << writeResult.min << ", max:" << writeResult.max
            << ", avg:" << writeResult.average << "]ns" << std::endl;
        std::cout << "MessageParcel WriteBuffer spend:[min:" << writeCppResult.min << ", max:" << writeCppResult.max
            << ", avg:" << writeCppResult.average << "]ns" << std::endl;
        std::cout << "OHIPCParcel ReadBuffer spend:[min:" << readResult.min << ", max:" << readResult.max
            << ", avg:" << readResult.average << "]ns" << std::endl;
        std::cout << "MessageParcel ReadBuffer spend:[min:" << readCppResult.min << ", max:" << readCppResult.max
            << ", avg:" << readCppResult.average << "]ns" << std::endl;
    }
    writeAvg /= TEST_PERFORMANCE_OPERATOR_GROUP;
    readAvg /= TEST_PERFORMANCE_OPERATOR_GROUP;
    writeCppAvg /= TEST_PERFORMANCE_OPERATOR_GROUP;
    readCppAvg /= TEST_PERFORMANCE_OPERATOR_GROUP;
    PerformanceStatistic(writeAvg, readAvg, writeCppAvg, readCppAvg);
}

HWTEST_F(IpcCApiParcelUnitTest, OH_IPCParcel_TestReadWriteInterfaceTokenPerformance_001, TestSize.Level1)
{
    uint32_t writeAvg = 0;
    uint32_t readAvg = 0;
    uint32_t writeCppAvg = 0;
    uint32_t readCppAvg = 0;
    for (int i = 0; i < TEST_PERFORMANCE_OPERATOR_GROUP; ++i) {
        PerformanceResult writeResult;
        PerformanceResult readResult;
        PerformanceResult writeCppResult;
        PerformanceResult readCppResult;
        ReadWriteInterfaceTokenPerformance(writeResult, readResult, writeCppResult, readCppResult);

        writeAvg += writeResult.average;
        readAvg += readResult.average;
        writeCppAvg += writeCppResult.average;
        readCppAvg += readCppResult.average;

        std::cout << "Test token len:" << MAX_INTERFACE_TOKEN_LEN << ", count:"
            << TEST_PERFORMANCE_OPERATOR_COUNT << std::endl;
        std::cout << "OHIPCParcel WriteInterfaceToken spend:[min:" << writeResult.min << ", max:"
            << writeResult.max << ", avg:" << writeResult.average << "]ns" << std::endl;
        std::cout << "MessageParcel WriteInterfaceToken spend:[min:" << writeCppResult.min
            << ", max:" << writeCppResult.max << ", avg:" << writeCppResult.average << "]ns" << std::endl;
        std::cout << "OHIPCParcel ReadInterfaceToken spend:[min:" << readResult.min << ", max:"
            << readResult.max << ", avg:" << readResult.average << "]ns" << std::endl;
        std::cout << "MessageParcel ReadInterfaceToken spend:[min:" << readCppResult.min << ", max:"
            << readCppResult.max << ", avg:" << readCppResult.average << "]ns" << std::endl;
    }
    writeAvg /= TEST_PERFORMANCE_OPERATOR_GROUP;
    readAvg /= TEST_PERFORMANCE_OPERATOR_GROUP;
    writeCppAvg /= TEST_PERFORMANCE_OPERATOR_GROUP;
    readCppAvg /= TEST_PERFORMANCE_OPERATOR_GROUP;
    PerformanceStatistic(writeAvg, readAvg, writeCppAvg, readCppAvg);
}
