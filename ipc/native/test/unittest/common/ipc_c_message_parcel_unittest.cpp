/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include <refbase.h>
#include <securec.h>
#include "c_ashmem.h"
#include "c_parcel.h"
#include "c_parcel_internal.h"
#include <fcntl.h>

using namespace testing::ext;
using namespace OHOS;

static const int NUMBER_CONSTANT = 100;
static const float FLOAT_CONSTANT = 1.1;
static const char *STRING_CONSTATN = "HELLO";

class IpcCMessageParcelUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void IpcCMessageParcelUnitTest::SetUpTestCase()
{}

void IpcCMessageParcelUnitTest::TearDownTestCase()
{}

void IpcCMessageParcelUnitTest::SetUp()
{}

void IpcCMessageParcelUnitTest::TearDown()
{}

static bool CParcelBytesAllocatorOk(void *stringData, char **buffer, int32_t len)
{
    if (buffer == nullptr || len < 0) {
        return false;
    }
    if (len != 0) {
        *buffer = (char *)malloc(len);
        if (*buffer == nullptr) {
            return false;
        }
        (void)memset_s(*buffer, len, 0, len);
    }
    void **ptr = reinterpret_cast<void **>(stringData);
    if (ptr != nullptr) {
        *ptr = *buffer;
    }
    return true;
}

static bool CParcelBytesAllocatorErr(void *stringData, char **buffer, int32_t len)
{
    (void)stringData;
    (void)buffer;
    (void)len;
    return false;
}

/**
 * @tc.name: CParcelRefCount
 * @tc.desc: Verify the CParcel reference count functions
 * @tc.type: FUNC
 */
HWTEST_F(IpcCMessageParcelUnitTest, CParcelRefCount, TestSize.Level1)
{
    CParcel *parcel = CParcelObtain();
    EXPECT_NE(parcel, nullptr);
    RefBase *ref = static_cast<RefBase *>(parcel);
    EXPECT_EQ(ref->GetSptrRefCount(), 1);
    CParcelIncStrongRef(parcel);
    EXPECT_EQ(ref->GetSptrRefCount(), 2);
    CParcelDecStrongRef(parcel);
    EXPECT_EQ(ref->GetSptrRefCount(), 1);
    CParcelIncStrongRef(nullptr);
    CParcelDecStrongRef(nullptr);
    // destroy the CParcel object
    CParcelDecStrongRef(parcel);
}

/**
 * @tc.name: CParcelBool
 * @tc.desc: Verify the CParcel for bool type functions
 * @tc.type: FUNC
 */
HWTEST_F(IpcCMessageParcelUnitTest, CParcelBool, TestSize.Level1)
{
    CParcel *parcel = CParcelObtain();
    EXPECT_NE(parcel, nullptr);
    EXPECT_EQ(CParcelWriteBool(nullptr, true), false);
    EXPECT_EQ(CParcelWriteBool(parcel, false), true);
    EXPECT_EQ(CParcelWriteBool(parcel, true), true);
    bool bool_val = true;
    EXPECT_EQ(CParcelReadBool(nullptr, &bool_val), false);
    EXPECT_EQ(CParcelReadBool(parcel, nullptr), false);
    EXPECT_EQ(CParcelReadBool(parcel, &bool_val), true);
    EXPECT_EQ(bool_val, false);
    EXPECT_EQ(CParcelReadBool(parcel, &bool_val), true);
    EXPECT_EQ(bool_val, true);
    // destroy the CParcel object
    CParcelDecStrongRef(parcel);
}

/**
 * @tc.name: CParcelInt8
 * @tc.desc: Verify the CParcel for int8_t type functions
 * @tc.type: FUNC
 */
HWTEST_F(IpcCMessageParcelUnitTest, CParcelInt8, TestSize.Level1)
{
    CParcel *parcel = CParcelObtain();
    EXPECT_NE(parcel, nullptr);
    int8_t int8_val = static_cast<int8_t>(NUMBER_CONSTANT);
    EXPECT_EQ(CParcelWriteInt8(nullptr, int8_val), false);
    EXPECT_EQ(CParcelWriteInt8(parcel, int8_val), true);
    EXPECT_EQ(CParcelReadInt8(nullptr, &int8_val), false);
    EXPECT_EQ(CParcelReadInt8(parcel, nullptr), false);
    EXPECT_EQ(CParcelReadInt8(parcel, &int8_val), true);
    EXPECT_EQ(int8_val, static_cast<int8_t>(NUMBER_CONSTANT));
    // destroy the CParcel object
    CParcelDecStrongRef(parcel);
}

/**
 * @tc.name: CParcelInt16
 * @tc.desc: Verify the CParcel for int16_t type functions
 * @tc.type: FUNC
 */
HWTEST_F(IpcCMessageParcelUnitTest, CParcelInt16, TestSize.Level1)
{
    CParcel *parcel = CParcelObtain();
    EXPECT_NE(parcel, nullptr);
    int16_t int16_val = static_cast<int16_t>(NUMBER_CONSTANT);
    EXPECT_EQ(CParcelWriteInt16(nullptr, int16_val), false);
    EXPECT_EQ(CParcelWriteInt16(parcel, int16_val), true);
    EXPECT_EQ(CParcelReadInt16(nullptr, &int16_val), false);
    EXPECT_EQ(CParcelReadInt16(parcel, nullptr), false);
    EXPECT_EQ(CParcelReadInt16(parcel, &int16_val), true);
    EXPECT_EQ(int16_val, static_cast<int16_t>(NUMBER_CONSTANT));
    // destroy the CParcel object
    CParcelDecStrongRef(parcel);
}

/**
 * @tc.name: CParcelInt32
 * @tc.desc: Verify the CParcel for int32_t type functions
 * @tc.type: FUNC
 */
HWTEST_F(IpcCMessageParcelUnitTest, CParcelInt32, TestSize.Level1)
{
    CParcel *parcel = CParcelObtain();
    EXPECT_NE(parcel, nullptr);
    int32_t int32_val = static_cast<int32_t>(NUMBER_CONSTANT);
    EXPECT_EQ(CParcelWriteInt32(nullptr, int32_val), false);
    EXPECT_EQ(CParcelWriteInt32(parcel, int32_val), true);
    EXPECT_EQ(CParcelReadInt32(nullptr, &int32_val), false);
    EXPECT_EQ(CParcelReadInt32(parcel, nullptr), false);
    EXPECT_EQ(CParcelReadInt32(parcel, &int32_val), true);
    EXPECT_EQ(int32_val, static_cast<int32_t>(NUMBER_CONSTANT));
    // destroy the CParcel object
    CParcelDecStrongRef(parcel);
}

/**
 * @tc.name: CParcelInt64
 * @tc.desc: Verify the CParcel for int32_t type functions
 * @tc.type: FUNC
 */
HWTEST_F(IpcCMessageParcelUnitTest, CParcelInt64, TestSize.Level1)
{
    CParcel *parcel = CParcelObtain();
    EXPECT_NE(parcel, nullptr);
    int64_t int64_val = static_cast<int64_t>(NUMBER_CONSTANT);
    EXPECT_EQ(CParcelWriteInt64(nullptr, int64_val), false);
    EXPECT_EQ(CParcelWriteInt64(parcel, int64_val), true);
    EXPECT_EQ(CParcelReadInt64(nullptr, &int64_val), false);
    EXPECT_EQ(CParcelReadInt64(parcel, nullptr), false);
    EXPECT_EQ(CParcelReadInt64(parcel, &int64_val), true);
    EXPECT_EQ(int64_val, static_cast<int64_t>(NUMBER_CONSTANT));
    // destroy the CParcel object
    CParcelDecStrongRef(parcel);
}

/**
 * @tc.name: CParcelFloat
 * @tc.desc: Verify the CParcel for float type functions
 * @tc.type: FUNC
 */
HWTEST_F(IpcCMessageParcelUnitTest, CParcelFloat, TestSize.Level1)
{
    CParcel *parcel = CParcelObtain();
    EXPECT_NE(parcel, nullptr);
    float float_val = static_cast<float>(FLOAT_CONSTANT);
    EXPECT_EQ(CParcelWriteFloat(nullptr, float_val), false);
    EXPECT_EQ(CParcelWriteFloat(parcel, float_val), true);
    EXPECT_EQ(CParcelReadFloat(nullptr, &float_val), false);
    EXPECT_EQ(CParcelReadFloat(parcel, nullptr), false);
    EXPECT_EQ(CParcelReadFloat(parcel, &float_val), true);
    EXPECT_TRUE(abs(float_val - static_cast<float>(FLOAT_CONSTANT)) < 0.0001);
    // destroy the CParcel object
    CParcelDecStrongRef(parcel);
}

/**
 * @tc.name: CParcelDouble
 * @tc.desc: Verify the CParcel for double type functions
 * @tc.type: FUNC
 */
HWTEST_F(IpcCMessageParcelUnitTest, CParcelDouble, TestSize.Level1)
{
    CParcel *parcel = CParcelObtain();
    EXPECT_NE(parcel, nullptr);
    double double_val = static_cast<double>(FLOAT_CONSTANT);
    EXPECT_EQ(CParcelWriteDouble(nullptr, double_val), false);
    EXPECT_EQ(CParcelWriteDouble(parcel, double_val), true);
    EXPECT_EQ(CParcelReadDouble(nullptr, &double_val), false);
    EXPECT_EQ(CParcelReadDouble(parcel, nullptr), false);
    EXPECT_EQ(CParcelReadDouble(parcel, &double_val), true);
    EXPECT_TRUE(abs(double_val - static_cast<double>(FLOAT_CONSTANT)) < 0.0001);
    // destroy the CParcel object
    CParcelDecStrongRef(parcel);
}

/**
 * @tc.name: CParcelString001
 * @tc.desc: Verify the CParcel for string type functions
 * @tc.type: FUNC
 */
HWTEST_F(IpcCMessageParcelUnitTest, CParcelString001, TestSize.Level1)
{
    CParcel *parcel = CParcelObtain();
    EXPECT_NE(parcel, nullptr);
    void *data = nullptr;
    EXPECT_EQ(CParcelReadString(parcel, reinterpret_cast<void *>(&data), CParcelBytesAllocatorOk), false);

    EXPECT_EQ(CParcelWriteString(nullptr, STRING_CONSTATN, strlen(STRING_CONSTATN)), false);
    EXPECT_EQ(CParcelWriteString(parcel, nullptr, strlen(STRING_CONSTATN)), false);
    EXPECT_EQ(CParcelWriteString(parcel, STRING_CONSTATN, -1), false);
    EXPECT_EQ(CParcelWriteString(parcel, STRING_CONSTATN, strlen(STRING_CONSTATN)), true);
    EXPECT_EQ(CParcelWriteString(parcel, nullptr, -1), true);

    EXPECT_EQ(CParcelReadString(nullptr, reinterpret_cast<void *>(&data), nullptr), false);
    EXPECT_EQ(CParcelReadString(parcel, reinterpret_cast<void *>(&data), CParcelBytesAllocatorOk), true);
    EXPECT_EQ(strncmp((reinterpret_cast<char *>(data)), STRING_CONSTATN, strlen(STRING_CONSTATN)), 0);
    if (data != nullptr) {
        free(data);
    }
    // destroy the CParcel object
    CParcelDecStrongRef(parcel);
}

/**
 * @tc.name: CParcelString002
 * @tc.desc: Verify the CParcel for string type functions
 * @tc.type: FUNC
 */
HWTEST_F(IpcCMessageParcelUnitTest, CParcelString002, TestSize.Level1)
{
    CParcel *parcel = CParcelObtain();
    EXPECT_NE(parcel, nullptr);
    EXPECT_EQ(CParcelWriteString(parcel, STRING_CONSTATN, strlen(STRING_CONSTATN)), true);
    void *data = nullptr;
    EXPECT_EQ(CParcelReadString(parcel, reinterpret_cast<void *>(&data), CParcelBytesAllocatorErr), false);
    // destroy the CParcel object
    CParcelDecStrongRef(parcel);
}

/**
 * @tc.name: CParcelString16001
 * @tc.desc: Verify the CParcel for string16 type functions
 * @tc.type: FUNC
 */
HWTEST_F(IpcCMessageParcelUnitTest, CParcelString16001, TestSize.Level1)
{
    CParcel *parcel = CParcelObtain();
    EXPECT_NE(parcel, nullptr);
    void *data = nullptr;
    EXPECT_EQ(CParcelReadString16(parcel, reinterpret_cast<void *>(&data), CParcelBytesAllocatorOk), false);

    EXPECT_EQ(CParcelWriteString16(nullptr, STRING_CONSTATN, strlen(STRING_CONSTATN)), false);
    EXPECT_EQ(CParcelWriteString16(parcel, nullptr, strlen(STRING_CONSTATN)), false);
    EXPECT_EQ(CParcelWriteString16(parcel, STRING_CONSTATN, -1), false);
    EXPECT_EQ(CParcelWriteString16(parcel, STRING_CONSTATN, strlen(STRING_CONSTATN)), true);
    EXPECT_EQ(CParcelWriteString16(parcel, nullptr, -1), true);

    EXPECT_EQ(CParcelReadString16(nullptr, reinterpret_cast<void *>(&data), nullptr), false);
    EXPECT_EQ(CParcelReadString16(parcel, reinterpret_cast<void *>(&data), CParcelBytesAllocatorOk), true);
    EXPECT_EQ(strncmp((reinterpret_cast<char *>(data)), STRING_CONSTATN, strlen(STRING_CONSTATN)), 0);
    if (data != nullptr) {
        free(data);
    }
    // destroy the CParcel object
    CParcelDecStrongRef(parcel);
}

/**
 * @tc.name: CParcelString16002
 * @tc.desc: Verify the CParcel for string16 type functions
 * @tc.type: FUNC
 */
HWTEST_F(IpcCMessageParcelUnitTest, CParcelString16002, TestSize.Level1)
{
    CParcel *parcel = CParcelObtain();
    EXPECT_NE(parcel, nullptr);
    EXPECT_EQ(CParcelWriteString16(parcel, STRING_CONSTATN, strlen(STRING_CONSTATN)), true);
    void *data = nullptr;
    EXPECT_EQ(CParcelReadString16(parcel, reinterpret_cast<void *>(&data), CParcelBytesAllocatorErr), false);
    // destroy the CParcel object
    CParcelDecStrongRef(parcel);
}

/**
 * @tc.name: CParcelInterfaceToken001
 * @tc.desc: Verify the CParcel for interface token functions
 * @tc.type: FUNC
 */
HWTEST_F(IpcCMessageParcelUnitTest, CParcelInterfaceToken001, TestSize.Level1)
{
    CParcel *parcel = CParcelObtain();
    EXPECT_NE(parcel, nullptr);
    void *data = nullptr;

    EXPECT_EQ(CParcelWriteInterfaceToken(nullptr, STRING_CONSTATN, strlen(STRING_CONSTATN)), false);
    EXPECT_EQ(CParcelWriteInterfaceToken(parcel, nullptr, strlen(STRING_CONSTATN)), false);
    EXPECT_EQ(CParcelWriteInterfaceToken(parcel, STRING_CONSTATN, strlen(STRING_CONSTATN)), true);

    EXPECT_EQ(CParcelReadInterfaceToken(nullptr, reinterpret_cast<void *>(&data), nullptr), false);
    EXPECT_EQ(CParcelReadInterfaceToken(parcel, reinterpret_cast<void *>(&data), CParcelBytesAllocatorOk), true);
    EXPECT_EQ(strncmp((reinterpret_cast<char *>(data)), STRING_CONSTATN, strlen(STRING_CONSTATN)), 0);
    if (data != nullptr) {
        free(data);
    }
    // destroy the CParcel object
    CParcelDecStrongRef(parcel);
}

/**
 * @tc.name: CParcelInterfaceToken002
 * @tc.desc: Verify the CParcel for interface token functions
 * @tc.type: FUNC
 */
HWTEST_F(IpcCMessageParcelUnitTest, CParcelInterfaceToken002, TestSize.Level1)
{
    CParcel *parcel = CParcelObtain();
    EXPECT_NE(parcel, nullptr);
    EXPECT_EQ(CParcelWriteInterfaceToken(parcel, STRING_CONSTATN, strlen(STRING_CONSTATN)), true);
    void *data = nullptr;
    EXPECT_EQ(CParcelReadInterfaceToken(parcel, reinterpret_cast<void *>(&data), CParcelBytesAllocatorErr), false);
    // destroy the CParcel object
    CParcelDecStrongRef(parcel);
}

/**
 * @tc.name: CParcelFileDescriptor
 * @tc.desc: Verify the CParcel for file descriptor functions
 * @tc.type: FUNC
 */
HWTEST_F(IpcCMessageParcelUnitTest, CParcelFileDescriptor, TestSize.Level1)
{
    CParcel *parcel = CParcelObtain();
    EXPECT_NE(parcel, nullptr);

    int32_t fd = open("/dev/null", O_RDONLY);
    EXPECT_TRUE(fd >= 0);
    EXPECT_EQ(CParcelWriteFileDescriptor(nullptr, fd), false);
    EXPECT_EQ(CParcelWriteFileDescriptor(parcel, fd), true);

    int32_t ret_fd;
    EXPECT_EQ(CParcelReadFileDescriptor(nullptr, &ret_fd), false);
    EXPECT_EQ(CParcelReadFileDescriptor(parcel, nullptr), false);
    EXPECT_EQ(CParcelReadFileDescriptor(parcel, &ret_fd), true);
    EXPECT_TRUE(ret_fd > 0);
    close(fd);
    close(ret_fd);
    // destroy the CParcel object
    CParcelDecStrongRef(parcel);
}

/**
 * @tc.name: CParcelDataInfoNullCheck
 * @tc.desc: Verify the CParcel data info null check
 * @tc.type: FUNC
 */
HWTEST_F(IpcCMessageParcelUnitTest, CParcelDataInfoNullCheck, TestSize.Level1)
{
    EXPECT_EQ(CParcelGetDataSize(nullptr), 0);
    EXPECT_EQ(CParcelSetDataSize(nullptr, 0), false);
    EXPECT_EQ(CParcelGetDataCapacity(nullptr), 0);
    EXPECT_EQ(CParcelSetDataCapacity(nullptr, 0), false);
    EXPECT_EQ(CParcelGetMaxCapacity(nullptr), 0);
    EXPECT_EQ(CParcelSetMaxCapacity(nullptr, 0), false);
    EXPECT_EQ(CParcelGetWritableBytes(nullptr), 0);
    EXPECT_EQ(CParcelGetReadableBytes(nullptr), 0);
    EXPECT_EQ(CParcelGetReadPosition(nullptr), 0);
    EXPECT_EQ(CParcelGetWritePosition(nullptr), 0);
    EXPECT_EQ(CParcelRewindRead(nullptr, 0), false);
    EXPECT_EQ(CParcelRewindWrite(nullptr, 0), false);
}

/**
 * @tc.name: CParcelDataInfo
 * @tc.desc: Verify the CParcel data info functions
 * @tc.type: FUNC
 */
HWTEST_F(IpcCMessageParcelUnitTest, CParcelDataInfo, TestSize.Level1)
{
    CParcel *parcel = CParcelObtain();
    EXPECT_NE(parcel, nullptr);

    uint32_t maxCapacity = CParcelGetMaxCapacity(parcel);
    EXPECT_TRUE(maxCapacity > 0);
    EXPECT_TRUE(CParcelSetMaxCapacity(parcel, maxCapacity + 1));
    EXPECT_EQ(CParcelGetMaxCapacity(parcel), maxCapacity + 1);
    EXPECT_EQ(CParcelGetDataSize(parcel), 0);
    EXPECT_EQ(CParcelGetDataCapacity(parcel), 0);
    EXPECT_EQ(CParcelGetWritableBytes(parcel), 0);
    EXPECT_EQ(CParcelGetReadableBytes(parcel), 0);
    EXPECT_EQ(CParcelGetReadPosition(parcel), 0);
    EXPECT_EQ(CParcelGetWritePosition(parcel), 0);

    EXPECT_TRUE(CParcelWriteInt32(parcel, 0));
    uint32_t dataSize = CParcelGetDataSize(parcel);
    EXPECT_TRUE(dataSize > 0);
    EXPECT_TRUE(CParcelGetDataCapacity(parcel) > 0);
    EXPECT_TRUE(CParcelGetWritableBytes(parcel) > 0);
    EXPECT_TRUE(CParcelGetReadableBytes(parcel) > 0);
    EXPECT_TRUE(CParcelGetReadPosition(parcel) == 0);
    EXPECT_TRUE(CParcelGetWritePosition(parcel) > 0);

    int32_t value;
    EXPECT_TRUE(CParcelReadInt32(parcel, &value));
    EXPECT_EQ(CParcelGetReadableBytes(parcel), 0);
    EXPECT_TRUE(CParcelGetReadPosition(parcel) > 0);

    EXPECT_TRUE(CParcelSetDataSize(parcel, dataSize - 1));
    EXPECT_TRUE(CParcelSetDataCapacity(parcel, dataSize + 1));
    EXPECT_TRUE(CParcelRewindRead(parcel, 0));
    EXPECT_TRUE(CParcelRewindWrite(parcel, 0));
    EXPECT_EQ(CParcelGetDataSize(parcel), 0);
    EXPECT_TRUE(CParcelGetDataCapacity(parcel) > 0);
    EXPECT_TRUE(CParcelGetWritableBytes(parcel) > 0);
    EXPECT_TRUE(CParcelGetReadableBytes(parcel) == 0);
    EXPECT_TRUE(CParcelGetReadPosition(parcel) == 0);
    EXPECT_TRUE(CParcelGetWritePosition(parcel) == 0);

    CParcelDecStrongRef(parcel);
}

/**
 * @tc.name: CParcelContainFileDescriptors
 * @tc.desc: Verify whether there is fd with this description
 * @tc.type: FUNC
 */
HWTEST_F(IpcCMessageParcelUnitTest, CParcelContainFileDescriptors, TestSize.Level1)
{
    CParcel *parcel = CParcelObtain();
    EXPECT_NE(parcel, nullptr);
    CParcelContainFileDescriptors(parcel);
    EXPECT_EQ(CParcelGetRawDataSize(parcel), 0);
    CParcelDecStrongRef(parcel);
}

/**
 * @tc.name: CParcelClearFileDescriptor
 * @tc.desc: Verify clear fd by this description
 * @tc.type: FUNC
 */
HWTEST_F(IpcCMessageParcelUnitTest, CParcelClearFileDescriptor, TestSize.Level1)
{
    CParcel *parcel = CParcelObtain();
    EXPECT_NE(parcel, nullptr);
    CParcelClearFileDescriptor(parcel);
    EXPECT_EQ(CParcelGetRawDataSize(parcel), 0);
    CParcelDecStrongRef(parcel);
}

/**
 * @tc.name: CParcelGetRawDataSize
 * @tc.desc: Get raw data size
 * @tc.type: FUNC
 */
HWTEST_F(IpcCMessageParcelUnitTest, CParcelGetRawDataSize, TestSize.Level1)
{
    CParcel *parcel = CParcelObtain();
    EXPECT_NE(parcel, nullptr);
    EXPECT_EQ(CParcelGetRawDataSize(parcel), 0);
    CParcelDecStrongRef(parcel);
}

/**
 * @tc.name: CParcelGetRawDataCapacity
 * @tc.desc: Get raw data capacity
 * @tc.type: FUNC
 */
HWTEST_F(IpcCMessageParcelUnitTest, CParcelGetRawDataCapacity, TestSize.Level1)
{
    CParcel *parcel = CParcelObtain();
    EXPECT_NE(parcel, nullptr);
    EXPECT_EQ(CParcelGetRawDataCapacity(parcel), 128 * 1024 * 1024);
    CParcelDecStrongRef(parcel);
}

/**
 * @tc.name: CParcelSetClearFdFlag
 * @tc.desc: Verify set clear fd flag
 * @tc.type: FUNC
 */
HWTEST_F(IpcCMessageParcelUnitTest, CParcelSetClearFdFlag, TestSize.Level1)
{
    CParcel *parcel = CParcelObtain();
    EXPECT_NE(parcel, nullptr);
    CParcelSetClearFdFlag(parcel);
    CParcelDecStrongRef(parcel);
}

/**
 * @tc.name: CParcelAppend
 * @tc.desc: Verify Whether the parcel is appended successfully
 * @tc.type: FUNC
 */
HWTEST_F(IpcCMessageParcelUnitTest, CParcelAppend, TestSize.Level1)
{
    CParcel *parcel = CParcelObtain();
    EXPECT_NE(parcel, nullptr);
    CParcel *parcel2= CParcelObtain();
    EXPECT_NE(parcel, nullptr);
    EXPECT_EQ(CParcelAppend(parcel, parcel2), true);
    CParcelDecStrongRef(parcel);
    CParcelDecStrongRef(parcel2);
}

/**
 * @tc.name: ReadAndWriteAshmemTest
 * @tc.desc: Verify the read and write ashmem function
 * @tc.type: FUNC
 */
HWTEST_F(IpcCMessageParcelUnitTest, ReadAndWriteAshmemTest, TestSize.Level1)
{
    CParcel *parcel = CParcelObtain();
    EXPECT_NE(parcel, nullptr);

    std::string name = "AshmemIpc";
    std::string ashmemString = "HelloWorld2023";
    CAshmem *ashmem = CreateCAshmem(name.c_str(), 1024);
    ASSERT_TRUE(ashmem != nullptr);
    EXPECT_EQ(MapReadAndWriteCAshmem(ashmem), true);
    EXPECT_EQ(WriteToCAshmem(ashmem, const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(ashmemString.c_str())),
        strlen(ashmemString.c_str()), 0), true);
    EXPECT_EQ(CParcelWriteAshmem(parcel, ashmem), true);
    EXPECT_EQ(CParcelRewindRead(parcel, 0), true);

    CAshmem *ashmem2 = CParcelReadAshmem(parcel);
    ASSERT_TRUE(ashmem2 != nullptr);
    ASSERT_TRUE(MapReadOnlyCAshmem(ashmem2));
    const void *content = ReadFromCAshmem(ashmem2, strlen(ashmemString.c_str()), 0);
    ASSERT_TRUE(content != nullptr);

    auto readContent = static_cast<const char *>(content);
    std::string str(readContent, strlen(ashmemString.c_str()));
    EXPECT_EQ(str, ashmemString);

    UnmapCAshmem(ashmem);
    CloseCAshmem(ashmem);
    UnmapCAshmem(ashmem2);
    CloseCAshmem(ashmem2);
}
