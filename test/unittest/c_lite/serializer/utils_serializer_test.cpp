/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <iostream>
#include <unistd.h>
#include <csignal>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "serializer.h"

using namespace testing::ext;
using namespace std;

const int BUFFER_SIZE = 200;
const int SMALL_BUFFER_SIZE = 100;

class UtilsSerializerTest : public testing::Test {
public:
    static void SetUpTestCase() { }
    static void TearDownTestCase() { }
    void SetUp() { }
    void TearDown() { }
};
struct TestData {
    bool boolTest;
    int8_t int8Test;
    int16_t int16Test;
    int32_t int32Test;
    uint8_t uint8Test;
    uint16_t uint16Test;
    uint32_t uint32Test;
};
struct Padded {
    char title;
    int32_t handle;
    uint64_t cookie;
};
struct Unpadded {
    char tip;
};

void WriteTestData(IpcIo* io, const struct TestData &data)
{
    bool result = false;

    result = WriteBool(io, data.boolTest);
    EXPECT_EQ(result, true);

    result = WriteInt8(io, data.int8Test);
    EXPECT_EQ(result, true);

    result = WriteInt16(io, data.int16Test);
    EXPECT_EQ(result, true);

    result = WriteInt32(io, data.int32Test);
    EXPECT_EQ(result, true);

    result = WriteUint8(io, data.uint8Test);
    EXPECT_EQ(result, true);

    result = WriteUint16(io, data.uint16Test);
    EXPECT_EQ(result, true);

    result = WriteUint32(io, data.uint32Test);
    EXPECT_EQ(result, true);
}

void ReadTestData(IpcIo* io, const struct TestData &data)
{
    bool boolVal;
    bool result = ReadBool(io, &boolVal);
    EXPECT_EQ(result, true);
    EXPECT_EQ(boolVal, data.boolTest);

    int8_t int8Val;
    result = ReadInt8(io, &int8Val);
    EXPECT_EQ(result, true);
    EXPECT_EQ(int8Val, data.int8Test);

    int16_t int16Val;
    result = ReadInt16(io, &int16Val);
    EXPECT_EQ(result, true);
    EXPECT_EQ(int16Val, data.int16Test);

    int32_t int32Val;
    result = ReadInt32(io, &int32Val);
    EXPECT_EQ(result, true);
    EXPECT_EQ(int32Val, data.int32Test);

    uint8_t uint8Val;
    result = ReadUint8(io, &uint8Val);
    EXPECT_EQ(result, true);
    EXPECT_EQ(uint8Val, data.uint8Test);

    uint16_t uint16Val;
    result = ReadUint16(io, &uint16Val);
    EXPECT_EQ(result, true);
    EXPECT_EQ(uint16Val, data.uint16Test);

    uint32_t uint32Val;
    result = ReadUint32(io, &uint32Val);
    EXPECT_EQ(result, true);
    EXPECT_EQ(uint32Val, data.uint32Test);
}

/**
 * @tc.name: test_serializer_WriteAndRead_001
 * @tc.desc: test serializer primary type read write.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_001, TestSize.Level0)
{
    uint8_t buffer[BUFFER_SIZE] = {0};
    int pid = -1;
    int ret = -1;
    int fd[2];

    if (pipe(fd) < 0) {
        perror("pipe error!\n");
        return;
    }

    struct TestData data = { true, -0x34, 0x5634, -0x12345678, 0x34, 0x5634, 0x12345678 };
    pid = fork();
    if (pid < 0) {
        return;
    }
    else if (pid == 0) {
        close(fd[0]);
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);

        WriteTestData(&io, data);
        ret = write(fd[1], buffer, io.bufferCur - io.bufferBase);
        sleep(1);
        close(fd[1]);
        _exit(pid);

    } else {
        close(fd[1]);

        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);

        sleep(2);
        ret = read(fd[0], buffer, BUFFER_SIZE);

        ReadTestData(&io, data);
        close(fd[0]);
    }
}

void WriteTestDataUnaligned(IpcIo* io, const struct TestData &data)
{
    bool result = false;

    result = WriteBoolUnaligned(io, data.boolTest);
    EXPECT_EQ(result, true);

    result = WriteInt8Unaligned(io, data.int8Test);
    EXPECT_EQ(result, true);

    result = WriteInt16Unaligned(io, data.int16Test);
    EXPECT_EQ(result, true);

    result = WriteUint8Unaligned(io, data.uint8Test);
    EXPECT_EQ(result, true);

    result = WriteUint16Unaligned(io, data.uint16Test);
    EXPECT_EQ(result, true);
}

void ReadTestDataUnaligned(IpcIo* io, const struct TestData &data)
{
    bool result = false;

    bool boolVal;
    result = ReadBoolUnaligned(io, &boolVal);
    EXPECT_EQ(boolVal, data.boolTest);

    int8_t int8Val;
    result = ReadInt8Unaligned(io, &int8Val);
    EXPECT_EQ(result, true);
    EXPECT_EQ(int8Val, data.int8Test);

    int16_t int16Val;
    result = ReadInt16Unaligned(io, &int16Val);
    EXPECT_EQ(result, true);
    EXPECT_EQ(int16Val, data.int16Test);

    uint8_t uint8Val;
    result = ReadUInt8Unaligned(io, &uint8Val);
    EXPECT_EQ(result, true);
    EXPECT_EQ(uint8Val, data.uint8Test);

    uint16_t uint16Val;
    result = ReadUInt16Unaligned(io, &uint16Val);
    EXPECT_EQ(result, true);
    EXPECT_EQ(uint16Val, data.uint16Test);
}

/**
 * @tc.name: test_serializer_WriteAndRead_002
 * @tc.desc: test serializer primary type read write.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_002, TestSize.Level0)
{
    uint8_t buffer[BUFFER_SIZE] = {0};
    int pid = -1;
    int ret = -1;
    int fd[2];

    if (pipe(fd) < 0) {
        perror("pipe error!\n");
        return;
    }
    struct TestData data = { true, -0x34, 0x5634, -0x12345678, 0x34, 0x5634, 0x12345678 };
    pid = fork();
    if (pid < 0) {
        return;
    } else if (pid == 0) {
        close(fd[0]);
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);

        WriteTestDataUnaligned(&io, data);
        ret = write(fd[1], buffer, io.bufferCur - io.bufferBase);
        sleep(1);
        close(fd[1]);
        _exit(pid);
    } else {
        close(fd[1]);

        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        sleep(2);
        ret = read(fd[0], buffer, BUFFER_SIZE);
        ReadTestDataUnaligned(&io, data);
        close(fd[0]);
    }
}

/**
 * @tc.name: test_serializer_WriteAndRead_003
 * @tc.desc: test serializer primary type read write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_003, TestSize.Level0)
{
    uint8_t buffer[BUFFER_SIZE] = {0};
    int pid = -1;
    int ret = -1;
    int fd[2];
    if (pipe(fd) < 0) {
        return;
    }
    bool result;
    int64_t int64Test = -0x1234567887654321;
    uint64_t uint64Test = 0x1234567887654321;
    pid = fork();
    if (pid < 0) {
        return;
    }
    else if (pid == 0) {
        close(fd[0]);
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        result = WriteInt64(&io, int64Test);
        EXPECT_EQ(result, true);
        result = WriteUint64(&io, uint64Test);
        EXPECT_EQ(result, true);
        ret = write(fd[1], buffer, io.bufferCur - io.bufferBase);
        sleep(1);
        close(fd[1]);
        _exit(pid);
    } else {
        close(fd[1]);
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        sleep(2);
        ret = read(fd[0], buffer, BUFFER_SIZE);
        int64_t int64Read;
        result = ReadInt64(&io, &int64Read);
        EXPECT_EQ(result, true);
        EXPECT_EQ(int64Read, int64Test);
        uint64_t uint64Read;
        result = ReadUint64(&io, &uint64Read);
        EXPECT_EQ(result, true);
        EXPECT_EQ(uint64Read, uint64Test);
        close(fd[0]);
    }
}

/**
 * @tc.name: test_serializer_String_001
 * @tc.desc: test serializer string read write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_String_001, TestSize.Level0)
{
    uint8_t buffer[BUFFER_SIZE] = {0};
    int pid = -1;
    int ret = -1;
    int fd[2];

    if (pipe(fd) < 0) {
        return;
    }
    bool result;
    const char stringWrite1[] = "asdfgh";
    const char stringWrite2[] = "123456";
    pid = fork();
    if (pid < 0) {
        return;
    } else if (pid == 0) {
        close(fd[0]);
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        result = WriteString(&io, stringWrite1);
        EXPECT_EQ(result, true);
        result = WriteString(&io, stringWrite2);
        EXPECT_EQ(result, true);
        ret = write(fd[1], buffer, io.bufferCur - io.bufferBase);
        sleep(1);
        close(fd[1]);
        _exit(pid);
    } else {
        close(fd[1]);
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        sleep(2);
        ret = read(fd[0], buffer, BUFFER_SIZE);

        uint8_t* stringRead1 = nullptr;
        size_t len;
        stringRead1 = ReadString(&io, &len);
        for (size_t i = 0; i < len; i++) {
            EXPECT_EQ(stringWrite1[i], stringRead1[i]);
        }
        uint8_t* stringRead2 = nullptr;
        stringRead2 = ReadString(&io, &len);
        for (size_t i = 0; i < len; i++) {
            EXPECT_EQ(stringWrite2[i], stringRead2[i]);
        }
        close(fd[0]);
    }
}

/**
 * @tc.name: test_serializer_WriteAndRead_String_002
 * @tc.desc: test serializer string read write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_String_002, TestSize.Level0)
{
    uint8_t buffer[BUFFER_SIZE] = {0};
    int pid = -1;
    int ret = -1;
    int fd[2];
    if (pipe(fd) < 0) {
        return;
    }
    bool result;
    uint16_t str16Write[] = { 0x5634, 0x5635, 0x5636, 0x5637, 0x5638, 0x5639,
    0x5640, 0x5641, 0x5642, 0x5643, 0x5644, 0x5645 };
    size_t length = sizeof(str16Write) / sizeof(uint16_t);
    pid = fork();
    if (pid < 0) {
        return;
    } else if (pid == 0) {
        close(fd[0]);
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        result = WriteString16(&io, str16Write, length);
        EXPECT_EQ(result, true);
        ret = write(fd[1], buffer, io.bufferCur - io.bufferBase);
        sleep(1);
        close(fd[1]);
        _exit(pid);
    } else {
        close(fd[1]);
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        sleep(2);
        ret = read(fd[0], buffer, BUFFER_SIZE);

        uint16_t* str16Read = nullptr;
        str16Read = ReadString16(&io, &length);
        for (size_t i = 0; i < length; i++) {
            EXPECT_EQ(str16Write[i], str16Read[i]);
        }
        close(fd[0]);
    }
}

/**
 * @tc.name: test_serializer_WriteAndRead_Float_001
 * @tc.desc: test serializer float and double types read write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_Float_001, TestSize.Level0)
{
    uint8_t buffer[BUFFER_SIZE] = {0};
    int pid = -1;
    int ret = -1;
    int fd[2];
    if (pipe(fd) < 0) {
        return;
    }
    bool result;
    float floatWrite = 12.345678f;
    double doubleWrite = 1345.7653;
    pid = fork();
    if (pid < 0) {
        return;
    } else if (pid == 0) {
        close(fd[0]);
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        result = WriteFloat(&io, floatWrite);
        EXPECT_EQ(result, true);
        result = WriteDouble(&io, doubleWrite);
        EXPECT_EQ(result, true);
        ret = write(fd[1], buffer, io.bufferCur - io.bufferBase);
        sleep(1);
        close(fd[1]);
        _exit(pid);
    } else {
        close(fd[1]);
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        sleep(2);
        ret = read(fd[0], buffer, BUFFER_SIZE);

        float floatRead;
        result = ReadFloat(&io, &floatRead);
        EXPECT_EQ(result, true);
        EXPECT_EQ(floatWrite, floatRead);
        double doubleRead;
        result = ReadDouble(&io, &doubleRead);
        EXPECT_EQ(doubleWrite, doubleRead);
        close(fd[0]);
    }
}

/**
 * @tc.name: test_serializer_Data_Structure_001
 * @tc.desc: test serializer struct data related function.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_Data_Structure_001, TestSize.Level0)
{
    uint8_t buffer[BUFFER_SIZE] = {0};
    int pid = -1;
    int ret = -1;
    int fd[2];
    if (pipe(fd) < 0) {
        return;
    }
    bool result;
    const struct Padded pad = { 'p', 0x34567890, 0x2345678998765432 };
    const struct Unpadded unpad = { 'u' };
    pid = fork();
    if (pid < 0) {
        return;
    } else if (pid == 0) {
        close(fd[0]);
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);

        result = WriteBuffer(&io, static_cast<const void*>(&pad), sizeof(struct Padded));
        EXPECT_EQ(true, result);
        result = WriteBuffer(&io, static_cast<const void*>(&unpad), sizeof(struct Unpadded));
        EXPECT_EQ(true, result);
        ret = write(fd[1], buffer, io.bufferCur - io.bufferBase);
        sleep(1);
        close(fd[1]);
        _exit(pid);
    } else {
        close(fd[1]);
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        sleep(2);
        ret = read(fd[0], buffer, BUFFER_SIZE);
        const struct Padded* padRead = reinterpret_cast<const struct Padded*>(ReadBuffer(&io, sizeof(struct Padded)));
        EXPECT_EQ(pad.title, padRead->title);
        EXPECT_EQ(pad.handle, padRead->handle);
        EXPECT_EQ(pad.cookie, padRead->cookie);
        const struct Unpadded* unpadRead =
            reinterpret_cast<const struct Unpadded *>(ReadBuffer(&io, sizeof(struct Unpadded)));
        EXPECT_EQ(unpad.tip, unpadRead->tip);
        close(fd[0]);
    }
}

/**
 * @tc.name: test_serializer_WriteAndReadVector_Bool_001
 * @tc.desc: test bool vector serializer write and read.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndReadVector_Bool_001, TestSize.Level0)
{
    uint8_t buffer[BUFFER_SIZE] = {0};
    int pid = -1;
    int ret = -1;
    int fd[2];
    if (pipe(fd) < 0) {
        return;
    }
    bool result;
    const bool boolTest[12] = { true, false, false, true, false, false, true, false, true, true, false, true };
    size_t sizeBool = sizeof(boolTest) / sizeof(bool);
    pid = fork();
    if (pid < 0) {
        return;
    } else if (pid == 0) {
        close(fd[0]);
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        result = WriteBoolVector(&io, boolTest, sizeBool);
        EXPECT_EQ(result, true);
        ret = write(fd[1], buffer, io.bufferCur - io.bufferBase);
        sleep(1);
        close(fd[1]);
        _exit(pid);
    } else {
        close(fd[1]);
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        sleep(2);
        ret = read(fd[0], buffer, BUFFER_SIZE);

        bool* boolRead = nullptr;
        size_t readLen = 0;
        boolRead = ReadBoolVector(&io, &readLen);
        EXPECT_EQ(readLen, sizeBool);
        for (size_t i = 0; i < readLen; i++) {
            EXPECT_EQ(boolTest[i], boolRead[i]);
        }
        free(boolRead);
        close(fd[0]);
    }
}

/**
 * @tc.name: test_serializer_Vector_001
 * @tc.desc: test int8_t and int16_t vector serializer write and read.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_Vector_001, TestSize.Level0)
{
    uint8_t buffer[BUFFER_SIZE] = {0};
    int pid = -1;
    int ret = -1;
    int fd[2];
    if (pipe(fd) < 0) {
        return;
    }
    bool result;
    const int8_t int8Test[12] = { -0x27, -0x28, -0x29, -0x30, 0x31, 0x32, -0x33, -0x34, -0x35, -0x36, -0x37, -0x38 };
    size_t sizeInt8 = sizeof(int8Test) / sizeof(int8_t);
    const int16_t int16Test[12] = { 0x1234, -0x2345, 0x3456, -0x4567, 0x5678,
    -0x1235, 0x1236, 0x1237, 0x1238, -0x1239, 0x1240, 0x1241 };
    size_t sizeInt16 = sizeof(int16Test) / sizeof(int16_t);
    pid = fork();
    if (pid == 0) {
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        result = WriteInt8Vector(&io, int8Test, sizeInt8);
        EXPECT_EQ(result, true);
        result = WriteInt16Vector(&io, int16Test, sizeInt16);
        EXPECT_EQ(result, true);
        ret = write(fd[1], buffer, io.bufferCur - io.bufferBase);
        sleep(1);
        close(fd[1]);
        _exit(pid);
    } else {
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        sleep(2);
        ret = read(fd[0], buffer, BUFFER_SIZE);
        int8_t* int8Read = nullptr;
        size_t readLen = 0;
        int8Read = ReadInt8Vector(&io, &readLen);
        EXPECT_EQ(readLen, sizeInt8);
        for (size_t i = 0; i < readLen; i++) {
            EXPECT_EQ(int8Test[i], int8Read[i]);
        }
        int16_t* int16Read = nullptr;
        int16Read = ReadInt16Vector(&io, &readLen);
        EXPECT_EQ(readLen, sizeInt16);
        for (size_t i = 0; i < readLen; i++) {
            EXPECT_EQ(int16Test[i], int16Read[i]);
        }
        free(int16Read);
        close(fd[0]);
    }
}

/**
 * @tc.name: test_serializer_Vector_002
 * @tc.desc: test int32_t and int64_t vector serializer write and read.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_Vector_002, TestSize.Level0)
{
    uint8_t buffer[BUFFER_SIZE] = {0};
    int pid = -1;
    int ret = -1;
    int fd[2];
    if (pipe(fd) < 0) {
        return;
    }
    bool result;
    const int32_t int32Test[12] = { 0x12345678, -0x23456789, 0x34567890, -0x45678901, 0x12345778, 0x12345878,
    -0x12345978, 0x12345878, -0x12345818, 0x12345828, 0x12345838, 0x12345848 };
    size_t sizeInt32 = sizeof(int32Test) / sizeof(int32_t);
    const int64_t int64Test[12] = { 0x1234567887654321, -0x2345678998765432, 0x1234567887654300,
    0x1234567887654301, 0x1234567887654302, 0x1234567887654303, -0x1234567887654304, 0x1234567887654305,
    0x1234567887654306, 0x1234567887654307, 0x1234567887654308, 0x1234567887654309 };
    size_t sizeInt64 = sizeof(int64Test) / sizeof(int64_t);
    pid = fork();
    if (pid == 0) {
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        result = WriteInt32Vector(&io, int32Test, sizeInt32);
        EXPECT_EQ(result, true);
        result = WriteInt64Vector(&io, int64Test, sizeInt64);
        EXPECT_EQ(result, true);
        ret = write(fd[1], buffer, io.bufferCur - io.bufferBase);
        sleep(1);
        close(fd[1]);
        _exit(pid);
    } else {
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        sleep(2);
        ret = read(fd[0], buffer, BUFFER_SIZE);
        size_t readLen = 0;
        int32_t* int32Read = nullptr;
        int32Read = ReadInt32Vector(&io, &readLen);
        EXPECT_EQ(readLen, sizeInt32);
        for (size_t i = 0; i < readLen; i++) {
            EXPECT_EQ(int32Test[i], int32Read[i]);
        }
        int64_t* int64Read = nullptr;
        int64Read = ReadInt64Vector(&io, &readLen);
        EXPECT_EQ(readLen, sizeInt64);
        for (size_t i = 0; i < readLen; i++) {
            EXPECT_EQ(int64Test[i], int64Read[i]);
        }
        close(fd[0]);
    }
}
/**
 * @tc.name: test_serializer_Vector_003
 * @tc.desc: test uint8_t and uint16_t vector serializer write and read.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_Vector_003, TestSize.Level0)
{
    uint8_t buffer[BUFFER_SIZE] = {0};
    int pid = -1;
    int ret = -1;
    int fd[2];
    if (pipe(fd) < 0) {
        return;
    }
    bool result;
    const uint8_t uint8Test[12] = { 0x01, 0x10, 0x20, 0x30, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    size_t sizeUint8 = sizeof(uint8Test) / sizeof(uint8_t);
    const uint16_t uint16Test[12] = { 0x1234, 0x2345, 0x3456, 0x4567, 0x5678, 0x1235, 0x1236,
    0x1237, 0x1238, 0x1239, 0x1240, 0x1241 };
    size_t sizeUint16 = sizeof(uint16Test) / sizeof(uint16_t);
    pid = fork();
    if (pid == 0) {
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        result = WriteUInt8Vector(&io, uint8Test, sizeUint8);
        EXPECT_EQ(result, true);
        result = WriteUInt16Vector(&io, uint16Test, sizeUint16);
        EXPECT_EQ(result, true);
        ret = write(fd[1], buffer, io.bufferCur - io.bufferBase);
        sleep(1);
        close(fd[1]);
        _exit(pid);
    } else {
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        sleep(2);
        ret = read(fd[0], buffer, BUFFER_SIZE);
        size_t readLen = 0;
        uint8_t* uint8Read = nullptr;
        uint8Read = ReadUInt8Vector(&io, &readLen);
        EXPECT_EQ(readLen, sizeUint8);
        for (size_t i = 0; i < readLen; i++) {
        EXPECT_EQ(uint8Test[i], uint8Read[i]);
        }
        uint16_t* uint16Read = nullptr;
        uint16Read = ReadUInt16Vector(&io, &readLen);
        EXPECT_EQ(readLen, sizeUint16);
        for (size_t i = 0; i < readLen; i++) {
            EXPECT_EQ(uint16Test[i], uint16Read[i]);
        }
        close(fd[0]);
    }
}

/**
 * @tc.name: test_serializer_Vector_004
 * @tc.desc: test int32_t and int64_t tvector serializer write and read.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_Vector_004, TestSize.Level0)
{
    uint8_t buffer[BUFFER_SIZE] = {0};
    int pid = -1;
    int ret = -1;
    int fd[2];
    if (pipe(fd) < 0) {
        return;
    }
    bool result;
    const uint32_t uint32Test[12] = { 0x12345678, 0x23456789, 0x34567890, 0x45678901, 0x12345778, 0x12345878,
    0x12345978, 0x12345878, 0x12345818, 0x12345828, 0x12345838, 0x12345848 };
    size_t sizeUint32 = sizeof(uint32Test) / sizeof(uint32_t);
    const uint64_t uint64Test[12] = { 0x1234567887654321, 0x2345678998765432, 0x1234567887654300, 0x1234567887654301,
    0x1234567887654302, 0x1234567887654303, 0x1234567887654304, 0x1234567887654305, 0x1234567887654306,
    0x1234567887654307, 0x1234567887654308, 0x1234567887654309 };
    size_t sizeUint64 = sizeof(uint64Test) / sizeof(uint64_t);
    pid = fork();
    if (pid == 0) {
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        result = WriteUInt32Vector(&io, uint32Test, sizeUint32);
        EXPECT_EQ(result, true);
        result = WriteUInt64Vector(&io, uint64Test, sizeUint64);
        EXPECT_EQ(result, true);
        ret = write(fd[1], buffer, io.bufferCur - io.bufferBase);
        sleep(1);
        close(fd[1]);
        _exit(pid);
    } else {
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        sleep(2);
        ret = read(fd[0], buffer, BUFFER_SIZE);
        size_t readLen = 0;
        uint32_t* uint32Read = nullptr;
        uint32Read = ReadUInt32Vector(&io, &readLen);
        EXPECT_EQ(readLen, sizeUint32);
        for (size_t i = 0; i < readLen; i++) {
            EXPECT_EQ(uint32Test[i], uint32Read[i]);
        }
        uint64_t* uint64Read = nullptr;
        uint64Read = ReadUInt64Vector(&io, &readLen);
        EXPECT_EQ(readLen, sizeUint64);
        for (size_t i = 0; i < readLen; i++) {
            EXPECT_EQ(uint64Test[i], uint64Read[i]);
        }
        close(fd[0]);
    }
}

/**
 * @tc.name: test_serializer_Vector_005
 * @tc.desc: test vector serializer read and write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_Vector_005, TestSize.Level0)
{
    uint8_t buffer[BUFFER_SIZE] = {0};
    int pid = -1;
    int ret = -1;
    int fd[2];
    if (pipe(fd) < 0) {
        return;
    }
    bool result;
    const float floatTest[12] = { 11221.132313, 11221.45678, 11221.45608, 11221.45618, 11221.45628,
    11221.45638, 11221.45648, 11221.45658, 11221.45668, 11221.45678, 11221.45688, 11221.45698 };
    size_t sizeFloat = sizeof(floatTest) / sizeof(float);
    const double doubleTest[12] = { 1122.132313, 1122.45678, 1122.45678, 1122.45660, 1122.45661, 1122.45662,
    1122.45663, 1122.45664, 1122.456765, 1122.45666, 1122.45667, 1122.45668 };
    size_t sizeDouble = sizeof(doubleTest) / sizeof(double);
    pid = fork();
    if (pid == 0) {
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        result = WriteFloatVector(&io, floatTest, sizeFloat);
        EXPECT_EQ(result, true);
        result = WriteDoubleVector(&io, doubleTest, sizeDouble);
        EXPECT_EQ(result, true);
        ret = write(fd[1], buffer, io.bufferCur - io.bufferBase);
        sleep(1);
        close(fd[1]);
        _exit(pid);
    } else {
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        sleep(2);
        ret = read(fd[0], buffer, BUFFER_SIZE);
        float* floatRead = nullptr;
        floatRead = ReadFloatVector(&io, &sizeFloat);
        for (size_t i = 0; i < sizeFloat; i++) {
            EXPECT_EQ(floatTest[i], floatRead[i]);
        }
        double* doubleRead = nullptr;
        doubleRead = ReadDoubleVector(&io, &sizeDouble);
        for (size_t i = 0; i < sizeDouble; i++) {
            EXPECT_EQ(doubleTest[i], doubleRead[i]);
        }
        close(fd[0]);
    }
}

/**
 * @tc.name: test_serializer_WriteAndRead_String_003
 * @tc.desc: test string serializer read and write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_String_003, TestSize.Level0)
{
    uint8_t buffer[BUFFER_SIZE] = {0};
    int pid = -1;
    int ret = -1;
    int fd[2];
    if (pipe(fd) < 0) {
        return;
    }
    bool result;
    const uint16_t interfaceTest[] = { 0x5634, 0x5635, 0x5636, 0x5637, 0x5638, 0x5639,
    0x5640, 0x5641, 0x5642, 0x5643, 0x5644, 0x5645 };
    size_t len = sizeof(interfaceTest) / sizeof(uint16_t);
    const double doubleTest[12] = { 1122.132313, 1122.45678, 1122.45678, 1122.45660, 1122.45661,
    1122.45662, 1122.45663, 1122.45664, 1122.456765, 1122.45666, 1122.45667, 1122.45668 };
    size_t sizeDouble = sizeof(doubleTest) / sizeof(double);
    pid = fork();
    if (pid == 0) {
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        result = WriteInterfaceToken(&io, interfaceTest, len);
        EXPECT_EQ(result, true);
        ret = write(fd[1], buffer, io.bufferCur - io.bufferBase);
        sleep(1);
        close(fd[1]);
        _exit(pid);
    } else {
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        sleep(2);
        ret = read(fd[0], buffer, BUFFER_SIZE);
        uint16_t* interfaceRead = nullptr;
        size_t length;
        interfaceRead = ReadInterfaceToken(&io, &length);
        for (size_t i = 0; i < length; i++) {
            EXPECT_EQ(interfaceTest[i], interfaceRead[i]);
        }
        close(fd[0]);
    }
}

/**
 * @tc.name: test_serializer_WriteAndRead_String_004
 * @tc.desc: test string serializer read and write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_String_004, TestSize.Level0)
{
    uint8_t buffer[BUFFER_SIZE] = {0};
    int pid = -1;
    int ret = -1;
    int fd[2];
    if (pipe(fd) < 0) {
        return;
    }
    bool result;
    const struct Padded testData = { 'p', 0x34567890, 0x2345678998765432 };
    size_t size = sizeof(struct Padded);
    const double doubleTest[12] = { 1122.132313, 1122.45678, 1122.45678, 1122.45660, 1122.45661, 1122.45662,
    1122.45663, 1122.45664, 1122.456765, 1122.45666, 1122.45667, 1122.45668 };
    size_t sizeDouble = sizeof(doubleTest) / sizeof(double);
    pid = fork();
    if (pid == 0) {
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        result = WriteRawData(&io, &testData, size);
        EXPECT_EQ(result, true);
        ret = write(fd[1], buffer, io.bufferCur - io.bufferBase);
        sleep(1);
        close(fd[1]);
        _exit(pid);
    } else {
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        sleep(2);
        ret = read(fd[0], buffer, BUFFER_SIZE);
        struct Padded* dataRead = nullptr;
        dataRead = reinterpret_cast<struct Padded*>(ReadRawData(&io, sizeof(struct Padded)));
        EXPECT_EQ(testData.title, dataRead->title);
        EXPECT_EQ(testData.handle, dataRead->handle);
        EXPECT_EQ(testData.cookie, dataRead->cookie);
        close(fd[0]);
    }
}

/**
 * @tc.name: test_serializer_WriteAndRead_Pointer_001
 * @tc.desc: test pointer serializer read and write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_Pointer_001, TestSize.Level0)
{
    uint8_t buffer[BUFFER_SIZE] = {0};
    int pid = -1;
    int ret = -1;
    int fd[2];
    if (pipe(fd) < 0) {
        return;
    }
    bool result;
    char* testData = "sjf";
    pid = fork();
    if (pid == 0) {
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        result = WritePointer(&io, (uintptr_t)testData);
        EXPECT_EQ(result, true);
        ret = write(fd[1], buffer, io.bufferCur - io.bufferBase);
        sleep(1);
        close(fd[1]);
        _exit(pid);
    } else {
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        sleep(2);
        ret = read(fd[0], buffer, BUFFER_SIZE);
        uintptr_t valueRead = ReadPointer(&io);
        EXPECT_EQ(0, strcmp(testData, (char*)valueRead));
        close(fd[0]);
    }
}

/**
 * @tc.name: test_serializer_WriteAndRead_threshold_001
 * @tc.desc: test threshold serializer read and write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_threshold_001, TestSize.Level0)
{
    IpcIo io;
    uint8_t buffer[SMALL_BUFFER_SIZE] = { 0 };
    IpcIoInit(&io, buffer, SMALL_BUFFER_SIZE, 0);
    const char* strwrite = "test for write string threshold********************************************************\
    #####################################################";

    bool result = WriteString(&io, strwrite);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: test_serializer_WriteAndRead_ioUninitialized_001
 * @tc.desc: test io uninitialized serializer read and write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_ioUninitialized_001, TestSize.Level0)
{
    IpcIo io;
    bool boolTest = false;
    bool result = WriteBool(&io, boolTest);
    EXPECT_EQ(result, false);

    int8_t int8Test = -0x34;
    result = WriteInt8(&io, int8Test);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: test_serializer_WriteAndRead_Maximum_001
 * @tc.desc: test serializer Maximum of primary type read write.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_Maximum_001, TestSize.Level0)
{
    uint8_t buffer[BUFFER_SIZE] = {0};
    int pid = -1;
    int ret = -1;
    int fd[2];
    if (pipe(fd) < 0) {
        return;
    }
    bool result;
    struct TestData data = { true, 0x7F, 0x7FFF, 0x7FFFFFFF, 0xFF, 0xFFFF, 0xFFFFFFFF };
    pid = fork();
    if (pid < 0) {
        return;
    } else if (pid == 0) {
        close(fd[0]);
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        WriteTestData(&io, data);
        ret = write(fd[1], buffer, io.bufferCur - io.bufferBase);
        sleep(1);
        close(fd[1]);
        _exit(pid);
    } else {
        close(fd[1]);
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        sleep(2);
        ret = read(fd[0], buffer, BUFFER_SIZE);
        ReadTestData(&io, data);
        close(fd[0]);
    }
}

/**
 * @tc.name: test_serializer_WriteAndRead_Maximum_002
 * @tc.desc: test serializer Maximum of primary type read write.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_Maximum_002, TestSize.Level0)
{
    uint8_t buffer[BUFFER_SIZE] = {0};
    int pid = -1;
    int ret = -1;
    int fd[2];
    if (pipe(fd) < 0) {
        perror("pipe error!\n");
        return;
    }
    bool result;
    struct TestData data = { true, 0x7F, 0x7FFF, 0x7FFFFFFF, 0xFF, 0xFFFF, 0xFFFFFFFF };
    pid = fork();
    if (pid < 0) {
        return;
    }
    else if (pid == 0) {
        close(fd[0]);
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        WriteTestDataUnaligned(&io, data);
        ret = write(fd[1], buffer, io.bufferCur - io.bufferBase);
        sleep(1);
        close(fd[1]);
        _exit(pid);
    } else {
        close(fd[1]);
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        sleep(2);
        ret = read(fd[0], buffer, BUFFER_SIZE);
        ReadTestDataUnaligned(&io, data);
        close(fd[0]);
    }
}

/**
 * @tc.name: test_serializer_WriteAndRead_Maximum_003
 * @tc.desc: test serializer primary type read write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_Maximum_003, TestSize.Level0)
{
    uint8_t buffer[BUFFER_SIZE] = {0};
    int pid = -1;
    int ret = -1;
    int fd[2];
    if (pipe(fd) < 0) {
        return;
    }
    bool result;
    int64_t int64Test = 0x7FFFFFFFFFFFFFFF;
    uint64_t uint64Test = 0xFFFFFFFFFFFFFFFF;
    pid = fork();
    if (pid < 0) {
        return;
    } else if (pid == 0) {
        close(fd[0]);
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        result = WriteInt64(&io, int64Test);
        EXPECT_EQ(result, true);
        result = WriteUint64(&io, uint64Test);
        EXPECT_EQ(result, true);
        ret = write(fd[1], buffer, io.bufferCur - io.bufferBase);
        sleep(1);
        close(fd[1]);
        _exit(pid);
    } else {
        close(fd[1]);
        IpcIo io;
        IpcIoInit(&io, buffer, BUFFER_SIZE, 0);
        sleep(2);
        ret = read(fd[0], buffer, BUFFER_SIZE);
        int64_t int64Read;
        result = ReadInt64(&io, &int64Read);
        EXPECT_EQ(result, true);
        EXPECT_EQ(int64Read, int64Test);
        uint64_t uint64Read;
        result = ReadUint64(&io, &uint64Read);
        EXPECT_EQ(result, true);
        EXPECT_EQ(uint64Read, uint64Test);
        close(fd[0]);
    }
}

/**
 * @tc.name: test_serializer_WriteAndRead_Abnormal_String_001
 * @tc.desc: test serializer Abnormal scene read write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_Abnormal_String_001, TestSize.Level2)
{
    IpcIo io;
    uint8_t buffer[BUFFER_SIZE] = { 0 };
    IpcIoInit(&io, buffer, BUFFER_SIZE, 0);

    const char *stringWrite = nullptr;
    bool result = WriteString(&io, stringWrite);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: test_serializer_WriteAndRead_Abnormal_String16_001
 * @tc.desc: test serializer Abnormal scene read write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_Abnormal_String16_001, TestSize.Level2)
{
    IpcIo io;
    uint8_t buffer[BUFFER_SIZE] = { 0 };
    IpcIoInit(&io, buffer, BUFFER_SIZE, 0);

    uint16_t str16Write[] = {};
    size_t length = sizeof(str16Write) / sizeof(uint16_t);
    bool result = WriteString16(&io, str16Write, length);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: test_serializer_WriteAndRead_Abnormal_Buffer_001
 * @tc.desc: test serializer Abnormal scene read write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_Abnormal_Buffer_001, TestSize.Level2)
{
    IpcIo io;
    uint8_t buffer[BUFFER_SIZE] = { 0 };
    IpcIoInit(&io, buffer, BUFFER_SIZE, 0);

    struct Padded pad;
    bool result = WriteBuffer(&io, static_cast<const void*>(&pad), 0);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: test_serializer_WriteAndRead_Abnormal_InterfaceToken_001
 * @tc.desc: test serializer Abnormal scene read write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_Abnormal_InterfaceToken_001, TestSize.Level2)
{
    IpcIo io;
    uint8_t buffer[BUFFER_SIZE] = { 0 };
    IpcIoInit(&io, buffer, BUFFER_SIZE, 0);

    const uint16_t interfaceTest[] = {};
    size_t len = sizeof(interfaceTest) / sizeof(uint16_t);
    bool result = WriteInterfaceToken(&io, interfaceTest, len);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: test_serializer_WriteAndRead_Abnormal_RawData_001
 * @tc.desc: test serializer Abnormal scene read write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_Abnormal_RawData_001, TestSize.Level2)
{
    IpcIo io;
    uint8_t buffer[BUFFER_SIZE] = { 0 };
    IpcIoInit(&io, buffer, BUFFER_SIZE, 0);

    struct Padded rawDataTest;
    bool result = WriteRawData(&io, &rawDataTest, 0);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: test_serializer_WriteAndRead_Abnormal_BoolVector_001
 * @tc.desc: test serializer Abnormal scene read write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_Abnormal_BoolVector_001, TestSize.Level2)
{
    IpcIo io;
    uint8_t buffer[BUFFER_SIZE] = { 0 };
    IpcIoInit(&io, buffer, BUFFER_SIZE, 0);

    const bool boolTest[] = {};
    size_t sizeBool = sizeof(boolTest) / sizeof(bool);
    bool result = WriteBoolVector(&io, boolTest, sizeBool);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: test_serializer_WriteAndRead_Abnormal_Int8Vector_001
 * @tc.desc: test serializer Abnormal scene read write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_Abnormal_Int8Vector_001, TestSize.Level2)
{
    IpcIo io;
    uint8_t buffer[BUFFER_SIZE] = { 0 };
    IpcIoInit(&io, buffer, BUFFER_SIZE, 0);

    const int8_t int8Test[] = {};
    size_t sizeInt8 = sizeof(int8Test) / sizeof(int8_t);
    bool result = WriteInt8Vector(&io, int8Test, sizeInt8);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: test_serializer_WriteAndRead_Abnormal_Int16Vector_001
 * @tc.desc: test serializer Abnormal scene read write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_Abnormal_Int16Vector_001, TestSize.Level2)
{
    IpcIo io;
    uint8_t buffer[BUFFER_SIZE] = { 0 };
    IpcIoInit(&io, buffer, BUFFER_SIZE, 0);

    const int16_t int16Test[] = {};
    size_t sizeInt16 = sizeof(int16Test) / sizeof(int16_t);
    bool result = WriteInt16Vector(&io, int16Test, sizeInt16);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: test_serializer_WriteAndRead_Abnormal_Int32Vector_001
 * @tc.desc: test serializer Abnormal scene read write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_Abnormal_Int32Vector_001, TestSize.Level2)
{
    IpcIo io;
    uint8_t buffer[BUFFER_SIZE] = { 0 };
    IpcIoInit(&io, buffer, BUFFER_SIZE, 0);

    const int32_t int32Test[] = {};
    size_t sizeInt32 = sizeof(int32Test) / sizeof(int32_t);
    bool result = WriteInt32Vector(&io, int32Test, sizeInt32);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: test_serializer_WriteAndRead_Abnormal_Int64Vector_001
 * @tc.desc: test serializer Abnormal scene read write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_Abnormal_Int64Vector_001, TestSize.Level2)
{
    IpcIo io;
    uint8_t buffer[BUFFER_SIZE] = { 0 };
    IpcIoInit(&io, buffer, BUFFER_SIZE, 0);

    const int64_t int64Test[] = {};
    size_t sizeInt64 = sizeof(int64Test) / sizeof(int64_t);
    bool result = WriteInt64Vector(&io, int64Test, sizeInt64);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: test_serializer_WriteAndRead_Abnormal_UInt8Vector_001
 * @tc.desc: test serializer Abnormal scene read write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_Abnormal_UInt8Vector_001, TestSize.Level2)
{
    IpcIo io;
    uint8_t buffer[BUFFER_SIZE] = { 0 };
    IpcIoInit(&io, buffer, BUFFER_SIZE, 0);

    const uint8_t uint8Test[] = {};
    size_t sizeUint8 = sizeof(uint8Test) / sizeof(uint8_t);
    bool result = WriteUInt8Vector(&io, uint8Test, sizeUint8);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: test_serializer_WriteAndRead_Abnormal_UInt16Vector_001
 * @tc.desc: test serializer Abnormal scene read write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_Abnormal_UInt16Vector_001, TestSize.Level2)
{
    IpcIo io;
    uint8_t buffer[BUFFER_SIZE] = { 0 };
    IpcIoInit(&io, buffer, BUFFER_SIZE, 0);

    const uint16_t uint16Test[] = {};
    size_t sizeUint16 = sizeof(uint16Test) / sizeof(uint16_t);
    bool result = WriteUInt16Vector(&io, uint16Test, sizeUint16);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: test_serializer_WriteAndRead_Abnormal_UInt32Vector_001
 * @tc.desc: test serializer Abnormal scene read write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_Abnormal_UInt32Vector_001, TestSize.Level2)
{
    IpcIo io;
    uint8_t buffer[BUFFER_SIZE] = { 0 };
    IpcIoInit(&io, buffer, BUFFER_SIZE, 0);

    const uint32_t uint32Test[] = {};
    size_t sizeUint32 = sizeof(uint32Test) / sizeof(uint32_t);
    bool result = WriteUInt32Vector(&io, uint32Test, sizeUint32);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: test_serializer_WriteAndRead_Abnormal_UInt64Vector_001
 * @tc.desc: test serializer Abnormal scene read write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_Abnormal_UInt64Vector_001, TestSize.Level2)
{
    IpcIo io;
    uint8_t buffer[BUFFER_SIZE] = { 0 };
    IpcIoInit(&io, buffer, BUFFER_SIZE, 0);

    const uint64_t uint64Test[] = {};
    size_t sizeUint64 = sizeof(uint64Test) / sizeof(uint64_t);
    bool result = WriteUInt64Vector(&io, uint64Test, sizeUint64);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: test_serializer_WriteAndRead_Abnormal_FloatVector_001
 * @tc.desc: test serializer Abnormal scene read write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_Abnormal_FloatVector_001, TestSize.Level2)
{
    IpcIo io;
    uint8_t buffer[BUFFER_SIZE] = { 0 };
    IpcIoInit(&io, buffer, BUFFER_SIZE, 0);

    const float floatTest[] = {};
    size_t sizeFloat = sizeof(floatTest) / sizeof(float);
    bool result = WriteFloatVector(&io, floatTest, sizeFloat);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: test_serializer_WriteAndRead_Abnormal_DoubleVector_001
 * @tc.desc: test serializer Abnormal scene read write.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsSerializerTest, test_serializer_WriteAndRead_Abnormal_DoubleVector_001, TestSize.Level2)
{
    IpcIo io;
    uint8_t buffer[BUFFER_SIZE] = { 0 };
    IpcIoInit(&io, buffer, BUFFER_SIZE, 0);

    const double doubleTest[] = {};
    size_t sizeDouble = sizeof(doubleTest) / sizeof(double);
    bool result = WriteDoubleVector(&io, doubleTest, sizeDouble);
    EXPECT_EQ(result, false);
}
