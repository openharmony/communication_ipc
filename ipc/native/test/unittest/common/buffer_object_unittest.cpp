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
#include <gmock/gmock.h>

#define private public
#include "buffer_object.h"
#include "ipc_types.h"
#undef private

using namespace testing::ext;
using namespace OHOS;

namespace {
constexpr uint32_t BUFF_SIZE_TEST = 128;
constexpr ssize_t BUFFER_WRITE_CURSOR_TEST = 8;
constexpr ssize_t BUFFER_READ_CURSOR_TEST  = 6;
constexpr uint32_t BUFF_SIZE_0 = 0;
constexpr uint32_t BUFFER_EXPANSION_SIZE = 2;
}

class BufferObjectUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void BufferObjectUnitTest::SetUpTestCase()
{
}

void BufferObjectUnitTest::TearDownTestCase()
{
}

void BufferObjectUnitTest::SetUp() {}

void BufferObjectUnitTest::TearDown() {}

/**
 * @tc.name: UpdateSendBufferTest001
 * @tc.desc: Verify the UpdateSendBuffer function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, UpdateSendBufferTest001, TestSize.Level1)
{
    BufferObject object;
    object.SetSendBufferWriteCursor(1);
    object.SetSendBufferReadCursor(1);
    object.UpdateSendBuffer(0);
    EXPECT_EQ(object.GetSendBufferReadCursor(), 0);
    EXPECT_EQ(object.GetSendBufferWriteCursor(), 0);
}

/**
 * @tc.name: UpdateSendBufferTest002
 * @tc.desc: Verify the UpdateSendBuffer function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, UpdateSendBufferTest002, TestSize.Level1)
{
    BufferObject object;
    object.sendBuffSize_ = BUFF_SIZE_TEST;
    object.SetSendBufferWriteCursor(BUFFER_WRITE_CURSOR_TEST);
    object.SetSendBufferReadCursor(BUFFER_READ_CURSOR_TEST);
    object.sendBuffer_ = new (std::nothrow) char[BUFF_SIZE_TEST]();
    object.UpdateSendBuffer(0);
    EXPECT_EQ(object.GetSendBufferWriteCursor(),
        BUFFER_WRITE_CURSOR_TEST - BUFFER_READ_CURSOR_TEST);
    if (object.sendBuffer_ != nullptr) {
        delete[] object.sendBuffer_;
        object.sendBuffer_ = nullptr;
    }
}

/**
 * @tc.name: UpdateSendBufferTest003
 * @tc.desc: Verify the UpdateSendBuffer function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, UpdateSendBufferTest003, TestSize.Level1)
{
    BufferObject object;
    object.sendBuffSize_ = BUFF_SIZE_TEST;
    object.SetSendBufferWriteCursor(BUFFER_WRITE_CURSOR_TEST);
    object.SetSendBufferReadCursor(BUFFER_READ_CURSOR_TEST);
    object.UpdateSendBuffer(0);
    EXPECT_EQ(object.GetSendBufferReadCursor(), 0);
    EXPECT_EQ(object.GetSendBufferWriteCursor(), 0);
}

/**
 * @tc.name: UpdateSendBufferTest004
 * @tc.desc: Verify the UpdateSendBuffer function when buffer expansion is needed
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, UpdateSendBufferTest004, TestSize.Level1)
{
    BufferObject object;
    object.sendBuffSize_ = BUFF_SIZE_TEST;
    object.SetSendBufferWriteCursor(BUFF_SIZE_TEST - 1);
    object.SetSendBufferReadCursor(0);
    object.sendBuffer_ = new (std::nothrow) char[BUFF_SIZE_TEST]();
    object.UpdateSendBuffer(BUFFER_EXPANSION_SIZE);
    EXPECT_GT(object.GetSendBufferSize(), BUFF_SIZE_TEST);
    if (object.sendBuffer_ != nullptr) {
        delete[] object.sendBuffer_;
        object.sendBuffer_ = nullptr;
    }
}

/**
 * @tc.name: UpdateReceiveBufferTest001
 * @tc.desc: Verify the UpdateReceiveBuffer function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, UpdateReceiveBufferTest001, TestSize.Level1)
{
    BufferObject object;
    object.SetReceiveBufferWriteCursor(1);
    object.SetReceiveBufferReadCursor(1);
    object.UpdateReceiveBuffer();
    EXPECT_EQ(object.GetReceiveBufferReadCursor(), 0);
    EXPECT_EQ(object.GetReceiveBufferWriteCursor(), 0);
}

/**
 * @tc.name: UpdateReceiveBufferTest002
 * @tc.desc: Verify the UpdateReceiveBuffer function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, UpdateReceiveBufferTest002, TestSize.Level1)
{
    BufferObject object;
    object.recvBuffSize_ = BUFF_SIZE_TEST;
    object.SetReceiveBufferWriteCursor(BUFFER_WRITE_CURSOR_TEST);
    object.SetReceiveBufferReadCursor(BUFFER_READ_CURSOR_TEST);
    object.receiveBuffer_ = new (std::nothrow)char[BUFF_SIZE_TEST]();
    object.UpdateReceiveBuffer();
    EXPECT_EQ(object.GetReceiveBufferWriteCursor(),
        BUFFER_WRITE_CURSOR_TEST - BUFFER_READ_CURSOR_TEST);
    if (object.receiveBuffer_ != nullptr) {
        delete[] object.receiveBuffer_;
        object.receiveBuffer_ = nullptr;
    }
}

/**
 * @tc.name: UpdateReceiveBufferTest003
 * @tc.desc: Verify the UpdateReceiveBuffer function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, UpdateReceiveBufferTest003, TestSize.Level1)
{
    BufferObject object;
    object.recvBuffSize_ = BUFF_SIZE_TEST;
    object.SetReceiveBufferWriteCursor(BUFFER_WRITE_CURSOR_TEST);
    object.SetReceiveBufferReadCursor(BUFFER_READ_CURSOR_TEST);
    object.UpdateReceiveBuffer();
    EXPECT_EQ(object.GetReceiveBufferReadCursor(), 0);
    EXPECT_EQ(object.GetReceiveBufferWriteCursor(), 0);
}

/**
 * @tc.name: UpdateReceiveBufferTest004
 * @tc.desc: Verify the UpdateReceiveBuffer function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, UpdateReceiveBufferTest004, TestSize.Level1)
{
    BufferObject object;
    object.recvBuffSize_ = BUFF_SIZE_TEST;
    object.SetReceiveBufferWriteCursor(BUFF_SIZE_TEST - 1);
    object.SetReceiveBufferReadCursor(BUFF_SIZE_TEST / 2);
    object.receiveBuffer_ = new (std::nothrow) char[BUFF_SIZE_TEST]();

    for (ssize_t i = 0; i < BUFF_SIZE_TEST - 1; ++i) {
        object.receiveBuffer_[i] = 'A';
    }

    object.UpdateReceiveBuffer();

    EXPECT_EQ(object.GetRecvBufferSize(), BUFF_SIZE_TEST);

    EXPECT_EQ(object.GetReceiveBufferWriteCursor(), BUFF_SIZE_TEST / 2 - 1);
    EXPECT_EQ(object.GetReceiveBufferReadCursor(), 0);
    EXPECT_EQ(object.receiveBuffer_[0], 'A');
    if (object.receiveBuffer_ != nullptr) {
        delete[] object.receiveBuffer_;
        object.receiveBuffer_ = nullptr;
    }
}

/**
 * @tc.name: GetSendBufferAndLockTest001
 * @tc.desc: Verify the GetSendBufferAndLock function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetSendBufferAndLockTest001, TestSize.Level1)
{
    BufferObject object;
    object.sendBuffSize_ = BUFF_SIZE_TEST;

    char * buffer = object.GetSendBufferAndLock(SOCKET_BUFF_SIZE_USER_HUGE + 1);
    EXPECT_EQ(buffer, nullptr);
}

/**
 * @tc.name: GetSendBufferAndLockTest002
 * @tc.desc: Verify the GetSendBufferAndLock function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetSendBufferAndLockTest002, TestSize.Level1)
{
    BufferObject object;
    object.sendBuffSize_ = BUFF_SIZE_TEST;
    object.sendBuffer_ = new (std::nothrow) char[BUFF_SIZE_TEST]();
    char * buffer = object.GetSendBufferAndLock(SOCKET_BUFF_SIZE_USER_S);
    EXPECT_NE(buffer, nullptr);
    EXPECT_EQ(object.GetSendBufferSize(), SOCKET_BUFF_SIZE_USER_S);
    if (object.sendBuffer_ != nullptr) {
        delete[] object.sendBuffer_;
        object.sendBuffer_ = nullptr;
    }
}

/**
 * @tc.name: GetSendBufferAndLockTest003
 * @tc.desc: Verify the GetSendBufferAndLock function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetSendBufferAndLockTest003, TestSize.Level1)
{
    BufferObject object;
    object.sendBuffSize_ = 0;
    object.sendBuffer_ = new (std::nothrow) char[BUFF_SIZE_TEST]();
    char * buffer = object.GetSendBufferAndLock(SOCKET_BUFF_SIZE_USER_S);
    EXPECT_NE(buffer, nullptr);
    if (object.sendBuffer_ != nullptr) {
        delete[] object.sendBuffer_;
        object.sendBuffer_ = nullptr;
    }
}

/**
 * @tc.name: GetSendBufferAndLockTest004
 * @tc.desc: Verify the GetSendBufferAndLock function with buffer expansion failure
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetSendBufferAndLockTest004, TestSize.Level1)
{
    BufferObject object;
    char* buffer = object.GetSendBufferAndLock(MAX_RAWDATA_SIZE);
    EXPECT_EQ(buffer, nullptr);
}

/**
 * @tc.name: GetReceiveBufferAndLockTest001
 * @tc.desc: Verify the GetReceiveBufferAndLock function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetReceiveBufferAndLockTest001, TestSize.Level1)
{
    BufferObject object;
    object.recvBuffSize_ = BUFF_SIZE_TEST;

    char * buffer = object.GetReceiveBufferAndLock(SOCKET_BUFF_SIZE_USER_HUGE + 1);
    EXPECT_EQ(buffer, nullptr);
}

/**
 * @tc.name: GetReceiveBufferAndLockTest002
 * @tc.desc: Verify the GetReceiveBufferAndLock function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetReceiveBufferAndLockTest002, TestSize.Level1)
{
    BufferObject object;
    object.recvBuffSize_ = BUFF_SIZE_TEST;
    object.receiveBuffer_ = new (std::nothrow) char[BUFF_SIZE_TEST]();
    char * buffer = object.GetReceiveBufferAndLock(SOCKET_BUFF_SIZE_USER_S);
    EXPECT_NE(buffer, nullptr);
    EXPECT_EQ(object.GetRecvBufferSize(), SOCKET_BUFF_SIZE_USER_S);
    if (object.receiveBuffer_ != nullptr) {
        delete[] object.receiveBuffer_;
        object.receiveBuffer_ = nullptr;
    }
}

/**
 * @tc.name: GetReceiveBufferAndLockTest003
 * @tc.desc: Verify the GetReceiveBufferAndLock function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetReceiveBufferAndLockTest003, TestSize.Level1)
{
    BufferObject object;
    object.recvBuffSize_ = 0;
    object.receiveBuffer_ = new (std::nothrow) char[BUFF_SIZE_TEST]();
    char * buffer = object.GetReceiveBufferAndLock(SOCKET_BUFF_SIZE_USER_S);
    EXPECT_NE(buffer, nullptr);
    if (object.receiveBuffer_ != nullptr) {
        delete[] object.receiveBuffer_;
        object.receiveBuffer_ = nullptr;
    }
}

/**
 * @tc.name: GetReceiveBufferAndLockTest004
 * @tc.desc: Verify the GetReceiveBufferAndLock function with buffer expansion failure
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetReceiveBufferAndLockTest004, TestSize.Level1)
{
    BufferObject object;
    char* buffer = object.GetReceiveBufferAndLock(MAX_RAWDATA_SIZE);
    EXPECT_EQ(buffer, nullptr);
}

/**
 * @tc.name: SetSendBufferWriteCursorTest001
 * @tc.desc: Verify the SetSendBufferWriteCursor function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, SetSendBufferWriteCursorTest001, TestSize.Level1)
{
    BufferObject object;
    object.SetSendBufferWriteCursor(1);
    EXPECT_EQ(object.GetSendBufferWriteCursor(), 1);
}

/**
 * @tc.name: SetSendBufferWriteCursorTest002
 * @tc.desc: Verify the SetSendBufferWriteCursor function with negative value
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, SetSendBufferWriteCursorTest002, TestSize.Level1)
{
    BufferObject object;
    object.SetSendBufferWriteCursor(-1);
    EXPECT_EQ(object.GetSendBufferWriteCursor(), -1);
}

/**
 * @tc.name: SetSendBufferReadCursorTest001
 * @tc.desc: Verify the SetSendBufferReadCursor function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, SetSendBufferReadTest001, TestSize.Level1)
{
    BufferObject object;
    object.SetSendBufferReadCursor(1);
    EXPECT_EQ(object.GetSendBufferReadCursor(), 1);
}

/**
 * @tc.name: SetSendBufferReadCursorTest002
 * @tc.desc: Verify the SetSendBufferReadCursor function with negative value
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, SetSendBufferReadCursorTest002, TestSize.Level1)
{
    BufferObject object;
    object.SetSendBufferReadCursor(-1);
    EXPECT_EQ(object.GetSendBufferReadCursor(), -1);
}

/**
 * @tc.name: SetReceiveBufferWriteCursorTest001
 * @tc.desc: Verify the SetReceiveBufferWriteCursor function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, SetReceiveBufferWriteCursorTest001, TestSize.Level1)
{
    BufferObject object;
    object.SetReceiveBufferWriteCursor(1);
    EXPECT_EQ(object.GetReceiveBufferWriteCursor(), 1);
}

/**
 * @tc.name: SetReceiveBufferWriteCursorTest002
 * @tc.desc: Verify the SetReceiveBufferWriteCursor function with negative value
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, SetReceiveBufferWriteCursorTest002, TestSize.Level1)
{
    BufferObject object;
    object.SetReceiveBufferWriteCursor(-1);
    EXPECT_EQ(object.GetReceiveBufferWriteCursor(), -1);
}

/**
 * @tc.name: SetReceiveBufferReadCursorTest001
 * @tc.desc: Verify the SetReceiveBufferReadCursor function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, SetReceiveBufferReadCursorTest001, TestSize.Level1)
{
    BufferObject object;
    object.SetReceiveBufferReadCursor(1);
    EXPECT_EQ(object.GetReceiveBufferReadCursor(), 1);
}

/**
 * @tc.name: SetReceiveBufferReadCursorTest002
 * @tc.desc: Verify the SetReceiveBufferReadCursor function with negative value
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, SetReceiveBufferReadCursorTest002, TestSize.Level1)
{
    BufferObject object;
    object.SetReceiveBufferReadCursor(-1);
    EXPECT_EQ(object.GetReceiveBufferReadCursor(), -1);
}

/**
 * @tc.name: GetNeedBufferSizeTest001
 * @tc.desc: Verify the GetNeedBufferSize function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetNeedBufferSizeTest001, TestSize.Level1)
{
    BufferObject object;
    EXPECT_EQ(object.GetNeedBufferSize(SOCKET_BUFF_SIZE_USER_S), SOCKET_BUFF_SIZE_USER_S);
}

/**
 * @tc.name: GetNeedBufferSizeTest002
 * @tc.desc: Verify the GetNeedBufferSize function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetNeedBufferSizeTest002, TestSize.Level1)
{
    BufferObject object;
    EXPECT_EQ(object.GetNeedBufferSize(SOCKET_BUFF_SIZE_USER_M), SOCKET_BUFF_SIZE_USER_M);
}

/**
 * @tc.name: GetNeedBufferSizeTest003
 * @tc.desc: Verify the GetNeedBufferSize function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetNeedBufferSizeTest003, TestSize.Level1)
{
    BufferObject object;
    EXPECT_EQ(object.GetNeedBufferSize(SOCKET_BUFF_SIZE_USER_L), SOCKET_BUFF_SIZE_USER_L);
}

/**
 * @tc.name: GetNeedBufferSizeTest004
 * @tc.desc: Verify the GetNeedBufferSize function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetNeedBufferSizeTest004, TestSize.Level1)
{
    BufferObject object;
    EXPECT_EQ(object.GetNeedBufferSize(SOCKET_BUFF_SIZE_USER_HUGE), SOCKET_BUFF_SIZE_USER_HUGE);
}

/**
 * @tc.name: GetNeedBufferSizeTest005
 * @tc.desc: Verify the GetNeedBufferSize function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetNeedBufferSizeTest005, TestSize.Level1)
{
    BufferObject object;
    uint32_t ret = 0;
    EXPECT_EQ(object.GetNeedBufferSize(SOCKET_BUFF_SIZE_USER_HUGE + 1), ret);
}

/**
 * @tc.name: deleteTest005
 * @tc.desc: Verify the delete function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, deleteTest005, TestSize.Level1)
{
    BufferObject object;
    object.sendBuffer_ = nullptr;
    object.receiveBuffer_ = nullptr;

    ASSERT_TRUE(object.sendBuffSize_ == 0);
}

/**
 * @tc.name: ExpandSendBufferTest001
 * @tc.desc: Verify the ExpandSendBuffer function when need size is greater than current size
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, ExpandSendBufferTest001, TestSize.Level1)
{
    BufferObject object;
    object.sendBuffSize_ = BUFF_SIZE_TEST;
    bool result = object.ExpandSendBuffer(SOCKET_BUFF_SIZE_USER_HUGE);
    EXPECT_EQ(result, true);
    EXPECT_GT(object.sendBuffSize_, BUFF_SIZE_TEST);
    if (object.sendBuffer_ != nullptr) {
        delete[] object.sendBuffer_;
        object.sendBuffer_ = nullptr;
    }
}

/**
 * @tc.name: ExpandSendBufferTest002
 * @tc.desc: Verify the ExpandSendBuffer function when need size is zero
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, ExpandSendBufferTest002, TestSize.Level1)
{
    BufferObject object;
    uint32_t needSize = object.GetNeedBufferSize(BUFF_SIZE_0);
    bool result = object.ExpandSendBuffer(needSize);
    EXPECT_EQ(result, true);
    EXPECT_EQ(object.sendBuffSize_, SOCKET_BUFF_SIZE_USER_S);
    if (object.sendBuffer_ != nullptr) {
        delete[] object.sendBuffer_;
        object.sendBuffer_ = nullptr;
    }
}

/**
 * @tc.name: ExpandSendBufferTest003
 * @tc.desc: Verify the ExpandSendBuffer function when new buffer allocation fails
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, ExpandSendBufferTest003, TestSize.Level1)
{
    BufferObject object;
    object.sendBuffSize_ = BUFF_SIZE_TEST;
    bool result = object.ExpandSendBuffer(MAX_RAWDATA_SIZE);
    EXPECT_EQ(result, true);
    EXPECT_EQ(object.sendBuffSize_, BUFF_SIZE_TEST);
    if (object.sendBuffer_ != nullptr) {
        delete[] object.sendBuffer_;
        object.sendBuffer_ = nullptr;
    }
}

/**
 * @tc.name: ReleaseSendBufferLockTest001
 * @tc.desc: Verify the ReleaseSendBufferLock function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, ReleaseSendBufferLockTest001, TestSize.Level1)
{
    BufferObject object;
    object.sendMutex_.lock();
    object.ReleaseSendBufferLock();
    EXPECT_EQ(object.sendMutex_.try_lock(), true);
    object.sendMutex_.unlock();
}

/**
 * @tc.name: ReleaseReceiveBufferLockTest001
 * @tc.desc: Verify the ReleaseReceiveBufferLock function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, ReleaseReceiveBufferLockTest001, TestSize.Level1)
{
    BufferObject object;
    object.recvMutex_.lock();
    object.ReleaseReceiveBufferLock();
    EXPECT_EQ(object.recvMutex_.try_lock(), true);
    object.recvMutex_.unlock();
}

/**
 * @tc.name: GetSendBufferSizeTest001
 * @tc.desc: Verify the GetSendBufferSize function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetSendBufferSizeTest001, TestSize.Level1)
{
    BufferObject object;
    object.sendBuffSize_ = BUFF_SIZE_TEST;
    EXPECT_EQ(object.GetSendBufferSize(), BUFF_SIZE_TEST);
}

/**
 * @tc.name: GetRecvBufferSizeTest001
 * @tc.desc: Verify the GetRecvBufferSize function
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetRecvBufferSizeTest001, TestSize.Level1)
{
    BufferObject object;
    object.recvBuffSize_ = BUFF_SIZE_TEST;
    EXPECT_EQ(object.GetRecvBufferSize(), BUFF_SIZE_TEST);
}
