/*
 * Copyright (C) 2022-2026 Huawei Device Co., Ltd.
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

namespace OHOS {
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
    void SetUp() override;
    void TearDown() override;
};

void BufferObjectUnitTest::SetUpTestCase()
{
}

void BufferObjectUnitTest::TearDownTestCase()
{
}

void BufferObjectUnitTest::SetUp() {}

void BufferObjectUnitTest::TearDown() {}

// ===== Original interface tests (deprecated) =====

/**
 * @tc.name: UpdateSendBufferTest001
 * @tc.desc: Verify the UpdateSendBuffer function with equal cursors
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
 * @tc.desc: Verify the UpdateSendBuffer function with valid cursors
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
 * @tc.desc: Verify the UpdateSendBuffer function with null buffer
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
 * @tc.desc: Verify UpdateSendBuffer with buffer expansion
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
 * @tc.name: UpdateSendBufferTest005
 * @tc.desc: Verify UpdateSendBuffer with max size buffer
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, UpdateSendBufferTest005, TestSize.Level1)
{
    BufferObject object;
    object.sendBuffSize_ = SOCKET_BUFF_SIZE_USER_S;
    object.SetSendBufferWriteCursor(BUFFER_WRITE_CURSOR_TEST);
    object.SetSendBufferReadCursor(1);
    object.sendBuffer_ = new (std::nothrow) char[SOCKET_BUFF_SIZE_USER_S]();
    object.UpdateSendBuffer(1);
    EXPECT_EQ(object.GetSendBufferWriteCursor(), BUFFER_WRITE_CURSOR_TEST);
    EXPECT_EQ(object.GetSendBufferReadCursor(), 1);
    if (object.sendBuffer_ != nullptr) {
        delete[] object.sendBuffer_;
        object.sendBuffer_ = nullptr;
    }
}

/**
 * @tc.name: UpdateReceiveBufferTest001
 * @tc.desc: Verify UpdateReceiveBuffer with equal cursors
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
 * @tc.desc: Verify UpdateReceiveBuffer with valid cursors
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
 * @tc.desc: Verify UpdateReceiveBuffer with null buffer
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
 * @tc.desc: Verify UpdateReceiveBuffer with partial data
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
 * @tc.name: UpdateReceiveBufferTest005
 * @tc.desc: Verify UpdateReceiveBuffer with max size buffer
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, UpdateReceiveBufferTest005, TestSize.Level1)
{
    BufferObject object;
    object.recvBuffSize_ = SOCKET_BUFF_SIZE_USER_S;
    object.SetReceiveBufferWriteCursor(BUFFER_WRITE_CURSOR_TEST);
    object.SetReceiveBufferReadCursor(1);
    object.receiveBuffer_ = new (std::nothrow) char[SOCKET_BUFF_SIZE_USER_S]();
    object.UpdateReceiveBuffer();
    EXPECT_EQ(object.GetReceiveBufferWriteCursor(), BUFFER_WRITE_CURSOR_TEST);
    EXPECT_EQ(object.GetReceiveBufferReadCursor(), 1);
    if (object.receiveBuffer_ != nullptr) {
        delete[] object.receiveBuffer_;
        object.receiveBuffer_ = nullptr;
    }
}

/**
 * @tc.name: GetSendBufferAndLockTest001
 * @tc.desc: Verify GetSendBufferAndLock with oversized request
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetSendBufferAndLockTest001, TestSize.Level1)
{
    BufferObject object;
    object.sendBuffSize_ = BUFF_SIZE_TEST;
    char* buffer = object.GetSendBufferAndLock(SOCKET_BUFF_SIZE_USER_HUGE + 1);
    EXPECT_EQ(buffer, nullptr);
}

/**
 * @tc.name: GetSendBufferAndLockTest002
 * @tc.desc: Verify GetSendBufferAndLock with valid size
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetSendBufferAndLockTest002, TestSize.Level1)
{
    BufferObject object;
    object.sendBuffSize_ = BUFF_SIZE_TEST;
    object.sendBuffer_ = new (std::nothrow) char[BUFF_SIZE_TEST]();
    char* buffer = object.GetSendBufferAndLock(SOCKET_BUFF_SIZE_USER_S);
    EXPECT_NE(buffer, nullptr);
    EXPECT_EQ(object.GetSendBufferSize(), SOCKET_BUFF_SIZE_USER_S);
    object.ReleaseSendBufferLock();
    if (object.sendBuffer_ != nullptr) {
        delete[] object.sendBuffer_;
        object.sendBuffer_ = nullptr;
    }
}

/**
 * @tc.name: GetSendBufferAndLockTest003
 * @tc.desc: Verify GetSendBufferAndLock with zero size buffer
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetSendBufferAndLockTest003, TestSize.Level1)
{
    BufferObject object;
    object.sendBuffSize_ = 0;
    object.sendBuffer_ = new (std::nothrow) char[BUFF_SIZE_TEST]();
    char* buffer = object.GetSendBufferAndLock(SOCKET_BUFF_SIZE_USER_S);
    EXPECT_NE(buffer, nullptr);
    object.ReleaseSendBufferLock();
    if (object.sendBuffer_ != nullptr) {
        delete[] object.sendBuffer_;
        object.sendBuffer_ = nullptr;
    }
}

/**
 * @tc.name: GetSendBufferAndLockTest004
 * @tc.desc: Verify GetSendBufferAndLock with MAX_RAWDATA_SIZE
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
 * @tc.desc: Verify GetReceiveBufferAndLock with oversized request
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetReceiveBufferAndLockTest001, TestSize.Level1)
{
    BufferObject object;
    object.recvBuffSize_ = BUFF_SIZE_TEST;
    char* buffer = object.GetReceiveBufferAndLock(SOCKET_BUFF_SIZE_USER_HUGE + 1);
    EXPECT_EQ(buffer, nullptr);
}

/**
 * @tc.name: GetReceiveBufferAndLockTest002
 * @tc.desc: Verify GetReceiveBufferAndLock with valid size
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetReceiveBufferAndLockTest002, TestSize.Level1)
{
    BufferObject object;
    object.recvBuffSize_ = BUFF_SIZE_TEST;
    object.receiveBuffer_ = new (std::nothrow) char[BUFF_SIZE_TEST]();
    char* buffer = object.GetReceiveBufferAndLock(SOCKET_BUFF_SIZE_USER_S);
    EXPECT_NE(buffer, nullptr);
    EXPECT_EQ(object.GetRecvBufferSize(), SOCKET_BUFF_SIZE_USER_S);
    object.ReleaseReceiveBufferLock();
    if (object.receiveBuffer_ != nullptr) {
        delete[] object.receiveBuffer_;
        object.receiveBuffer_ = nullptr;
    }
}

/**
 * @tc.name: GetReceiveBufferAndLockTest003
 * @tc.desc: Verify GetReceiveBufferAndLock with zero size buffer
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetReceiveBufferAndLockTest003, TestSize.Level1)
{
    BufferObject object;
    object.recvBuffSize_ = 0;
    object.receiveBuffer_ = new (std::nothrow) char[BUFF_SIZE_TEST]();
    char* buffer = object.GetReceiveBufferAndLock(SOCKET_BUFF_SIZE_USER_S);
    EXPECT_NE(buffer, nullptr);
    object.ReleaseReceiveBufferLock();
    if (object.receiveBuffer_ != nullptr) {
        delete[] object.receiveBuffer_;
        object.receiveBuffer_ = nullptr;
    }
}

/**
 * @tc.name: GetReceiveBufferAndLockTest004
 * @tc.desc: Verify GetReceiveBufferAndLock with MAX_RAWDATA_SIZE
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
 * @tc.desc: Verify SetSendBufferWriteCursor with valid value
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
 * @tc.desc: Verify SetSendBufferWriteCursor with invalid value -1
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, SetSendBufferWriteCursorTest002, TestSize.Level1)
{
    BufferObject object;
    object.SetSendBufferWriteCursor(-1);
    EXPECT_NE(object.GetSendBufferWriteCursor(), -1);
}

/**
 * @tc.name: SetSendBufferReadTest001
 * @tc.desc: Verify SetSendBufferReadCursor with valid value
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
 * @tc.desc: Verify SetSendBufferReadCursor with value -1
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
 * @tc.desc: Verify SetReceiveBufferWriteCursor with valid value
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
 * @tc.desc: Verify SetReceiveBufferWriteCursor with invalid value -1
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, SetReceiveBufferWriteCursorTest002, TestSize.Level1)
{
    BufferObject object;
    object.SetReceiveBufferWriteCursor(-1);
    EXPECT_NE(object.GetReceiveBufferWriteCursor(), -1);
}

/**
 * @tc.name: SetReceiveBufferReadCursorTest001
 * @tc.desc: Verify SetReceiveBufferReadCursor with valid value
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
 * @tc.desc: Verify SetReceiveBufferReadCursor with value -1
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
 * @tc.desc: Verify GetNeedBufferSize returns SOCKET_BUFF_SIZE_USER_S
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetNeedBufferSizeTest001, TestSize.Level1)
{
    BufferObject object;
    EXPECT_EQ(object.GetNeedBufferSize(SOCKET_BUFF_SIZE_USER_S), SOCKET_BUFF_SIZE_USER_S);
}

/**
 * @tc.name: GetNeedBufferSizeTest002
 * @tc.desc: Verify GetNeedBufferSize returns SOCKET_BUFF_SIZE_USER_M
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetNeedBufferSizeTest002, TestSize.Level1)
{
    BufferObject object;
    EXPECT_EQ(object.GetNeedBufferSize(SOCKET_BUFF_SIZE_USER_M), SOCKET_BUFF_SIZE_USER_M);
}

/**
 * @tc.name: GetNeedBufferSizeTest003
 * @tc.desc: Verify GetNeedBufferSize returns SOCKET_BUFF_SIZE_USER_L
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetNeedBufferSizeTest003, TestSize.Level1)
{
    BufferObject object;
    EXPECT_EQ(object.GetNeedBufferSize(SOCKET_BUFF_SIZE_USER_L), SOCKET_BUFF_SIZE_USER_L);
}

/**
 * @tc.name: GetNeedBufferSizeTest004
 * @tc.desc: Verify GetNeedBufferSize returns SOCKET_BUFF_SIZE_USER_HUGE
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetNeedBufferSizeTest004, TestSize.Level1)
{
    BufferObject object;
    EXPECT_EQ(object.GetNeedBufferSize(SOCKET_BUFF_SIZE_USER_HUGE), SOCKET_BUFF_SIZE_USER_HUGE);
}

/**
 * @tc.name: GetNeedBufferSizeTest005
 * @tc.desc: Verify GetNeedBufferSize with oversized value returns 0
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetNeedBufferSizeTest005, TestSize.Level1)
{
    BufferObject object;
    uint32_t ret = 0;
    EXPECT_EQ(object.GetNeedBufferSize(SOCKET_BUFF_SIZE_USER_HUGE + 1), ret);
}

/**
 * @tc.name: DeleteTest005
 * @tc.desc: Verify buffer object initial state
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, DeleteTest005, TestSize.Level1)
{
    BufferObject object;
    object.sendBuffer_ = nullptr;
    object.receiveBuffer_ = nullptr;
    ASSERT_TRUE(object.sendBuffSize_ == 0);
}

/**
 * @tc.name: ExpandSendBufferTest001
 * @tc.desc: Verify ExpandSendBuffer with large size
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, ExpandSendBufferTest001, TestSize.Level1)
{
    BufferObject object;
    object.sendBuffSize_ = BUFF_SIZE_TEST;
    bool result = object.ExpandSendBuffer(SOCKET_BUFF_SIZE_USER_HUGE);
    EXPECT_EQ(result, true);
    EXPECT_GT(object.sendBuffSize_, static_cast<ssize_t>(BUFF_SIZE_TEST));
    if (object.sendBuffer_ != nullptr) {
        delete[] object.sendBuffer_;
        object.sendBuffer_ = nullptr;
    }
}

/**
 * @tc.name: ExpandSendBufferTest002
 * @tc.desc: Verify ExpandSendBuffer with zero size
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, ExpandSendBufferTest002, TestSize.Level1)
{
    BufferObject object;
    uint32_t needSize = object.GetNeedBufferSize(BUFF_SIZE_0);
    bool result = object.ExpandSendBuffer(needSize);
    EXPECT_EQ(result, true);
    EXPECT_EQ(object.sendBuffSize_, static_cast<ssize_t>(SOCKET_BUFF_SIZE_USER_S));
    if (object.sendBuffer_ != nullptr) {
        delete[] object.sendBuffer_;
        object.sendBuffer_ = nullptr;
    }
}

/**
 * @tc.name: ExpandSendBufferTest003
 * @tc.desc: Verify ExpandSendBuffer with MAX_RAWDATA_SIZE
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, ExpandSendBufferTest003, TestSize.Level1)
{
    BufferObject object;
    object.sendBuffSize_ = BUFF_SIZE_TEST;
    bool result = object.ExpandSendBuffer(MAX_RAWDATA_SIZE);
    EXPECT_EQ(result, true);
    EXPECT_EQ(object.sendBuffSize_, static_cast<ssize_t>(BUFF_SIZE_TEST));
    if (object.sendBuffer_ != nullptr) {
        delete[] object.sendBuffer_;
        object.sendBuffer_ = nullptr;
    }
}

/**
 * @tc.name: ReleaseSendBufferLockTest001
 * @tc.desc: Verify ReleaseSendBufferLock releases mutex
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
 * @tc.desc: Verify ReleaseReceiveBufferLock releases mutex
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
 * @tc.desc: Verify GetSendBufferSize returns correct size
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
 * @tc.desc: Verify GetRecvBufferSize returns correct size
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetRecvBufferSizeTest001, TestSize.Level1)
{
    BufferObject object;
    object.recvBuffSize_ = BUFF_SIZE_TEST;
    EXPECT_EQ(object.GetRecvBufferSize(), BUFF_SIZE_TEST);
}

// ===== New interface tests (Ex suffix) =====

/**
 * @tc.name: BufferLockGuardTest001
 * @tc.desc: Verify BufferLockGuard lock/unlock functionality
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, BufferLockGuardTest001, TestSize.Level1)
{
    std::mutex mtx;
    BufferLockGuard guard(mtx);
    EXPECT_TRUE(guard.IsLocked());
    EXPECT_FALSE(mtx.try_lock());
    guard.Unlock();
    EXPECT_FALSE(guard.IsLocked());
    EXPECT_TRUE(mtx.try_lock());
    mtx.unlock();
}

/**
 * @tc.name: AcquireSendBufferTest001
 * @tc.desc: Verify AcquireSendBuffer with oversized request returns null
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, AcquireSendBufferTest001, TestSize.Level1)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_HUGE + 1);
    EXPECT_EQ(ctx.buffer, nullptr);
    EXPECT_EQ(ctx.size, 0);
    EXPECT_FALSE(ctx.lockGuard.IsLocked());
}

/**
 * @tc.name: AcquireSendBufferTest002
 * @tc.desc: Verify AcquireSendBuffer with valid size
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, AcquireSendBufferTest002, TestSize.Level1)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_S);
    EXPECT_NE(ctx.buffer, nullptr);
    EXPECT_EQ(ctx.size, static_cast<ssize_t>(SOCKET_BUFF_SIZE_USER_S));
    EXPECT_TRUE(ctx.lockGuard.IsLocked());
    EXPECT_EQ(object.GetSendBufferWriteCursor(), 0);
    EXPECT_EQ(object.GetSendBufferReadCursor(), 0);
}

/**
 * @tc.name: AcquireSendBufferTest003
 * @tc.desc: Verify AcquireSendBuffer with MAX_RAWDATA_SIZE returns null
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, AcquireSendBufferTest003, TestSize.Level1)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(MAX_RAWDATA_SIZE);
    EXPECT_EQ(ctx.buffer, nullptr);
    EXPECT_FALSE(ctx.lockGuard.IsLocked());
}

/**
 * @tc.name: AcquireReceiveBufferTest001
 * @tc.desc: Verify AcquireReceiveBuffer with oversized request returns null
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, AcquireReceiveBufferTest001, TestSize.Level1)
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(SOCKET_BUFF_SIZE_USER_HUGE + 1);
    EXPECT_EQ(ctx.buffer, nullptr);
    EXPECT_EQ(ctx.size, 0);
    EXPECT_FALSE(ctx.lockGuard.IsLocked());
}

/**
 * @tc.name: AcquireReceiveBufferTest002
 * @tc.desc: Verify AcquireReceiveBuffer with valid size
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, AcquireReceiveBufferTest002, TestSize.Level1)
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(SOCKET_BUFF_SIZE_USER_S);
    EXPECT_NE(ctx.buffer, nullptr);
    EXPECT_EQ(ctx.size, static_cast<ssize_t>(SOCKET_BUFF_SIZE_USER_S));
    EXPECT_TRUE(ctx.lockGuard.IsLocked());
    EXPECT_EQ(object.GetReceiveBufferWriteCursor(), 0);
    EXPECT_EQ(object.GetReceiveBufferReadCursor(), 0);
}

/**
 * @tc.name: AcquireReceiveBufferTest003
 * @tc.desc: Verify AcquireReceiveBuffer with MAX_RAWDATA_SIZE returns null
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, AcquireReceiveBufferTest003, TestSize.Level1)
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(MAX_RAWDATA_SIZE);
    EXPECT_EQ(ctx.buffer, nullptr);
    EXPECT_FALSE(ctx.lockGuard.IsLocked());
}

/**
 * @tc.name: UpdateSendBufferLockedTest001
 * @tc.desc: Verify UpdateSendBufferLocked with equal cursors
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, UpdateSendBufferLockedTest001, TestSize.Level1)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_S);
    object.SetSendBufferWriteCursorEx(1);
    object.SetSendBufferReadCursorEx(1);
    char* result = object.UpdateSendBufferLocked(0);
    EXPECT_EQ(object.GetSendBufferReadCursor(), 0);
    EXPECT_EQ(object.GetSendBufferWriteCursor(), 0);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: UpdateSendBufferLockedTest002
 * @tc.desc: Verify UpdateSendBufferLocked with valid cursors
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, UpdateSendBufferLockedTest002, TestSize.Level1)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(BUFF_SIZE_TEST);
    object.SetSendBufferWriteCursorEx(BUFFER_WRITE_CURSOR_TEST);
    object.SetSendBufferReadCursorEx(BUFFER_READ_CURSOR_TEST);
    char* result = object.UpdateSendBufferLocked(0);
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(object.GetSendBufferWriteCursor(),
        BUFFER_WRITE_CURSOR_TEST - BUFFER_READ_CURSOR_TEST);
    EXPECT_EQ(object.GetSendBufferReadCursor(), 0);
}

/**
 * @tc.name: UpdateSendBufferLockedTest003
 * @tc.desc: Verify UpdateSendBufferLocked with buffer expansion
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, UpdateSendBufferLockedTest003, TestSize.Level1)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(BUFF_SIZE_TEST);
    object.SetSendBufferWriteCursorEx(BUFFER_WRITE_CURSOR_TEST);
    object.SetSendBufferReadCursorEx(BUFFER_READ_CURSOR_TEST);
    char* result = object.UpdateSendBufferLocked(BUFFER_EXPANSION_SIZE);
    EXPECT_NE(result, nullptr);
    EXPECT_GT(object.GetSendBufferSizeEx(), static_cast<ssize_t>(BUFF_SIZE_TEST));
    EXPECT_EQ(object.GetSendBufferWriteCursor(),
        BUFFER_WRITE_CURSOR_TEST - BUFFER_READ_CURSOR_TEST);
    EXPECT_EQ(object.GetSendBufferReadCursor(), 0);
}

/**
 * @tc.name: UpdateSendBufferLockedTest004
 * @tc.desc: Verify UpdateSendBufferLocked with max size buffer
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, UpdateSendBufferLockedTest004, TestSize.Level1)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_S);
    object.SetSendBufferWriteCursorEx(BUFFER_WRITE_CURSOR_TEST);
    object.SetSendBufferReadCursorEx(1);
    char* result = object.UpdateSendBufferLocked(1);
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(object.GetSendBufferWriteCursor(), BUFFER_WRITE_CURSOR_TEST);
    EXPECT_EQ(object.GetSendBufferReadCursor(), 1);
}

/**
 * @tc.name: UpdateReceiveBufferLockedTest001
 * @tc.desc: Verify UpdateReceiveBufferLocked with equal cursors
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, UpdateReceiveBufferLockedTest001, TestSize.Level1)
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(SOCKET_BUFF_SIZE_USER_S);
    object.SetReceiveBufferWriteCursorEx(1);
    object.SetReceiveBufferReadCursorEx(1);
    char* result = object.UpdateReceiveBufferLocked(0);
    EXPECT_EQ(object.GetReceiveBufferReadCursor(), 0);
    EXPECT_EQ(object.GetReceiveBufferWriteCursor(), 0);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: UpdateReceiveBufferLockedTest002
 * @tc.desc: Verify UpdateReceiveBufferLocked with valid cursors
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, UpdateReceiveBufferLockedTest002, TestSize.Level1)
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(BUFF_SIZE_TEST);
    object.SetReceiveBufferWriteCursorEx(BUFFER_WRITE_CURSOR_TEST);
    object.SetReceiveBufferReadCursorEx(BUFFER_READ_CURSOR_TEST);
    char* result = object.UpdateReceiveBufferLocked(0);
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(object.GetReceiveBufferWriteCursor(),
        BUFFER_WRITE_CURSOR_TEST - BUFFER_READ_CURSOR_TEST);
    EXPECT_EQ(object.GetReceiveBufferReadCursor(), 0);
}

/**
 * @tc.name: UpdateReceiveBufferLockedTest003
 * @tc.desc: Verify UpdateReceiveBufferLocked with buffer expansion
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, UpdateReceiveBufferLockedTest003, TestSize.Level1)
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(BUFF_SIZE_TEST);
    object.SetReceiveBufferWriteCursorEx(BUFFER_WRITE_CURSOR_TEST);
    object.SetReceiveBufferReadCursorEx(BUFFER_READ_CURSOR_TEST);
    char* result = object.UpdateReceiveBufferLocked(BUFFER_EXPANSION_SIZE);
    EXPECT_NE(result, nullptr);
    EXPECT_GT(object.GetRecvBufferSizeEx(), static_cast<ssize_t>(BUFF_SIZE_TEST));
    EXPECT_EQ(object.GetReceiveBufferWriteCursor(),
        BUFFER_WRITE_CURSOR_TEST - BUFFER_READ_CURSOR_TEST);
    EXPECT_EQ(object.GetReceiveBufferReadCursor(), 0);
}

/**
 * @tc.name: UpdateReceiveBufferLockedTest004
 * @tc.desc: Verify UpdateReceiveBufferLocked with max size buffer
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, UpdateReceiveBufferLockedTest004, TestSize.Level1)
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(SOCKET_BUFF_SIZE_USER_S);
    object.SetReceiveBufferWriteCursorEx(BUFFER_WRITE_CURSOR_TEST);
    object.SetReceiveBufferReadCursorEx(1);
    char* result = object.UpdateReceiveBufferLocked(1);
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(object.GetReceiveBufferWriteCursor(), BUFFER_WRITE_CURSOR_TEST);
    EXPECT_EQ(object.GetReceiveBufferReadCursor(), 1);
}

/**
 * @tc.name: SetSendBufferWriteCursorExTest001
 * @tc.desc: Verify SetSendBufferWriteCursorEx with valid value
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, SetSendBufferWriteCursorExTest001, TestSize.Level1)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_S);
    bool result = object.SetSendBufferWriteCursorEx(1);
    EXPECT_TRUE(result);
    EXPECT_EQ(object.GetSendBufferWriteCursor(), 1);
}

/**
 * @tc.name: SetSendBufferWriteCursorExTest002
 * @tc.desc: Verify SetSendBufferWriteCursorEx with invalid value -1
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, SetSendBufferWriteCursorExTest002, TestSize.Level1)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_S);
    bool result = object.SetSendBufferWriteCursorEx(-1);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SetSendBufferWriteCursorExTest003
 * @tc.desc: Verify SetSendBufferWriteCursorEx with out-of-bounds value
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, SetSendBufferWriteCursorExTest003, TestSize.Level1)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_S);
    bool result = object.SetSendBufferWriteCursorEx(SOCKET_BUFF_SIZE_USER_S + 1);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SetSendBufferReadCursorExTest001
 * @tc.desc: Verify SetSendBufferReadCursorEx with valid value
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, SetSendBufferReadCursorExTest001, TestSize.Level1)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_S);
    bool result = object.SetSendBufferReadCursorEx(1);
    EXPECT_TRUE(result);
    EXPECT_EQ(object.GetSendBufferReadCursor(), 1);
}

/**
 * @tc.name: SetSendBufferReadCursorExTest002
 * @tc.desc: Verify SetSendBufferReadCursorEx with invalid value -1
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, SetSendBufferReadCursorExTest002, TestSize.Level1)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_S);
    bool result = object.SetSendBufferReadCursorEx(-1);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SetReceiveBufferWriteCursorExTest001
 * @tc.desc: Verify SetReceiveBufferWriteCursorEx with valid value
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, SetReceiveBufferWriteCursorExTest001, TestSize.Level1)
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(SOCKET_BUFF_SIZE_USER_S);
    bool result = object.SetReceiveBufferWriteCursorEx(1);
    EXPECT_TRUE(result);
    EXPECT_EQ(object.GetReceiveBufferWriteCursor(), 1);
}

/**
 * @tc.name: SetReceiveBufferWriteCursorExTest002
 * @tc.desc: Verify SetReceiveBufferWriteCursorEx with invalid value -1
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, SetReceiveBufferWriteCursorExTest002, TestSize.Level1)
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(SOCKET_BUFF_SIZE_USER_S);
    bool result = object.SetReceiveBufferWriteCursorEx(-1);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SetReceiveBufferReadCursorExTest001
 * @tc.desc: Verify SetReceiveBufferReadCursorEx with valid value
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, SetReceiveBufferReadCursorExTest001, TestSize.Level1)
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(SOCKET_BUFF_SIZE_USER_S);
    bool result = object.SetReceiveBufferReadCursorEx(1);
    EXPECT_TRUE(result);
    EXPECT_EQ(object.GetReceiveBufferReadCursor(), 1);
}

/**
 * @tc.name: SetReceiveBufferReadCursorExTest002
 * @tc.desc: Verify SetReceiveBufferReadCursorEx with invalid value -1
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, SetReceiveBufferReadCursorExTest002, TestSize.Level1)
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(SOCKET_BUFF_SIZE_USER_S);
    bool result = object.SetReceiveBufferReadCursorEx(-1);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: GetSendBufferSizeExTest001
 * @tc.desc: Verify GetSendBufferSizeEx returns correct size
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetSendBufferSizeExTest001, TestSize.Level1)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_L);
    EXPECT_EQ(object.GetSendBufferSizeEx(), static_cast<ssize_t>(SOCKET_BUFF_SIZE_USER_L));
}

/**
 * @tc.name: GetRecvBufferSizeExTest001
 * @tc.desc: Verify GetRecvBufferSizeEx returns correct size
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetRecvBufferSizeExTest001, TestSize.Level1)
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(SOCKET_BUFF_SIZE_USER_L);
    EXPECT_EQ(object.GetRecvBufferSizeEx(), static_cast<ssize_t>(SOCKET_BUFF_SIZE_USER_L));
}

/**
 * @tc.name: ShrinkSendBufferIfNeededTest001
 * @tc.desc: Verify ShrinkSendBufferIfNeeded shrinks large buffer to small
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, ShrinkSendBufferIfNeededTest001, TestSize.Level1)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_L);
    EXPECT_EQ(object.GetSendBufferSizeEx(), static_cast<ssize_t>(SOCKET_BUFF_SIZE_USER_L));
    object.SetSendBufferWriteCursorEx(0);
    object.SetSendBufferReadCursorEx(0);
    object.ShrinkSendBufferIfNeeded();
    EXPECT_EQ(object.GetSendBufferSizeEx(), static_cast<ssize_t>(SOCKET_BUFF_SIZE_USER_S));
}

/**
 * @tc.name: ShrinkSendBufferIfNeededTest002
 * @tc.desc: Verify ShrinkSendBufferIfNeeded keeps small buffer unchanged
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, ShrinkSendBufferIfNeededTest002, TestSize.Level1)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_S);
    EXPECT_EQ(object.GetSendBufferSizeEx(), static_cast<ssize_t>(SOCKET_BUFF_SIZE_USER_S));
    object.SetSendBufferWriteCursorEx(0);
    object.SetSendBufferReadCursorEx(0);
    object.ShrinkSendBufferIfNeeded();
    EXPECT_EQ(object.GetSendBufferSizeEx(), static_cast<ssize_t>(SOCKET_BUFF_SIZE_USER_S));
}

/**
 * @tc.name: ShrinkReceiveBufferIfNeededTest001
 * @tc.desc: Verify ShrinkReceiveBufferIfNeeded shrinks large buffer to small
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, ShrinkReceiveBufferIfNeededTest001, TestSize.Level1)
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(SOCKET_BUFF_SIZE_USER_L);
    EXPECT_EQ(object.GetRecvBufferSizeEx(), static_cast<ssize_t>(SOCKET_BUFF_SIZE_USER_L));
    object.SetReceiveBufferWriteCursorEx(0);
    object.SetReceiveBufferReadCursorEx(0);
    object.ShrinkReceiveBufferIfNeeded();
    EXPECT_EQ(object.GetRecvBufferSizeEx(), static_cast<ssize_t>(SOCKET_BUFF_SIZE_USER_S));
}

/**
 * @tc.name: ShrinkReceiveBufferIfNeededTest002
 * @tc.desc: Verify ShrinkReceiveBufferIfNeeded keeps small buffer unchanged
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, ShrinkReceiveBufferIfNeededTest002, TestSize.Level1)
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(SOCKET_BUFF_SIZE_USER_S);
    EXPECT_EQ(object.GetRecvBufferSizeEx(), static_cast<ssize_t>(SOCKET_BUFF_SIZE_USER_S));
    object.SetReceiveBufferWriteCursorEx(0);
    object.SetReceiveBufferReadCursorEx(0);
    object.ShrinkReceiveBufferIfNeeded();
    EXPECT_EQ(object.GetRecvBufferSizeEx(), static_cast<ssize_t>(SOCKET_BUFF_SIZE_USER_S));
}

/**
 * @tc.name: GetProgressiveBufferSizeTest001
 * @tc.desc: Verify GetProgressiveBufferSize returns correct progressive sizes
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetProgressiveBufferSizeTest001, TestSize.Level1)
{
    BufferObject object;
    EXPECT_EQ(object.GetProgressiveBufferSize(0), SOCKET_BUFF_SIZE_USER_S);
    EXPECT_EQ(object.GetProgressiveBufferSize(SOCKET_BUFF_SIZE_USER_S), SOCKET_BUFF_SIZE_USER_SM);
    EXPECT_EQ(object.GetProgressiveBufferSize(SOCKET_BUFF_SIZE_USER_SM), SOCKET_BUFF_SIZE_USER_M);
    EXPECT_EQ(object.GetProgressiveBufferSize(SOCKET_BUFF_SIZE_USER_M), SOCKET_BUFF_SIZE_USER_ML);
    EXPECT_EQ(object.GetProgressiveBufferSize(SOCKET_BUFF_SIZE_USER_ML), SOCKET_BUFF_SIZE_USER_L);
    EXPECT_EQ(object.GetProgressiveBufferSize(SOCKET_BUFF_SIZE_USER_L), SOCKET_BUFF_SIZE_USER_XL);
    EXPECT_EQ(object.GetProgressiveBufferSize(SOCKET_BUFF_SIZE_USER_XL), SOCKET_BUFF_SIZE_USER_2L);
    EXPECT_EQ(object.GetProgressiveBufferSize(SOCKET_BUFF_SIZE_USER_2L), SOCKET_BUFF_SIZE_USER_3L);
    EXPECT_EQ(object.GetProgressiveBufferSize(SOCKET_BUFF_SIZE_USER_3L), SOCKET_BUFF_SIZE_USER_HUGE);
    EXPECT_EQ(object.GetProgressiveBufferSize(SOCKET_BUFF_SIZE_USER_HUGE), 0);
}

/**
 * @tc.name: GetExpandedBufferSizeTest001
 * @tc.desc: Verify GetExpandedBufferSize calculates correct expanded size
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, GetExpandedBufferSizeTest001, TestSize.Level1)
{
    BufferObject object;
    EXPECT_EQ(object.GetExpandedBufferSize(SOCKET_BUFF_SIZE_USER_S, SOCKET_BUFF_SIZE_USER_M),
        SOCKET_BUFF_SIZE_USER_M);
    EXPECT_EQ(object.GetExpandedBufferSize(SOCKET_BUFF_SIZE_USER_S, SOCKET_BUFF_SIZE_USER_S),
        SOCKET_BUFF_SIZE_USER_SM);
    EXPECT_EQ(object.GetExpandedBufferSize(SOCKET_BUFF_SIZE_USER_M, SOCKET_BUFF_SIZE_USER_S),
        SOCKET_BUFF_SIZE_USER_M);
    EXPECT_EQ(object.GetExpandedBufferSize(SOCKET_BUFF_SIZE_USER_HUGE, SOCKET_BUFF_SIZE_USER_HUGE + 1), 0);
}

/**
 * @tc.name: TryExpandSendBufferLockedTest001
 * @tc.desc: Verify TryExpandSendBufferLocked expands buffer successfully
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, TryExpandSendBufferLockedTest001, TestSize.Level1)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_S);
    object.SetSendBufferWriteCursorEx(SOCKET_BUFF_SIZE_USER_S - 10);
    object.SetSendBufferReadCursorEx(0);
    bool result = object.TryExpandSendBufferLocked(100);
    EXPECT_TRUE(result);
    EXPECT_GT(object.GetSendBufferSizeEx(), static_cast<ssize_t>(SOCKET_BUFF_SIZE_USER_S));
}

/**
 * @tc.name: TryExpandSendBufferLockedTest002
 * @tc.desc: Verify TryExpandSendBufferLocked with large buffer and cursor offset
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, TryExpandSendBufferLockedTest002, TestSize.Level1)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_XL);
    object.SetSendBufferWriteCursorEx(SOCKET_BUFF_SIZE_USER_XL - 8);
    object.SetSendBufferReadCursorEx(SOCKET_BUFF_SIZE_USER_XL - 100);
    bool result = object.TryExpandSendBufferLocked(30 * 1024);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: TryExpandSendBufferLockedTest003
 * @tc.desc: Verify TryExpandSendBufferLocked fails at max size
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, TryExpandSendBufferLockedTest003, TestSize.Level1)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_HUGE);
    object.SetSendBufferWriteCursorEx(SOCKET_BUFF_SIZE_USER_HUGE - 1);
    object.SetSendBufferReadCursorEx(0);
    bool result = object.TryExpandSendBufferLocked(SOCKET_BUFF_SIZE_USER_HUGE);
    EXPECT_FALSE(result);
    EXPECT_EQ(object.GetSendBufferWriteCursor(), 0);
    EXPECT_EQ(object.GetSendBufferReadCursor(), 0);
}

/**
 * @tc.name: TryExpandSendBufferLockedTest004
 * @tc.desc: Verify TryExpandSendBufferLocked handles invalid cursor state
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, TryExpandSendBufferLockedTest004, TestSize.Level1)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_S);
    object.sendBufferCursorW_ = 10;
    object.sendBufferCursorR_ = 50;
    bool result = object.TryExpandSendBufferLocked(100);
    EXPECT_FALSE(result);
    EXPECT_EQ(object.sendBufferCursorW_, 0);
    EXPECT_EQ(object.sendBufferCursorR_, 0);
}

/**
 * @tc.name: TryExpandReceiveBufferLockedTest001
 * @tc.desc: Verify TryExpandReceiveBufferLocked expands buffer successfully
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, TryExpandReceiveBufferLockedTest001, TestSize.Level1)
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(SOCKET_BUFF_SIZE_USER_S);
    object.SetReceiveBufferWriteCursorEx(SOCKET_BUFF_SIZE_USER_S - 10);
    object.SetReceiveBufferReadCursorEx(0);
    bool result = object.TryExpandReceiveBufferLocked(100);
    EXPECT_TRUE(result);
    EXPECT_GT(object.GetRecvBufferSizeEx(), static_cast<ssize_t>(SOCKET_BUFF_SIZE_USER_S));
}

/**
 * @tc.name: TryExpandReceiveBufferLockedTest002
 * @tc.desc: Verify TryExpandReceiveBufferLocked with large buffer and cursor offset
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, TryExpandReceiveBufferLockedTest002, TestSize.Level1)
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(SOCKET_BUFF_SIZE_USER_XL);
    object.SetReceiveBufferWriteCursorEx(SOCKET_BUFF_SIZE_USER_XL - 8);
    object.SetReceiveBufferReadCursorEx(SOCKET_BUFF_SIZE_USER_XL - 100);
    bool result = object.TryExpandReceiveBufferLocked(30 * 1024);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: TryExpandReceiveBufferLockedTest003
 * @tc.desc: Verify TryExpandReceiveBufferLocked fails at max size
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, TryExpandReceiveBufferLockedTest003, TestSize.Level1)
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(SOCKET_BUFF_SIZE_USER_HUGE);
    object.SetReceiveBufferWriteCursorEx(SOCKET_BUFF_SIZE_USER_HUGE - 1);
    object.SetReceiveBufferReadCursorEx(0);
    bool result = object.TryExpandReceiveBufferLocked(SOCKET_BUFF_SIZE_USER_HUGE);
    EXPECT_FALSE(result);
    EXPECT_EQ(object.GetReceiveBufferWriteCursor(), 0);
    EXPECT_EQ(object.GetReceiveBufferReadCursor(), 0);
}

/**
 * @tc.name: TryExpandReceiveBufferLockedTest004
 * @tc.desc: Verify TryExpandReceiveBufferLocked handles invalid cursor state
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, TryExpandReceiveBufferLockedTest004, TestSize.Level1)
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(SOCKET_BUFF_SIZE_USER_S);
    object.recvBufferCursorW_ = 10;
    object.recvBufferCursorR_ = 50;
    bool result = object.TryExpandReceiveBufferLocked(100);
    EXPECT_FALSE(result);
    EXPECT_EQ(object.recvBufferCursorW_, 0);
    EXPECT_EQ(object.recvBufferCursorR_, 0);
}

/**
 * @tc.name: TryMemmoveSendBufferTest001
 * @tc.desc: Verify TryMemmoveSendBuffer moves data correctly
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, TryMemmoveSendBufferTest001, TestSize.Level1)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_S);
    object.SetSendBufferWriteCursorEx(100);
    object.SetSendBufferReadCursorEx(50);
    bool result = object.TryMemmoveSendBuffer();
    EXPECT_TRUE(result);
}

/**
 * @tc.name: TryMemmoveReceiveBufferTest001
 * @tc.desc: Verify TryMemmoveReceiveBuffer moves data correctly
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, TryMemmoveReceiveBufferTest001, TestSize.Level1)
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(SOCKET_BUFF_SIZE_USER_S);
    object.SetReceiveBufferWriteCursorEx(100);
    object.SetReceiveBufferReadCursorEx(50);
    bool result = object.TryMemmoveReceiveBuffer();
    EXPECT_TRUE(result);
}

/**
 * @tc.name: MemmoveSendBufferIfInsufficientTest001
 * @tc.desc: Verify MemmoveSendBufferIfInsufficient when space is sufficient
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, MemmoveSendBufferIfInsufficientTest001, TestSize.Level1)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_L);
    object.SetSendBufferWriteCursorEx(100);
    object.SetSendBufferReadCursorEx(50);
    bool result = object.MemmoveSendBufferIfInsufficient(1000);
    EXPECT_TRUE(result);
    EXPECT_EQ(object.GetSendBufferWriteCursor(), 100);
    EXPECT_EQ(object.GetSendBufferReadCursor(), 50);
}

/**
 * @tc.name: MemmoveSendBufferIfInsufficientTest002
 * @tc.desc: Verify MemmoveSendBufferIfInsufficient triggers memmove when insufficient
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, MemmoveSendBufferIfInsufficientTest002, TestSize.Level1)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_S);
    object.SetSendBufferWriteCursorEx(SOCKET_BUFF_SIZE_USER_S - 10);
    object.SetSendBufferReadCursorEx(100);
    ssize_t expectedMoveLen = SOCKET_BUFF_SIZE_USER_S - 110;
    bool result = object.MemmoveSendBufferIfInsufficient(50);
    EXPECT_TRUE(result);
    EXPECT_EQ(object.GetSendBufferWriteCursor(), expectedMoveLen);
    EXPECT_EQ(object.GetSendBufferReadCursor(), 0);
}

/**
 * @tc.name: MemmoveSendBufferIfInsufficientTest003
 * @tc.desc: Verify MemmoveSendBufferIfInsufficient fails when still insufficient after memmove
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, MemmoveSendBufferIfInsufficientTest003, TestSize.Level1)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_S);
    object.SetSendBufferWriteCursorEx(SOCKET_BUFF_SIZE_USER_S - 10);
    object.SetSendBufferReadCursorEx(0);
    bool result = object.MemmoveSendBufferIfInsufficient(SOCKET_BUFF_SIZE_USER_S);
    EXPECT_FALSE(result);
    EXPECT_EQ(object.GetSendBufferWriteCursor(), 0);
    EXPECT_EQ(object.GetSendBufferReadCursor(), 0);
}

/**
 * @tc.name: MemmoveReceiveBufferIfInsufficientTest001
 * @tc.desc: Verify MemmoveReceiveBufferIfInsufficient when space is sufficient
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, MemmoveReceiveBufferIfInsufficientTest001, TestSize.Level1)
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(SOCKET_BUFF_SIZE_USER_L);
    object.SetReceiveBufferWriteCursorEx(100);
    object.SetReceiveBufferReadCursorEx(50);
    bool result = object.MemmoveReceiveBufferIfInsufficient(1000);
    EXPECT_TRUE(result);
    EXPECT_EQ(object.GetReceiveBufferWriteCursor(), 100);
    EXPECT_EQ(object.GetReceiveBufferReadCursor(), 50);
}

/**
 * @tc.name: MemmoveReceiveBufferIfInsufficientTest002
 * @tc.desc: Verify MemmoveReceiveBufferIfInsufficient triggers memmove when insufficient
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, MemmoveReceiveBufferIfInsufficientTest002, TestSize.Level1)
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(SOCKET_BUFF_SIZE_USER_S);
    object.SetReceiveBufferWriteCursorEx(SOCKET_BUFF_SIZE_USER_S - 10);
    object.SetReceiveBufferReadCursorEx(100);
    ssize_t expectedMoveLen = SOCKET_BUFF_SIZE_USER_S - 110;
    bool result = object.MemmoveReceiveBufferIfInsufficient(50);
    EXPECT_TRUE(result);
    EXPECT_EQ(object.GetReceiveBufferWriteCursor(), expectedMoveLen);
    EXPECT_EQ(object.GetReceiveBufferReadCursor(), 0);
}

/**
 * @tc.name: MemmoveReceiveBufferIfInsufficientTest003
 * @tc.desc: Verify MemmoveReceiveBufferIfInsufficient fails when still insufficient after memmove
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, MemmoveReceiveBufferIfInsufficientTest003, TestSize.Level1)
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(SOCKET_BUFF_SIZE_USER_S);
    object.SetReceiveBufferWriteCursorEx(SOCKET_BUFF_SIZE_USER_S - 10);
    object.SetReceiveBufferReadCursorEx(0);
    bool result = object.MemmoveReceiveBufferIfInsufficient(SOCKET_BUFF_SIZE_USER_S);
    EXPECT_FALSE(result);
    EXPECT_EQ(object.GetReceiveBufferWriteCursor(), 0);
    EXPECT_EQ(object.GetReceiveBufferReadCursor(), 0);
}

/**
 * @tc.name: SmartExpandAvoidDoubleExpandTest
 * @tc.desc: Verify smart expansion avoids unnecessary double expansion
 * @tc.type: FUNC
 */
HWTEST_F(BufferObjectUnitTest, SmartExpandAvoidDoubleExpandTest, TestSize.Level1)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_XL);
    object.SetSendBufferWriteCursorEx(120 * 1024);
    object.SetSendBufferReadCursorEx(0);
    char* result = object.UpdateSendBufferLocked(30 * 1024);
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(object.GetSendBufferSizeEx(), static_cast<ssize_t>(SOCKET_BUFF_SIZE_USER_2L));
}
} // namespace OHOS