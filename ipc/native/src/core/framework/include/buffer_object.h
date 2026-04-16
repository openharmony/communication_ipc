/*
 * Copyright (C) 2021-2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_IPC_BUFFER_OBJECT_H
#define OHOS_IPC_BUFFER_OBJECT_H

#include <cstdint>
#include <mutex>
#include <pthread.h>
#include <string>
#include <sys/types.h>

#include "nocopyable.h"

namespace OHOS {
constexpr int SOCKET_DEFAULT_BUFF_SIZE = 4 * 1024;
constexpr int SOCKET_MAX_BUFF_SIZE = 1024 * 1024;
constexpr int SOCKET_BUFF_RESERVED_SIZE = 256;
constexpr size_t MAX_RAWDATA_SIZE = 128 * 1024 * 1024;

// 9-level progressive buffer sizing
constexpr uint32_t SOCKET_BUFF_SIZE_USER_S    = 4 * 1024;
constexpr uint32_t SOCKET_BUFF_SIZE_USER_SM   = 8 * 1024;
constexpr uint32_t SOCKET_BUFF_SIZE_USER_M    = 16 * 1024;
constexpr uint32_t SOCKET_BUFF_SIZE_USER_ML   = 32 * 1024;
constexpr uint32_t SOCKET_BUFF_SIZE_USER_L    = 64 * 1024;
constexpr uint32_t SOCKET_BUFF_SIZE_USER_XL   = 128 * 1024;
constexpr uint32_t SOCKET_BUFF_SIZE_USER_2L   = 256 * 1024;
constexpr uint32_t SOCKET_BUFF_SIZE_USER_3L   = 512 * 1024;
constexpr uint32_t SOCKET_BUFF_SIZE_USER_HUGE = 1024 * 1024;

class BufferLockGuard {
public:
    explicit BufferLockGuard(std::mutex& mtx) : mutex_(&mtx), locked_(true)
    {
        mutex_->lock();
    }

    BufferLockGuard(BufferLockGuard&& other) noexcept : mutex_(other.mutex_), locked_(other.locked_)
    {
        other.mutex_ = nullptr;
        other.locked_ = false;
    }

    BufferLockGuard& operator=(BufferLockGuard&& other) noexcept
    {
        if (this != &other) {
            if (locked_ && mutex_) {
                mutex_->unlock();
            }
            mutex_ = other.mutex_;
            locked_ = other.locked_;
            other.mutex_ = nullptr;
            other.locked_ = false;
        }
        return *this;
    }

    ~BufferLockGuard()
    {
        if (locked_ && mutex_) {
            mutex_->unlock();
        }
    }

    void Unlock()
    {
        if (locked_ && mutex_) {
            mutex_->unlock();
            locked_ = false;
        }
    }

    bool IsLocked() const { return locked_; }

private:
    std::mutex* mutex_;
    bool locked_;
    DISALLOW_COPY(BufferLockGuard);
};

struct SendBufferContext {
    char* buffer;
    ssize_t size;
    BufferLockGuard lockGuard;
};

struct ReceiveBufferContext {
    char* buffer;
    ssize_t size;
    BufferLockGuard lockGuard;
};

class BufferObject {
public:
    BufferObject();
    ~BufferObject();

    // ===== Original interfaces (deprecated, strict order for ABI compatibility) =====
    [[deprecated("use UpdateReceiveBufferLocked instead")]]
    void UpdateReceiveBuffer();

    [[deprecated("use UpdateSendBufferLocked instead")]]
    void UpdateSendBuffer(uint32_t userDataSize);

    [[deprecated("use AcquireSendBuffer instead")]]
    char* GetSendBufferAndLock(uint32_t size);

    [[deprecated("use AcquireReceiveBuffer instead")]]
    char* GetReceiveBufferAndLock(uint32_t size);

    [[deprecated("lock is managed by AcquireSendBuffer automatically")]]
    void ReleaseSendBufferLock();

    [[deprecated("lock is managed by AcquireReceiveBuffer automatically")]]
    void ReleaseReceiveBufferLock();

    ssize_t GetReceiveBufferWriteCursor() const;

    [[deprecated("use SetReceiveBufferWriteCursorEx instead")]]
    void SetReceiveBufferWriteCursor(ssize_t newWriteCursor);

    ssize_t GetReceiveBufferReadCursor() const;

    [[deprecated("use SetReceiveBufferReadCursorEx instead")]]
    void SetReceiveBufferReadCursor(ssize_t newReadCursor);

    ssize_t GetSendBufferWriteCursor() const;

    [[deprecated("use SetSendBufferWriteCursorEx instead")]]
    void SetSendBufferWriteCursor(ssize_t newWriteCursor);

    ssize_t GetSendBufferReadCursor() const;

    [[deprecated("use SetSendBufferReadCursorEx instead")]]
    void SetSendBufferReadCursor(ssize_t newReadCursor);

    uint32_t GetNeedBufferSize(uint32_t size) const;

    [[deprecated("use GetSendBufferSizeEx instead")]]
    uint32_t GetSendBufferSize() const;

    [[deprecated("use GetRecvBufferSizeEx instead")]]
    uint32_t GetRecvBufferSize() const;

    // ===== New interfaces (recommended, Ex suffix for extended/checked version) =====
    // NOTE: Caller must hold sendMutex_ (via AcquireSendBuffer) before calling.
    bool SetSendBufferWriteCursorEx(ssize_t newWriteCursor);

    // NOTE: Caller must hold sendMutex_ (via AcquireSendBuffer) before calling.
    bool SetSendBufferReadCursorEx(ssize_t newReadCursor);

    // NOTE: Caller must hold recvMutex_ (via AcquireReceiveBuffer) before calling.
    bool SetReceiveBufferWriteCursorEx(ssize_t newWriteCursor);

    // NOTE: Caller must hold recvMutex_ (via AcquireReceiveBuffer) before calling.
    bool SetReceiveBufferReadCursorEx(ssize_t newReadCursor);

    // NOTE: Caller must hold sendMutex_ (via AcquireSendBuffer) before calling.
    ssize_t GetSendBufferSizeEx() const;

    // NOTE: Caller must hold recvMutex_ (via AcquireReceiveBuffer) before calling.
    ssize_t GetRecvBufferSizeEx() const;

    // RAII interface: acquire buffer with lock guard. Lock is automatically released when context destroyed.
    SendBufferContext AcquireSendBuffer(uint32_t size);
    ReceiveBufferContext AcquireReceiveBuffer(uint32_t size);

    // NOTE: Caller must hold lock (via AcquireSendBuffer) before calling.
    // Returns buffer pointer (may differ from ctx.buffer if reallocated).
    char* UpdateSendBufferLocked(uint32_t userDataSize);

    // NOTE: Caller must hold lock (via AcquireReceiveBuffer) before calling.
    char* UpdateReceiveBufferLocked(uint32_t userDataSize);

    // NOTE: Caller must hold sendMutex_ (via AcquireSendBuffer) before calling.
    void ShrinkSendBufferIfNeeded();

    // NOTE: Caller must hold recvMutex_ (via AcquireReceiveBuffer) before calling.
    void ShrinkReceiveBufferIfNeeded();

private:
    DISALLOW_COPY_AND_MOVE(BufferObject);

    bool ExpandSendBuffer(uint32_t size);
    bool ExpandReceiveBuffer(uint32_t size);
    uint32_t GetProgressiveBufferSize(uint32_t currentSize) const;
    uint32_t GetExpandedBufferSize(uint32_t currentBuffSize, uint32_t totalNeedSize) const;

    bool TryExpandSendBufferLocked(uint32_t userDataSize);
    bool TryExpandReceiveBufferLocked(uint32_t userDataSize);
    bool TryMemmoveSendBuffer();
    bool TryMemmoveReceiveBuffer();
    bool MemmoveSendBufferIfInsufficient(uint32_t userDataSize);
    bool MemmoveReceiveBufferIfInsufficient(uint32_t userDataSize);

    ssize_t recvBufferCursorW_ = 0;
    ssize_t recvBufferCursorR_ = 0;
    ssize_t sendBufferCursorW_ = 0;
    ssize_t sendBufferCursorR_ = 0;
    char* receiveBuffer_ = nullptr;
    char* sendBuffer_ = nullptr;
    std::mutex sendMutex_;
    std::mutex recvMutex_;
    ssize_t sendBuffSize_ = 0;
    ssize_t recvBuffSize_ = 0;
};
} // namespace OHOS
#endif // OHOS_IPC_BUFFER_OBJECT_H