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

#include "buffer_object.h"

#include "ipc_debug.h"
#include "log_tags.h"
#include "securec.h"
#include "sys_binder.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_COMMON, "BufferObject" };

BufferObject::BufferObject()
{
}

BufferObject::~BufferObject()
{
    if (receiveBuffer_ != nullptr) {
        delete[] receiveBuffer_;
        receiveBuffer_ = nullptr;
    }
    if (sendBuffer_ != nullptr) {
        delete[] sendBuffer_;
        sendBuffer_ = nullptr;
    }
}

void BufferObject::UpdateReceiveBuffer()
{
    if (recvBufferCursorW_ <= recvBufferCursorR_) {
        recvBufferCursorR_ = 0;
        recvBufferCursorW_ = 0;
        return;
    }
    if (recvBuffSize_ - recvBufferCursorW_ < SOCKET_BUFF_RESERVED_SIZE &&
        recvBufferCursorW_ - recvBufferCursorR_ < recvBufferCursorR_) {
        errno_t memcpyResult = memmove_s(receiveBuffer_, recvBufferCursorW_ - recvBufferCursorR_,
            receiveBuffer_ + recvBufferCursorR_, recvBufferCursorW_ - recvBufferCursorR_);
        if (memcpyResult != EOK) {
            recvBufferCursorW_ = 0;
        } else {
            recvBufferCursorW_ = recvBufferCursorW_ - recvBufferCursorR_;
        }
        recvBufferCursorR_ = 0;
    }
}

void BufferObject::UpdateSendBuffer(uint32_t userDataSize)
{
    if (sendBufferCursorW_ <= sendBufferCursorR_) {
        sendBufferCursorW_ = 0;
        sendBufferCursorR_ = 0;
        return;
    }
    if (sendBuffSize_ - sendBufferCursorW_ <= static_cast<ssize_t>(userDataSize)) {
        ExpandSendBuffer(static_cast<uint32_t>(sendBuffSize_) + static_cast<uint32_t>(sendBuffSize_));
    }
    if (sendBuffSize_ - sendBufferCursorW_ < SOCKET_BUFF_RESERVED_SIZE &&
        sendBufferCursorW_ - sendBufferCursorR_ < sendBufferCursorR_) {
        errno_t memcpyResult = memmove_s(sendBuffer_, sendBufferCursorW_ - sendBufferCursorR_,
            sendBuffer_ + sendBufferCursorR_, sendBufferCursorW_ - sendBufferCursorR_);
        if (memcpyResult != EOK) {
            sendBufferCursorW_ = 0;
        } else {
            sendBufferCursorW_ = sendBufferCursorW_ - sendBufferCursorR_;
        }
        sendBufferCursorR_ = 0;
    }
}

char* BufferObject::GetSendBufferAndLock(uint32_t size)
{
    uint32_t needSize = GetNeedBufferSize(size);
    if (needSize == 0) {
        return nullptr;
    }
    sendMutex_.lock();
    if (!ExpandSendBuffer(size)) {
        sendMutex_.unlock();
        return nullptr;
    }
    return sendBuffer_;
}

char* BufferObject::GetReceiveBufferAndLock(uint32_t size)
{
    uint32_t needSize = GetNeedBufferSize(size);
    if (needSize == 0) {
        return nullptr;
    }
    recvMutex_.lock();
    if (needSize > static_cast<uint32_t>(recvBuffSize_)) {
        char* newBuffer = new (std::nothrow) char[needSize];
        if (newBuffer == nullptr) {
            recvMutex_.unlock();
            return nullptr;
        }
        if (receiveBuffer_ != nullptr && recvBuffSize_ > 0) {
            errno_t memcpyResult = memcpy_s(newBuffer, needSize, receiveBuffer_, static_cast<size_t>(recvBuffSize_));
            if (memcpyResult != EOK) {
                delete[] newBuffer;
                recvMutex_.unlock();
                return nullptr;
            }
        }
        delete[] receiveBuffer_;
        receiveBuffer_ = newBuffer;
        recvBuffSize_ = static_cast<ssize_t>(needSize);
    }
    return receiveBuffer_;
}

void BufferObject::ReleaseSendBufferLock()
{
    sendMutex_.unlock();
}

void BufferObject::ReleaseReceiveBufferLock()
{
    recvMutex_.unlock();
}

void BufferObject::SetReceiveBufferWriteCursor(ssize_t newWriteCursor)
{
    if (newWriteCursor < 0) {
        return;
    }
    recvBufferCursorW_ = newWriteCursor;
}

void BufferObject::SetReceiveBufferReadCursor(ssize_t newReadCursor)
{
    recvBufferCursorR_ = newReadCursor;
}

void BufferObject::SetSendBufferWriteCursor(ssize_t newWriteCursor)
{
    if (newWriteCursor < 0) {
        return;
    }
    sendBufferCursorW_ = newWriteCursor;
}

void BufferObject::SetSendBufferReadCursor(ssize_t newReadCursor)
{
    sendBufferCursorR_ = newReadCursor;
}

uint32_t BufferObject::GetSendBufferSize() const
{
    return static_cast<uint32_t>(sendBuffSize_);
}

uint32_t BufferObject::GetRecvBufferSize() const
{
    return static_cast<uint32_t>(recvBuffSize_);
}

bool BufferObject::SetSendBufferWriteCursorEx(ssize_t newWriteCursor)
{
    if (newWriteCursor < 0) {
        ZLOGE(LOG_LABEL, "Invalid send write cursor: %{public}zd", newWriteCursor);
        return false;
    }
    if (sendBuffSize_ > 0 && newWriteCursor > sendBuffSize_) {
        ZLOGE(LOG_LABEL, "Send write cursor %{public}zd exceeds buffer size %{public}zd",
            newWriteCursor, sendBuffSize_);
        return false;
    }
    sendBufferCursorW_ = newWriteCursor;
    return true;
}

bool BufferObject::SetSendBufferReadCursorEx(ssize_t newReadCursor)
{
    if (newReadCursor < 0) {
        ZLOGE(LOG_LABEL, "Invalid send read cursor: %{public}zd", newReadCursor);
        return false;
    }
    if (sendBuffSize_ > 0 && newReadCursor > sendBuffSize_) {
        ZLOGE(LOG_LABEL, "Send read cursor %{public}zd exceeds buffer size %{public}zd",
            newReadCursor, sendBuffSize_);
        return false;
    }
    sendBufferCursorR_ = newReadCursor;
    return true;
}

bool BufferObject::SetReceiveBufferWriteCursorEx(ssize_t newWriteCursor)
{
    if (newWriteCursor < 0) {
        ZLOGE(LOG_LABEL, "Invalid receive write cursor: %{public}zd", newWriteCursor);
        return false;
    }
    if (recvBuffSize_ > 0 && newWriteCursor > recvBuffSize_) {
        ZLOGE(LOG_LABEL, "Receive write cursor %{public}zd exceeds buffer size %{public}zd",
            newWriteCursor, recvBuffSize_);
        return false;
    }
    recvBufferCursorW_ = newWriteCursor;
    return true;
}

bool BufferObject::SetReceiveBufferReadCursorEx(ssize_t newReadCursor)
{
    if (newReadCursor < 0) {
        ZLOGE(LOG_LABEL, "Invalid receive read cursor: %{public}zd", newReadCursor);
        return false;
    }
    if (recvBuffSize_ > 0 && newReadCursor > recvBuffSize_) {
        ZLOGE(LOG_LABEL, "Receive read cursor %{public}zd exceeds buffer size %{public}zd",
            newReadCursor, recvBuffSize_);
        return false;
    }
    recvBufferCursorR_ = newReadCursor;
    return true;
}

ssize_t BufferObject::GetSendBufferSizeEx() const
{
    return sendBuffSize_;
}

ssize_t BufferObject::GetRecvBufferSizeEx() const
{
    return recvBuffSize_;
}

// RAII interface: acquire send buffer with lock guard
SendBufferContext BufferObject::AcquireSendBuffer(uint32_t size)
{
    BufferLockGuard lockGuard(sendMutex_);
    uint32_t needSize = GetNeedBufferSize(size);
    if (needSize == 0) {
        ZLOGE(LOG_LABEL, "Invalid send buffer size request: %{public}u (max: %{public}u)",
            size, SOCKET_BUFF_SIZE_USER_HUGE);
        lockGuard.Unlock();
        return SendBufferContext{nullptr, 0, std::move(lockGuard)};
    }
    if (!ExpandSendBuffer(needSize)) {
        ZLOGE(LOG_LABEL, "Expand send buffer failed, needSize: %{public}u", needSize);
        lockGuard.Unlock();
        return SendBufferContext{nullptr, 0, std::move(lockGuard)};
    }
    return SendBufferContext{sendBuffer_, sendBuffSize_, std::move(lockGuard)};
}

ReceiveBufferContext BufferObject::AcquireReceiveBuffer(uint32_t size)
{
    BufferLockGuard lockGuard(recvMutex_);
    uint32_t needSize = GetNeedBufferSize(size);
    if (needSize == 0) {
        ZLOGE(LOG_LABEL, "Invalid receive buffer size request: %{public}u (max: %{public}u)",
            size, SOCKET_BUFF_SIZE_USER_HUGE);
        lockGuard.Unlock();
        return ReceiveBufferContext{nullptr, 0, std::move(lockGuard)};
    }
    if (!ExpandReceiveBuffer(needSize)) {
        ZLOGE(LOG_LABEL, "Expand receive buffer failed, needSize: %{public}u", needSize);
        lockGuard.Unlock();
        return ReceiveBufferContext{nullptr, 0, std::move(lockGuard)};
    }
    return ReceiveBufferContext{receiveBuffer_, recvBuffSize_, std::move(lockGuard)};
}

bool BufferObject::ExpandSendBuffer(uint32_t size)
{
    uint32_t needSize = GetNeedBufferSize(size);
    if (needSize == 0) {
        return true;
    }
    if (needSize > static_cast<uint32_t>(sendBuffSize_)) {
        char* newBuffer = new (std::nothrow) char[needSize];
        if (newBuffer == nullptr) {
            return false;
        }
        if (sendBuffer_ != nullptr && sendBuffSize_ > 0) {
            errno_t result = memcpy_s(newBuffer, needSize, sendBuffer_, static_cast<size_t>(sendBuffSize_));
            if (result != EOK) {
                delete[] newBuffer;
                return false;
            }
        }
        delete[] sendBuffer_;
        sendBuffer_ = newBuffer;
        sendBuffSize_ = static_cast<ssize_t>(needSize);
    }
    return true;
}

bool BufferObject::ExpandReceiveBuffer(uint32_t size)
{
    if (size == 0) {
        ZLOGE(LOG_LABEL, "Expand receive buffer called with size 0");
        recvBufferCursorW_ = 0;
        recvBufferCursorR_ = 0;
        return false;
    }
    ssize_t targetSize = static_cast<ssize_t>(size);
    if (targetSize <= recvBuffSize_) {
        return true;
    }
    char* newBuffer = new (std::nothrow) char[size];
    if (newBuffer == nullptr) {
        ZLOGE(LOG_LABEL, "Allocate receive buffer failed, size: %{public}u", size);
        recvBufferCursorW_ = 0;
        recvBufferCursorR_ = 0;
        return false;
    }
    if (receiveBuffer_ != nullptr && recvBuffSize_ > 0) {
        errno_t result = memcpy_s(newBuffer, size, receiveBuffer_, static_cast<size_t>(recvBuffSize_));
        if (result != EOK) {
            ZLOGE(LOG_LABEL, "memcpy_s failed in expand receive buffer, result: %{public}d", result);
            delete[] newBuffer;
            recvBufferCursorW_ = 0;
            recvBufferCursorR_ = 0;
            return false;
        }
    }
    delete[] receiveBuffer_;
    receiveBuffer_ = newBuffer;
    recvBuffSize_ = targetSize;
    return true;
}

uint32_t BufferObject::GetNeedBufferSize(uint32_t size) const
{
    if (size <= SOCKET_BUFF_SIZE_USER_S) {
        return SOCKET_BUFF_SIZE_USER_S;
    } else if (size <= SOCKET_BUFF_SIZE_USER_SM) {
        return SOCKET_BUFF_SIZE_USER_SM;
    } else if (size <= SOCKET_BUFF_SIZE_USER_M) {
        return SOCKET_BUFF_SIZE_USER_M;
    } else if (size <= SOCKET_BUFF_SIZE_USER_ML) {
        return SOCKET_BUFF_SIZE_USER_ML;
    } else if (size <= SOCKET_BUFF_SIZE_USER_L) {
        return SOCKET_BUFF_SIZE_USER_L;
    } else if (size <= SOCKET_BUFF_SIZE_USER_XL) {
        return SOCKET_BUFF_SIZE_USER_XL;
    } else if (size <= SOCKET_BUFF_SIZE_USER_2L) {
        return SOCKET_BUFF_SIZE_USER_2L;
    } else if (size <= SOCKET_BUFF_SIZE_USER_3L) {
        return SOCKET_BUFF_SIZE_USER_3L;
    } else if (size <= SOCKET_BUFF_SIZE_USER_HUGE) {
        return SOCKET_BUFF_SIZE_USER_HUGE;
    }
    ZLOGE(LOG_LABEL, "Buffer size exceeds maximum limit: %{public}u (max: %{public}u)",
        size, SOCKET_BUFF_SIZE_USER_HUGE);
    return 0;
}

uint32_t BufferObject::GetProgressiveBufferSize(uint32_t currentSize) const
{
    if (currentSize < SOCKET_BUFF_SIZE_USER_S) return SOCKET_BUFF_SIZE_USER_S;
    if (currentSize < SOCKET_BUFF_SIZE_USER_SM) return SOCKET_BUFF_SIZE_USER_SM;
    if (currentSize < SOCKET_BUFF_SIZE_USER_M) return SOCKET_BUFF_SIZE_USER_M;
    if (currentSize < SOCKET_BUFF_SIZE_USER_ML) return SOCKET_BUFF_SIZE_USER_ML;
    if (currentSize < SOCKET_BUFF_SIZE_USER_L) return SOCKET_BUFF_SIZE_USER_L;
    if (currentSize < SOCKET_BUFF_SIZE_USER_XL) return SOCKET_BUFF_SIZE_USER_XL;
    if (currentSize < SOCKET_BUFF_SIZE_USER_2L) return SOCKET_BUFF_SIZE_USER_2L;
    if (currentSize < SOCKET_BUFF_SIZE_USER_3L) return SOCKET_BUFF_SIZE_USER_3L;
    if (currentSize < SOCKET_BUFF_SIZE_USER_HUGE) return SOCKET_BUFF_SIZE_USER_HUGE;
    return 0;
}

uint32_t BufferObject::GetExpandedBufferSize(uint32_t currentBuffSize, uint32_t totalNeedSize) const
{
    uint32_t alignedNeed = GetNeedBufferSize(totalNeedSize);
    if (alignedNeed == 0) return 0;
    if (alignedNeed > currentBuffSize) return alignedNeed;
    if (alignedNeed == currentBuffSize) return GetProgressiveBufferSize(currentBuffSize);
    return currentBuffSize;
}

bool BufferObject::TryExpandSendBufferLocked(uint32_t userDataSize)
{
    ssize_t usedSpace = sendBufferCursorW_ - sendBufferCursorR_;
    if (usedSpace < 0) {
        ZLOGE(LOG_LABEL, "Invalid cursor state: write=%{public}zd < read=%{public}zd",
            sendBufferCursorW_, sendBufferCursorR_);
        sendBufferCursorW_ = 0;
        sendBufferCursorR_ = 0;
        return false;
    }
    constexpr ssize_t SSIZE_MAX_VAL = static_cast<ssize_t>(SOCKET_BUFF_SIZE_USER_HUGE);
    if (usedSpace > SSIZE_MAX_VAL - userDataSize - SOCKET_BUFF_RESERVED_SIZE) {
        ZLOGE(LOG_LABEL, "Integer overflow detected: usedSpace=%{public}zd, userDataSize=%{public}u",
            usedSpace, userDataSize);
        sendBufferCursorW_ = 0;
        sendBufferCursorR_ = 0;
        return false;
    }
    ssize_t totalNeed = usedSpace + userDataSize + SOCKET_BUFF_RESERVED_SIZE;
    if (totalNeed <= 0 || totalNeed > SOCKET_BUFF_SIZE_USER_HUGE) {
        ZLOGE(LOG_LABEL, "Invalid totalNeed: %{public}zd (max: %{public}u)",
            totalNeed, SOCKET_BUFF_SIZE_USER_HUGE);
        sendBufferCursorW_ = 0;
        sendBufferCursorR_ = 0;
        return false;
    }
    uint32_t nextSize = GetExpandedBufferSize(static_cast<uint32_t>(sendBuffSize_),
        static_cast<uint32_t>(totalNeed));
    if (nextSize == 0) {
        ZLOGE(LOG_LABEL, "Cannot expand send buffer beyond limit, totalNeed: %{public}zd", totalNeed);
        sendBufferCursorW_ = 0;
        sendBufferCursorR_ = 0;
        return false;
    }
    if (!ExpandSendBuffer(nextSize)) {
        ZLOGE(LOG_LABEL, "Expand send buffer failed, nextSize: %{public}u", nextSize);
        sendBufferCursorW_ = 0;
        sendBufferCursorR_ = 0;
        return false;
    }
    return MemmoveSendBufferIfInsufficient(userDataSize);
}

bool BufferObject::MemmoveSendBufferIfInsufficient(uint32_t userDataSize)
{
    ssize_t remainingSpace = sendBuffSize_ - sendBufferCursorW_;
    if (remainingSpace <= static_cast<ssize_t>(userDataSize)) {
        ssize_t moveLen = sendBufferCursorW_ - sendBufferCursorR_;
        errno_t result = memmove_s(sendBuffer_, static_cast<size_t>(moveLen),
            sendBuffer_ + sendBufferCursorR_, static_cast<size_t>(moveLen));
        if (result != EOK) {
            ZLOGE(LOG_LABEL, "memmove_s failed in send buffer, result: %{public}d", result);
            sendBufferCursorW_ = 0;
            sendBufferCursorR_ = 0;
            return false;
        }
        sendBufferCursorW_ = moveLen;
        sendBufferCursorR_ = 0;
    }
    ssize_t remaining = sendBuffSize_ - sendBufferCursorW_;
    if (remaining <= static_cast<ssize_t>(userDataSize)) {
        ZLOGE(LOG_LABEL, "Insufficient space after memmove in send buffer");
        sendBufferCursorW_ = 0;
        sendBufferCursorR_ = 0;
        return false;
    }
    return true;
}

bool BufferObject::TryMemmoveSendBuffer()
{
    ssize_t moveLen = sendBufferCursorW_ - sendBufferCursorR_;
    ssize_t tailSpace = sendBuffSize_ - sendBufferCursorW_;
    if (tailSpace < SOCKET_BUFF_RESERVED_SIZE && moveLen < sendBufferCursorR_ && moveLen > 0) {
        errno_t result = memmove_s(sendBuffer_, static_cast<size_t>(moveLen),
            sendBuffer_ + sendBufferCursorR_, static_cast<size_t>(moveLen));
        if (result != EOK) {
            ZLOGE(LOG_LABEL, "memmove_s failed in send buffer, result: %{public}d", result);
            sendBufferCursorW_ = 0;
            sendBufferCursorR_ = 0;
            return false;
        }
        sendBufferCursorW_ = moveLen;
        sendBufferCursorR_ = 0;
    }
    return true;
}

char* BufferObject::UpdateSendBufferLocked(uint32_t userDataSize)
{
    if (sendBufferCursorW_ <= sendBufferCursorR_) {
        sendBufferCursorW_ = 0;
        sendBufferCursorR_ = 0;
        return sendBuffer_;
    }
    ssize_t remainingSpace = sendBuffSize_ - sendBufferCursorW_;
    if (remainingSpace <= static_cast<ssize_t>(userDataSize)) {
        if (!TryExpandSendBufferLocked(userDataSize)) {
            return nullptr;
        }
    }
    if (!TryMemmoveSendBuffer()) {
        return nullptr;
    }
    return sendBuffer_;
}

bool BufferObject::TryExpandReceiveBufferLocked(uint32_t userDataSize)
{
    ssize_t usedSpace = recvBufferCursorW_ - recvBufferCursorR_;
    if (usedSpace < 0) {
        ZLOGE(LOG_LABEL, "Invalid cursor state: write=%{public}zd < read=%{public}zd",
            recvBufferCursorW_, recvBufferCursorR_);
        recvBufferCursorW_ = 0;
        recvBufferCursorR_ = 0;
        return false;
    }
    constexpr ssize_t SSIZE_MAX_VAL = static_cast<ssize_t>(SOCKET_BUFF_SIZE_USER_HUGE);
    if (usedSpace > SSIZE_MAX_VAL - userDataSize - SOCKET_BUFF_RESERVED_SIZE) {
        ZLOGE(LOG_LABEL, "Integer overflow detected: usedSpace=%{public}zd, userDataSize=%{public}u",
            usedSpace, userDataSize);
        recvBufferCursorW_ = 0;
        recvBufferCursorR_ = 0;
        return false;
    }
    ssize_t totalNeed = usedSpace + userDataSize + SOCKET_BUFF_RESERVED_SIZE;
    if (totalNeed <= 0 || totalNeed > SOCKET_BUFF_SIZE_USER_HUGE) {
        ZLOGE(LOG_LABEL, "Invalid totalNeed: %{public}zd (max: %{public}u)",
            totalNeed, SOCKET_BUFF_SIZE_USER_HUGE);
        recvBufferCursorW_ = 0;
        recvBufferCursorR_ = 0;
        return false;
    }
    uint32_t nextSize = GetExpandedBufferSize(static_cast<uint32_t>(recvBuffSize_),
        static_cast<uint32_t>(totalNeed));
    if (nextSize == 0) {
        ZLOGE(LOG_LABEL, "Cannot expand receive buffer beyond limit, totalNeed: %{public}zd", totalNeed);
        recvBufferCursorW_ = 0;
        recvBufferCursorR_ = 0;
        return false;
    }
    if (!ExpandReceiveBuffer(nextSize)) {
        ZLOGE(LOG_LABEL, "Expand receive buffer failed, nextSize: %{public}u", nextSize);
        recvBufferCursorW_ = 0;
        recvBufferCursorR_ = 0;
        return false;
    }
    return MemmoveReceiveBufferIfInsufficient(userDataSize);
}

bool BufferObject::MemmoveReceiveBufferIfInsufficient(uint32_t userDataSize)
{
    ssize_t remainingSpace = recvBuffSize_ - recvBufferCursorW_;
    if (remainingSpace <= static_cast<ssize_t>(userDataSize)) {
        ssize_t recvMoveLen = recvBufferCursorW_ - recvBufferCursorR_;
        errno_t result = memmove_s(receiveBuffer_, static_cast<size_t>(recvMoveLen),
            receiveBuffer_ + recvBufferCursorR_, static_cast<size_t>(recvMoveLen));
        if (result != EOK) {
            ZLOGE(LOG_LABEL, "memmove_s failed in receive buffer, result: %{public}d", result);
            recvBufferCursorW_ = 0;
            recvBufferCursorR_ = 0;
            return false;
        }
        recvBufferCursorW_ = recvMoveLen;
        recvBufferCursorR_ = 0;
    }
    ssize_t remaining = recvBuffSize_ - recvBufferCursorW_;
    if (remaining <= static_cast<ssize_t>(userDataSize)) {
        ZLOGE(LOG_LABEL, "Insufficient space after memmove in receive buffer");
        recvBufferCursorW_ = 0;
        recvBufferCursorR_ = 0;
        return false;
    }
    return true;
}

bool BufferObject::TryMemmoveReceiveBuffer()
{
    ssize_t recvMoveLen = recvBufferCursorW_ - recvBufferCursorR_;
    ssize_t tailSpace = recvBuffSize_ - recvBufferCursorW_;
    if (tailSpace < SOCKET_BUFF_RESERVED_SIZE && recvMoveLen < recvBufferCursorR_ && recvMoveLen > 0) {
        errno_t result = memmove_s(receiveBuffer_, static_cast<size_t>(recvMoveLen),
            receiveBuffer_ + recvBufferCursorR_, static_cast<size_t>(recvMoveLen));
        if (result != EOK) {
            ZLOGE(LOG_LABEL, "memmove_s failed in receive buffer, result: %{public}d", result);
            recvBufferCursorW_ = 0;
            recvBufferCursorR_ = 0;
            return false;
        }
        recvBufferCursorW_ = recvMoveLen;
        recvBufferCursorR_ = 0;
    }
    return true;
}

char* BufferObject::UpdateReceiveBufferLocked(uint32_t userDataSize)
{
    if (recvBufferCursorW_ <= recvBufferCursorR_) {
        recvBufferCursorR_ = 0;
        recvBufferCursorW_ = 0;
        return receiveBuffer_;
    }
    ssize_t remainingSpace = recvBuffSize_ - recvBufferCursorW_;
    if (remainingSpace <= static_cast<ssize_t>(userDataSize)) {
        if (!TryExpandReceiveBufferLocked(userDataSize)) {
            return nullptr;
        }
    }
    if (!TryMemmoveReceiveBuffer()) {
        return nullptr;
    }
    return receiveBuffer_;
}

void BufferObject::ShrinkSendBufferIfNeeded()
{
    const ssize_t SHRINK_THRESHOLD = SOCKET_BUFF_SIZE_USER_S;
    if (sendBuffSize_ > SHRINK_THRESHOLD && sendBufferCursorW_ == sendBufferCursorR_) {
        char* newBuffer = new (std::nothrow) char[SHRINK_THRESHOLD];
        if (newBuffer != nullptr) {
            delete[] sendBuffer_;
            sendBuffer_ = newBuffer;
            sendBuffSize_ = SHRINK_THRESHOLD;
            sendBufferCursorW_ = 0;
            sendBufferCursorR_ = 0;
        }
    }
}

void BufferObject::ShrinkReceiveBufferIfNeeded()
{
    const ssize_t SHRINK_THRESHOLD = SOCKET_BUFF_SIZE_USER_S;
    if (recvBuffSize_ > SHRINK_THRESHOLD && recvBufferCursorW_ == recvBufferCursorR_) {
        char* newBuffer = new (std::nothrow) char[SHRINK_THRESHOLD];
        if (newBuffer != nullptr) {
            delete[] receiveBuffer_;
            receiveBuffer_ = newBuffer;
            recvBuffSize_ = SHRINK_THRESHOLD;
            recvBufferCursorW_ = 0;
            recvBufferCursorR_ = 0;
        }
    }
}

ssize_t BufferObject::GetSendBufferWriteCursor() const
{
    return sendBufferCursorW_;
}

ssize_t BufferObject::GetSendBufferReadCursor() const
{
    return sendBufferCursorR_;
}

ssize_t BufferObject::GetReceiveBufferWriteCursor() const
{
    return recvBufferCursorW_;
}

ssize_t BufferObject::GetReceiveBufferReadCursor() const
{
    return recvBufferCursorR_;
}
} // namespace OHOS