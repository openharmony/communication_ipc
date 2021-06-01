/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "securec.h"
#include "sys_binder.h"

namespace OHOS {
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

/* update buffer need get mutex first */
void BufferObject::UpdateSendBuffer()
{
    if (sendBufferCursorW_ <= sendBufferCursorR_) {
        sendBufferCursorW_ = 0;
        sendBufferCursorR_ = 0;
        return;
    }
    /* check whether buffer size is enough, if not, move write/read cursor to head */
    if (sendBuffSize_ - sendBufferCursorW_ < SOCKET_BUFF_RESERVED_SIZE) {
        /* writeCursor always bigger than readCursor */
        if (sendBufferCursorW_ - sendBufferCursorR_ < sendBufferCursorR_) {
            auto memcpyResult = memmove_s(sendBuffer_, sendBufferCursorW_ - sendBufferCursorR_,
                sendBuffer_ + sendBufferCursorR_, sendBufferCursorW_ - sendBufferCursorR_);
            if (memcpyResult != EOK) {
                sendBufferCursorW_ = 0; // drop data in buffer, if memmove failed
            } else {
                sendBufferCursorW_ = sendBufferCursorW_ - sendBufferCursorR_;
            }
            sendBufferCursorR_ = 0;
        }
    }
}

/* update buffer need get mutex first */
void BufferObject::UpdateReceiveBuffer()
{
    if (recvBufferCursorW_ <= recvBufferCursorR_) {
        recvBufferCursorR_ = 0;
        recvBufferCursorW_ = 0;
        return;
    }
    /* check whether buffer size is enough, if not, move write/read cursor to head */
    if (recvBuffSize_ - recvBufferCursorW_ < SOCKET_BUFF_RESERVED_SIZE) {
        /* writeCursor always bigger than readCursor */
        if (recvBufferCursorW_ - recvBufferCursorR_ < recvBufferCursorR_) {
            auto memcpyResult = memmove_s(receiveBuffer_, recvBufferCursorW_ - recvBufferCursorR_,
                receiveBuffer_ + recvBufferCursorR_, recvBufferCursorW_ - recvBufferCursorR_);
            if (memcpyResult != EOK) {
                recvBufferCursorW_ = 0; // drop data in buffer, if memmove failed
            } else {
                recvBufferCursorW_ = recvBufferCursorW_ - recvBufferCursorR_;
            }
            recvBufferCursorR_ = 0;
        }
    }
}

char *BufferObject::GetSendBufferAndLock(uint32_t size)
{
    uint32_t needSize = GetNeedBufferSize(size);
    if (needSize == 0) {
        return nullptr;
    }
    sendMutex_.lock();
    if (needSize > sendBuffSize_) {
        char *newBuffer_ = new (std::nothrow) char[needSize];
        if (newBuffer_ == nullptr) {
            sendMutex_.unlock();
            return nullptr;
        }

        if ((sendBuffer_ != nullptr) && (sendBuffSize_ != 0)) {
            int memcpyResult = memcpy_s(newBuffer_, needSize, sendBuffer_, sendBuffSize_);
            if (memcpyResult != 0) {
                delete[] newBuffer_;
                sendMutex_.unlock();
                return nullptr;
            }
        }

        delete[] sendBuffer_;
        sendBuffer_ = newBuffer_;
        sendBuffSize_ = needSize;
    }

    /* attention: need unlock mutex by caller */
    return sendBuffer_;
}

char *BufferObject::GetReceiveBufferAndLock(uint32_t size)
{
    uint32_t needSize = GetNeedBufferSize(size);
    if (needSize == 0) {
        return nullptr;
    }
    recvMutex_.lock();
    if (needSize > recvBuffSize_) {
        char *newBuffer_ = new (std::nothrow) char[needSize];
        if (newBuffer_ == nullptr) {
            recvMutex_.unlock();
            return nullptr;
        }

        if ((receiveBuffer_ != nullptr) && (recvBuffSize_ != 0)) {
            int memcpyResult = memcpy_s(newBuffer_, needSize, receiveBuffer_, recvBuffSize_);
            if (memcpyResult != 0) {
                delete[] newBuffer_;
                recvMutex_.unlock();
                return nullptr;
            }
        }

        delete[] receiveBuffer_;
        receiveBuffer_ = newBuffer_;
        recvBuffSize_ = needSize;
    }

    /* attention: need unlock mutex by caller */
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

ssize_t BufferObject::GetReceiveBufferWriteCursor() const
{
    return recvBufferCursorW_;
}

void BufferObject::SetReceiveBufferWriteCursor(ssize_t newWriteCursor)
{
    recvBufferCursorW_ = newWriteCursor;
}

ssize_t BufferObject::GetReceiveBufferReadCursor() const
{
    return recvBufferCursorR_;
}

void BufferObject::SetReceiveBufferReadCursor(ssize_t newReadCursor)
{
    recvBufferCursorR_ = newReadCursor;
}

ssize_t BufferObject::GetSendBufferWriteCursor() const
{
    return sendBufferCursorW_;
}

void BufferObject::SetSendBufferWriteCursor(ssize_t newWriteCursor)
{
    sendBufferCursorW_ = newWriteCursor;
}

ssize_t BufferObject::GetSendBufferReadCursor() const
{
    return sendBufferCursorR_;
}

void BufferObject::SetSendBufferReadCursor(ssize_t newReadCursor)
{
    sendBufferCursorR_ = newReadCursor;
}

uint32_t BufferObject::GetNeedBufferSize(uint32_t size) const
{
    if (size <= SOCKET_BUFF_SIZE_USER_S) {
        return SOCKET_BUFF_SIZE_USER_S;
    } else if (size <= SOCKET_BUFF_SIZE_USER_M) {
        return SOCKET_BUFF_SIZE_USER_M;
    } else if (size <= SOCKET_BUFF_SIZE_USER_L) {
        return SOCKET_BUFF_SIZE_USER_L;
    } else if (size <= SOCKET_BUFF_SIZE_USER_HUGE) {
        return SOCKET_BUFF_SIZE_USER_HUGE;
    } else {
        return 0;
    }
}

uint32_t BufferObject::GetSendBufferSize() const
{
    return sendBuffSize_;
}

uint32_t BufferObject::GetRecvBufferSize() const
{
    return recvBuffSize_;
}
} // namespace OHOS
