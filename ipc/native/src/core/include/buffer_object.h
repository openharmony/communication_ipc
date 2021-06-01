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

#ifndef OHOS_IPC_BUFFER_OBJECT_H
#define OHOS_IPC_BUFFER_OBJECT_H

#include <pthread.h>
#include <mutex>
#include <string>
#include <cstdint>
#include <sys/types.h>

#include "nocopyable.h"

namespace OHOS {
constexpr int SOCKET_DEFAULT_BUFF_SIZE = 4 * 1024;
constexpr int SOCKET_MAX_BUFF_SIZE = 1024 * 1024;
constexpr int SOCKET_BUFF_RESERVED_SIZE = 256;
constexpr size_t MAX_RAWDATA_SIZE = 128 * 1024 * 1024; // 128M

constexpr uint32_t SOCKET_BUFF_SIZE_USER_S = 4 * 1024;
constexpr uint32_t SOCKET_BUFF_SIZE_USER_M = 16 * 1024;
constexpr uint32_t SOCKET_BUFF_SIZE_USER_L = 64 * 1024;
constexpr uint32_t SOCKET_BUFF_SIZE_USER_HUGE = 1024 * 1024;

class BufferObject {
public:
    explicit BufferObject();

    ~BufferObject();

    void UpdateReceiveBuffer();
    void UpdateSendBuffer();
    char *GetSendBufferAndLock(uint32_t size);
    char *GetReceiveBufferAndLock(uint32_t size);
    void ReleaseSendBufferLock();
    void ReleaseReceiveBufferLock();
    ssize_t GetReceiveBufferWriteCursor() const;
    void SetReceiveBufferWriteCursor(ssize_t newWriteCursor);
    ssize_t GetReceiveBufferReadCursor() const;
    void SetReceiveBufferReadCursor(ssize_t newReadCursor);
    ssize_t GetSendBufferWriteCursor() const;
    void SetSendBufferWriteCursor(ssize_t newWriteCursor);
    ssize_t GetSendBufferReadCursor() const;
    void SetSendBufferReadCursor(ssize_t newReadCursor);
    uint32_t GetNeedBufferSize(uint32_t size) const;
    uint32_t GetSendBufferSize() const;
    uint32_t GetRecvBufferSize() const;

private:
    DISALLOW_COPY_AND_MOVE(BufferObject);
    ssize_t recvBufferCursorW_ = 0;
    ssize_t recvBufferCursorR_ = 0;
    ssize_t sendBufferCursorW_ = 0;
    ssize_t sendBufferCursorR_ = 0;
    char *receiveBuffer_ = nullptr;
    char *sendBuffer_ = nullptr;
    std::mutex sendMutex_;
    std::mutex recvMutex_;
    uint32_t sendBuffSize_ = 0;
    uint32_t recvBuffSize_ = 0;
};
} // namespace OHOS
#endif // OHOS_IPC_BUFFER_OBJECT_H
