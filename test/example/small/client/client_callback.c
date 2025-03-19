/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <inttypes.h>

#include "client_callback.h"
#include "rpc_errno.h"
#include "rpc_log.h"

typedef struct {
    int32_t funIdType;
    void (*handler)(IpcIo *);
} ClientCallbackHandler;

static void OnBoolRecv(IpcIo *reply)
{
    bool recvData;
    ReadBool(reply, &recvData);
    RPC_LOG_INFO("[ipc_test_client] OnBoolRecv called, recv=%s", recvData ? "true" : "false");
    return;
}

static void OnInt8Recv(IpcIo *reply)
{
    int8_t recvData;
    ReadInt8(reply, &recvData);
    RPC_LOG_INFO("[ipc_test_client] OnInt8Recv called, recv=%" PRId8 "", recvData);
    return;
}

static void OnInt16Recv(IpcIo *reply)
{
    int16_t recvData;
    ReadInt16(reply, &recvData);
    RPC_LOG_INFO("[ipc_test_client] OnInt16Recv called, recv=%" PRId16 "", recvData);
    return;
}

static void OnInt32Recv(IpcIo *reply)
{
    int32_t recvData;
    ReadInt32(reply, &recvData);
    RPC_LOG_INFO("[ipc_test_client] OnInt16Recv called, recv=%" PRId32 "", recvData);
    return;
}

static void OnInt64Recv(IpcIo *reply)
{
    int64_t recvData;
    ReadInt64(reply, &recvData);
    RPC_LOG_INFO("[ipc_test_client] OnInt64Recv called, recv=%" PRId64 "", recvData);
    return;
}

static void OnUint8Recv(IpcIo *reply)
{
    uint8_t recvData;
    ReadUint8(reply, &recvData);
    RPC_LOG_INFO("[ipc_test_client] OnUint8Recv called, recv=%" PRIu8 "", recvData);
    return;
}

static void OnUint16Recv(IpcIo *reply)
{
    uint16_t recvData;
    ReadUint16(reply, &recvData);
    RPC_LOG_INFO("[ipc_test_client] OnUint16Recv called, recv=%" PRIu16 "", recvData);
    return;
}

static void OnUint32Recv(IpcIo *reply)
{
    uint32_t recvData;
    ReadUint32(reply, &recvData);
    RPC_LOG_INFO("[ipc_test_client] OnUint32Recv called, recv=%" PRIu32 "", recvData);
    return;
}

static void OnUint64Recv(IpcIo *reply)
{
    uint64_t recvData;
    ReadUint64(reply, &recvData);
    RPC_LOG_INFO("[ipc_test_client] OnUint64Recv called, recv=%" PRIu64 "", recvData);
    return;
}

static void OnFloatRecv(IpcIo *reply)
{
    float recvData;
    ReadFloat(reply, &recvData);
    RPC_LOG_INFO("[ipc_test_client] OnFloatRecv called, recv=%f", recvData);
    return;
}

static void OnDoubleRecv(IpcIo *reply)
{
    double recvData;
    ReadDouble(reply, &recvData);
    RPC_LOG_INFO("[ipc_test_client] OnDoubleRecv called, recv=%f", recvData);
    return;
}

static void OnInt8VectorRecv(IpcIo *reply)
{
    int8_t *dataVector = NULL;
    size_t size = 0;
    dataVector = ReadInt8Vector(reply, &size);
    if (dataVector == NULL || size == 0) {
        RPC_LOG_ERROR("[ipc_test_client] OnInt8VectorRecv error, vector is null");
        return;
    }
    RPC_LOG_INFO("[ipc_test_client] OnInt8VectorRecv called, size=%zu, start=%" PRId8 ", end=%" PRId8 "",
        size, dataVector[0], dataVector[size - 1]);
    return;
}

static void OnInt16VectorRecv(IpcIo *reply)
{
    int16_t *dataVector = NULL;
    size_t size = 0;
    dataVector = ReadInt16Vector(reply, &size);
    if (dataVector == NULL || size == 0) {
        RPC_LOG_ERROR("[ipc_test_client] OnInt16VectorRecv error, vector is null");
        return;
    }
    RPC_LOG_INFO("[ipc_test_client] OnInt16VectorRecv called, size=%zu, start=%" PRId16 ", end=%" PRId16 "",
        size, dataVector[0], dataVector[size - 1]);
    return;
}

static void OnInt32VectorRecv(IpcIo *reply)
{
    int32_t *dataVector = NULL;
    size_t size = 0;
    dataVector = ReadInt32Vector(reply, &size);
    if (dataVector == NULL || size == 0) {
        RPC_LOG_ERROR("[ipc_test_client] OnInt32VectorRecv error, vector is null");
        return;
    }
    RPC_LOG_INFO("[ipc_test_client] OnInt32VectorRecv called, size=%zu, start=%" PRId32 ", end=%" PRId32 "",
        size, dataVector[0], dataVector[size - 1]);
    return;
}

static void OnInt64VectorRecv(IpcIo *reply)
{
    int64_t *dataVector = NULL;
    size_t size = 0;
    dataVector = ReadInt64Vector(reply, &size);
    if (dataVector == NULL || size == 0) {
        RPC_LOG_ERROR("[ipc_test_client] OnInt64VectorRecv error, vector is null");
        return;
    }
    RPC_LOG_INFO("[ipc_test_client] OnInt64VectorRecv called, size=%zu, start=%" PRId64 ", end=%" PRId64 "",
        size, dataVector[0], dataVector[size - 1]);
    return;
}

static void OnUint8VectorRecv(IpcIo *reply)
{
    uint8_t *dataVector = NULL;
    size_t size = 0;
    dataVector = ReadUInt8Vector(reply, &size);
    if (dataVector == NULL || size == 0) {
        RPC_LOG_ERROR("[ipc_test_client] OnUint8VectorRecv error, vector is null");
        return;
    }
    RPC_LOG_INFO("[ipc_test_client] OnUint8VectorRecv called, size=%zu, start=%" PRIu8 ", end=%" PRIu8 "",
        size, dataVector[0], dataVector[size - 1]);
    return;
}

static void OnUint16VectorRecv(IpcIo *reply)
{
    uint16_t *dataVector = NULL;
    size_t size = 0;
    dataVector = ReadUInt16Vector(reply, &size);
    if (dataVector == NULL || size == 0) {
        RPC_LOG_ERROR("[ipc_test_client] OnUint16VectorRecv error, vector is null");
        return;
    }
    RPC_LOG_INFO("[ipc_test_client] OnUint16VectorRecv called, size=%zu, start=%" PRIu16 ", end=%" PRIu16 "",
        size, dataVector[0], dataVector[size - 1]);
    return;
}

static void OnUint32VectorRecv(IpcIo *reply)
{
    uint32_t *dataVector = NULL;
    size_t size = 0;
    dataVector = ReadUInt32Vector(reply, &size);
    if (dataVector == NULL || size == 0) {
        RPC_LOG_ERROR("[ipc_test_client] OnUint32VectorRecv error, vector is null");
        return;
    }
    RPC_LOG_INFO("[ipc_test_client] OnUint32VectorRecv called, size=%zu, start=%" PRIu32 ", end=%" PRIu32 "",
        size, dataVector[0], dataVector[size - 1]);
    return;
}

static void OnUint64VectorRecv(IpcIo *reply)
{
    uint64_t *dataVector = NULL;
    size_t size = 0;
    dataVector = ReadUInt64Vector(reply, &size);
    if (dataVector == NULL || size == 0) {
        RPC_LOG_ERROR("[ipc_test_client] OnUint64VectorRecv error, vector is null");
        return;
    }
    RPC_LOG_INFO("[ipc_test_client] OnUint64VectorRecv called, size=%zu, start=%" PRIu64 ", end=%" PRIu64 "",
        size, dataVector[0], dataVector[size - 1]);
    return;
}

static void OnFloatVectorRecv(IpcIo *reply)
{
    float *dataVector = NULL;
    size_t size = 0;
    dataVector = ReadFloatVector(reply, &size);
    if (dataVector == NULL || size == 0) {
        RPC_LOG_ERROR("[ipc_test_client] OnFloatVectorRecv error, vector is null");
        return;
    }
    RPC_LOG_INFO("[ipc_test_client] OnFloatVectorRecv called, size=%zu, start=%f, end=%f",
        size, dataVector[0], dataVector[size - 1]);
    return;
}

static void OnDoubleVectorRecv(IpcIo *reply)
{
    double *dataVector = NULL;
    size_t size = 0;
    dataVector = ReadDoubleVector(reply, &size);
    if (dataVector == NULL || size == 0) {
        RPC_LOG_ERROR("[ipc_test_client] OnFloatVectorRecv error, vector is null");
        return;
    }
    RPC_LOG_INFO("[ipc_test_client] OnFloatVectorRecv called, size=%zu, start=%f, end=%f",
        size, dataVector[0], dataVector[size - 1]);
    return;
}

static void OnStringRecv(IpcIo *reply)
{
    size_t len = 0;
    const char *recvData = (char *)ReadString(reply, &len);
    if (recvData == NULL) {
        RPC_LOG_ERROR("[ipc_test_client] OnStringRecv error, recvData is null");
        return;
    }
    RPC_LOG_INFO("[ipc_test_client] OnStringRecv called, recv=%s", recvData);
    return;
}

static void OnFileDescriptorRecv(IpcIo *reply)
{
    (void)reply;
    RPC_LOG_INFO("[ipc_test_client] OnFileDescriptorRecv called");
    return;
}

static void OnRawDataRecv(IpcIo *reply)
{
    SvcIdentity *recvData = NULL;
    recvData = ReadRawData(reply, sizeof(SvcIdentity));
    if (recvData == NULL) {
        RPC_LOG_ERROR("[ipc_test_client] OnRawDataRecv error, recvData is null");
        return;
    }
    RPC_LOG_ERROR("[ipc_test_client] OnRawDataRecv success");
    return;
}

static void OnBufferRecv(IpcIo *reply)
{
    SvcIdentity *recvData = NULL;
    recvData = ReadBuffer(reply, sizeof(SvcIdentity));
    if (recvData == NULL) {
        RPC_LOG_ERROR("[ipc_test_client] OnBufferRecv error, recvData is null");
        return;
    }
    RPC_LOG_ERROR("[ipc_test_client] OnBufferRecv success");
    return;
}

static ClientCallbackHandler g_clientCallbackHandler[] = {
    { BOOL_TYPE, OnBoolRecv },
    { INT8_TYPE, OnInt8Recv },
    { INT16_TYPE, OnInt16Recv },
    { INT32_TYPE, OnInt32Recv },
    { INT64_TYPE, OnInt64Recv },
    { UINT8_TYPE, OnUint8Recv },
    { UINT16_TYPE, OnUint16Recv },
    { UINT32_TYPE, OnUint32Recv },
    { UINT64_TYPE, OnUint64Recv },
    { FLOAT_TYPE, OnFloatRecv },
    { DOUBLE_TYPE, OnDoubleRecv },

    { VECTOR_INT8_TYPE, OnInt8VectorRecv },
    { VECTOR_INT16_TYPE, OnInt16VectorRecv },
    { VECTOR_INT32_TYPE, OnInt32VectorRecv },
    { VECTOR_INT64_TYPE, OnInt64VectorRecv },
    { VECTOR_UINT8_TYPE, OnUint8VectorRecv },
    { VECTOR_UINT16_TYPE, OnUint16VectorRecv },
    { VECTOR_UINT32_TYPE, OnUint32VectorRecv },
    { VECTOR_UINT64_TYPE, OnUint64VectorRecv },
    { VECTOR_FLOAT_TYPE, OnFloatVectorRecv },
    { VECTOR_DOUBLE_TYPE, OnDoubleVectorRecv },

    { CHAR_TYPE, OnStringRecv },
    { FD_TYPE, OnFileDescriptorRecv },
    { RAW_DATA_TYPE, OnRawDataRecv },
    { BUFFER_TYPE, OnBufferRecv },
};

int32_t ClientSendSyncMessageCallback(void *info, int ret, IpcIo *reply)
{
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("[ipc_test_client] OnSendSyncMessageCallback error, ret=%d", ret);
        return ERR_FAILED;
    }
    Reply *replyInfo = (Reply *)info;
    for (uint32_t i = 0; i < sizeof(g_clientCallbackHandler) / sizeof(ClientCallbackHandler); i++) {
        if (g_clientCallbackHandler[i].funIdType == replyInfo->id) {
            g_clientCallbackHandler[i].handler(reply);
            return ERR_NONE;
        }
    }
    RPC_LOG_ERROR("[ipc_test_client] OnSendSyncMessageCallback invalid func, id=%d", replyInfo->id);
    return ERR_INVALID_PARAM;
}