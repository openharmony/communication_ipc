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
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "ipc_skeleton.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "securec.h"
#include "serializer.h"
#include "server_business_impl.h"

#define PKG_NAME_LIMIT 65
#define SERVER_TEST_NUMBER 101
#define HALF_PI (acosl(-1) / 2)
#define SERVER_VECTOR_LEN 20
#define SERVER_SEND_STRING "im server"

typedef struct DeathCbArg {
    char *pkgName;
    int32_t pid;
    uint32_t cbId;
} DeathCbArg;

// only support one client connected
typedef struct ClientSvc {
    char name[PKG_NAME_LIMIT];
    SvcIdentity clientSvc;
    bool isConnect;
} ClientSvc;

typedef struct {
    enum DataType id;
    int32_t (*func)(IpcIo *req, IpcIo *reply);
} ServerInvokeCmd;

static ClientSvc g_clientSvc = {.isConnect = false};

static void ClientDeathCb(void *args)
{
    if (args == NULL) {
        RPC_LOG_INFO("[ipc_test_server] args NULL");
        return;
    }
    DeathCbArg* deathArg = (DeathCbArg*)args;
    RPC_LOG_INFO("[ipc_test_server] client dead, reset, pid=%d, pkgname=%s", deathArg->pid, deathArg->pkgName);
    free(deathArg->pkgName);
    free(deathArg);
    ReleaseSvc(g_clientSvc.clientSvc);
    memset_s(&g_clientSvc, sizeof(ClientSvc), 0, sizeof(ClientSvc));
    g_clientSvc.isConnect = false;
    return;
}

static void AddDeathCb(const char *pkgName, size_t len)
{
    if (pkgName == NULL || len <= 0 || len > PKG_NAME_LIMIT) {
        RPC_LOG_ERROR("[ipc_test_server] pkgName or len error");
        return;
    }
    // DeathCbArg free in death callback
    DeathCbArg *argStrcut = (DeathCbArg*)malloc(sizeof(DeathCbArg));
    if (argStrcut == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] argStrcut molloc null");
        return;
    }

    char *tmpName = (char *)malloc(len + 1);
    if (tmpName == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] tmpName molloc null");
        free(argStrcut);
        return;
    }
    if (strcpy_s(tmpName, len + 1, pkgName) != ERR_NONE) {
        RPC_LOG_ERROR("[ipc_test_server] strcpy_s pkgName error");
        free(tmpName);
        free(argStrcut);
        return;
    }
    argStrcut->pkgName = tmpName;
    argStrcut->pid = GetCallingPid();
    AddDeathRecipient(g_clientSvc.clientSvc, ClientDeathCb, argStrcut, &argStrcut->cbId);
    return;
}

static int32_t RegisterOnService(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] registe to service");
    if (g_clientSvc.isConnect) {
        RPC_LOG_INFO("[ipc_test_server] client already connected, pkgname=%s", g_clientSvc.name);
        return ERR_NONE;
    }

    // recv client pkgname and svc
    size_t len = 0;
    const char *pkgName = (const char*)ReadString(req, &len);
    if ((pkgName == NULL) || (len == 0)) {
        RPC_LOG_ERROR("[ipc_test_server] RegisterOnService read pkgname or len failed");
        return ERR_FAILED;
    }
    SvcIdentity svc;
    ReadRemoteObject(req, &svc);
    RPC_LOG_ERROR("[ipc_test_server] recv pkgname from client, pkgname=%s", pkgName);

    // save on server
    if (strncpy_s(g_clientSvc.name, PKG_NAME_LIMIT, pkgName, strlen(pkgName)) != ERR_NONE ||
        memcpy_s(&g_clientSvc.clientSvc, sizeof(SvcIdentity), &svc, sizeof(SvcIdentity)) != ERR_NONE) {
        RPC_LOG_ERROR("[ipc_test_server] g_clientSvc set value failed");
        return ERR_FAILED;
    }
    g_clientSvc.isConnect = true;

    AddDeathCb(pkgName, len);
    RPC_LOG_INFO("[ipc_test_server] registe to server end");
    return ERR_NONE;
}


static int32_t OnBoolReceived(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] RecvBool called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] invalid param");
        return ERR_INVALID_PARAM;
    }
    bool data;
    ReadBool(req, &data);
    // reply to client
    bool replyData = true;
    WriteBool(reply, replyData);

    RPC_LOG_INFO("[ipc_test_server] RecvBool success, recv=%s", data ? "true" : "false");
    return ERR_NONE;
}

static int32_t OnInt8Received(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] OnInt8Received called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] invalid param");
        return ERR_INVALID_PARAM;
    }
    int8_t data;
    ReadInt8(req, &data);
    // reply to client
    int8_t replyData = SERVER_TEST_NUMBER;
    WriteInt8(reply, replyData);

    RPC_LOG_INFO("[ipc_test_server] OnInt8Received success, recv=%" PRId8"", data);
    return ERR_NONE;
}

static int32_t OnInt16Received(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] OnInt16Received called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] invalid param");
        return ERR_INVALID_PARAM;
    }
    int16_t data;
    ReadInt16(req, &data);
    // reply to client
    int16_t replyData = SERVER_TEST_NUMBER;
    WriteInt16(reply, replyData);

    RPC_LOG_INFO("[ipc_test_server] OnInt16Received success, recv=%" PRId16 "", data);
    return ERR_NONE;
}

static int32_t OnInt32Received(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] OnInt32Received called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] invalid param");
        return ERR_INVALID_PARAM;
    }
    int32_t data;
    ReadInt32(req, &data);
    // reply to client
    int32_t replyData = SERVER_TEST_NUMBER;
    WriteInt32(reply, replyData);

    RPC_LOG_INFO("[ipc_test_server] OnInt32Received success, recv=%" PRId32 "", data);
    return ERR_NONE;
}

static int32_t OnInt64Received(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] OnInt64Received called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] invalid param");
        return ERR_INVALID_PARAM;
    }
    int64_t data;
    ReadInt64(req, &data);
    // reply to client
    int64_t replyData = SERVER_TEST_NUMBER;
    WriteInt64(reply, replyData);

    RPC_LOG_INFO("[ipc_test_server] OnInt64Received success, recv=%" PRId64 "", data);
    return ERR_NONE;
}

static int32_t OnUint8Received(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] OnUint8Received called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] invalid param");
        return ERR_INVALID_PARAM;
    }
    uint8_t data;
    ReadUint8(req, &data);
    // reply to client
    uint8_t replyData = SERVER_TEST_NUMBER;
    WriteUint8(reply, replyData);

    RPC_LOG_INFO("[ipc_test_server] OnUint8Received success, recv=%" PRIu8 "", data);
    return ERR_NONE;
}

static int32_t OnUint16Received(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] OnUint16Received called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] invalid param");
        return ERR_INVALID_PARAM;
    }
    uint16_t data;
    ReadUint16(req, &data);
    // reply to client
    uint16_t replyData = SERVER_TEST_NUMBER;
    WriteUint16(reply, replyData);

    RPC_LOG_INFO("[ipc_test_server] OnUint16Received success, recv=%" PRIu16 "", data);
    return ERR_NONE;
}

static int32_t OnUint32Received(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] OnUint32Received called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] invalid param");
        return ERR_INVALID_PARAM;
    }
    uint32_t data;
    ReadUint32(req, &data);
    // reply to client
    uint32_t replyData = SERVER_TEST_NUMBER;
    WriteUint32(reply, replyData);

    RPC_LOG_INFO("[ipc_test_server] OnUint32Received success, recv=%" PRIu32 "", data);
    return ERR_NONE;
}

static int32_t OnUint64Received(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] OnUint64Received called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] invalid param");
        return ERR_INVALID_PARAM;
    }
    uint64_t data;
    ReadUint64(req, &data);
    // reply to client
    uint64_t replyData = SERVER_TEST_NUMBER;
    WriteUint64(reply, replyData);

    RPC_LOG_INFO("[ipc_test_server] OnUint64Received success, recv=%" PRIu64 "", data);
    return ERR_NONE;
}

static int32_t OnFloatReceived(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] OnFloatReceived called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] invalid param");
        return ERR_INVALID_PARAM;
    }
    float data;
    ReadFloat(req, &data);
    // reply to client
    float replyData = (float)HALF_PI;
    WriteFloat(reply, replyData);

    RPC_LOG_INFO("[ipc_test_server] OnFloatReceived success, recv=%f", data);
    return ERR_NONE;
}

static int32_t OnDoubleReceived(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] OnDoubleReceived called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] invalid param");
        return ERR_INVALID_PARAM;
    }
    double data;
    ReadDouble(req, &data);
    // reply to client
    double replyData = HALF_PI;
    WriteDouble(reply, replyData);

    RPC_LOG_INFO("[ipc_test_server] OnDoubleReceived success, recv=%f", data);
    return ERR_NONE;
}

static int32_t OnInt8VectorReceived(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] OnInt8VectorReceived called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] invalid param");
        return ERR_INVALID_PARAM;
    }
    int8_t *data = NULL;
    size_t size = 0;
    data = ReadInt8Vector(req, &size);
    if (data == NULL || size <= 0) {
        RPC_LOG_ERROR("[ipc_test_server] OnInt8VectorReceived error, vector is null or empty");
        return ERR_FAILED;
    }

    // reply to client
    int8_t replyData[SERVER_VECTOR_LEN];
    for (int i = 0; i < SERVER_VECTOR_LEN; i++) {
        replyData[i] = SERVER_TEST_NUMBER + i;
    }
    WriteInt8Vector(reply, replyData, SERVER_VECTOR_LEN);

    RPC_LOG_INFO("[ipc_test_server] OnInt8VectorReceived called, size=%zu, start=%" PRId8 ", end=%" PRId8 "",
        size, data[0], data[size - 1]);
    return ERR_NONE;
}

static int32_t OnInt16VectorReceived(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] OnInt16VectorReceived called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] invalid param");
        return ERR_INVALID_PARAM;
    }
    int16_t *data = NULL;
    size_t size = 0;
    data = ReadInt16Vector(req, &size);
    if (data == NULL || size <= 0) {
        RPC_LOG_ERROR("[ipc_test_server] OnInt16VectorReceived error, vector is null or empty");
        return ERR_FAILED;
    }

    // reply to client
    int16_t replyData[SERVER_VECTOR_LEN];
    for (int i = 0; i < SERVER_VECTOR_LEN; i++) {
        replyData[i] = SERVER_TEST_NUMBER + i;
    }
    WriteInt16Vector(reply, replyData, SERVER_VECTOR_LEN);

    RPC_LOG_INFO("[ipc_test_server] OnInt16VectorReceived called, size=%zu, start=%" PRId16 ", end=%" PRId16 "",
        size, data[0], data[size - 1]);
    return ERR_NONE;
}

static int32_t OnInt32VectorReceived(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] OnInt32VectorReceived called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] invalid param");
        return ERR_INVALID_PARAM;
    }
    int32_t *data = NULL;
    size_t size = 0;
    data = ReadInt32Vector(req, &size);
    if (data == NULL || size <= 0) {
        RPC_LOG_ERROR("[ipc_test_server] OnInt32VectorReceived error, vector is null or empty");
        return ERR_FAILED;
    }

    // reply to client
    int32_t replyData[SERVER_VECTOR_LEN];
    for (int i = 0; i < SERVER_VECTOR_LEN; i++) {
        replyData[i] = SERVER_TEST_NUMBER + i;
    }
    WriteInt32Vector(reply, replyData, SERVER_VECTOR_LEN);

    RPC_LOG_INFO("[ipc_test_server] OnInt32VectorReceived called, size=%zu, start=%" PRId32 ", end=%" PRId32 "",
        size, data[0], data[size - 1]);
    return ERR_NONE;
}

static int32_t OnInt64VectorReceived(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] OnInt64VectorReceived called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] invalid param");
        return ERR_INVALID_PARAM;
    }
    int64_t *data = NULL;
    size_t size = 0;
    data = ReadInt64Vector(req, &size);
    if (data == NULL || size <= 0) {
        RPC_LOG_ERROR("[ipc_test_server] OnInt64VectorReceived error, vector is null or empty");
        return ERR_FAILED;
    }

    // reply to client
    int64_t replyData[SERVER_VECTOR_LEN];
    for (int i = 0; i < SERVER_VECTOR_LEN; i++) {
        replyData[i] = SERVER_TEST_NUMBER + i;
    }
    WriteInt64Vector(reply, replyData, SERVER_VECTOR_LEN);

    RPC_LOG_INFO("[ipc_test_server] OnInt64VectorReceived called, size=%zu, start=%" PRId64 ", end=%" PRId64 "",
        size, data[0], data[size - 1]);
    return ERR_NONE;
}

static int32_t OnUint8VectorReceived(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] OnUint8VectorReceived called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] invalid param");
        return ERR_INVALID_PARAM;
    }
    uint8_t *data = NULL;
    size_t size = 0;
    data = ReadUInt8Vector(req, &size);
    if (data == NULL || size <= 0) {
        RPC_LOG_ERROR("[ipc_test_server] OnUint8VectorReceived error, vector is null or empty");
        return ERR_FAILED;
    }

    // reply to client
    uint8_t replyData[SERVER_VECTOR_LEN];
    for (int i = 0; i < SERVER_VECTOR_LEN; i++) {
        replyData[i] = SERVER_TEST_NUMBER + i;
    }
    WriteUInt8Vector(reply, replyData, SERVER_VECTOR_LEN);

    RPC_LOG_INFO("[ipc_test_server] OnUint8VectorReceived called, size=%zu, start=%" PRIu8 ", end=%" PRIu8 "",
        size, data[0], data[size - 1]);
    return ERR_NONE;
}

static int32_t OnUint16VectorReceived(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] OnUint16VectorReceived called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] invalid param");
        return ERR_INVALID_PARAM;
    }
    uint16_t *data = NULL;
    size_t size = 0;
    data = ReadUInt16Vector(req, &size);
    if (data == NULL || size <= 0) {
        RPC_LOG_ERROR("[ipc_test_server] OnUint16VectorReceived error, vector is null or empty");
        return ERR_FAILED;
    }

    // reply to client
    uint16_t replyData[SERVER_VECTOR_LEN];
    for (int i = 0; i < SERVER_VECTOR_LEN; i++) {
        replyData[i] = SERVER_TEST_NUMBER + i;
    }
    WriteUInt16Vector(reply, replyData, SERVER_VECTOR_LEN);

    RPC_LOG_INFO("[ipc_test_server] OnUint16VectorReceived called, size=%zu, start=%" PRIu16 ", end=%" PRIu16 "",
        size, data[0], data[size - 1]);
    return ERR_NONE;
}

static int32_t OnUint32VectorReceived(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] OnUint32VectorReceived called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] invalid param");
        return ERR_INVALID_PARAM;
    }
    uint32_t *data = NULL;
    size_t size = 0;
    data = ReadUInt32Vector(req, &size);
    if (data == NULL || size <= 0) {
        RPC_LOG_ERROR("[ipc_test_server] OnUint32VectorReceived error, vector is null or empty");
        return ERR_FAILED;
    }

    // reply to client
    uint32_t replyData[SERVER_VECTOR_LEN];
    for (int i = 0; i < SERVER_VECTOR_LEN; i++) {
        replyData[i] = SERVER_TEST_NUMBER + i;
    }
    WriteUInt32Vector(reply, replyData, SERVER_VECTOR_LEN);

    RPC_LOG_INFO("[ipc_test_server] OnUint32VectorReceived called, size=%zu, start=%" PRIu32 ", end=%" PRIu32 "",
        size, data[0], data[size - 1]);
    return ERR_NONE;
}

static int32_t OnUint64VectorReceived(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] OnUint64VectorReceived called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] invalid param");
        return ERR_INVALID_PARAM;
    }
    uint64_t *data = NULL;
    size_t size = 0;
    data = ReadUInt64Vector(req, &size);
    if (data == NULL || size <= 0) {
        RPC_LOG_ERROR("[ipc_test_server] OnUint64VectorReceived error, vector is null or empty");
        return ERR_FAILED;
    }

    // reply to client
    uint64_t replyData[SERVER_VECTOR_LEN];
    for (int i = 0; i < SERVER_VECTOR_LEN; i++) {
        replyData[i] = SERVER_TEST_NUMBER + i;
    }
    WriteUInt64Vector(reply, replyData, SERVER_VECTOR_LEN);

    RPC_LOG_INFO("[ipc_test_server] OnUint64VectorReceived called, size=%zu, start=%" PRIu64 ", end=%" PRIu64 "",
        size, data[0], data[size - 1]);
    return ERR_NONE;
}

static int32_t OnFloatVectorReceived(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] OnFloatVectorReceived called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] invalid param");
        return ERR_INVALID_PARAM;
    }
    float *data = NULL;
    size_t size = 0;
    data = ReadFloatVector(req, &size);
    if (data == NULL || size <= 0) {
        RPC_LOG_ERROR("[ipc_test_server] OnFloatVectorReceived error, vector is null or empty");
        return ERR_FAILED;
    }

    // reply to client
    float replyData[SERVER_VECTOR_LEN];
    for (int i = 0; i < SERVER_VECTOR_LEN; i++) {
        replyData[i] = HALF_PI + i;
    }
    WriteFloatVector(reply, replyData, SERVER_VECTOR_LEN);

    RPC_LOG_INFO("[ipc_test_server] OnFloatVectorReceived called, size=%zu, start=%f, end=%f",
        size, data[0], data[size - 1]);
    return ERR_NONE;
}

static int32_t OnDoubleVectorReceived(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] OnDoubleVectorReceived called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] invalid param");
        return ERR_INVALID_PARAM;
    }
    double *data = NULL;
    size_t size = 0;
    data = ReadDoubleVector(req, &size);
    if (data == NULL || size <= 0) {
        RPC_LOG_ERROR("[ipc_test_server] OnDoubleVectorReceived error, vector is null or empty");
        return ERR_FAILED;
    }

    // reply to client
    double replyData[SERVER_VECTOR_LEN];
    for (int i = 0; i < SERVER_VECTOR_LEN; i++) {
        replyData[i] = HALF_PI + i;
    }
    WriteDoubleVector(reply, replyData, SERVER_VECTOR_LEN);

    RPC_LOG_INFO("[ipc_test_server] OnDoubleVectorReceived called, size=%zu, start=%f, end=%f",
        size, data[0], data[size - 1]);
    return ERR_NONE;
}

static int32_t OnStringReceived(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] OnStringReceived called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] invalid param");
        return ERR_INVALID_PARAM;
    }
    size_t len;
    const char *data = (char *)ReadString(req, &len);
    if (data == NULL || len == 0) {
        RPC_LOG_ERROR("[ipc_test_server] OnStringReceived error");
        return ERR_FAILED;
    }

    // reply to client
    WriteString(reply, (char *)SERVER_SEND_STRING);

    RPC_LOG_INFO("[ipc_test_server] OnStringReceived success, recv=%s", data);
    return ERR_NONE;
}

static int32_t OnFileDescriptorReceived(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] OnFileDescriptorReceived called");
    int fd = ReadFileDescriptor(req);
    if (fd < 0) {
        RPC_LOG_ERROR("[ipc_test_server] OnFileDescriptorReceived fd error");
        return ERR_FAILED;
    }

    RPC_LOG_INFO("[ipc_test_server] OnFileDescriptorReceived fd=%d", fd);
    const char *data = (char *)SERVER_SEND_STRING;
    ssize_t bytesWritten = write(fd, data, strnlen(data, MAX_IO_SIZE));
    if (bytesWritten == -1) {
        RPC_LOG_ERROR("[ipc_test_server] OnFileDescriptorReceived write error");
        close(fd);
        return ERR_FAILED;
    }
    close(fd);
    RPC_LOG_INFO("[ipc_test_server] OnFileDescriptorReceived success");
    return ERR_NONE;
}

static int32_t OnRawDataReceived(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] OnRawDataReceived called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] invalid param");
        return ERR_INVALID_PARAM;
    }
    SvcIdentity *data = (SvcIdentity *)ReadRawData(req, sizeof(SvcIdentity));
    if (data == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] OnRawDataReceived error, recv null");
        return ERR_FAILED;
    }

    // reply to client
    WriteRawData(reply, data, sizeof(SvcIdentity));
    RPC_LOG_INFO("[ipc_test_server] OnRawDataReceived success");
    return ERR_NONE;
}

static int32_t OnBufferReceived(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] OnBufferReceived called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] invalid param");
        return ERR_INVALID_PARAM;
    }
    SvcIdentity *data = (SvcIdentity *)ReadBuffer(req, sizeof(SvcIdentity));
    if (data == NULL) {
        RPC_LOG_ERROR("[ipc_test_server] OnBufferReceived error, recv null");
        return ERR_FAILED;
    }

    // reply to client
    WriteBuffer(reply, data, sizeof(SvcIdentity));
    RPC_LOG_INFO("[ipc_test_server] OnBufferReceived success");
    return ERR_NONE;
}

static ServerInvokeCmd g_serverInvokeCmdTbl[] = {
    { REGISTER_ON_SERVICE, RegisterOnService},
    { BOOL_TYPE, OnBoolReceived },

    { INT8_TYPE, OnInt8Received },
    { INT16_TYPE, OnInt16Received },
    { INT32_TYPE, OnInt32Received },
    { INT64_TYPE, OnInt64Received },
    { UINT8_TYPE, OnUint8Received },
    { UINT16_TYPE, OnUint16Received },
    { UINT32_TYPE, OnUint32Received },
    { UINT64_TYPE, OnUint64Received },
    { FLOAT_TYPE, OnFloatReceived },
    { DOUBLE_TYPE, OnDoubleReceived },

    { VECTOR_INT8_TYPE, OnInt8VectorReceived },
    { VECTOR_INT16_TYPE, OnInt16VectorReceived },
    { VECTOR_INT32_TYPE, OnInt32VectorReceived },
    { VECTOR_INT64_TYPE, OnInt64VectorReceived },
    { VECTOR_UINT8_TYPE, OnUint8VectorReceived },
    { VECTOR_UINT16_TYPE, OnUint16VectorReceived },
    { VECTOR_UINT32_TYPE, OnUint32VectorReceived },
    { VECTOR_UINT64_TYPE, OnUint64VectorReceived },
    { VECTOR_FLOAT_TYPE, OnFloatVectorReceived },
    { VECTOR_DOUBLE_TYPE, OnDoubleVectorReceived },

    { CHAR_TYPE, OnStringReceived },
    { FD_TYPE, OnFileDescriptorReceived },
    { RAW_DATA_TYPE, OnRawDataReceived },
    { BUFFER_TYPE, OnBufferReceived },
};

int32_t DispatchInvoke(IServerProxy *iProxy, int funcId, void *origin, IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] Dispatch recv funcId=%d", funcId);
    for (uint32_t i = 0; i < sizeof(g_serverInvokeCmdTbl) / sizeof(ServerInvokeCmd); i++) {
        if (funcId == g_serverInvokeCmdTbl[i].id) {
            return g_serverInvokeCmdTbl[i].func(req, reply);
        }
    }
    RPC_LOG_INFO("[ipc_test_server]not support funcId=%d", funcId);
    return ERR_NONE;
}