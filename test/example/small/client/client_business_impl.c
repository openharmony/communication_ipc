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

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <ohos_init.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "client_business_impl.h"
#include "client_callback.h"
#include "common.h"
#include "ipc_skeleton.h"
#include "iproxy_client.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "samgr_lite.h"
#include "serializer.h"

#define WAIT_SERVER_READY_INTERVAL_COUNT 50
#define CLIENT_TEST_NUMBER 100
#define PI acosl(-1)
#define CLIENT_VECTOR_LEN 10
#define INVALID_FD (-1)
#define FD_TIMEOUT 10 // 10s
#define CLIENT_SEND_STRING "im client"

#define InitSendData(ioPtr, data, dataType) \
    uint8_t tmpData[IPC_BUFFER_SIZE] = {0}; \
    IpcIoInit((ioPtr), tmpData, IPC_BUFFER_SIZE, OBJ_NUM); \
    Write##dataType((ioPtr), (data))

#define InitSendPtr(ioPtr, dataPtr, dataType, size) \
    uint8_t tmpData[IPC_BUFFER_SIZE] = {0}; \
    IpcIoInit((ioPtr), tmpData, IPC_BUFFER_SIZE, OBJ_NUM); \
    Write##dataType((ioPtr), (dataPtr), (size))

static SvcIdentity g_clientIdentify;
static IClientProxy *g_serverProxy = NULL;
static int g_pipeFd[2] = {INVALID_FD, INVALID_FD};
static pthread_mutex_t g_pipeFdMutex = PTHREAD_MUTEX_INITIALIZER;

static int32_t InitPipe()
{
    pthread_mutex_lock(&g_pipeFdMutex);
    if (g_pipeFd[0] != INVALID_FD || g_pipeFd[1] != INVALID_FD) {
        RPC_LOG_INFO("[ipc_test_client] pipe already init");
        pthread_mutex_unlock(&g_pipeFdMutex);
        return ERR_NONE;
    }
    
    if (pipe(g_pipeFd) < 0) {
        RPC_LOG_ERROR("[ipc_test_client] create pipe error");
        pthread_mutex_unlock(&g_pipeFdMutex);
        return ERR_FAILED;
    }
    pthread_mutex_unlock(&g_pipeFdMutex);
    return ERR_NONE;
}

static void DeinitPipe()
{
    pthread_mutex_lock(&g_pipeFdMutex);
    if (g_pipeFd[1] != INVALID_FD) {
        close(g_pipeFd[1]);
    }
    if (g_pipeFd[0] != INVALID_FD) {
        close(g_pipeFd[0]);
    }
    g_pipeFd[1] = INVALID_FD;
    g_pipeFd[0] = INVALID_FD;
    pthread_mutex_unlock(&g_pipeFdMutex);
    return;
}

static int32_t StartTimerForFdEvent()
{
    struct sigevent event = {
        .sigev_notify = SIGEV_THREAD,
        .sigev_notify_function = DeinitPipe,
    };
    timer_t timerid;
    if (timer_create(CLOCK_REALTIME, &event, &timerid) == -1) {
        RPC_LOG_ERROR("[ipc_test_client] timer_create error");
        return ERR_FAILED;
    }
    struct itimerspec its = {
        .it_value.tv_sec = FD_TIMEOUT
    };
    if (timer_settime(timerid, 0, &its, NULL) == -1) {
        RPC_LOG_ERROR("[ipc_test_client] timer_settime error");
        return ERR_FAILED;
    }
    RPC_LOG_INFO("[ipc_test_client] start timer wait timeout success");
    return ERR_NONE;
}

static void SetClientIdentity(unsigned int handle, uintptr_t token, uintptr_t cookie)
{
    g_clientIdentify.handle = handle;
    g_clientIdentify.token = token;
    g_clientIdentify.cookie = cookie;
    return;
}

static IClientProxy *GetServerProxy(void)
{
    IClientProxy *clientProxy = NULL;

    RPC_LOG_INFO("[ipc_test_client] start get client proxy");
    int32_t proxyInitCount = 0;
    while (clientProxy == NULL) {
        proxyInitCount++;
        if (proxyInitCount == WAIT_SERVER_READY_INTERVAL_COUNT) {
            RPC_LOG_ERROR("[ipc_test_client] get server proxy error");
            return NULL;
        }
        IUnknown *iUnknown = SAMGR_GetInstance()->GetDefaultFeatureApi(IPC_TEST_SMALL);
        if (iUnknown == NULL) {
            RPC_LOG_ERROR("iUnknown is null");
            sleep(1);
            continue;
        }
        RPC_LOG_INFO("[ipc_test_client] GetDefaultFeatureApi success");

        int32_t ret = iUnknown->QueryInterface(iUnknown, CLIENT_PROXY_VER, (void **)&clientProxy);
        if (ret != EC_SUCCESS || clientProxy == NULL) {
            RPC_LOG_ERROR("QueryInterface failed [%d]", ret);
            sleep(1);
            continue;
        }
    }

    RPC_LOG_INFO("[ipc_test_client] get client proxy ok");
    return clientProxy;
}

static int32_t DoSend(IpcIo *data, int32_t messageCode, bool isAsync)
{
    // client send data through samgr_lite
    if (messageCode <= TYPE_START || messageCode >= TYPE_END) {
        RPC_LOG_ERROR("[ipc_test_client] messageCode error, code=%d", messageCode);
        return ERR_INVALID_PARAM;
    }

    // callback==NULL will send TF_OP_ASYNC message, else TF_OP_SYNC
    Reply reply = {.id = messageCode};
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, (uint32_t)messageCode,
        data, &reply, isAsync ? NULL : ClientSendSyncMessageCallback);
    if (ans != ERR_NONE) {
        RPC_LOG_ERROR("[ipc_test_client] DoSend error, code=%d, ret=%d", messageCode, ans);
        return ERR_FAILED;
    }
    return ERR_NONE;
}

static int32_t RemoteRequest(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
{
    (void)data;
    (void)reply;
    (void)option;
    RPC_LOG_ERROR("[ipc_test_client] RemoteRequest is called, code=%u", code);
    return ERR_NONE;
}

void InitLocalIdentity()
{
    static IpcObjectStub objectStub = {
        .func = RemoteRequest,
        .args = NULL,
        .isRemote = false
    };
    SvcIdentity clientIdentity = {
        .handle = IPC_INVALID_HANDLE,
        .token = SERVICE_TYPE_ANONYMOUS,
        .cookie = (uintptr_t)&objectStub
    };
    // save to local
    SetClientIdentity(clientIdentity.handle, clientIdentity.token, clientIdentity.cookie);
    return;
}

void RegisterToService()
{
    g_serverProxy = GetServerProxy();
    if (g_serverProxy == NULL) {
        RPC_LOG_ERROR("[ipc_test_client] g_serverProxy null");
        return;
    }

    // write pkgname and svc
    IpcIo request;
    uint8_t temData[IPC_BUFFER_SIZE];
    IpcIoInit(&request, temData, IPC_BUFFER_SIZE, OBJ_NUM);
    WriteString(&request, (char *)IPC_TEST_SMALL);
    if (!WriteRemoteObject(&request, &g_clientIdentify)) {
        RPC_LOG_ERROR("[ipc_test_client] WriteRemoteObject error");
    }

    int32_t ret = ERR_FAILED;
    if (g_serverProxy->Invoke(g_serverProxy, REGISTER_ON_SERVICE, &request, &ret, NULL) != ERR_NONE) {
        RPC_LOG_INFO("[ipc_test_client] invoker error");
        return;
    }
    RPC_LOG_INFO("[ipc_test_client] RegisterToService start");
    return;
}

void SendBool()
{
    RPC_LOG_INFO("[ipc_test_client] ------ SendBool start ------");
    IpcIo io;
    IpcIo *ioPtr = &io;
    bool sendData = false;
    InitSendData(ioPtr, sendData, Bool);

    // send sync to server
    (void)DoSend(ioPtr, BOOL_TYPE, false);

    // send async to server
    (void)DoSend(ioPtr, BOOL_TYPE, true);
    RPC_LOG_INFO("[ipc_test_client] ------ SendBool end ------");
    return;
}

void SendInt8()
{
    RPC_LOG_INFO("[ipc_test_client] ------ SendInt8 start ------");
    IpcIo io;
    IpcIo *ioPtr = &io;
    int8_t sendData = CLIENT_TEST_NUMBER;
    InitSendData(ioPtr, sendData, Int8);

    // send sync to server
    (void)DoSend(ioPtr, INT8_TYPE, false);

    // send async to server
    (void)DoSend(ioPtr, INT8_TYPE, true);
    RPC_LOG_INFO("[ipc_test_client] ------ SendInt8 end ------");
    return;
}

void SendInt16()
{
    RPC_LOG_INFO("[ipc_test_client] ------ SendInt16 start ------");
    IpcIo io;
    IpcIo *ioPtr = &io;
    int16_t sendData = CLIENT_TEST_NUMBER;
    InitSendData(ioPtr, sendData, Int16);

    // send sync to server
    (void)DoSend(ioPtr, INT16_TYPE, false);

    // send async to server
    (void)DoSend(ioPtr, INT16_TYPE, true);
    RPC_LOG_INFO("[ipc_test_client] ------ SendInt16 end ------");
    return;
}

void SendInt32()
{
    RPC_LOG_INFO("[ipc_test_client] ------ SendInt32 start ------");
    IpcIo io;
    IpcIo *ioPtr = &io;
    int32_t sendData = CLIENT_TEST_NUMBER;
    InitSendData(ioPtr, sendData, Int32);

    // send sync to server
    (void)DoSend(ioPtr, INT32_TYPE, false);

    // send async to server
    (void)DoSend(ioPtr, INT32_TYPE, true);
    RPC_LOG_INFO("[ipc_test_client] ------ SendInt32 end ------");
    return;
}

void SendInt64()
{
    RPC_LOG_INFO("[ipc_test_client] ------ SendInt64 start ------");
    IpcIo io;
    IpcIo *ioPtr = &io;
    int64_t sendData = CLIENT_TEST_NUMBER;
    InitSendData(ioPtr, sendData, Int64);

    // send sync to server
    (void)DoSend(ioPtr, INT64_TYPE, false);

    // send async to server
    (void)DoSend(ioPtr, INT64_TYPE, true);
    RPC_LOG_INFO("[ipc_test_client] ------ SendInt64 end ------");
    return;
}

void SendUint8()
{
    RPC_LOG_INFO("[ipc_test_client] ------ SendUint8 start ------");
    IpcIo io;
    IpcIo *ioPtr = &io;
    uint8_t sendData = CLIENT_TEST_NUMBER;
    InitSendData(ioPtr, sendData, Uint8);

    // send sync to server
    (void)DoSend(ioPtr, UINT8_TYPE, false);

    // send async to server
    (void)DoSend(ioPtr, UINT8_TYPE, true);
    RPC_LOG_INFO("[ipc_test_client] ------ SendUint8 end ------");
    return;
}

void SendUint16()
{
    RPC_LOG_INFO("[ipc_test_client] ------ SendUint16 start ------");
    IpcIo io;
    IpcIo *ioPtr = &io;
    uint16_t sendData = CLIENT_TEST_NUMBER;
    InitSendData(ioPtr, sendData, Uint16);

    // send sync to server
    (void)DoSend(ioPtr, UINT16_TYPE, false);

    // send async to server
    (void)DoSend(ioPtr, UINT16_TYPE, true);
    RPC_LOG_INFO("[ipc_test_client] ------ SendUint16 end ------");
    return;
}

void SendUint32()
{
    RPC_LOG_INFO("[ipc_test_client] ------ SendUint32 start ------");
    IpcIo io;
    IpcIo *ioPtr = &io;
    uint32_t sendData = CLIENT_TEST_NUMBER;
    InitSendData(ioPtr, sendData, Uint32);

    // send sync to server
    (void)DoSend(ioPtr, UINT32_TYPE, false);

    // send async to server
    (void)DoSend(ioPtr, UINT32_TYPE, true);
    RPC_LOG_INFO("[ipc_test_client] ------ SendUint32 end ------");
    return;
}

void SendUint64()
{
    RPC_LOG_INFO("[ipc_test_client] ------ SendUint64 start ------");
    IpcIo io;
    IpcIo *ioPtr = &io;
    uint64_t sendData = CLIENT_TEST_NUMBER;
    InitSendData(ioPtr, sendData, Uint64);

    // send sync to server
    (void)DoSend(ioPtr, UINT64_TYPE, false);

    // send async to server
    (void)DoSend(ioPtr, UINT64_TYPE, true);
    RPC_LOG_INFO("[ipc_test_client] ------ SendUint64 end ------");
    return;
}

void SendFloat()
{
    RPC_LOG_INFO("[ipc_test_client] ------ SendFloat start ------");
    IpcIo io;
    IpcIo *ioPtr = &io;
    float sendData = PI;
    InitSendData(ioPtr, sendData, Float);

    // send sync to server
    (void)DoSend(ioPtr, FLOAT_TYPE, false);

    // send async to server
    (void)DoSend(ioPtr, FLOAT_TYPE, true);
    RPC_LOG_INFO("[ipc_test_client] ------ SendFloat end ------");
    return;
}

void SendDouble()
{
    RPC_LOG_INFO("[ipc_test_client] ------ SendDouble start ------");
    IpcIo io;
    IpcIo *ioPtr = &io;
    double sendData = PI;
    InitSendData(ioPtr, sendData, Double);

    // send sync to server
    (void)DoSend(ioPtr, DOUBLE_TYPE, false);

    // send async to server
    (void)DoSend(ioPtr, DOUBLE_TYPE, true);
    RPC_LOG_INFO("[ipc_test_client] ------ SendDouble end ------");
    return;
}

void SendInt8Vector()
{
    RPC_LOG_INFO("[ipc_test_client] ------ SendInt8Vector start ------");
    IpcIo io;
    IpcIo *ioPtr = &io;
    int8_t sendData[CLIENT_VECTOR_LEN];
    for (int i = 0; i < CLIENT_VECTOR_LEN; i++) {
        sendData[i] = CLIENT_TEST_NUMBER + i;
    }
    InitSendPtr(ioPtr, sendData, Int8Vector, CLIENT_VECTOR_LEN);
    // send sync to server
    (void)DoSend(ioPtr, VECTOR_INT8_TYPE, false);

    // send async to server
    (void)DoSend(ioPtr, VECTOR_INT8_TYPE, true);
    RPC_LOG_INFO("[ipc_test_client] ------ SendInt8Vector end ------");
    return;
}

void SendInt16Vector()
{
    RPC_LOG_INFO("[ipc_test_client] ------ SendInt16Vector start ------");
    IpcIo io;
    IpcIo *ioPtr = &io;
    int16_t sendData[CLIENT_VECTOR_LEN];
    for (int i = 0; i < CLIENT_VECTOR_LEN; i++) {
        sendData[i] = CLIENT_TEST_NUMBER + i;
    }
    InitSendPtr(ioPtr, sendData, Int16Vector, CLIENT_VECTOR_LEN);
    // send sync to server
    (void)DoSend(ioPtr, VECTOR_INT16_TYPE, false);

    // send async to server
    (void)DoSend(ioPtr, VECTOR_INT16_TYPE, true);
    RPC_LOG_INFO("[ipc_test_client] ------ SendInt16Vector end ------");
    return;
}

void SendInt32Vector()
{
    RPC_LOG_INFO("[ipc_test_client] ------ SendInt32Vector start ------");
    IpcIo io;
    IpcIo *ioPtr = &io;
    int32_t sendData[CLIENT_VECTOR_LEN];
    for (int i = 0; i < CLIENT_VECTOR_LEN; i++) {
        sendData[i] = CLIENT_TEST_NUMBER + i;
    }
    InitSendPtr(ioPtr, sendData, Int32Vector, CLIENT_VECTOR_LEN);
    // send sync to server
    (void)DoSend(ioPtr, VECTOR_INT32_TYPE, false);

    // send async to server
    (void)DoSend(ioPtr, VECTOR_INT32_TYPE, true);
    RPC_LOG_INFO("[ipc_test_client] ------ SendInt32Vector end ------");
    return;
}

void SendInt64Vector()
{
    RPC_LOG_INFO("[ipc_test_client] ------ SendInt64Vector start ------");
    IpcIo io;
    IpcIo *ioPtr = &io;
    int64_t sendData[CLIENT_VECTOR_LEN];
    for (int i = 0; i < CLIENT_VECTOR_LEN; i++) {
        sendData[i] = CLIENT_TEST_NUMBER + i;
    }
    InitSendPtr(ioPtr, sendData, Int64Vector, CLIENT_VECTOR_LEN);
    // send sync to server
    (void)DoSend(ioPtr, VECTOR_INT64_TYPE, false);

    // send async to server
    (void)DoSend(ioPtr, VECTOR_INT64_TYPE, true);
    RPC_LOG_INFO("[ipc_test_client] ------ SendInt64Vector end ------");
    return;
}

void SendUint8Vector()
{
    RPC_LOG_INFO("[ipc_test_client] ------ SendUint8Vector start ------");
    IpcIo io;
    IpcIo *ioPtr = &io;
    uint8_t sendData[CLIENT_VECTOR_LEN];
    for (int i = 0; i < CLIENT_VECTOR_LEN; i++) {
        sendData[i] = CLIENT_TEST_NUMBER + i;
    }
    InitSendPtr(ioPtr, sendData, UInt8Vector, CLIENT_VECTOR_LEN);
    // send sync to server
    (void)DoSend(ioPtr, VECTOR_UINT8_TYPE, false);

    // send async to server
    (void)DoSend(ioPtr, VECTOR_UINT8_TYPE, true);
    RPC_LOG_INFO("[ipc_test_client] ------ SendUint8Vector end ------");
    return;
}

void SendUint16Vector()
{
    RPC_LOG_INFO("[ipc_test_client] ------ SendUint16Vector start ------");
    IpcIo io;
    IpcIo *ioPtr = &io;
    uint16_t sendData[CLIENT_VECTOR_LEN];
    for (int i = 0; i < CLIENT_VECTOR_LEN; i++) {
        sendData[i] = CLIENT_TEST_NUMBER + i;
    }
    InitSendPtr(ioPtr, sendData, UInt16Vector, CLIENT_VECTOR_LEN);
    // send sync to server
    (void)DoSend(ioPtr, VECTOR_UINT16_TYPE, false);

    // send async to server
    (void)DoSend(ioPtr, VECTOR_UINT16_TYPE, true);
    RPC_LOG_INFO("[ipc_test_client] ------ SendUint16Vector end ------");
    return;
}

void SendUint32Vector()
{
    RPC_LOG_INFO("[ipc_test_client] ------ SendUint32Vector start ------");
    IpcIo io;
    IpcIo *ioPtr = &io;
    uint32_t sendData[CLIENT_VECTOR_LEN];
    for (int i = 0; i < CLIENT_VECTOR_LEN; i++) {
        sendData[i] = CLIENT_TEST_NUMBER + i;
    }
    InitSendPtr(ioPtr, sendData, UInt32Vector, CLIENT_VECTOR_LEN);
    // send sync to server
    (void)DoSend(ioPtr, VECTOR_UINT32_TYPE, false);

    // send async to server
    (void)DoSend(ioPtr, VECTOR_UINT32_TYPE, true);
    RPC_LOG_INFO("[ipc_test_client] ------ SendUint32Vector end ------");
    return;
}

void SendUint64Vector()
{
    RPC_LOG_INFO("[ipc_test_client] ------ SendUint64Vector start ------");
    IpcIo io;
    IpcIo *ioPtr = &io;
    uint64_t sendData[CLIENT_VECTOR_LEN];
    for (int i = 0; i < CLIENT_VECTOR_LEN; i++) {
        sendData[i] = CLIENT_TEST_NUMBER + i;
    }
    InitSendPtr(ioPtr, sendData, UInt64Vector, CLIENT_VECTOR_LEN);
    // send sync to server
    (void)DoSend(ioPtr, VECTOR_UINT64_TYPE, false);

    // send async to server
    (void)DoSend(ioPtr, VECTOR_UINT64_TYPE, true);
    RPC_LOG_INFO("[ipc_test_client] ------ SendUint64Vector end ------");
    return;
}

void SendFloatVector()
{
    RPC_LOG_INFO("[ipc_test_client] ------ SendFloatVector start ------");
    IpcIo io;
    IpcIo *ioPtr = &io;
    float sendData[CLIENT_VECTOR_LEN];
    for (int i = 0; i < CLIENT_VECTOR_LEN; i++) {
        sendData[i] = PI + i;
    }
    InitSendPtr(ioPtr, sendData, FloatVector, CLIENT_VECTOR_LEN);
    // send sync to server
    (void)DoSend(ioPtr, VECTOR_FLOAT_TYPE, false);

    // send async to server
    (void)DoSend(ioPtr, VECTOR_FLOAT_TYPE, true);
    RPC_LOG_INFO("[ipc_test_client] ------ SendFloatVector end ------");
    return;
}

void SendDoubleVector()
{
    RPC_LOG_INFO("[ipc_test_client] ------ SendDoubleVector start ------");
    IpcIo io;
    IpcIo *ioPtr = &io;
    double sendData[CLIENT_VECTOR_LEN];
    for (int i = 0; i < CLIENT_VECTOR_LEN; i++) {
        sendData[i] = PI + i;
    }
    InitSendPtr(ioPtr, sendData, DoubleVector, CLIENT_VECTOR_LEN);
    // send sync to server
    (void)DoSend(ioPtr, VECTOR_DOUBLE_TYPE, false);

    // send async to server
    (void)DoSend(ioPtr, VECTOR_DOUBLE_TYPE, true);
    RPC_LOG_INFO("[ipc_test_client] ------ SendDoubleVector end ------");
    return;
}

void SendString()
{
    RPC_LOG_INFO("[ipc_test_client] ------ SendString start ------");
    IpcIo io;
    IpcIo *ioPtr = &io;
    const char *sendData = (char *)CLIENT_SEND_STRING;
    InitSendData(ioPtr, sendData, String);

    // send sync to server
    (void)DoSend(ioPtr, CHAR_TYPE, false);

    // send async to server
    (void)DoSend(ioPtr, CHAR_TYPE, true);
    RPC_LOG_INFO("[ipc_test_client] ------ SendString end ------");
    return;
}

void SendFileDescriptor()
{
    RPC_LOG_INFO("[ipc_test_client] ------ SendFileDescriptor start ------");
    IpcIo io;
    IpcIo *ioPtr = &io;
    if (InitPipe() != ERR_NONE) {
        return;
    }

    if (StartTimerForFdEvent() != ERR_NONE) {
        return;
    }

    InitSendData(ioPtr, g_pipeFd[1], FileDescriptor);
    (void)DoSend(ioPtr, FD_TYPE, false);

    // block on response or timeout
    char buffer[100];
    RPC_LOG_INFO("[ipc_test_client] SendFileDescriptor waiting for data reading, timeout=%d...", (int32_t)FD_TIMEOUT);
    ssize_t readLen = read(g_pipeFd[0], buffer, sizeof(buffer));
    if (readLen == 0) {
        RPC_LOG_ERROR("[ipc_test_client] SendFileDescriptor read error, read timeout");
    } else if (readLen < 0) {
        RPC_LOG_ERROR("[ipc_test_client] SendFileDescriptor read failed, err=%d", errno);
        DeinitPipe();
    } else {
        buffer[readLen] = '\0';
        RPC_LOG_INFO("[ipc_test_client] SendFileDescriptor receive size=%d data=%s", readLen, buffer);
        DeinitPipe();
    }
    RPC_LOG_INFO("[ipc_test_client] ------ SendFileDescriptor end ------");
    return;
}

void SendRawData()
{
    RPC_LOG_INFO("[ipc_test_client] ------ SendRawData start ------");
    IpcIo io;
    IpcIo *ioPtr = &io;
    InitSendPtr(ioPtr, &g_clientIdentify, RawData, sizeof(SvcIdentity));

    // send sync to server
    (void)DoSend(ioPtr, RAW_DATA_TYPE, false);

    // send async to server
    (void)DoSend(ioPtr, RAW_DATA_TYPE, true);
    RPC_LOG_INFO("[ipc_test_client] ------ SendRawData end ------");
    return;
}

void SendBuffer()
{
    RPC_LOG_INFO("[ipc_test_client] ------ SendBuffer start ------");
    IpcIo io;
    IpcIo *ioPtr = &io;
    // send struct svc test
    InitSendPtr(ioPtr, &g_clientIdentify, Buffer, sizeof(SvcIdentity));

    // send sync to server
    (void)DoSend(ioPtr, BUFFER_TYPE, false);

    // send async to server
    (void)DoSend(ioPtr, BUFFER_TYPE, true);
    RPC_LOG_INFO("[ipc_test_client] ------ SendBuffer end ------");
    return;
}