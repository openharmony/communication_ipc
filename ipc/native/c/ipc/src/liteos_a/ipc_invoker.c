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

#include "ipc_invoker.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <threads.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "rpc_errno.h"
#include "rpc_log.h"
#include "lite_ipc.h"
#include "ipc_types.h"
#include "ipc_process_skeleton.h"

#define MAX_SA_SIZE (0x100)
#define LITEIPC_VERSION_MIN_REQUIRE (2)
uint32_t g_threadId = 0;
static RemoteInvoker g_ipcInvoker;

typedef struct {
    int32_t fd;
    size_t mmapSize;
    void *mmapAddr;
} IpcConnector;

static IpcConnector *g_connector = NULL;
static pthread_mutex_t g_connectorMutex = PTHREAD_MUTEX_INITIALIZER;

IpcCallback g_ipcCallback = {
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .handleId = IPC_INVALID_HANDLE,
    .threadWorking = false
};

static inline void InitIpcCallback(void)
{
    UtilsListInit(&g_ipcCallback.apis);
}

static IpcConnector *OpenDriver(void)
{
    IpcConnector *connector = (IpcConnector *)malloc(sizeof(IpcConnector));
    if (connector == NULL) {
        RPC_LOG_ERROR("liteipc malloc failed: %d.", errno);
        return NULL;
    }
    connector->fd = open(LITEIPC_DRIVER, O_RDWR);
    if (connector->fd < 0) {
        RPC_LOG_ERROR("liteipc open failed error : %d.", errno);
        goto OPEN_ERR;
    }
    connector->mmapAddr = mmap(NULL, MMAP_MAX_SIZE, PROT_READ, MAP_PRIVATE, connector->fd, 0);
    if (connector->mmapAddr == MAP_FAILED) {
        RPC_LOG_ERROR("liteipc mmap failed: %d.", errno);
        goto MMAP_ERR;
    }
    connector->mmapSize = MMAP_MAX_SIZE;
    InitIpcCallback();
    IpcVersion version;
    int ret = ioctl(connector->fd, IPC_GET_VERSION, &version);
    if (ret != 0) {
        RPC_LOG_ERROR("liteipc get version failed error : %d.\n", ret);
        goto VERSION_ERR;
    }

    uint16_t major = (version.driverVersion) & 0xffff;
    uint16_t minor = (version.driverVersion >> 16) & 0xffff;
    if (major < LITEIPC_VERSION_MIN_REQUIRE) {
        RPC_LOG_ERROR("liteipc outdated version: %d.%d\n", major, minor);
        goto VERSION_ERR;
    }
    return connector;

VERSION_ERR:
MMAP_ERR:
    close(connector->fd);
OPEN_ERR:
    free(connector);
    return NULL;
}

static void CloseDriver(void)
{
    if (g_connector == NULL) {
        return;
    }
    pthread_mutex_lock(&g_connectorMutex);
    munmap(g_connector->mmapAddr, g_connector->mmapSize);
    close(g_connector->fd);
    free(g_connector);
    g_connector = NULL;
    pthread_mutex_unlock(&g_connectorMutex);
}

static int32_t AcquireHandle(int32_t handle)
{
    return ERR_NONE;
}

static int32_t ReleaseHandle(int32_t handle)
{
    return ERR_NONE;
}

static int32_t IpcFreeBuffer(void *buffer)
{
    if (buffer == NULL) {
        RPC_LOG_ERROR("Invalid parameter, null pointer: %d.", errno);
        return ERR_INVALID_PARAM;
    }
    if (g_connector == NULL) {
        RPC_LOG_ERROR("liteipc driver not init");
        return ERR_IPC_SKELETON_NOT_INIT;
    }

    IpcContent content = {
        .flag = BUFF_FREE,
        .buffToFree = buffer
    };
    return ioctl(g_connector->fd, IPC_SEND_RECV_MSG, &content);
}

static void IpcIoInitFromMsg(IpcIo *io, const IpcMsg *msg)
{
    if ((io == NULL) || (msg == NULL)) {
        return;
    }
    io->bufferCur = io->bufferBase = (char *)(intptr_t)msg->data;
    io->offsetsCur = io->offsetsBase = (size_t *)(intptr_t)(msg->offsets);
    io->bufferLeft = msg->dataSz;
    io->offsetsLeft = msg->spObjNum;
    io->flag = IPC_IO_INITIALIZED;
}

static bool IpcIoAvailable(IpcIo *io)
{
    bool ret = false;
    if (io != NULL) {
        ret = (io->flag & IPC_IO_INITIALIZED) && !(io->flag & IPC_IO_OVERFLOW);
    }
    return ret;
}

static int32_t CheckIpcIo(IpcIo *data)
{
    uint32_t totalSize;

    if (data == NULL) {
        return ERR_NONE;
    }

    if ((IpcIoAvailable(data) == false) || (data->bufferCur == NULL) || (data->bufferBase == NULL) ||
        (data->offsetsCur == NULL) ||(data->offsetsBase == NULL) ||
        ((intptr_t)data->bufferBase < (intptr_t)data->offsetsCur)) {
        return ERR_INVALID_PARAM;
    }

    totalSize = data->bufferCur - data->bufferBase + ((char*)data->offsetsCur - (char*)data->offsetsBase);
    if (totalSize > MAX_IO_SIZE) {
        RPC_LOG_ERROR("IpcIo data too big, please use IpcIoPushDataBuff to push big data, error: %d.", errno);
        return ERR_FAILED;
    }
    return ERR_NONE;
}

static void SendReply(IpcMsg *ipcMsg, IpcIo *reply)
{
    int32_t ret;

    if (ipcMsg == NULL) {
        RPC_LOG_ERROR("Invalid parameter, null pointer.");
        return;
    }

    ret = CheckIpcIo(reply);
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("CheckIpcIo failed,ret = %d.", ret);
        return;
    }

    if (g_connector == NULL) {
        RPC_LOG_ERROR("liteipc driver not init");
        return;
    }
    IpcMsg out = {
        .type = MT_REPLY,
        .target.handle = ipcMsg->taskID,
        .code = ipcMsg->code,
        .flag = ipcMsg->flag,
        .timestamp = ipcMsg->timestamp,
        .dataSz = reply->bufferCur - reply->bufferBase,
        .data = (void *)reply->bufferBase,
        .offsets = reply->offsetsBase,
        .spObjNum = ((char *)reply->offsetsCur - (char *)reply->offsetsBase) / sizeof(size_t)
    };
    IpcContent content = {
        .flag = SEND | BUFF_FREE,
        .outMsg = &out,
        .buffToFree = ipcMsg
    };

    ret = ioctl(g_connector->fd, IPC_SEND_RECV_MSG, &content);
    if (ret < 0) {
        RPC_LOG_ERROR("Liteipc driver ioctl failed: %d.", errno);
    }
}

static void SendFailedReply(IpcMsg *ipcMsg)
{
    int32_t ret;

    if (ipcMsg == NULL) {
        RPC_LOG_ERROR("Invalid parameter, null pointer.");
        return;
    }

    if (g_connector == NULL) {
        RPC_LOG_ERROR("liteipc driver not init");
        return;
    }

    IpcMsg out = {
        .type = MT_FAILED_REPLY,
        .target.handle = ipcMsg->taskID,
        .code = ipcMsg->code,
        .flag = ipcMsg->flag,
        .timestamp = ipcMsg->timestamp,
        .dataSz = 0,
        .data = NULL,
        .offsets = NULL,
        .spObjNum = 0
    };
    IpcContent content = {
        .flag = SEND | BUFF_FREE,
        .outMsg = &out,
        .buffToFree = ipcMsg
    };

    ret = ioctl(g_connector->fd, IPC_SEND_RECV_MSG, &content);
    if (ret < 0) {
        RPC_LOG_ERROR("Liteipc driver ioctl failed: %d.", errno);
    }
}


static void CallDeathCallback(IpcMsg *ipcMsg)
{
    IpcSkeleton *ipcSkeleton = GetCurrentSkeleton();
    if (ipcSkeleton == NULL) {
        RPC_LOG_ERROR("GetCurrentSkeleton return null");
        return;
    }
    DeathCallback *node = NULL;
    RPC_LOG_INFO("<thread>for each list");
    UTILS_DL_LIST_FOR_EACH_ENTRY(node, &ipcSkeleton->objects, DeathCallback, list)
    {
        RPC_LOG_INFO("SendObituary node->handle: %d, ipcMsg->target.token: %d", node->handle, ipcMsg->target.token);
        if (node->handle == ipcMsg->target.token) {
            SendObituary(node);
            break;
        }
    }
}

static void CallIpcCallback(IpcMsg *ipcMsg, HdlerArg *hdlerArg)
{
    for (uint32_t i = 0; i < hdlerArg->num; i++) {
        if (hdlerArg->useFlag == false) {
            continue;
        }
        ThreadContext *threadContext = GetCurrentThreadContext();
        const pid_t oldPid = threadContext->callerPid;
        const pid_t oldUid = threadContext->callerUid;
        threadContext->callerPid = ipcMsg->processID;
        threadContext->callerUid = (pid_t)ipcMsg->userID;
        MessageOption option = {
            .flags = ipcMsg->flag,
            .args = hdlerArg->cbs[i].args
        };
        IpcIo reply;
        uint8 tempData[MAX_IO_SIZE];
        IpcIoInit(&reply, tempData, MAX_IO_SIZE, MAX_OBJ_NUM);
        int32_t error = OnRemoteRequestInner(ipcMsg->code, &hdlerArg->io, &reply, option, &hdlerArg->cbs[i]);
        if (error < 0) {
            RPC_LOG_ERROR("OnRemoteRequestInner failed, error = %d", error);
        }
        if (!(ipcMsg->flag & TF_OP_ASYNC)) {
            SendReply(ipcMsg, &reply);
        } else {
            IpcFreeBuffer((void *)ipcMsg);
        }
        threadContext->callerPid = oldPid;
        threadContext->callerUid = oldUid;
    }
    free(hdlerArg);
}

static void *CallbackBatchHandler(HdlerArg *hdlerArg)
{
    pthread_detach(pthread_self());
    IpcMsg *ipcMsg = (IpcMsg *)hdlerArg->msg;
    switch (ipcMsg->type) {
        case MT_DEATH_NOTIFY:
            CallDeathCallback(ipcMsg);
            break;
        case MT_REQUEST:
            CallIpcCallback(ipcMsg, hdlerArg);
            break;
        default:
            RPC_LOG_ERROR("ipcMsg type unknow.");
            break;
    }
    return NULL;
}

static void GetDeathCallback(IpcMsg* msg, HdlerArg* arg)
{
    if (pthread_mutex_lock(&g_ipcCallback.mutex) != 0) {
        RPC_LOG_ERROR("Get callback mutex failed.");
        return;
    }
    arg->msg = msg;
    arg->num = MAX_DEATH_CALLBACK_NUM;
    (void)pthread_mutex_unlock(&g_ipcCallback.mutex);
}

static void GetIpcCallback(IpcMsg* msg, HdlerArg* arg)
{
    if (pthread_mutex_lock(&g_ipcCallback.mutex) != 0) {
        RPC_LOG_ERROR("Get callback mutex failed.");
        return;
    }
    IpcIoInitFromMsg(&arg->io, msg);
    arg->msg = msg;

    AnonymousApi* node = NULL;
    UTILS_DL_LIST_FOR_EACH_ENTRY(node, &g_ipcCallback.apis, AnonymousApi, list)
    {
        if (node->token == msg->target.token) {
            arg->num = 1;
            arg->useFlag = true;
            arg->cbs = &node->hdlerPair;
            (void)pthread_mutex_unlock(&g_ipcCallback.mutex);
            return;
        }
    }
    arg->num = 0;
    arg->useFlag = false;
    arg->cbs = NULL;
    (void)pthread_mutex_unlock(&g_ipcCallback.mutex);
}

static void CallbackDispatchLoop(void)
{
    while (1) {
        IpcContent content = {.flag = RECV};
        sched_yield();
        int32_t ret = ioctl(g_connector->fd, IPC_SEND_RECV_MSG, &content);
        if (ret < 0) {
            continue;
        }

        HdlerArg *tArg = (HdlerArg *)malloc(sizeof(HdlerArg));
        if (tArg == NULL) {
            goto ERROR_MALLOC;
        }
        IpcMsg *ipcMsg = content.inMsg;
        switch (ipcMsg->type) {
            case MT_DEATH_NOTIFY:
                GetDeathCallback(ipcMsg, tArg);
                break;
            case MT_REQUEST:
                GetIpcCallback(ipcMsg, tArg);
                break;
            default:
                RPC_LOG_ERROR("Callback thread received an unrecognized message.(type=%d)", ipcMsg->type);
                goto ERROR_MSG;
        }
        if (tArg->num == 0) {
            RPC_LOG_ERROR("failed tArg->num = 0");
            goto ERROR_MSG;
        }

        pthread_t tid;
        ret = pthread_create(&tid, NULL, CallbackBatchHandler, tArg);
        if (ret == 0) {
            continue;
        }
        RPC_LOG_ERROR("Create handle thread failed.");

ERROR_MSG:
        free(tArg);
ERROR_MALLOC:
        if ((ipcMsg->type == MT_REQUEST) && (ipcMsg->flag == TF_OP_SYNC)) {
            SendFailedReply(ipcMsg);
        } else {
            IpcFreeBuffer((void *)ipcMsg);
        }
    }
}

static void *CallbackDispatch(void)
{
    if (g_connector == NULL) {
        RPC_LOG_ERROR("liteipc driver not init");
        return NULL;
    }

    int32_t ret = ioctl(g_connector->fd, IPC_SET_IPC_THREAD, 0);
    g_threadId = syscall(SYS_gettid);
    g_ipcCallback.handleId = ret;
    g_ipcCallback.threadWorking = true;
    CallbackDispatchLoop();
    g_ipcCallback.threadWorking = false;
    return NULL;
}

IpcCallback *GetIpcCb(void)
{
    return &g_ipcCallback;
}

uint32_t GetThreadId(void)
{
    return g_threadId;
}

int32_t StartCallbackDispatch(void)
{
    if (!g_ipcCallback.threadWorking) {
        pthread_attr_t threadAttr;
        pthread_attr_init(&threadAttr);
        pthread_attr_setdetachstate(&threadAttr, PTHREAD_CREATE_DETACHED);

        pthread_t tid;
        int32_t ret = pthread_create(&tid, &threadAttr, CallbackDispatch, NULL);
        if (ret != 0) {
            RPC_LOG_ERROR("Create callback dispatch thread failed.");
            return ERR_FAILED;
        }

        struct timespec spark, now;
        clock_gettime(CLOCK_REALTIME, &spark);
        sched_yield();
        while (!g_ipcCallback.threadWorking) {
            clock_gettime(CLOCK_REALTIME, &now);
            if (now.tv_sec - spark.tv_sec > 1) {
                RPC_LOG_INFO("Wait callback thread starting timeout.");
                return ERR_FAILED;
            }
            sched_yield();
        }
        return ERR_NONE;
    }
    return ERR_NONE;
}

static void IpcJoinThreadLoop(void)
{
    IpcObjectStub *objectStub = (IpcObjectStub *)GetObjectStub(0);
    if (objectStub == NULL) {
        RPC_LOG_INFO("objectStub is NULL.");
        return;
    }
    while (1) {
        IpcContent content = {.flag = RECV};
        int32_t ret = ioctl(g_connector->fd, IPC_SEND_RECV_MSG, &content);
        if (ret < 0) {
            RPC_LOG_ERROR("ioctl request fail.");
            continue;
        }
        IpcMsg *ipcMsg = content.inMsg;
        ThreadContext *threadContext = GetCurrentThreadContext();
        const pid_t oldPid = threadContext->callerPid;
        const pid_t oldUid = threadContext->callerUid;
        threadContext->callerPid = ipcMsg->processID;
        threadContext->callerUid = (pid_t)ipcMsg->userID;

        IpcIo data, reply;
        IpcIoInitFromMsg(&data, ipcMsg);
        uint8 tempData[MAX_IO_SIZE];
        IpcIoInit(&reply, tempData, MAX_IO_SIZE, MAX_OBJ_NUM);
        MessageOption option = {
            .flags = ipcMsg->flag,
            .args = objectStub->args
        };
        int32_t error = OnRemoteRequestInner(ipcMsg->code, &data, &reply, option, objectStub);
        if (error < 0) {
            RPC_LOG_ERROR("OnRemoteRequestInner failed, error = %d", error);
        }
        if (!(ipcMsg->flag & TF_OP_ASYNC)) {
            SendReply(ipcMsg, &reply);
        } else {
            IpcFreeBuffer((void *)ipcMsg);
        }
        threadContext->callerPid = oldPid;
        threadContext->callerUid = oldUid;
    }
}

static void IpcJoinThread(bool initiative)
{
    if (g_connector == NULL) {
        RPC_LOG_ERROR("liteipc driver not init");
        return;
    }
    IpcJoinThreadLoop();
}

static int32_t IpcSetMaxWorkThread(int32_t maxThreadNum)
{
    return ERR_NONE;
}

static int32_t IpcSetRegistryObject(SvcIdentity target, SvcIdentity *samgr)
{
    (void)target;
    (void)samgr;
    if (g_connector == NULL) {
        RPC_LOG_ERROR("liteipc driver not init");
        return ERR_IPC_SKELETON_NOT_INIT;
    }
    int32_t ret = ioctl(g_connector->fd, IPC_SET_CMS, MAX_SA_SIZE);
    if (ret == ERR_NONE) {
        GetObjectStub(target.cookie);
        RPC_LOG_INFO("set samgr success!!");
        return ERR_NONE;
    }
    RPC_LOG_ERROR("set samgr failed");
    return IPC_INVOKER_IOCTL_FAILED;
}

static int32_t IpcSendRequest(SvcIdentity target, uint32_t code, IpcIo *data, IpcIo *reply,
    MessageOption option, uintptr_t *buffer)
{
    int32_t ret;

    if ((option.flags > TF_OP_ASYNC) || ((option.flags == TF_OP_SYNC) && (buffer == NULL))) {
        RPC_LOG_ERROR("Invalid parameter, null pointer.");
        return ERR_INVALID_PARAM;
    }

    ret = CheckIpcIo(data);
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("CheckIpcIo failed.");
        return ret;
    }

    if (g_connector == NULL) {
        RPC_LOG_ERROR("liteipc driver not init");
        return ERR_IPC_SKELETON_NOT_INIT;
    }
    IpcMsg msg = {
        .type = MT_REQUEST,
        .target = target,
        .code = code,
        .flag = option.flags,
        .dataSz = (data == NULL) ? 0 : data->bufferCur - data->bufferBase,
        .data =  (data == NULL) ? NULL : data->bufferBase,
        .offsets =  (data == NULL) ? NULL : data->offsetsBase,
        .spObjNum =  (data == NULL) ? 0 : ((char *)data->offsetsCur - (char *)data->offsetsBase) / sizeof(size_t)
    };

    IpcContent content = {
        .outMsg = &msg,
        .flag = (option.flags == TF_OP_ASYNC) ? SEND : (SEND | RECV)
    };

    ret = ioctl(g_connector->fd, IPC_SEND_RECV_MSG, &content);
    if (ret < 0) {
        RPC_LOG_ERROR("send ioctl failed: %d.", errno);
        return IPC_INVOKER_IOCTL_FAILED;
    }

    if (option.flags != TF_OP_ASYNC) {
        if (reply != NULL) {
            IpcIoInitFromMsg(reply, content.inMsg);
        }
        *buffer = (uintptr_t)content.inMsg;
    }

    return ret;
}

static int32_t IpcAddDeathRecipient(int32_t handle, void *cookie)
{
    if (!g_ipcCallback.threadWorking) {
        pthread_mutex_lock(&g_ipcCallback.mutex);
        int32_t ret = StartCallbackDispatch();
        if (ret < 0) {
            RPC_LOG_ERROR("IpcAddDeathRecipient StartCallbackDispatch failed.");
            pthread_mutex_unlock(&g_ipcCallback.mutex);
            return false;
        }
        pthread_mutex_unlock(&g_ipcCallback.mutex);
    }
    return ERR_NONE;
}

static int32_t IpcRemoveDeathRecipient(int32_t handle, void *cookie)
{
    return ERR_NONE;
}

static void IpcExitCurrentThread(void)
{
}

static IpcConnector *InitIpcConnector(void);

static void InvokerResetIpc(void)
{
    if (g_connector != NULL) {
        free(g_connector);
        g_connector = NULL;
    }

    pthread_mutex_init(&g_connectorMutex, NULL);
    g_ipcCallback.handleId = IPC_INVALID_HANDLE;
    g_ipcCallback.threadWorking = false;
    pthread_mutex_init(&(g_ipcCallback.mutex), NULL);

    if (InitIpcConnector() == NULL) {
        RPC_LOG_ERROR("init liteipc invoker failed: %d.", errno);
    }
}

static IpcConnector *InitIpcConnector(void)
{
    if (g_connector == NULL) {
        if (pthread_mutex_lock(&g_connectorMutex) != 0) {
            RPC_LOG_ERROR("init liteipc connector lock failed: %d.", errno);
            return NULL;
        }
        if (g_connector == NULL) {
            IpcConnector *connector = OpenDriver();
            if (connector == NULL) {
                pthread_mutex_unlock(&g_connectorMutex);
                RPC_LOG_ERROR("create liteipc connector failed: %d.", errno);
                return NULL;
            }
            g_connector = connector;
            g_ipcInvoker.connector = g_connector;
            g_ipcInvoker.AcquireHandle = AcquireHandle;
            g_ipcInvoker.ReleaseHandle = ReleaseHandle;
            g_ipcInvoker.SendRequest = IpcSendRequest;
            g_ipcInvoker.FreeBuffer = IpcFreeBuffer;
            g_ipcInvoker.SetMaxWorkThread = IpcSetMaxWorkThread;
            g_ipcInvoker.JoinThread = IpcJoinThread;
            g_ipcInvoker.SetRegistryObject = IpcSetRegistryObject;
            g_ipcInvoker.AddDeathRecipient = IpcAddDeathRecipient;
            g_ipcInvoker.RemoveDeathRecipient = IpcRemoveDeathRecipient;
            g_ipcInvoker.ExitCurrentThread = IpcExitCurrentThread;
            g_ipcInvoker.InvokerResetIpc = InvokerResetIpc;
        }
        pthread_mutex_unlock(&g_connectorMutex);
    }

    return g_connector;
}

RemoteInvoker *GetIpcInvoker(void)
{
    if (InitIpcConnector() == NULL) {
        RPC_LOG_ERROR("init liteipc invoker failed: %d.", errno);
        return NULL;
    }

    return &g_ipcInvoker;
}

void DeinitIpcInvoker(RemoteInvoker *invoker)
{
    if (invoker != &g_ipcInvoker) {
        return;
    }
    CloseDriver();
}