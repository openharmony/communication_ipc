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

#include "ipc_invoker.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include "ipc_process_skeleton.h"
#include "ipc_thread_pool.h"
#include "ipc_types.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "rpc_os_adapter.h"
#include "rpc_types.h"
#include "securec.h"
#include "sys_binder.h"

#define READ_BUFFER_SIZE 32

#define ALIGN_SZ 4
#define IPC_IO_ALIGN(sz) (((sz) + ALIGN_SZ - 1) & (~(ALIGN_SZ - 1)))

typedef struct {
    int32_t fd;
    size_t mmapSize;
    void *mmapAddr;
} BinderConnector;

struct FreeData {
    uint32_t cmd;
    binder_uintptr_t buffer;
}__attribute__((packed));

struct TransactData {
    uint32_t cmd;
    struct binder_transaction_data btd;
}__attribute__((packed));

static RemoteInvoker g_ipcInvoker;
static BinderConnector *g_connector = NULL;
static pthread_mutex_t g_connectorMutex = PTHREAD_MUTEX_INITIALIZER;

static BinderConnector *OpenDriver(void)
{
    BinderConnector *connector = (BinderConnector *)calloc(1, sizeof(BinderConnector));
    if (connector == NULL) {
        RPC_LOG_ERROR("ipc open driver malloc failed.");
        return NULL;
    }
    connector->fd = open(BINDER_DRIVER, O_RDWR);
    if (connector->fd < 0) {
        RPC_LOG_ERROR("Open liteipc driver failed error %d.", errno);
        goto OPEN_ERR;
    }
    connector->mmapAddr = mmap(NULL, MMAP_MAX_SIZE, PROT_READ, MAP_PRIVATE, connector->fd, 0);
    if (connector->mmapAddr == MAP_FAILED) {
        RPC_LOG_ERROR("Mmap failed.");
        goto MMAP_ERR;
    }
    connector->mmapSize = MMAP_MAX_SIZE;
    return connector;

MMAP_ERR:
    close(connector->fd);
OPEN_ERR:
    free(connector);
    return NULL;
}

static void DeleteBinderConnector(void)
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

static int32_t BinderWrite(void *data, size_t len)
{
    struct binder_write_read bwr;
    int32_t res;

    bwr.write_size = len;
    bwr.write_consumed = 0;
    bwr.write_buffer = (uintptr_t)data;
    bwr.read_size = 0;
    bwr.read_consumed = 0;
    bwr.read_buffer = 0;
    res = ioctl(g_connector->fd, BINDER_WRITE_READ, &bwr);
    if (res < 0) {
        RPC_LOG_ERROR("binder write ioctl failed errno = %d.", errno);
        return IPC_INVOKER_IOCTL_FAILED;
    }
    return ERR_NONE;
}

static int32_t AcquireHandle(int32_t handle)
{
    uint32_t cmd[2];
    cmd[0] = BC_ACQUIRE;
    cmd[1] = handle;
    int32_t ret = BinderWrite(&cmd, sizeof(cmd));
    return ret;
}

static int32_t ReleaseHandle(int32_t handle)
{
    RPC_LOG_ERROR("SA dead delete it, handle = %d.", handle);
    uint32_t cmd[2];
    cmd[0] = BC_RELEASE;
    cmd[1] = handle;
    int32_t ret = BinderWrite(&cmd, sizeof(cmd));
    return ret;
}

static void ToTransData(uint32_t handle, uint32_t code, uint32_t option,
    const IpcIo *data, struct TransactData *buf)
{
    buf->btd.target.handle = handle;
    buf->btd.code = code;
    buf->btd.flags = option;
    buf->btd.cookie = 0;
    buf->btd.sender_pid = RpcGetPid();
    buf->btd.sender_euid = RpcGetUid();
    buf->btd.data_size = (data == NULL) ? 0 : (data->bufferCur - data->bufferBase);
    buf->btd.data.ptr.buffer = (data == NULL) ? 0 : (binder_uintptr_t)data->bufferBase;
    buf->btd.offsets_size = (data == NULL) ? 0 : ((char*)data->offsetsCur - (char*)data->offsetsBase);
    buf->btd.offsets_size = IPC_IO_ALIGN(buf->btd.offsets_size);
    buf->btd.data.ptr.offsets = (data == NULL) ? 0 : (binder_uintptr_t)data->offsetsBase;
}

static void ToIpcData(const struct binder_transaction_data *tr, IpcIo *data)
{
    data->bufferBase = data->bufferCur = (char *)tr->data.ptr.buffer;
    data->bufferLeft = (size_t)tr->data_size;
    data->offsetsBase = data->offsetsCur = (size_t *)tr->data.ptr.offsets;
    data->offsetsLeft = (tr->offsets_size) / sizeof(binder_size_t);
    data->flag = IPC_IO_INITIALIZED;
}

static void BinderRefDone(const struct binder_ptr_cookie *ptrCookie, uint32_t cmd)
{
    struct {
        uint32_t cmd;
        struct binder_ptr_cookie payload;
    } __attribute__((packed)) data;

    if (cmd == BR_ACQUIRE) {
        data.cmd = BC_ACQUIRE_DONE;
    } else {
        data.cmd = BC_INCREFS_DONE;
    }
    data.payload.ptr = ptrCookie->ptr;
    data.payload.cookie = ptrCookie->cookie;
    BinderWrite(&data, sizeof(data));
}

static int32_t IpcFreeBuffer(void *ptr)
{
    if (ptr == NULL) {
        return ERR_NONE;
    }

    struct FreeData data = {0};
    data.cmd = BC_FREE_BUFFER;
    data.buffer = (binder_uintptr_t)ptr;
    int32_t ret = BinderWrite(&data, sizeof(data));
    return ret;
}

static int32_t SendReply(IpcIo *reply, const int32_t *status)
{
    struct TransactData buf;
    buf.cmd = BC_REPLY;
    int32_t ret;
    if (reply->bufferCur > reply->bufferBase) {
        ToTransData(0, 0, 0, reply, &buf);
    } else if (status != NULL) {
        buf.btd.flags = TF_OP_STATUS_CODE;
        buf.btd.data_size = sizeof(int32_t);
        buf.btd.offsets_size = 0;
        buf.btd.data.ptr.buffer = (uintptr_t)status;
        buf.btd.data.ptr.offsets = 0;
    }
    ret = BinderWrite(&buf, sizeof(buf));
    return ret;
}

static void HandleTransaction(const struct binder_transaction_data *tr)
{
    ThreadContext *threadContext = GetCurrentThreadContext();
    const pid_t oldPid = threadContext->callerPid;
    const pid_t oldUid = threadContext->callerUid;
    threadContext->callerPid = tr->sender_pid;
    threadContext->callerUid = (pid_t)tr->sender_euid;
    IpcObjectStub *objectStub;
    if (tr->target.ptr != 0) {
        objectStub = (IpcObjectStub *)tr->cookie;
    } else {
        objectStub = (IpcObjectStub *)(GetRegistryObject()->cookie);
    }
    threadContext->objectStub = objectStub;
    IpcIo data;
    ToIpcData(tr, &data);
    MessageOption option = {
        .flags = tr->flags,
        .args = objectStub->args
    };
    IpcIo reply;
    uint8 tempData[MAX_IO_SIZE];
    IpcIoInit(&reply, tempData, MAX_IO_SIZE, MAX_OBJ_NUM);
    int32_t error = OnRemoteRequestInner(tr->code, &data, &reply, option, objectStub);
    if (tr->flags & TF_ONE_WAY) {
        IpcFreeBuffer((void *)(tr->data.ptr.buffer));
    } else {
        IpcFreeBuffer((void *)(tr->data.ptr.buffer));
        SendReply(&reply, &error);
    }
    threadContext->callerPid = oldPid;
    threadContext->callerUid = oldUid;
}

static void HandleReply(IpcIo *reply, const struct binder_transaction_data *tr, uintptr_t *buffer)
{
    if (reply == NULL || buffer == NULL) {
        RPC_LOG_ERROR("no need reply, free the buffer.");
        IpcFreeBuffer((void *)(tr->data.ptr.buffer));
        return;
    }
    ToIpcData(tr, reply);
    *buffer = (uintptr_t)tr->data.ptr.buffer;
}

static void HandleDeadBinderDone(void *cookie)
{
    struct {
        uint32_t cmd;
        binder_uintptr_t cookie;
    } __attribute__((packed)) data;
    data.cmd = BC_DEAD_BINDER_DONE;
    data.cookie = (binder_uintptr_t)cookie;
    BinderWrite(&data, sizeof(data));
}

static void HandleDeadBinder(uintptr_t ptr)
{
    DeathCallback *death = (DeathCallback *)(uintptr_t) *(binder_uintptr_t *)ptr;
    if (death != NULL) {
        RPC_LOG_INFO("dead binder now call SendObituary.");
        SendObituary(death);
        HandleDeadBinderDone(death);
    }
}

static int32_t BinderParse(IpcIo *reply, uintptr_t ptr, size_t size, uintptr_t *buffer)
{
    int32_t ret = 1;
    uintptr_t end = ptr + (uintptr_t) size;
    while (ptr < end) {
        uint32_t cmd = *(uint32_t *) ptr;
        ptr += sizeof(uint32_t);
        switch (cmd) {
            case BR_NOOP:
            case BR_TRANSACTION_COMPLETE:
                break;
            case BR_INCREFS:
            case BR_ACQUIRE: {
                struct binder_ptr_cookie *ptrCookie = (struct binder_ptr_cookie *) ptr;
                if ((end - ptr) < sizeof(*ptrCookie)) {
                    return IPC_INVOKER_INVALID_DATA;
                }
                BinderRefDone(ptrCookie, cmd);
                ptr += sizeof(*ptrCookie);
                break;
            }
            case BR_RELEASE:
            case BR_DECREFS:
                ptr += sizeof(struct binder_ptr_cookie);
                break;
            case BR_SPAWN_LOOPER: {
                SpawnThread(SPAWN_PASSIVE, IF_PROT_DEFAULT);
                break;
            }
            case BR_TRANSACTION: {
                struct binder_transaction_data *tr = (struct binder_transaction_data *) ptr;
                if ((end - ptr) < sizeof(*tr)) {
                    return IPC_INVOKER_INVALID_DATA;
                }
                HandleTransaction(tr);
                ptr += sizeof(*tr);
                break;
            }
            case BR_REPLY: {
                struct binder_transaction_data *tr = (struct binder_transaction_data *) ptr;
                if ((end - ptr) < sizeof(*tr)) {
                    return IPC_INVOKER_INVALID_DATA;
                }
                HandleReply(reply, tr, buffer);
                ptr += sizeof(*tr);
                ret = 0;
                break;
            }
            case BR_DEAD_BINDER: {
                HandleDeadBinder(ptr);
                ptr += sizeof(binder_uintptr_t);
                break;
            }
            case BR_CLEAR_DEATH_NOTIFICATION_DONE: {
                ptr += sizeof(binder_uintptr_t);
                break;
            }
            case BR_FAILED_REPLY:
                ret = IPC_INVOKER_FAILED_REPLY;
                break;
            case BR_DEAD_REPLY:
                ret = ERR_DEAD_OBJECT;
                break;
            default:
                ret = IPC_INVOKER_UNKNOWN_CODE;
        }
    }
    return ret;
}

static void IpcJoinThread(bool initiative)
{
    struct binder_write_read bwr;
    uint32_t readbuf[READ_BUFFER_SIZE];
    int32_t ret;

    bwr.write_size = 0;
    bwr.write_consumed = 0;
    bwr.write_buffer = 0;

    if (initiative) {
        readbuf[0] = BC_ENTER_LOOPER;
    } else {
        readbuf[0] = BC_REGISTER_LOOPER;
    }
    BinderWrite(readbuf, sizeof(uint32_t));
    for (; ;) {
        bwr.read_size = sizeof(readbuf);
        bwr.read_consumed = 0;
        bwr.read_buffer = (uintptr_t)readbuf;
        ret = ioctl(g_connector->fd, BINDER_WRITE_READ, &bwr);
        if (ret < 0) {
            RPC_LOG_ERROR("ioctl failed errno = %d.", errno);
            break;
        }
        ret = BinderParse(0, (uintptr_t)readbuf, bwr.read_consumed, NULL);
        if (ret == 0) {
            RPC_LOG_ERROR("unexpected reply");
            break;
        }
        if (ret < 0) {
            RPC_LOG_ERROR("io error ret = %d errno = %d.", ret, errno);
            break;
        }
    }
}

static int32_t IpcSetMaxWorkThread(int32_t maxThreadNum)
{
    if (g_connector == NULL) {
        RPC_LOG_ERROR("ipc driver not init");
        return ERR_FAILED;
    }
    int32_t ret = ioctl(g_connector->fd, BINDER_SET_MAX_THREADS, &maxThreadNum);
    return ret;
}

static int32_t IpcSetRegistryObject(SvcIdentity target, SvcIdentity *samgr)
{
    if (g_connector == NULL) {
        RPC_LOG_ERROR("ipc driver not init");
        return ERR_FAILED;
    }
    int32_t ret = ioctl(g_connector->fd, BINDER_SET_CONTEXT_MGR, 0);
    if (ret == ERR_NONE) {
        samgr->handle = -1;
        samgr->cookie = target.cookie;
        RPC_LOG_INFO("set samgr success!!");
        return ERR_NONE;
    }
    RPC_LOG_ERROR("set samgr failed");
    return ERR_FAILED;
}

static int32_t InternalRequest(SvcIdentity sid, uint32_t code, IpcIo *data, IpcIo *reply, uint32_t flags)
{
    RPC_LOG_INFO("Internal ipc request called");
    IpcObjectStub *objectStub = (IpcObjectStub *)(sid.cookie);
    if (objectStub == NULL) {
        RPC_LOG_INFO("ipc object stub is null");
        return ERR_INVALID_PARAM;
    }
    if (data != NULL && data->flag == IPC_IO_INITIALIZED) {
        data->bufferLeft = data->bufferCur - data->bufferBase;
        data->offsetsLeft = ((char*)data->offsetsCur - (char*)data->offsetsBase) / sizeof(size_t);
        data->bufferCur = data->bufferBase;
        data->offsetsCur = data->offsetsBase;
    }
    if (flags == TF_OP_SYNC && reply != NULL) {
        uint8 tempData[MAX_IO_SIZE];
        IpcIoInit(reply, tempData, MAX_IO_SIZE, MAX_OBJ_NUM);
    }
    MessageOption option = {
        .flags = flags,
        .args = objectStub->args
    };
    int32_t error = OnRemoteRequestInner(code, data, reply, option, objectStub);
    if (flags == TF_OP_SYNC && reply != NULL) {
        reply->bufferLeft = reply->bufferCur - reply->bufferBase;
        reply->offsetsLeft = ((char*)reply->offsetsCur - (char*)reply->offsetsBase) / sizeof(size_t);
        reply->bufferCur = reply->bufferBase;
        reply->offsetsCur = reply->offsetsBase;
    }
    return error;
}

static int32_t IpcSendRequest(SvcIdentity target, uint32_t code, IpcIo *data, IpcIo *reply,
    MessageOption option, uintptr_t *buffer)
{
    if (g_connector == NULL) {
        return ERR_FAILED;
    }
    if (target.handle < 0) {
        if (buffer != NULL) {
            *buffer = 0;
        }
        return InternalRequest(target, code, data, reply, option.flags);
    }
    int32_t ret;
    struct TransactData buf;
    buf.cmd = BC_TRANSACTION;
    ToTransData(target.handle, code, option.flags, data, &buf);
    struct binder_write_read bwr = {.write_size = sizeof(buf), .write_consumed = 0, .write_buffer = (uintptr_t)&buf};
    uint32_t readbuf[READ_BUFFER_SIZE] = {0};
    if (option.flags != TF_OP_ASYNC) {
        while (1) {
            bwr.read_size = sizeof(readbuf);
            bwr.read_consumed = 0;
            bwr.read_buffer = (uintptr_t)readbuf;
            if (ioctl(g_connector->fd, BINDER_WRITE_READ, &bwr) < ERR_NONE) {
                RPC_LOG_ERROR("ipc send request ioctl failed.");
                return IPC_INVOKER_IOCTL_FAILED;
            }
            ret = BinderParse(reply, (uintptr_t)readbuf, bwr.read_consumed, buffer);
            if (ret == 0) {
                break;
            }
            if (ret < 0) {
                RPC_LOG_ERROR("ipc send request failed res = %d.", ret);
                break;
            }
        }
    } else {
        if (buffer != NULL) {
            *buffer = 0;
        }
        bwr.read_size = sizeof(readbuf);
        bwr.read_consumed = 0;
        bwr.read_buffer = (uintptr_t)readbuf;
        if (ioctl(g_connector->fd, BINDER_WRITE_READ, &bwr) < ERR_NONE) {
            RPC_LOG_ERROR("ipc send request ioctl failed.");
            return IPC_INVOKER_IOCTL_FAILED;
        }
        ret = BinderParse(reply, (uintptr_t)readbuf, bwr.read_consumed, NULL);
        ret = (ret == 1) ? 0 : ret;
    }
    return ret;
}

static int32_t IpcAddDeathRecipient(int32_t handle, void *cookie)
{
    struct {
        uint32_t cmd;
        struct binder_handle_cookie payload;
    } __attribute__((packed)) data;
    data.cmd = BC_REQUEST_DEATH_NOTIFICATION;
    data.payload.handle = handle;
    data.payload.cookie = (binder_uintptr_t)cookie;
    return BinderWrite(&data, sizeof(data));
}

static int32_t IpcRemoveDeathRecipient(int32_t handle, void *cookie)
{
    struct {
        uint32_t cmd;
        struct binder_handle_cookie payload;
    } __attribute__((packed)) data;

    data.cmd = BC_CLEAR_DEATH_NOTIFICATION;
    data.payload.handle = handle;
    data.payload.cookie = (binder_uintptr_t)cookie;
    return BinderWrite(&data, sizeof(data));
}

static void IpcExitCurrentThread(void)
{
    ioctl(g_connector->fd, BINDER_THREAD_EXIT, 0);
}

static void InvokerResetIpc(void) {}

static BinderConnector *InitBinderConnector(void)
{
    if (g_connector == NULL) {
        if (pthread_mutex_lock(&g_connectorMutex) != 0) {
            RPC_LOG_ERROR("init binder connector lock failed.");
            return NULL;
        }
        if (g_connector == NULL) {
            BinderConnector *temp = OpenDriver();
            if (temp == NULL) {
                pthread_mutex_unlock(&g_connectorMutex);
                RPC_LOG_ERROR("create binder connector  failed.");
                return NULL;
            }
            g_connector = temp;
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
    if (InitBinderConnector() == NULL) {
        RPC_LOG_ERROR("init binder invoker failed.");
        return NULL;
    }
    return &g_ipcInvoker;
}

void DeinitIpcInvoker(RemoteInvoker *invoker)
{
    if (invoker != &g_ipcInvoker) {
        return;
    }
    DeleteBinderConnector();
}