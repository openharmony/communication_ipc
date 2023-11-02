/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <threads.h>
#include <pthread.h>
#include "ipc_skeleton.h"
#include "rpc_log.h"
#include "lite_ipc.h"
#include "serializer_inner.h"

#define IPC_IO_RETURN_IF_FAIL(value)                                             \
    do {                                                                         \
        if (!(value)) {                                                          \
            RPC_LOG_ERROR("IPC_ASSERT_ERR: [%s:%d]\n", __FUNCTION__, __LINE__);  \
            if (io != NULL) {                                                    \
                io->flag |= IPC_IO_OVERFLOW;                                     \
            }                                                                    \
            return NULL;                                                         \
        }                                                                        \
    } while (0)

thread_local uintptr_t g_objectStub = NULL;

uintptr_t GetObjectStub(uintptr_t cookie)
{
    if (cookie != NULL) {
        g_objectStub = cookie;
    }
    return g_objectStub;
}

static SpecialObj* IoPushSpecObj(IpcIo* io)
{
    IPC_IO_RETURN_IF_FAIL(io != NULL);
    IPC_IO_RETURN_IF_FAIL(io->offsetsCur != NULL);
    SpecialObj* ptr = IoPush(io, sizeof(SpecialObj));
    if ((ptr != NULL) && io->offsetsLeft) {
        io->offsetsLeft--;
        *(io->offsetsCur) = (char*)ptr - io->bufferBase;
        io->offsetsCur++;
        return ptr;
    } else {
        io->flag |= IPC_IO_OVERFLOW;
        return NULL;
    }
}

static SpecialObj* IoPopSpecObj(IpcIo* io)
{
    IPC_IO_RETURN_IF_FAIL(io != NULL);
    IPC_IO_RETURN_IF_FAIL(io->offsetsCur != NULL);
    if ((io->offsetsLeft == 0) || (*(io->offsetsCur) != io->bufferCur - io->bufferBase)) {
        goto ERROR;
    }

    SpecialObj* obj = IoPop(io, sizeof(SpecialObj));
    if (obj != NULL) {
        io->offsetsCur++;
        io->offsetsLeft--;
        return obj;
    }

ERROR:
    io->flag |= IPC_IO_OVERFLOW;
    return NULL;
}

static int32_t AddList(IpcObjectStub *stub, uint32_t *token, IpcCallback *ipcCallback)
{
    int32_t ret = -1;
    pthread_mutex_lock(&ipcCallback->mutex);
    static uint32_t index = 0;
    AnonymousApi *anonymousApi = (AnonymousApi *)malloc(sizeof(AnonymousApi));
    if (anonymousApi == NULL) {
        RPC_LOG_ERROR("anonymousApi malloc failed");
        pthread_mutex_unlock(&ipcCallback->mutex);
        return ret;
    }
    *token = index++;
    anonymousApi->token = *token;
    ret = memcpy_s((char *)&anonymousApi->hdlerPair, sizeof(IpcObjectStub), stub, sizeof(IpcObjectStub));
    if (ret == 0) {
        UtilsListAdd(&ipcCallback->apis, &anonymousApi->list);
        pthread_mutex_unlock(&ipcCallback->mutex);
        return ret;
    }
    RPC_LOG_ERROR("anonymousApi memcpy_s failed");
    free(anonymousApi);
    anonymousApi = NULL;
    pthread_mutex_unlock(&ipcCallback->mutex);
    return ret;
}

bool WriteRemoteObject(IpcIo *io, const SvcIdentity *svc)
{
    if (io == NULL) {
        return false;
    }
    if (svc == NULL) {
        io->flag |= IPC_IO_OVERFLOW;
        return false;
    }
    SpecialObj* ptr = IoPushSpecObj(io);
    if (ptr == NULL) {
        return false;
    }
    ptr->type = OBJ_SVC;
    ptr->content.svc.handle = svc->handle;
    ptr->content.svc.token = svc->token;
    ptr->content.svc.cookie = svc->cookie;
    if (ptr->content.svc.handle != IPC_INVALID_HANDLE) {
        return true;
    }
    IpcObjectStub *stub = (IpcObjectStub *)ptr->content.svc.cookie;
    if (ptr->content.svc.token == SERVICE_TYPE_NORMAL) {
        g_objectStub = stub;
    } else if (ptr->content.svc.token == SERVICE_TYPE_ANONYMOUS) {
        IpcCallback *ipcCallback = GetIpcCb();
        uint32_t token;
        int32_t ret = AddList(stub, &token, ipcCallback);
        if (ret != 0) {
            RPC_LOG_ERROR("Add list failed.");
            return false;
        }
        ptr->content.svc.token = token;
        if (!ipcCallback->threadWorking) {
            pthread_mutex_lock(&ipcCallback->mutex);
            ret = StartCallbackDispatch();
            if (ret < 0) {
                RPC_LOG_ERROR("WriteRemoteObject StartCallbackDispatch failed.");
                pthread_mutex_unlock(&ipcCallback->mutex);
                return false;
            }
            pthread_mutex_unlock(&ipcCallback->mutex);
        }
        ptr->content.svc.handle = GetThreadId();
    }
    return true;
}

bool ReadRemoteObject(IpcIo *io, SvcIdentity *svc)
{
    SpecialObj* ptr = IoPopSpecObj(io);
    if (ptr == NULL || ptr->type != OBJ_SVC) {
        return false;
    } else {
        *svc = ptr->content.svc;
        WaitForProxyInit(svc);
        return true;
    }
}

bool WriteFileDescriptor(IpcIo *io, uint32_t fd)
{
    SpecialObj* ptr = IoPushSpecObj(io);
    if (ptr != NULL) {
        ptr->type = OBJ_FD;
        ptr->content.fd = fd;
        return true;
    }
    return false;
}

int32_t ReadFileDescriptor(IpcIo *io)
{
    SpecialObj* ptr = IoPopSpecObj(io);
    if (ptr == NULL || ptr->type != OBJ_FD) {
        return -1;
    } else {
        return ptr->content.fd;
    }
}
