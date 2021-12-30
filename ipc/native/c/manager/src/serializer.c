/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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


#include "serializer.h"

#include <stdlib.h>
#include <string.h>
#ifdef __LINUX__
#include "sys_binder.h"
#endif
#include "ipc_process_skeleton.h"
#include "rpc_log.h"
#include "securec.h"

#define MAX_IO_SIZE 8192UL
#define MAX_OBJ_NUM 32UL

#define ALIGN_SZ 4
#define IPC_IO_ALIGN(sz) (((sz) + ALIGN_SZ - 1) & (~(ALIGN_SZ - 1)))

#define IPC_IO_RETURN_IF_FAIL(value)                                             \
    do {                                                                         \
        if (!(value)) {                                                          \
            printf("IPC_CHECK failed: %s:%d\n", __FUNCTION__, __LINE__);        \
            if (io != NULL) {                                                    \
                io->flag |= IPC_IO_OVERFLOW;                                     \
            }                                                                    \
            return NULL;                                                         \
        }                                                                        \
    } while (0)


void IpcIoInit(IpcIo *io, void *buffer, size_t bufferSize, size_t maxobjects)
{
    if ((io == NULL) || (buffer == NULL) || (bufferSize == 0) ||
        (bufferSize > MAX_IO_SIZE) || (maxobjects > MAX_OBJ_NUM)) {
        return;
    }
    size_t objectsSize = maxobjects * sizeof(size_t);

    if (objectsSize > bufferSize) {
        io->flag = IPC_IO_OVERFLOW;
        io->bufferLeft = 0;
        io->offsetsLeft = 0;
        return;
    }

    io->bufferCur = io->bufferBase = (char *)buffer + objectsSize;
    io->offsetsCur = io->offsetsBase = (size_t *)buffer;
    io->bufferLeft = bufferSize - objectsSize;
    io->offsetsLeft = maxobjects;
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

static void *IoPush(IpcIo *io, size_t size)
{
    IPC_IO_RETURN_IF_FAIL(io != NULL);
    IPC_IO_RETURN_IF_FAIL(IpcIoAvailable(io));
    size = IPC_IO_ALIGN(size);
    if (size > io->bufferLeft) {
        io->flag |= IPC_IO_OVERFLOW;
        RPC_LOG_ERROR("IoPush IPC_IO_OVERFLOW.");
        return NULL;
    } else {
        void *ptr = io->bufferCur;
        io->bufferCur += size;
        io->bufferLeft -= size;
        return ptr;
    }
}

static void *IoPop(IpcIo *io, size_t size)
{
    IPC_IO_RETURN_IF_FAIL(io != NULL);
    IPC_IO_RETURN_IF_FAIL(IpcIoAvailable(io));
    size = IPC_IO_ALIGN(size);

    if (io->bufferLeft < size) {
        io->bufferLeft = 0;
        io->flag |= IPC_IO_OVERFLOW;
        return NULL;
    } else {
        void *ptr = io->bufferCur;
        io->bufferCur += size;
        io->bufferLeft -= size;
        return ptr;
    }
}

#ifdef __LINUX__
static struct flat_binder_object *IoPushBinderObj(IpcIo *io)
{
    IPC_IO_RETURN_IF_FAIL(io != NULL);
    IPC_IO_RETURN_IF_FAIL(io->offsetsCur != NULL);
    struct flat_binder_object *ptr = NULL;
    ptr = IoPush(io, sizeof(struct flat_binder_object));
    if ((ptr != NULL) && io->offsetsLeft) {
        io->offsetsLeft--;
        *(io->offsetsCur) = (char*)ptr - (char*)io->bufferBase;
        io->offsetsCur++;
        return ptr;
    } else {
        io->flag |= IPC_IO_OVERFLOW;
        return NULL;
    }
}

static bool IpcIoPushObject(IpcIo *io, uint32_t token, uint32_t cookie)
{
    struct flat_binder_object *ptr = IoPushBinderObj(io);
    if (ptr == NULL) {
        RPC_LOG_ERROR("Io push object IPC_IO_OVERFLOW.");
        return false;
    }
    ptr->flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    ptr->type = BINDER_TYPE_BINDER;
    ptr->binder = (uintptr_t)cookie;
    ptr->cookie = cookie;
    return true;
}

static bool IpcIoPushRef(IpcIo *io, uint32_t handle, uint32_t cookie)
{
    struct flat_binder_object *ptr = IoPushBinderObj(io);
    if (ptr == NULL) {
        RPC_LOG_ERROR("Io push ref IPC_IO_OVERFLOW.");
        return false;
    }
    ptr->flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    ptr->type = BINDER_TYPE_HANDLE;
    ptr->handle = handle;
    ptr->cookie = cookie;
    return true;
}

struct flat_binder_object *IpcIoPopRef(IpcIo *io)
{
    IPC_IO_RETURN_IF_FAIL(io != NULL);
    IPC_IO_RETURN_IF_FAIL(io->offsetsCur != NULL);
    if (io->offsetsLeft == 0) {
        io->flag |= IPC_IO_OVERFLOW;
        return NULL;
    }
    struct flat_binder_object *obj = (struct flat_binder_object *)IoPop(io, sizeof(struct flat_binder_object));
    if (obj != NULL) {
        io->offsetsCur++;
        io->offsetsLeft--;
        return obj;
    }
    return NULL;
}

bool WriteRemoteObject(IpcIo *io, const SvcIdentity *svc)
{
    if (io == NULL || svc == NULL) {
        RPC_LOG_ERROR("push io or svc is NULL ...");
        return false;
    }
    bool res;
    if (svc->handle <= 0) {
        res = IpcIoPushObject(io, svc->token, svc->cookie);
    } else {
        res = IpcIoPushRef(io, svc->handle, svc->cookie);
    }
    return res;
}

bool ReadRemoteObject(IpcIo *io, SvcIdentity *svc)
{
    if (io == NULL || svc == NULL) {
        return false;
    }
    struct flat_binder_object *obj = IpcIoPopRef(io);
    if (obj == NULL) {
        RPC_LOG_ERROR("ReadRemoteObject failed: obj is null");
        return false;
    }
    if (obj->type == BINDER_TYPE_BINDER) {
        svc->token = obj->binder;
        svc->handle = MIN_BINDER_HANDLE;
        svc->cookie = obj->cookie;
    } else {
        WaitForProxyInit(obj->handle);
        svc->handle = obj->handle;
        svc->cookie = obj->cookie;
    }
    return true;
}

bool WriteFileDescriptor(IpcIo *io, uint32_t fd)
{
    if (io == NULL) {
        RPC_LOG_ERROR("push fd io is NULL.");
        return false;
    }
    struct flat_binder_object *ptr = IoPushBinderObj(io);
    if (ptr == NULL) {
        RPC_LOG_ERROR("Io push fd IPC_IO_OVERFLOW.\n");
        return false;
    }
    ptr->flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    ptr->type = BINDER_TYPE_FD;
    ptr->binder = 0;
    ptr->cookie = 1;
    ptr->handle = fd;
    return true;
}

int32_t ReadFileDescriptor(IpcIo *io)
{
    if (io == NULL) {
        return -1;
    }
    struct flat_binder_object *obj = IpcIoPopRef(io);
    if (obj == NULL) {
        RPC_LOG_ERROR("ReadFileDescriptor failed: obj is null");
        return -1;
    }
    if (obj->type == BINDER_TYPE_FD) {
        return obj->handle;
    }
    RPC_LOG_ERROR("ReadFileDescriptor failed: type:%d", obj->type);
    return -1;
}
#else
bool WriteRemoteObject(IpcIo *io, const SvcIdentity *svc)
{
    (void)io;
    (void)svc;
    return false;
}

bool WriteFileDescriptor(IpcIo *io, uint32_t fd)
{
    (void)io;
    (void)fd;
    return false;
}

bool ReadRemoteObject(IpcIo *io, SvcIdentity *svc)
{
    (void)io;
    (void)svc;
    return false;
}

int32_t ReadFileDescriptor(IpcIo *io)
{
    (void)io;
    return -1;
}
#endif