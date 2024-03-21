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
#include "serializer_inner.h"

#include "ipc_process_skeleton.h"
#include "rpc_log.h"
#include "securec.h"
#include "sys_binder.h"

static struct flat_binder_object *IoPushBinderObj(IpcIo *io)
{
    if (io->offsetsCur == NULL) {
        RPC_LOG_ERROR("Io push object current is null.");
        return NULL;
    }
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

static bool IpcIoPushObject(IpcIo *io, uint32_t token, uintptr_t cookie)
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

static bool IpcIoPushRef(IpcIo *io, uint32_t handle, uintptr_t cookie)
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

static struct flat_binder_object *IpcIoPopRef(IpcIo *io)
{
    if (io->offsetsCur == NULL) {
        RPC_LOG_ERROR("Io push object current is null.");
        return NULL;
    }
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
        svc->handle = IPC_INVALID_HANDLE;
        svc->cookie = obj->cookie;
    } else {
        svc->handle = obj->handle;
        svc->cookie = obj->cookie;
        WaitForProxyInit(svc);
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
