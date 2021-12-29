/*
 * Copyright (c) 2020 Huawei Device Co., Ltd.
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
#include "securec.h"
#include <stdlib.h>
#include <string.h>
#ifndef __LITEOS_M__
#include "sys_binder.h"
#endif
#include "rpc_log.h"
#include "ipc_process_skeleton.h"

#define MAX_IO_SIZE 8192UL
#define MAX_OBJ_NUM 32UL
#define MAX_DATA_BUFF_SIZE 65536UL

#define ALIGN_SZ 4
#define IPC_IO_ALIGN(sz) (((sz) + ALIGN_SZ - 1) & (~(ALIGN_SZ - 1)))

#define IPC_IO_RETURN_IF_FAIL(value)                                             \
    do {                                                                         \
        if (!(value)) {                                                          \
            printf("IPC_ASSERT failed: %s:%d\n", __FUNCTION__, __LINE__); \
            if (io != NULL) {                                                    \
                io->flag |= IPC_IO_OVERFLOW;                                     \
            }                                                                    \
            return NULL;                                                         \
        }                                                                        \
    } while (0)

static void* IoPop(IpcIo* io, size_t size);

void IpcIoInit(IpcIo* io, void* buffer, size_t bufferSize, size_t maxobjects)
{
    if ((io == NULL) || (buffer == NULL) || (bufferSize == 0) || (bufferSize > MAX_IO_SIZE) || (maxobjects > MAX_OBJ_NUM)) {
        return;
    }
    size_t objectsSize = maxobjects * sizeof(size_t);

    if (objectsSize > bufferSize) {
        io->flag = IPC_IO_OVERFLOW;
        io->bufferLeft = 0;
        io->offsetsLeft = 0;
        return;
    }

    io->bufferCur = io->bufferBase = (char*)buffer + objectsSize;
    io->offsetsCur = io->offsetsBase = (size_t*)buffer;
    io->bufferLeft = bufferSize - objectsSize;
    io->offsetsLeft = maxobjects;
    io->flag = IPC_IO_INITIALIZED;
}

bool IpcIoAvailable(IpcIo* io)
{
    bool ret = false;
    if (io != NULL) {
        ret = (io->flag & IPC_IO_INITIALIZED) && !(io->flag & IPC_IO_OVERFLOW);
    }
    return ret;
}

static void* IoPush(IpcIo* io, size_t size)
{
    IPC_IO_RETURN_IF_FAIL(io != NULL);
    IPC_IO_RETURN_IF_FAIL(IpcIoAvailable(io));
    size = IPC_IO_ALIGN(size);
    if (size > io->bufferLeft) {
        io->flag |= IPC_IO_OVERFLOW;
        RPC_LOG_ERROR("IoPush IPC_IO_OVERFLOW.");
        return NULL;
    } else {
        void* ptr = io->bufferCur;
        io->bufferCur += size;
        io->bufferLeft -= size;
        return ptr;
    }
}

static void* IoPushUnaligned(IpcIo* io, size_t size)
{
    IPC_IO_RETURN_IF_FAIL(io != NULL);
    IPC_IO_RETURN_IF_FAIL(IpcIoAvailable(io));
    if (size > io->bufferLeft) {
        io->flag |= IPC_IO_OVERFLOW;
        return NULL;
    } else {
        void* ptr = io->bufferCur;
        io->bufferCur += size;
        io->bufferLeft -= size;
        return ptr;
    }
}

void IpcIoPushInt32(IpcIo* io, int32_t n)
{
    int32_t* ptr = (int32_t*)IoPush(io, sizeof(n));
    if (ptr != NULL) {
        *ptr = n;
    }
}

void IpcIoPushUint32(IpcIo* io, uint32_t n)
{
    uint32_t* ptr = (uint32_t*)IoPush(io, sizeof(n));
    if (ptr != NULL) {
        *ptr = n;
    }
}

void IpcIoPushChar(IpcIo* io, char c)
{
    IpcIoPushInt32(io, (int32_t)c);
}

void IpcIoPushCharUnaligned(IpcIo* io, char c)
{
    char* ptr = (char*)IoPushUnaligned(io, sizeof(c));
    if (ptr != NULL) {
        *ptr = c;
    }
}

void IpcIoPushBool(IpcIo* io, bool b)
{
    IpcIoPushInt32(io, (int32_t)b);
}

void IpcIoPushBoolUnaligned(IpcIo* io, bool b)
{
    bool* ptr = (bool*)IoPushUnaligned(io, sizeof(b));
    if (ptr != NULL) {
        *ptr = b;
    }
}

void IpcIoPushIntptr(IpcIo* io, intptr_t intptr)
{
    intptr_t* ptr = (intptr_t*)IoPush(io, sizeof(intptr));
    if (ptr != NULL) {
        *ptr = intptr;
    }
}

void IpcIoPushUintptr(IpcIo* io, uintptr_t uintptr)
{
    uintptr_t* ptr = (uintptr_t*)IoPush(io, sizeof(uintptr));
    if (ptr != NULL) {
        *ptr = uintptr;
    }
}

void IpcIoPushInt8(IpcIo* io, int8_t n)
{
    IpcIoPushInt32(io, (int32_t)n);
}

void IpcIoPushInt8Unaligned(IpcIo* io, int8_t n)
{
    int8_t* ptr = (int8_t*)IoPushUnaligned(io, sizeof(n));
    if (ptr != NULL) {
        *ptr = n;
    }
}

void IpcIoPushUint8(IpcIo* io, uint8_t n)
{
    IpcIoPushUint32(io, (uint32_t)n);
}

void IpcIoPushUint8Unaligned(IpcIo* io, uint8_t n)
{
    uint8_t* ptr = (uint8_t*)IoPushUnaligned(io, sizeof(n));
    if (ptr != NULL) {
        *ptr = n;
    }
}

void IpcIoPushInt16(IpcIo* io, int16_t n)
{
    IpcIoPushInt32(io, (int32_t)n);
}

void IpcIoPushInt16Unaligned(IpcIo* io, int16_t n)
{
    int16_t* ptr = (int16_t*)IoPushUnaligned(io, sizeof(n));
    if (ptr != NULL) {
        *ptr = n;
    }
}

void IpcIoPushUint16(IpcIo* io, uint16_t n)
{
    IpcIoPushUint32(io, (uint32_t)n);
}

void IpcIoPushUint16Unaligned(IpcIo* io, uint16_t n)
{
    uint16_t* ptr = (uint16_t*)IoPushUnaligned(io, sizeof(n));
    if (ptr != NULL) {
        *ptr = n;
    }
}

void IpcIoPushInt64(IpcIo* io, int64_t n)
{
    int64_t* ptr = (int64_t*)IoPush(io, sizeof(n));
    if (ptr != NULL) {
        *ptr = n;
    }
}

void IpcIoPushUint64(IpcIo* io, uint64_t n)
{
    uint64_t* ptr = (uint64_t*)IoPush(io, sizeof(n));
    if (ptr != NULL) {
        *ptr = n;
    }
}

void IpcIoPushFloat(IpcIo* io, float n)
{
    float* ptr = (float*)IoPush(io, sizeof(n));
    if (ptr != NULL) {
        *ptr = n;
    }
}

void IpcIoPushDouble(IpcIo* io, double n)
{
    double* ptr = (double*)IoPush(io, sizeof(n));
    if (ptr != NULL) {
        *ptr = n;
    }
}

void IpcIoPushString(IpcIo* io, const char* cstr)
{
    unsigned char* str = (unsigned char*)cstr;
    size_t len;
    uint8_t* ptr = NULL;

    if (io == NULL) {
        return;
    }
    if (str == NULL) {
        io->flag |= IPC_IO_OVERFLOW;
        return;
    }

    len = strlen(cstr);
    if (len == MAX_IO_SIZE) {
        io->flag |= IPC_IO_OVERFLOW;
        return;
    }

    /* Note: The payload will carry 32bit size instead of size_t */
    IpcIoPushUint32(io, (uint32_t)len);
    ptr = (uint8_t*)IoPush(io, len + 1);
    if (ptr != NULL) {
        if (memset_s(ptr, IPC_IO_ALIGN(len + 1), 0, IPC_IO_ALIGN(len + 1)) != EOK) {
            io->flag |= IPC_IO_OVERFLOW;
            return;
        }
        if (memcpy_s(ptr, IPC_IO_ALIGN(len + 1), str, len + 1) != EOK) {
            io->flag |= IPC_IO_OVERFLOW;
        }
    }
}

static void* IoPop(IpcIo* io, size_t size)
{
    IPC_IO_RETURN_IF_FAIL(io != NULL);
    IPC_IO_RETURN_IF_FAIL(IpcIoAvailable(io));
    size = IPC_IO_ALIGN(size);

    if (io->bufferLeft < size) {
        io->bufferLeft = 0;
        io->flag |= IPC_IO_OVERFLOW;
        return NULL;
    } else {
        void* ptr = io->bufferCur;
        io->bufferCur += size;
        io->bufferLeft -= size;
        return ptr;
    }
}

static void* IoPopUnaligned(IpcIo* io, size_t size)
{
    IPC_IO_RETURN_IF_FAIL(io != NULL);
    IPC_IO_RETURN_IF_FAIL(IpcIoAvailable(io));

    if (io->bufferLeft < size) {
        io->bufferLeft = 0;
        io->flag |= IPC_IO_OVERFLOW;
        return NULL;
    } else {
        void* ptr = io->bufferCur;
        io->bufferCur += size;
        io->bufferLeft -= size;
        return ptr;
    }
}

char IpcIoPopChar(IpcIo* io)
{
    char* ptr = (char*)IoPop(io, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

char IpcIoPopCharUnaligned(IpcIo* io)
{
    char* ptr = (char*)IoPopUnaligned(io, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

bool IpcIoPopBool(IpcIo* io)
{
    bool* ptr = (bool*)IoPop(io, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

bool IpcIoPopBoolUnaligned(IpcIo* io)
{
    bool* ptr = (bool*)IoPopUnaligned(io, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

intptr_t IpcIoPopIntptr(IpcIo* io)
{
    intptr_t* ptr = (intptr_t*)IoPop(io, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

uintptr_t IpcIoPopUintptr(IpcIo* io)
{
    uintptr_t* ptr = (uintptr_t*)IoPop(io, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

int8_t IpcIoPopInt8(IpcIo* io)
{
    int8_t* ptr = (int8_t*)IoPop(io, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

int8_t IpcIoPopInt8Unaligned(IpcIo* io)
{
    int8_t* ptr = (int8_t*)IoPopUnaligned(io, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

uint8_t IpcIoPopUint8(IpcIo* io)
{
    uint8_t* ptr = (uint8_t*)IoPop(io, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

uint8_t IpcIoPopUint8Unaligned(IpcIo* io)
{
    uint8_t* ptr = (uint8_t*)IoPopUnaligned(io, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

int16_t IpcIoPopInt16(IpcIo* io)
{
    int16_t* ptr = (int16_t*)IoPop(io, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

int16_t IpcIoPopInt16Unaligned(IpcIo* io)
{
    int16_t* ptr = (int16_t*)IoPopUnaligned(io, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

uint16_t IpcIoPopUint16(IpcIo* io)
{
    uint16_t* ptr = (uint16_t*)IoPop(io, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

uint16_t IpcIoPopUint16Unaligned(IpcIo* io)
{
    uint16_t* ptr = (uint16_t*)IoPopUnaligned(io, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

int32_t IpcIoPopInt32(IpcIo* io)
{
    int32_t* ptr = (int32_t*)IoPop(io, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

uint32_t IpcIoPopUint32(IpcIo* io)
{
    uint32_t* ptr = (uint32_t*)IoPop(io, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

int64_t IpcIoPopInt64(IpcIo* io)
{
    int64_t* ptr = (int64_t*)IoPop(io, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

uint64_t IpcIoPopUint64(IpcIo* io)
{
    uint64_t* ptr = (uint64_t*)IoPop(io, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

float IpcIoPopFloat(IpcIo* io)
{
    float* ptr = (float*)IoPop(io, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

double IpcIoPopDouble(IpcIo* io)
{
    double* ptr = (double*)IoPop(io, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

uint8_t* IpcIoPopString(IpcIo* io, size_t* sz)
{
    size_t len;

    /* Note: The payload will carry 32bit size instead of size_t */
    len = (size_t)IpcIoPopUint32(io);
    if (sz != NULL) {
        *sz = len;
    }
    if (len > MAX_IO_SIZE) {
        return NULL;
    }
    return (uint8_t*)IoPop(io, len + 1);
}

void* IpcIoPopFlatObj(IpcIo* io, uint32_t* size)
{
    IPC_IO_RETURN_IF_FAIL(size != NULL);
    *size = (size_t)IpcIoPopUint32(io);
    if (*size > MAX_IO_SIZE) {
        return NULL;
    }
    return (void*)IoPop(io, *size);
}

void IpcIoPushFlatObj(IpcIo* io, const void* obj, uint32_t size)
{
    if (io == NULL) {
        return;
    }
    if ((obj == NULL) || (size == 0) || (size > MAX_IO_SIZE)) {
        io->flag |= IPC_IO_OVERFLOW;
        return;
    }
    IpcIoPushUint32(io, size);
    int32_t* ptr = (int32_t*)IoPush(io, size);
    if (ptr != NULL) {
        if (memcpy_s(ptr, size, obj, size) != EOK) {
            io->flag |= IPC_IO_OVERFLOW;
        }
    }
}

#ifndef __LITEOS_M__
static struct flat_binder_object* IoPushBinderObj(IpcIo* io)
{
    IPC_IO_RETURN_IF_FAIL(io != NULL);
    IPC_IO_RETURN_IF_FAIL(io->offsetsCur != NULL);
    struct flat_binder_object* ptr = NULL;
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

static bool IpcIoPushObject(IpcIo* io, uint32_t token, uint32_t cookie)
{
    struct flat_binder_object* ptr = IoPushBinderObj(io);
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

static bool IpcIoPushRef(IpcIo* io, uint32_t handle, uint32_t cookie)
{
    struct flat_binder_object* ptr = IoPushBinderObj(io);
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

struct flat_binder_object* IpcIoPopRef(IpcIo *io)
{
    IPC_IO_RETURN_IF_FAIL(io != NULL);
    IPC_IO_RETURN_IF_FAIL(io->offsetsCur != NULL);
    if (io->offsetsLeft == 0) {
        io->flag |= IPC_IO_OVERFLOW;
        return NULL;
    }
    struct flat_binder_object* obj = (struct flat_binder_object*)IoPop(io, sizeof(struct flat_binder_object));
    if (obj != NULL) {
        io->offsetsCur++;
        io->offsetsLeft--;
        return obj;
    }
    return NULL;
}

bool IpcIoPushSvc(IpcIo* io, const SvcIdentity* svc)
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

bool IpcIoPopSvc(IpcIo* io, SvcIdentity *svc)
{
    if (io == NULL || svc == NULL) {
        return false;
    }
    struct flat_binder_object* obj = IpcIoPopRef(io);
    if (obj == NULL) {
        RPC_LOG_ERROR("IpcIoPopSvc failed: obj is null");
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

bool IpcIoPushFd(IpcIo* io, uint32_t fd)
{
   if (io == NULL) {
        RPC_LOG_ERROR("push fd io is NULL.");
        return false;
    }
    struct flat_binder_object* ptr = IoPushBinderObj(io);
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

int32_t IpcIoPopFd(IpcIo* io)
{
    if (io == NULL) {
        return -1;
    }
    struct flat_binder_object* obj = IpcIoPopRef(io);
    if (obj == NULL) {
        RPC_LOG_ERROR("IpcIoPopFd failed: obj is null");
        return -1;
    }
    if (obj && obj->type == BINDER_TYPE_FD) {
        return obj->handle;
    }
    RPC_LOG_ERROR("IpcIoPopFd failed: type:%d", obj->type);
    return -1;
}
#else
bool IpcIoPushSvc(IpcIo* io, const SvcIdentity* svc)
{
    (void)io;
    (void)svc;
    return false;
}

bool IpcIoPushFd(IpcIo* io, uint32_t fd)
{
    (void)io;
    (void)fd;
    return false;
}

bool IpcIoPopSvc(IpcIo* io, SvcIdentity* svc)
{
    (void)io;
    (void)svc;
    return false;
}

int32_t IpcIoPopFd(IpcIo* io)
{
    (void)io;
    return -1;
}
#endif