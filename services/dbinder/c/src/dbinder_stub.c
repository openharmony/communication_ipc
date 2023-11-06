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

#include "dbinder_stub.h"

#include <stdbool.h>

#include "dbinder_service_inner.h"
#include "ipc_process_skeleton.h"
#include "ipc_skeleton.h"
#include "ipc_thread_pool.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "securec.h"

#define IPC_INVALID_HANDLE (-1)

static int32_t GetDigits(int32_t number)
{
    int32_t n = 0;
    while (number > 0) {
        n++;
        number /= ID_DIGITS;
    }
    if (n == 0) {
        n++;
    }
    return n;
}

static char *CreateDatabusName(void)
{
    int32_t pid = (int32_t)GetCallingPid();
    int32_t pidLen = GetDigits(pid);
    int32_t uid = (int32_t)GetCallingUid();
    int32_t uidLen = GetDigits(uid);

    uint32_t sessionNameLen = SESSION_NAME_LEGNTH + pidLen + uidLen;
    char *sessionName = (char *)malloc(sessionNameLen + 1);
    if (sessionName == NULL) {
        RPC_LOG_ERROR("sessionName mallo failed");
        return NULL;
    }
    if (sprintf_s(sessionName, sessionNameLen + 1, "DBinder%d_%d", uid, pid) == -1) {
        RPC_LOG_ERROR("sessionName sprintf failed");
        free(sessionName);
        return NULL;
    }
    return sessionName;
}

static int32_t ProcessProto(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption *option)
{
    int32_t result = ERR_NONE;
    ThreadContext *threadContext = GetCurrentThreadContext();
    if (threadContext == NULL) {
        RPC_LOG_ERROR("ProcessProto threadContext is null");
        return ERR_FAILED;
    }

    SessionInfo *session = QuerySessionObject((uintptr_t)threadContext->objectStub);
    if (session == NULL) {
        RPC_LOG_ERROR("client find session is null");
        return ERR_FAILED;
    }
    const char *localBusName = CreateDatabusName();
    if (localBusName == NULL) {
        RPC_LOG_ERROR("ProcessProto CreateDatabusName failed");
        return ERR_FAILED;
    }

    switch (session->type) {
        case DATABUS_TYPE: {
            WriteUint32(reply, IF_PROT_DATABUS);
            WriteUint64(reply, session->stubIndex);
            WriteString(reply, session->serviceName);
            WriteString(reply, session->deviceIdInfo.toDeviceId);
            WriteString(reply, session->deviceIdInfo.fromDeviceId);
            WriteString(reply, localBusName);
            break;
        }
        default: {
            result = ERR_FAILED;
            break;
        }
    }
    free((void *)localBusName);
    return result;
}

static int32_t DBinderRemoteRequest(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption *option)
{
    int32_t ret = -1;
    switch (code) {
        case GET_PROTO_INFO: {
            ret = ProcessProto(code, data, reply, option);
            break;
        }
        default: {
            RPC_LOG_ERROR("unknown dbinder code %u", code);
            break;
        }
    }
    return ret;
}

int32_t GetDBinderStub(const char *serviceName, const char *deviceID,
    uintptr_t binderObject, DBinderServiceStub *dBinderServiceStub)
{
    if (strcpy_s(dBinderServiceStub->serviceName, SERVICENAME_LENGTH + 1, serviceName) != EOK
        || strcpy_s(dBinderServiceStub->deviceID, DEVICEID_LENGTH + 1, deviceID) != EOK) {
        RPC_LOG_ERROR("dBinderServiceStub string copy failed");
        return ERR_FAILED;
    }

    IpcObjectStub *objectStub = (IpcObjectStub *)malloc(sizeof(IpcObjectStub));
    if (objectStub == NULL) {
        RPC_LOG_ERROR("objectStub malloc failed");
        return ERR_FAILED;
    }
    objectStub->func = (OnRemoteRequest)DBinderRemoteRequest;
    objectStub->isRemote = true;

    dBinderServiceStub->binderObject = binderObject;
    dBinderServiceStub->svc.handle = IPC_INVALID_HANDLE;
    dBinderServiceStub->svc.token = (uintptr_t)objectStub;
    dBinderServiceStub->svc.cookie = (uintptr_t)objectStub;
    return ERR_NONE;
}
