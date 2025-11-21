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

#include "ipc_proxy_inner.h"

#include <securec.h>
#include <stddef.h>
#include <string.h>

#include "dbinder_invoker.h"
#include "dbinder_types.h"
#include "dbinder_service_inner.h"
#include "ipc_thread_pool.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "rpc_process_skeleton.h"

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

static int32_t MakeInvokerListenReply(ProxyObject *proxyObject, uint64_t stubIndex, IpcIo *reply, uintptr_t *ptr)
{
    ptr = (uintptr_t *)calloc(1, RPC_IPC_LENGTH);
    if (ptr == NULL) {
        RPC_LOG_ERROR("InvokerListenThread ptr calloc failed");
        return ERR_FAILED;
    }
    IpcIoInit(reply, (void *)ptr, RPC_IPC_LENGTH, 0);

    if (!WriteUint64(reply, stubIndex)) {
        RPC_LOG_ERROR("InvokerListenThread WriteUint64 failed");
        free((void *)ptr);
        return ERR_FAILED;
    }
    if (!WriteString(reply, proxyObject->sessionName)) {
        RPC_LOG_ERROR("InvokerListenThread WriteString failed");
        free((void *)ptr);
        return ERR_FAILED;
    }
    ((IpcIo *)reply)->bufferCur = ((IpcIo *)reply)->bufferBase;
    return ERR_NONE;
}

int32_t InvokerListenThread(ProxyObject *proxyObject, const char *localDeviceID, const char *remoteDeviceID,
    uint32_t pid, uint32_t uid, IpcIo *reply, uintptr_t *ptr)
{
    if (proxyObject == NULL) {
        RPC_LOG_ERROR("InvokerListenThread proxy is null");
        return ERR_FAILED;
    }
    int32_t sessionNameLen = strlen(proxyObject->sessionName);

    RpcSkeleton *current = GetCurrentRpcSkeleton();
    if (current == NULL) {
        RPC_LOG_ERROR("GetCurrentSkeleton failed");
        return ERR_FAILED;
    }
    if (CreateTransServer(proxyObject->sessionName) != ERR_NONE) {
        return ERR_FAILED;
    }

    if (current->sessionName != NULL) {
        free(current->sessionName);
        current->sessionName = NULL;
    }
    if (sessionNameLen == 0 || sessionNameLen > SERVICENAME_LENGTH) {
        RPC_LOG_ERROR("sessionNameLen invalid");
        return ERR_FAILED;
    }
    current->sessionName = (char *)malloc(sessionNameLen + 1);
    if (current->sessionName == NULL) {
        return ERR_FAILED;
    }
    if (strcpy_s(current->sessionName, sessionNameLen + 1, proxyObject->sessionName) != EOK) {
        free(current->sessionName);
        return ERR_FAILED;
    }

    StubObject *stubObject = (StubObject *)malloc(sizeof(StubObject));
    if (stubObject == NULL) {
        return ERR_FAILED;
    }
    uint64_t stubIndex = GetNewStubIndex();
    stubObject->stubIndex = stubIndex;
    IpcObjectStub *cookie = (IpcObjectStub *)(proxyObject->proxy->cookie);
    stubObject->func = cookie->func;
    if (AddStubByIndex(stubObject) != ERR_NONE) {
        free(stubObject);
        return ERR_FAILED;
    }

    return MakeInvokerListenReply(proxyObject, stubIndex, reply, ptr);
}

int32_t GetPidAndUidInfo(ProxyObject *proxyObject)
{
    if (proxyObject == NULL) {
        RPC_LOG_ERROR("GetPidAndUidInfo proxy is null");
        return ERR_FAILED;
    }

    int32_t pid = (int32_t)GetCallingPid();
    int32_t pidLen = GetDigits(pid);
    int32_t uid = (int32_t)GetCallingUid();
    int32_t uidLen = GetDigits(uid);

    uint32_t sessionNameLen = SESSION_NAME_LEGNTH + pidLen + uidLen;
    proxyObject->sessionName = (char *)malloc(sessionNameLen + 1);
    if (proxyObject->sessionName == NULL) {
        RPC_LOG_ERROR("sessionName mallo failed");
        return ERR_FAILED;
    }
    if (sprintf_s(proxyObject->sessionName, sessionNameLen + 1, "DBinder%d_%d", uid, pid) == -1) {
        RPC_LOG_ERROR("sessionName sprintf failed");
        free(proxyObject->sessionName);
        return ERR_FAILED;
    }

    return ERR_NONE;
}

char *GetDataBusName(void)
{
    return NULL;
}

static int GetSessionFromDBinderService(SvcIdentity *svc)
{
    RPC_LOG_INFO("GetSessionFromDBinderService start");

    int32_t proto = IF_PROT_DATABUS;
    SessionInfo *session = QuerySessionObject(svc->cookie);
    if (session == NULL) {
        RPC_LOG_ERROR("client find session is null");
        return proto;
    }

    HandleSessionList *sessionObject = (HandleSessionList *)malloc(sizeof(HandleSessionList));
    if (sessionObject == NULL) {
        RPC_LOG_ERROR("UpdateDatabusClientSession sessionObject malloc failed");
        return proto;
    }

    HandleToIndexList *handleToIndex = (HandleToIndexList *)malloc(sizeof(HandleToIndexList));
    if (handleToIndex == NULL) {
        RPC_LOG_ERROR("UpdateDatabusClientSession handleToIndex malloc failed");
        free(sessionObject);
        return proto;
    }
    handleToIndex->handle = svc->handle;
    handleToIndex->index = session->stubIndex;

    if (AttachHandleToIndex(handleToIndex) != ERR_NONE) {
        RPC_LOG_ERROR("AttachHandleToIndex failed");
        free(sessionObject);
        free(handleToIndex);
        return proto;
    }

    if (CreateTransServer(session->serviceName) != ERR_NONE) {
        RPC_LOG_ERROR("create bus server fail name = %s, localID = %s",
            session->serviceName, session->deviceIdInfo.fromDeviceId);
        DetachHandleToIndex(handleToIndex);
        free(sessionObject);
        free(handleToIndex);
        return proto;
    }

    UpdateClientSession(svc->handle, sessionObject, session->serviceName, session->deviceIdInfo.toDeviceId);
    return proto;
}

void UpdateProto(SvcIdentity *svc)
{
    if (svc->handle < 0) {
        RPC_LOG_ERROR("UpdateProto handle invalid");
        return;
    }

    ThreadContext *threadContext = GetCurrentThreadContext();
    if (threadContext == NULL) {
        RPC_LOG_ERROR("UpdateProto threadContext is null");
        return;
    }
    HandleSessionList *sessionObject = QueryProxySession(svc->handle);
    if (sessionObject != NULL) {
        threadContext->proto = IF_PROT_DATABUS;
        return;
    }
    threadContext->proto = GetSessionFromDBinderService(svc);
    RPC_LOG_INFO("UpdateProto get proto: %d", threadContext->proto);
}