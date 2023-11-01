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

#include "dbinder_invoker.h"
#include "dbinder_types.h"
#include "ipc_process_skeleton.h"
#include "ipc_thread_pool.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "rpc_process_skeleton.h"
#include "securec.h"
#include "serializer.h"

static void UpdateDatabusClientSession(int32_t handle, IpcIo *reply)
{
    uint64_t stubIndex;
    if (!ReadUint64(reply, &stubIndex)) {
        return;
    }

    size_t len;
    char *serviceName = (char *)ReadString(reply, &len);
    char *peerID = (char *)ReadString(reply, &len);
    char *localID = (char *)ReadString(reply, &len);
    char *localBusName = (char *)ReadString(reply, &len);

    HandleSessionList *sessionObject = (HandleSessionList *)calloc(1, sizeof(HandleSessionList));
    if (sessionObject == NULL) {
        RPC_LOG_ERROR("UpdateDatabusClientSession sessionObject malloc failed");
        return;
    }

    HandleToIndexList *handleToIndex = (HandleToIndexList *)malloc(sizeof(HandleToIndexList));
    if (handleToIndex == NULL) {
        RPC_LOG_ERROR("UpdateDatabusClientSession handleToIndex malloc failed");
        free(sessionObject);
        return;
    }
    handleToIndex->handle = handle;
    handleToIndex->index = stubIndex;

    if (AttachHandleToIndex(handleToIndex) != ERR_NONE) {
        RPC_LOG_ERROR("AttachHandleToIndex failed");
        free(sessionObject);
        free(handleToIndex);
        return;
    }

    if (CreateTransServer(localBusName) != ERR_NONE) {
        RPC_LOG_ERROR("create bus server fail name = %s, localID = %s", localBusName, localID);
        DetachHandleToIndex(handleToIndex);
        free(sessionObject);
        free(handleToIndex);
        return;
    }

    UpdateClientSession(handle, sessionObject, serviceName, peerID);
}

static int GetSessionFromDBinderService(uint32_t handle)
{
    RPC_LOG_INFO("GetSessionFromDBinderService start");
    IpcIo data;
    IpcIo reply;
    uint8_t dataAlloc[RPC_IPC_LENGTH_LONG];
    IpcIoInit(&data, dataAlloc, RPC_IPC_LENGTH_LONG, 0);
    MessageOption option = {
        .flags = TF_OP_SYNC
    };
    SvcIdentity target = {
        .handle = handle
    };
    uintptr_t ptr;
    int32_t ret = ProcessSendRequest(target, GET_PROTO_INFO, &data, &reply, option, &ptr);
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("sendrequest GET_PROTO_INFO failed, error %d", ret);
        FreeBuffer((void *)ptr);
        return IF_PROT_BINDER;
    }
    uint32_t proto;
    if (!ReadUint32(&reply, &proto)) {
        FreeBuffer((void *)ptr);
        return IF_PROT_BINDER;
    }

    switch (proto) {
        case IF_PROT_DATABUS: {
            UpdateDatabusClientSession(handle, &reply);
            break;
        }
        default: {
            proto = IF_PROT_BINDER;
            break;
        }
    }

    FreeBuffer((void *)ptr);
    return proto;
}

int32_t InvokerListenThread(ProxyObject *proxyObject, const char *localDeviceID, const char *remoteDeviceID,
    uint32_t pid, uint32_t uid, IpcIo *reply, uintptr_t *ptr)
{
    if (proxyObject == NULL || localDeviceID == NULL || remoteDeviceID == NULL) {
        return ERR_FAILED;
    }

    IpcIo *ipcReply = (IpcIo *)reply;

    IpcIo data;
    uint8_t dataAlloc[RPC_IPC_LENGTH_LONG];
    IpcIoInit(&data, dataAlloc, RPC_IPC_LENGTH_LONG, 0);
    WriteUint16(&data, DATABUS_TYPE);
    WriteString(&data, localDeviceID);
    WriteUint32(&data, pid);
    WriteUint32(&data, uid);
    WriteString(&data, remoteDeviceID);
    WriteString(&data, proxyObject->sessionName);
    MessageOption option = {
        .flags = TF_OP_SYNC
    };

    int32_t ret = SendRequest(*proxyObject->proxy, INVOKE_LISTEN_THREAD, &data, ipcReply, option, ptr);
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("INVOKE_LISTEN_THREAD failed");
    }
    return ret;
}

int32_t GetPidAndUidInfo(ProxyObject *proxyObject)
{
    if (proxyObject == NULL) {
        RPC_LOG_ERROR("GetPidAndUidInfo proxy is null");
        return ERR_FAILED;
    }

    IpcIo data;
    IpcIo reply;
    uint8_t dataAlloc[RPC_IPC_LENGTH];
    IpcIoInit(&data, dataAlloc, RPC_IPC_LENGTH, 0);
    MessageOption option = {
        .flags = TF_OP_SYNC
    };
    uintptr_t ptr;

    int32_t ret = SendRequest(*proxyObject->proxy, GET_UIDPID_INFO, &data, &reply, option, &ptr);
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("sendrequest GET_UIDPID_INFO failed, error %d", ret);
        FreeBuffer((void *)ptr);
        return ERR_FAILED;
    }

    size_t len;
    char *sessionName = (char *)ReadString(&reply, &len);

    proxyObject->sessionName = (char *)malloc(len + 1);
    if (proxyObject->sessionName == NULL) {
        RPC_LOG_ERROR("GetPidAndUidInfo proxy name malloc failed");
        FreeBuffer((void *)ptr);
        return ERR_FAILED;
    }
    if (strcpy_s(proxyObject->sessionName, len + 1, sessionName) != 0) {
        RPC_LOG_ERROR("GetPidAndUidInfo proxy name copy failed");
        free(proxyObject->sessionName);
        FreeBuffer((void *)ptr);
        return ERR_FAILED;
    }

    FreeBuffer((void *)ptr);
    return ERR_NONE;
}

char *GetDataBusName(void)
{
    IpcIo data;
    IpcIo reply;
    uint8_t dataAlloc[RPC_IPC_LENGTH];
    IpcIoInit(&data, dataAlloc, RPC_IPC_LENGTH, 0);
    MessageOption option = {
        .flags = TF_OP_SYNC
    };
    uintptr_t ptr;
    int32_t ret = ProcessSendRequest(*GetContextObject(), GRANT_DATABUS_NAME, &data, &reply, option, &ptr);
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("sendrequest GRANT_DATABUS_NAME failed, error %d", ret);
        FreeBuffer((void *)ptr);
        return NULL;
    }

    int32_t proto;
    if (!ReadInt32(&reply, &proto)) {
        FreeBuffer((void *)ptr);
        return NULL;
    }

    if (proto != IF_PROT_DATABUS) {
        RPC_LOG_INFO("GetDataBusName normal binder");
        FreeBuffer((void *)ptr);
        return NULL;
    }
    size_t len;
    const char *name = (const char *)ReadString(&reply, &len);
    RPC_LOG_INFO("GetDataBusName name %s, len %d", name, len);
    char *sessionName = (char *)malloc(len + 1);
    if (sessionName == NULL) {
        RPC_LOG_ERROR("GetDataBusName sessionName malloc failed");
        FreeBuffer((void *)ptr);
        return NULL;
    }
    if (strcpy_s(sessionName, len + 1, name) != EOK) {
        RPC_LOG_ERROR("GetDataBusName sessionName copy failed");
        free(sessionName);
        FreeBuffer((void *)ptr);
        return NULL;
    }

    FreeBuffer((void *)ptr);
    return sessionName;
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
    threadContext->proto = GetSessionFromDBinderService(svc->handle);
    RPC_LOG_INFO("UpdateProto get proto: %d", threadContext->proto);
}