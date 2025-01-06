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

#include "dbinder_service.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#include "dbinder_ipc_adapter.h"
#include "dbinder_service_inner.h"
#include "dbinder_stub.h"
#include "dbinder_trans_callback.h"
#include "ipc_skeleton.h"
#include "ipc_proxy_inner.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "rpc_session_handle.h"
#include "rpc_trans.h"
#include "rpc_types.h"
#include "securec.h"
#include "serializer.h"
#include "utils_list.h"

typedef struct {
    UTILS_DL_LIST list;
    char *serviceName;
    uintptr_t binder;
} RemoteBinderObjects;

typedef struct {
    UTILS_DL_LIST remoteBinderObjects;
    pthread_mutex_t mutex;
} RemoteBinderObjectsList;

typedef struct {
    UTILS_DL_LIST dBinderStubs;
    pthread_mutex_t mutex;
} DBinderStubRegistedList;

typedef struct {
    UTILS_DL_LIST list;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    uint32_t seqNumber;
} ThreadLockInfo;

typedef struct {
    UTILS_DL_LIST threadLocks;
    pthread_mutex_t mutex;
} ThreadLockInfoList;

typedef struct {
    UTILS_DL_LIST sessionInfos;
    pthread_mutex_t mutex;
} SessionInfoList;

typedef struct {
    UTILS_DL_LIST proxyObject;
    pthread_mutex_t mutex;
} ProxyObjectList;

static RemoteBinderObjectsList g_binderList = {.mutex = PTHREAD_MUTEX_INITIALIZER};
static DBinderStubRegistedList g_stubRegistedList = {.mutex = PTHREAD_MUTEX_INITIALIZER};
static ThreadLockInfoList g_threadLockInfoList = {.mutex = PTHREAD_MUTEX_INITIALIZER};
static SessionInfoList g_sessionInfoList = {.mutex = PTHREAD_MUTEX_INITIALIZER};
static ProxyObjectList g_proxyObjectList = {.mutex = PTHREAD_MUTEX_INITIALIZER};
static SessionIdList g_sessionIdList = {
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .condition = PTHREAD_COND_INITIALIZER
};

static TransInterface *g_trans = NULL;
static char const *DBINDER_SESSION_NAME = "DBinderService";
static const uint32_t RETRY_TIMES = 2;
static const int32_t FIRST_SYS_ABILITY_ID = 0x00000001;
static const int32_t LAST_SYS_ABILITY_ID = 0x00ffffff;
static int g_listInit = 0;

static int32_t InitDBinder(void)
{
    if (g_listInit == 0) {
        UtilsListInit(&g_binderList.remoteBinderObjects);
        UtilsListInit(&g_stubRegistedList.dBinderStubs);
        UtilsListInit(&g_threadLockInfoList.threadLocks);
        UtilsListInit(&g_sessionInfoList.sessionInfos);
        UtilsListInit(&g_proxyObjectList.proxyObject);
        UtilsListInit(&g_sessionIdList.idList);
        g_listInit = 1;
    }
    return ERR_NONE;
}

static char *GetRegisterService(uintptr_t binderObject)
{
    RemoteBinderObjects *node = NULL;
    pthread_mutex_lock(&g_binderList.mutex);
    UTILS_DL_LIST_FOR_EACH_ENTRY(node, &g_binderList.remoteBinderObjects, RemoteBinderObjects, list)
    {
        if (node->binder == binderObject) {
            pthread_mutex_unlock(&g_binderList.mutex);
            return node->serviceName;
        }
    }
    pthread_mutex_unlock(&g_binderList.mutex);
    return NULL;
}

static void AddRegisterService(RemoteBinderObjects *binderObject)
{
    pthread_mutex_lock(&g_binderList.mutex);
    UtilsListAdd(&g_binderList.remoteBinderObjects, &binderObject->list);
    pthread_mutex_unlock(&g_binderList.mutex);
}

static int32_t CheckBinderParams(const void *serviceName, uint32_t nameLen, const char *deviceID,
    uint32_t idLen, void *remoteObject)
{
    if (serviceName == NULL || deviceID == NULL || remoteObject == NULL) {
        RPC_LOG_ERROR("MakeRemoteBinder null poiter");
        return ERR_FAILED;
    }

    if (strlen((char *)serviceName) != nameLen || strlen(deviceID) != idLen) {
        RPC_LOG_ERROR("MakeRemoteBinder length invalid");
        return ERR_FAILED;
    }
    return ERR_NONE;
}

static DBinderServiceStub *QueryDBinderStub(const char *serviceName, const char *deviceID,
    uintptr_t binderObject)
{
    pthread_mutex_lock(&g_stubRegistedList.mutex);
    DBinderServiceStub *node = NULL;
    UTILS_DL_LIST_FOR_EACH_ENTRY(node, &g_stubRegistedList.dBinderStubs, DBinderServiceStub, list)
    {
        if (IsSameStub(node, serviceName, deviceID, binderObject)) {
            RPC_LOG_INFO("find dBinderStub in g_stubRegistedList");
            pthread_mutex_unlock(&g_stubRegistedList.mutex);
            return node;
        }
    }
    pthread_mutex_unlock(&g_stubRegistedList.mutex);
    return NULL;
}

static void AddDBinderStub(DBinderServiceStub *stub)
{
    pthread_mutex_lock(&g_stubRegistedList.mutex);
    UtilsListAdd(&g_stubRegistedList.dBinderStubs, &stub->list);
    pthread_mutex_unlock(&g_stubRegistedList.mutex);
}

static DBinderServiceStub *FindOrNewDBinderStub(const char *serviceName, uint32_t nameLen,
    const char *deviceID, uint32_t idLen, uintptr_t binderObject)
{
    if (serviceName == NULL || deviceID == NULL) {
        RPC_LOG_ERROR("FindOrNewDBinderStub get null input params");
        return NULL;
    }

    DBinderServiceStub *node = QueryDBinderStub(serviceName, deviceID, binderObject);
    if (node != NULL) {
        RPC_LOG_INFO("DBinderStub cached already");
        return node;
    }

    node = (DBinderServiceStub *)malloc(sizeof(DBinderServiceStub));
    if (node == NULL) {
        RPC_LOG_ERROR("dBinderServiceStub malloc failed");
        return NULL;
    }
    if (GetDBinderStub(serviceName, deviceID, binderObject, node) != ERR_NONE)  {
        RPC_LOG_ERROR("GetDBinderStub failed");
        free(node);
        return NULL;
    }

    AddDBinderStub(node);
    return node;
}

static int32_t SendDataToRemote(const char *deviceId, const DHandleEntryTxRx *msg)
{
    if (deviceId == NULL || msg == NULL) {
        return ERR_FAILED;
    }

    int32_t sessionId = g_trans->Connect(DBINDER_SESSION_NAME, deviceId, NULL);
    if (sessionId < 0) {
        RPC_LOG_ERROR("SendDataToRemote connect failed");
        return ERR_FAILED;
    }

    if (WaitForSessionIdReady(&g_sessionIdList, sessionId) != ERR_NONE) {
        RPC_LOG_ERROR("SendDataToRemote connect failed, sessionId=%d", sessionId);
        return ERR_FAILED;
    }

    if (g_trans->Send(sessionId, (void *)msg, msg->head.len) != ERR_NONE) {
        RPC_LOG_ERROR("SendDataToRemote send failed");
        return ERR_FAILED;
    }

    return ERR_NONE;
}

static int32_t SendEntryToRemote(DBinderServiceStub *stub, const uint32_t seqNumber)
{
    char *toDeviceID = stub->deviceID;
    if (toDeviceID == NULL) {
        RPC_LOG_ERROR("toDeviceID invalid");
        return ERR_FAILED;
    }
    uint32_t toDeviceIDLength = (uint32_t)strlen(toDeviceID);

    char localDeviceID[DEVICEID_LENGTH + 1];
    if (g_trans->GetLocalDeviceID(DBINDER_SESSION_NAME, localDeviceID) != ERR_NONE) {
        RPC_LOG_ERROR("GetLocalDeviceID failed");
        return ERR_FAILED;
    }
    uint32_t localDeviceIDLength = (uint32_t)strlen(localDeviceID);
    if (toDeviceIDLength > DEVICEID_LENGTH || localDeviceIDLength > DEVICEID_LENGTH) {
        RPC_LOG_ERROR("deviceID invalid");
        return ERR_FAILED;
    }

    DHandleEntryTxRx message = {
        .head.len = sizeof(DHandleEntryTxRx),
        .head.version = VERSION_NUM,
        .transType = DATABUS_TYPE,
        .dBinderCode = MESSAGE_AS_INVOKER,
        .fromPort = 0,
        .toPort = 0,
        .stubIndex = stub->binderObject,
        .seqNumber = seqNumber,
        .binderObject = stub->binderObject,
        .deviceIdInfo.afType = DATABBUS_TYPE,
        .stub = (uintptr_t)(stub->svc.cookie),
        .pid = (uint32_t)GetCallingPid(),
        .uid = (uint32_t)GetCallingUid()
    };
    if (memcpy_s(message.deviceIdInfo.fromDeviceId, DEVICEID_LENGTH, localDeviceID, localDeviceIDLength) != EOK ||
        memcpy_s(message.deviceIdInfo.toDeviceId, DEVICEID_LENGTH, toDeviceID, toDeviceIDLength) != EOK) {
            RPC_LOG_ERROR("deviceIdInfo memory copy failed");
            return ERR_FAILED;
        }
    message.deviceIdInfo.fromDeviceId[localDeviceIDLength] = '\0';
    message.deviceIdInfo.toDeviceId[toDeviceIDLength] = '\0';

    if (SendDataToRemote(toDeviceID, &message) != ERR_NONE) {
        RPC_LOG_ERROR("SendDataToRemote failed");
        return ERR_FAILED;
    }
    return ERR_NONE;
}

static int32_t AttachThreadLockInfo(ThreadLockInfo *threadLockInfo)
{
    pthread_mutex_lock(&g_threadLockInfoList.mutex);
    UtilsListAdd(&g_threadLockInfoList.threadLocks, &threadLockInfo->list);
    pthread_mutex_unlock(&g_threadLockInfoList.mutex);
    return ERR_NONE;
}

static void DetachThreadLockInfo(ThreadLockInfo *threadLockInfo)
{
    pthread_mutex_lock(&g_threadLockInfoList.mutex);
    UtilsListDelete(&threadLockInfo->list);
    pthread_mutex_unlock(&g_threadLockInfoList.mutex);
}

static ThreadLockInfo *NewThreadLock(void)
{
    ThreadLockInfo *threadLockInfo = (ThreadLockInfo *)malloc(sizeof(ThreadLockInfo));
    if (threadLockInfo == NULL) {
        RPC_LOG_ERROR("threadLockInfo malloc failed");
        return NULL;
    }
    if (pthread_mutex_init(&threadLockInfo->mutex, NULL) != 0) {
        RPC_LOG_ERROR("threadLockInfo mutex init failed");
        free(threadLockInfo);
        return NULL;
    }
    if (pthread_cond_init(&threadLockInfo->condition, NULL) != 0) {
        RPC_LOG_ERROR("threadLockInfo condition init failed");
        free(threadLockInfo);
        return NULL;
    }

    return threadLockInfo;
}

static int32_t GetWaitTime(struct timespec *waitTime)
{
    struct timeval now;
    if (gettimeofday(&now, NULL) != 0) {
        RPC_LOG_ERROR("gettimeofday failed");
        return ERR_FAILED;
    }
    waitTime->tv_sec = now.tv_sec + RPC_DEFAULT_SEND_WAIT_TIME;
    waitTime->tv_nsec = now.tv_usec * USECTONSEC;

    return ERR_NONE;
}

static int32_t InvokerRemoteDBinder(DBinderServiceStub *dBinderServiceStub, uint32_t seqNumber)
{
    if (dBinderServiceStub == NULL) {
        RPC_LOG_ERROR("InvokerRemoteDBinder dBinderServiceStub is NULL");
        return ERR_FAILED;
    }

    int32_t ret = ERR_FAILED;
    ThreadLockInfo *threadLockInfo = NewThreadLock();
    if (threadLockInfo == NULL) {
        return ret;
    }
    threadLockInfo->seqNumber = seqNumber;
    ret = AttachThreadLockInfo(threadLockInfo);
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("AttachThreadLockInfo failed");
        free(threadLockInfo);
        return ret;
    }

    pthread_mutex_lock(&threadLockInfo->mutex);
    ret = SendEntryToRemote(dBinderServiceStub, seqNumber);
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("send entry to remote dbinderService failed");
    } else {
        struct timespec waitTime;
        ret = GetWaitTime(&waitTime);
        if (ret != ERR_NONE) {
            DetachThreadLockInfo(threadLockInfo);
            pthread_mutex_unlock(&threadLockInfo->mutex);
            free(threadLockInfo);
            return ERR_FAILED;
        }

        ret = pthread_cond_timedwait(&threadLockInfo->condition, &threadLockInfo->mutex, &waitTime);
        if (ret == ETIMEDOUT) {
            RPC_LOG_ERROR("InvokerRemoteDBinder wait for reply timeout");
            DetachThreadLockInfo(threadLockInfo);
            pthread_mutex_unlock(&threadLockInfo->mutex);
            free(threadLockInfo);
            return ERR_FAILED;
        }
        RPC_LOG_INFO("InvokerRemoteDBinder wakeup!");
    }

    if (QuerySessionObject((uintptr_t)(dBinderServiceStub->svc.cookie)) == NULL) {
        RPC_LOG_ERROR("QuerySessionObject is null");
        ret = ERR_FAILED;
    }

    DetachThreadLockInfo(threadLockInfo);
    pthread_mutex_unlock(&threadLockInfo->mutex);
    free(threadLockInfo);

    return ret;
}

static uint32_t GetSeqNumber(void)
{
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    static uint32_t seqNumber = 0;
    pthread_mutex_lock(&mutex);
    seqNumber++;
    pthread_mutex_unlock(&mutex);
    return seqNumber;
}

static int32_t AttachSessionObject(SessionInfo *sessionInfo)
{
    pthread_mutex_lock(&g_sessionInfoList.mutex);
    UtilsListAdd(&g_sessionInfoList.sessionInfos, &sessionInfo->list);
    pthread_mutex_unlock(&g_sessionInfoList.mutex);
    return ERR_NONE;
}

static void DetachSessionObject(SessionInfo *sessionInfo)
{
    pthread_mutex_lock(&g_sessionInfoList.mutex);
    UtilsListDelete(&sessionInfo->list);
    pthread_mutex_unlock(&g_sessionInfoList.mutex);
}

SessionInfo *QuerySessionObject(uintptr_t stub)
{
    SessionInfo *node = NULL;
    pthread_mutex_lock(&g_sessionInfoList.mutex);
    UTILS_DL_LIST_FOR_EACH_ENTRY(node, &g_sessionInfoList.sessionInfos, SessionInfo, list)
    {
        if (node->stub == stub) {
            pthread_mutex_unlock(&g_sessionInfoList.mutex);
            return node;
        }
    }
    pthread_mutex_unlock(&g_sessionInfoList.mutex);
    return NULL;
}

static void DeleteDBinderStub(DBinderServiceStub *stub)
{
    if (stub == NULL) {
        RPC_LOG_ERROR("DeleteDBinderStub get null stub");
        return;
    }
    pthread_mutex_lock(&g_stubRegistedList.mutex);
    UtilsListDelete(&stub->list);
    pthread_mutex_unlock(&g_stubRegistedList.mutex);
}

static ProxyObject *QueryProxyObject(uintptr_t binderObject)
{
    ProxyObject *node = NULL;
    pthread_mutex_lock(&g_proxyObjectList.mutex);
    UTILS_DL_LIST_FOR_EACH_ENTRY(node, &g_proxyObjectList.proxyObject, ProxyObject, list)
    {
        if (node->binderObject == binderObject) {
            pthread_mutex_unlock(&g_proxyObjectList.mutex);
            return node;
        }
    }
    pthread_mutex_unlock(&g_proxyObjectList.mutex);
    return NULL;
}

static int32_t AttachProxyObject(ProxyObject *proxy)
{
    pthread_mutex_lock(&g_proxyObjectList.mutex);
    UtilsListAdd(&g_proxyObjectList.proxyObject, &proxy->list);
    pthread_mutex_unlock(&g_proxyObjectList.mutex);
    return ERR_NONE;
}

static void DetachProxyObject(ProxyObject *proxy)
{
    pthread_mutex_lock(&g_proxyObjectList.mutex);
    UtilsListDelete(&proxy->list);
    pthread_mutex_unlock(&g_proxyObjectList.mutex);
}

static void DbinderSaDeathRecipient(void *args)
{
    if (args == NULL) {
        RPC_LOG_ERROR("DbinderSaDeathRecipient args is null");
        return;
    }
    ProxyObject *proxyObject = (ProxyObject *)args;
    RPC_LOG_INFO("DbinderSaDeathRecipient cbiId %d", proxyObject->cbId);
    DetachProxyObject(proxyObject);
}

static ProxyObject *FindOrNewProxy(uintptr_t binderObject, int32_t systemAbilityId)
{
    ProxyObject *proxyObject = QueryProxyObject(binderObject);
    if (proxyObject != NULL) {
        RPC_LOG_INFO("FindOrNewProxy found cached proxy");
        return proxyObject;
    }

    char *serviceName = GetRegisterService(binderObject);
    if (serviceName == NULL && (systemAbilityId < FIRST_SYS_ABILITY_ID || systemAbilityId > LAST_SYS_ABILITY_ID)) {
        RPC_LOG_ERROR("service is not registered in this device, saId:%d", systemAbilityId);
        return NULL;
    }

    proxyObject = RpcGetSystemAbility(systemAbilityId);
    if (proxyObject == NULL) {
        RPC_LOG_ERROR("RpcGetSystemAbility failed, saId: %d", systemAbilityId);
        return NULL;
    }
    proxyObject->binderObject = binderObject;

    int32_t ret = AddDeathRecipient(*proxyObject->proxy, DbinderSaDeathRecipient,
        (void *)proxyObject, &proxyObject->cbId);
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("FindOrNewProxy AddDeathRecipient failed, error %d", ret);
        free(proxyObject->proxy);
        free(proxyObject);
        return NULL;
    }

    if (AttachProxyObject(proxyObject) != ERR_NONE) {
        RPC_LOG_ERROR("FindOrNewProxy AttachProxyObject failed");
        RemoveDeathRecipient(*proxyObject->proxy, proxyObject->cbId);
        free(proxyObject->proxy);
        free(proxyObject);
        return NULL;
    }
    return proxyObject;
}

static int32_t GetDatabusNameByProxy(ProxyObject *proxy)
{
    if (proxy == NULL) {
        RPC_LOG_ERROR("GetDatabusNameByProxy proxy is null");
        return ERR_FAILED;
    }

    if (proxy->sessionName != NULL && strlen(proxy->sessionName) > 0) {
        RPC_LOG_ERROR("GetDatabusNameByProxy proxy got sessionName already");
        return ERR_NONE;
    }
    if (GetPidAndUidInfo(proxy) != ERR_NONE) {
        RPC_LOG_ERROR("GetDatabusNameByProxy GetPidAndUidInfo failed");
        return ERR_FAILED;
    }
    return ERR_NONE;
}

static int32_t OnRemoteInvokerDataBusMessage(ProxyObject *proxy, DHandleEntryTxRx *replyMessage,
    const char *remoteDeviceID, uint32_t pid, uint32_t uid)
{
    if (remoteDeviceID == NULL || strlen(remoteDeviceID) > DEVICEID_LENGTH) {
        RPC_LOG_ERROR("remote deviceID invalid");
        return ERR_FAILED;
    }

    if (GetDatabusNameByProxy(proxy) != ERR_NONE) {
        RPC_LOG_ERROR("GetDatabusNameByProxy failed");
        return ERR_FAILED;
    }

    char localDeviceId[DEVICEID_LENGTH + 1];
    int32_t ret = g_trans->GetLocalDeviceID(DBINDER_SESSION_NAME, localDeviceId);
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("OnRemoteInvokerDataBusMessage GetLocalDeviceID failed");
        return ERR_FAILED;
    }

    IpcIo reply;
    uintptr_t ptr;
    ret = InvokerListenThread(proxy, localDeviceId, remoteDeviceID, pid, uid, &reply, &ptr);
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("INVOKE_LISTEN_THREAD failed");
        FreeBuffer((void *)ptr);
        return ERR_FAILED;
    }

    uint64_t stubIndex;
    if (!ReadUint64(&reply, &stubIndex)) {
        FreeBuffer((void *)ptr);
        return ERR_FAILED;
    }

    size_t sessionLen;
    char *serverSessionName = (char *)ReadString(&reply, &sessionLen);

    if (stubIndex == 0 || serverSessionName == NULL || sessionLen > SERVICENAME_LENGTH) {
        RPC_LOG_ERROR("INVOKE_LISTEN_THREAD reply stubIndex or sessionName invalid");
        FreeBuffer((void *)ptr);
        return ERR_FAILED;
    }

    replyMessage->dBinderCode = MESSAGE_AS_REPLY;
    replyMessage->stubIndex = stubIndex;
    replyMessage->serviceNameLength = (uint16_t)sessionLen;
    if (memcpy_s(replyMessage->serviceName, SERVICENAME_LENGTH, serverSessionName, sessionLen) != 0) {
        RPC_LOG_ERROR("replyMessage serviceName memcpy failed");
        FreeBuffer((void *)ptr);
        return ERR_FAILED;
    }
    replyMessage->serviceName[replyMessage->serviceNameLength] = '\0';
    FreeBuffer((void *)ptr);
    return ERR_NONE;
}

static void *OnRemoteInvokerMessage(void *args)
{
    pthread_detach(pthread_self());
    DHandleEntryTxRx *message = (DHandleEntryTxRx *)args;
    ProxyObject *saProxy = FindOrNewProxy(message->binderObject, (int32_t)message->stubIndex);
    if (saProxy == NULL) {
        RPC_LOG_ERROR("OnRemoteInvokerMessage get SA Proxy failed");
        return (void *)ERR_FAILED;
    }

    DHandleEntryTxRx replyMessage;
    if (memcpy_s(&replyMessage, sizeof(DHandleEntryTxRx), message, sizeof(DHandleEntryTxRx)) != EOK) {
        RPC_LOG_ERROR("OnRemoteInvokerMessage replyMessage memcpy failed");
        return (void *)ERR_FAILED;
    }
    char *fromDeviceID = replyMessage.deviceIdInfo.fromDeviceId;

    switch (replyMessage.transType) {
        case DATABUS_TYPE: {
            if (OnRemoteInvokerDataBusMessage(saProxy, &replyMessage, fromDeviceID,
                message->pid, message->uid) != ERR_NONE) {
                RPC_LOG_ERROR("OnRemoteInvokerMessage Invoker Databus Message fail");
                return (void *)ERR_FAILED;
            }
            break;
        }
        default: {
            RPC_LOG_ERROR("OnRemoteInvokerMessage msg transType invalid");
            return (void *)ERR_FAILED;
        }
    }

    if (SendDataToRemote(fromDeviceID, &replyMessage) != ERR_NONE) {
        RPC_LOG_ERROR("fail to send data from server DBS to client DBS");
        return (void *)ERR_FAILED;
    }
    return (void *)ERR_NONE;
}

static ThreadLockInfo *QueryThreadLockInfo(uint32_t seqNumber)
{
    ThreadLockInfo *node = NULL;
    pthread_mutex_lock(&g_threadLockInfoList.mutex);
    UTILS_DL_LIST_FOR_EACH_ENTRY(node, &g_threadLockInfoList.threadLocks, ThreadLockInfo, list)
    {
        if (node->seqNumber == seqNumber) {
            pthread_mutex_unlock(&g_threadLockInfoList.mutex);
            return node;
        }
    }
    pthread_mutex_unlock(&g_threadLockInfoList.mutex);
    return NULL;
}

static void WakeupThreadByStub(uint32_t seqNumber)
{
    ThreadLockInfo *threadLockInfo = QueryThreadLockInfo(seqNumber);
    if (threadLockInfo == NULL) {
        RPC_LOG_ERROR("threadLockInfo is not exist");
        return;
    }
    pthread_mutex_lock(&threadLockInfo->mutex);
    pthread_cond_signal(&threadLockInfo->condition);
    pthread_mutex_unlock(&threadLockInfo->mutex);
}

static bool HasDBinderStub(uintptr_t binderObject)
{
    DBinderServiceStub *node;
    pthread_mutex_lock(&g_stubRegistedList.mutex);
    UTILS_DL_LIST_FOR_EACH_ENTRY(node, &g_stubRegistedList.dBinderStubs, DBinderServiceStub, list)
    {
        if (node->binderObject == binderObject) {
            pthread_mutex_unlock(&g_stubRegistedList.mutex);
            return true;
        }
    }
    pthread_mutex_unlock(&g_stubRegistedList.mutex);
    return false;
}

static void MakeSessionByReplyMessage(const DHandleEntryTxRx *replyMessage)
{
    if (replyMessage == NULL) {
        RPC_LOG_ERROR("replyMessage is null");
        return;
    }
    if (!HasDBinderStub(replyMessage->binderObject)) {
        RPC_LOG_ERROR("invalid stub object");
        return;
    }
    if (QuerySessionObject(replyMessage->stub) != NULL) {
        RPC_LOG_ERROR("invoker remote session already, do nothing");
        return;
    }

    SessionInfo *session = (SessionInfo *)malloc(sizeof(SessionInfo));
    if (session == NULL) {
        RPC_LOG_ERROR("session malloc failed");
        return;
    }
    if (memcpy_s(&session->deviceIdInfo, sizeof(struct DeviceIdInfo),
        &replyMessage->deviceIdInfo, sizeof(struct DeviceIdInfo)) != 0) {
        RPC_LOG_ERROR("deviceIdInfo memory copy failed");
        free(session);
        return;
    }
    if (strcpy_s(session->serviceName, SERVICENAME_LENGTH + 1, replyMessage->serviceName) != EOK) {
        RPC_LOG_ERROR("session serviceName copy failed");
        free(session);
        return;
    }
    session->serviceName[replyMessage->serviceNameLength] = '\0';

    session->socketFd = 0;
    session->stubIndex = replyMessage->stubIndex;
    session->toPort = replyMessage->toPort;
    session->fromPort = replyMessage->fromPort;
    session->type = replyMessage->transType;
    session->stub = replyMessage->stub;

    if (session->stubIndex == 0) {
        RPC_LOG_ERROR("stubIndex invalid");
        free(session);
        return;
    }
    if (AttachSessionObject(session) != 0) {
        RPC_LOG_ERROR("AttachSessionObject failed");
        free(session);
        return;
    }
}

static int32_t OnRemoteReplyMessage(const DHandleEntryTxRx *replyMessage)
{
    MakeSessionByReplyMessage(replyMessage);
    WakeupThreadByStub(replyMessage->seqNumber);
    return ERR_NONE;
}

SessionIdList *GetSessionIdList(void)
{
    return &g_sessionIdList;
}

int32_t StartDBinderService(void)
{
    static bool isDBinderCreated = false;
    int32_t ret = ERR_NONE;
    if (isDBinderCreated) {
        return ret;
    }

    g_trans = GetRpcTrans();
    if (g_trans == NULL) {
        RPC_LOG_ERROR("GetRpcTrans failed");
        return ERR_FAILED;
    }
    ret = g_trans->StartListen(DBINDER_SESSION_NAME, (void *)GetDBinderTransCallback());
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("StartListen failed");
        return ret;
    }

    ret = InitDBinder();
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("InitDBinder failed");
    }
    isDBinderCreated = true;
    return ret;
}

int32_t RegisterRemoteProxy(const void *name, uint32_t len, int32_t systemAbility)
{
    int32_t ret = InitDBinder();
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("InitDBinder failed");
    }
    if (name == NULL || systemAbility < 0) {
        RPC_LOG_ERROR("RegisterRemoteProxy name is null or systemAbility invalid");
        return ERR_FAILED;
    }
    const char *serviceName = (const char *)name;
    RPC_LOG_INFO("register remote proxy, service name = %s", serviceName);

    RemoteBinderObjects *binderObject = (RemoteBinderObjects *)malloc(sizeof(RemoteBinderObjects));
    if (binderObject == NULL) {
        RPC_LOG_ERROR("binder object malloc failed");
        return ERR_FAILED;
    }

    uintptr_t binder = (uintptr_t)systemAbility;
    binderObject->binder = binder;

    if (len == 0 || len > SERVICENAME_LENGTH || len != strlen(serviceName)) {
        RPC_LOG_ERROR("RegisterRemoteProxy name length invalid");
        free(binderObject);
        return ERR_FAILED;
    }
    binderObject->serviceName = (char *)malloc(len + 1);
    if (binderObject->serviceName == NULL) {
        RPC_LOG_ERROR("RegisterRemoteProxy binderObject->serviceName malloc failed");
        free(binderObject);
        return ERR_FAILED;
    }

    if (strcpy_s(binderObject->serviceName, len + 1, serviceName) != EOK) {
        RPC_LOG_ERROR("RegisterRemoteProxy binderObject->serviceName copy failed");
        free(binderObject->serviceName);
        free(binderObject);
        return ERR_FAILED;
    }

    AddRegisterService(binderObject);
    return ERR_NONE;
}

int32_t MakeRemoteBinder(const void *serviceName, uint32_t nameLen, const char *deviceID, uint32_t idLen,
    uintptr_t binderObject, uint64_t pid, void *remoteObject)
{
    RPC_LOG_INFO("MakeRemoteBinder start");
    if (CheckBinderParams(serviceName, nameLen, deviceID, idLen, remoteObject) != ERR_NONE) {
        RPC_LOG_ERROR("MakeRemoteBinder failed");
        return ERR_FAILED;
    }

    const char *name = (const char *)serviceName;
    DBinderServiceStub *dBinderServiceStub  = FindOrNewDBinderStub(name, nameLen, deviceID, idLen, binderObject);
    if (dBinderServiceStub == NULL) {
        RPC_LOG_ERROR("FindOrNewDBinderStub return null");
        return ERR_FAILED;
    }

    uint32_t retryTimes = 0;
    int32_t ret;
    do {
        ret = InvokerRemoteDBinder(dBinderServiceStub, GetSeqNumber());
        retryTimes++;
    } while (ret != ERR_NONE && (retryTimes < RETRY_TIMES));

    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("fail to invoke service, service name = %s", serviceName);
        SessionInfo *sessionObject = QuerySessionObject((uintptr_t)(dBinderServiceStub->svc.cookie));
        if (sessionObject != NULL) {
            DetachSessionObject(sessionObject);
            free(sessionObject);
        }
        DeleteDBinderStub(dBinderServiceStub);
        free((void *)dBinderServiceStub->svc.cookie);
        free(dBinderServiceStub);
    } else {
        if (memcpy_s(remoteObject, sizeof(SvcIdentity), &dBinderServiceStub->svc, sizeof(SvcIdentity)) != 0) {
            RPC_LOG_ERROR("svc memory copy failed");
            ret = ERR_FAILED;
        }
    }

    return ret;
}

int32_t OnRemoteMessageTask(const DHandleEntryTxRx *message)
{
    if (message == NULL) {
        RPC_LOG_ERROR("OnRemoteMessageTask message is NULL");
        return ERR_FAILED;
    }

    int32_t ret;
    switch (message->dBinderCode) {
        case MESSAGE_AS_INVOKER: {
            pthread_t threadId;
            ret = pthread_create(&threadId, NULL, OnRemoteInvokerMessage, (void *)message);
            if (ret != 0) {
                RPC_LOG_ERROR("OnRemoteMessageTask pthread_create failed %d", ret);
                ret = ERR_FAILED;
                break;
            }

            ret = ERR_NONE;
            break;
        }
        case MESSAGE_AS_REPLY: {
            ret = OnRemoteReplyMessage(message);
            break;
        }
        default: {
            RPC_LOG_ERROR("OnRemoteMessageTask dbindercode=%d valid", message->dBinderCode);
            ret = ERR_FAILED;
            break;
        }
    }
    return ret;
}
