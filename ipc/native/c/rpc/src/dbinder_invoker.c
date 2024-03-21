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

#include "dbinder_invoker.h"

#include <inttypes.h>
#include <unistd.h>

#include "securec.h"
#include "utils_list.h"

#include "dbinder_types.h"
#include "ipc_process_skeleton.h"
#include "ipc_skeleton.h"
#include "ipc_thread_pool.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "rpc_process_skeleton.h"
#include "rpc_session_handle.h"
#include "rpc_trans.h"
#include "rpc_trans_callback.h"
#include "rpc_types.h"

#define BC_TRANSACTION 1076388608
#define BC_REPLY 1076388609

static const int DBINDER_MAGICWORD = 0X4442494E;
static const int SOCKET_MAX_BUFF_SIZE = 1024 * 1024;
static RemoteInvoker *g_rpcInvoker = NULL;

void DeleteRpcInvoker(RemoteInvoker *remoteInvoker)
{
    if (remoteInvoker == NULL) {
        return;
    }
    free(remoteInvoker);
}

static HandleSessionList *GetSessionObject(uint32_t handle, uint32_t sessionId)
{
    if (handle != 0) {
        /* transact case */
        return QueryProxySession(handle);
    } else {
        /* reply case */
        return QueryStubSession(sessionId);
    }
}

static uint64_t GetUniqueSeqNumber(int cmd)
{
    if (cmd == BC_TRANSACTION) {
        return ProcessGetSeqNumber();
    } else if (cmd == BC_REPLY) {
        ThreadContext *threadContext = GetCurrentThreadContext();
        if (threadContext == NULL) {
            RPC_LOG_ERROR("GetUniqueSeqNumber threadContext is null");
            return 0;
        }
        return threadContext->seqNumber;
    }
    return 0;
}

static void ToTransData(const IpcIo *data, dbinder_transaction_data *buf)
{
    buf->buffer_size = (data == NULL) ? 0 : (data->bufferCur - data->bufferBase);
    buf->offsets = buf->buffer_size;
    buf->offsets_size = (data == NULL) ? 0 :
        (uint64_t)((data->offsetsCur - data->offsetsBase) * sizeof(size_t));
}

static void ToIpcData(const dbinder_transaction_data *tr, IpcIo *data)
{
    data->bufferBase = data->bufferCur = (char *)(tr->buffer);
    data->offsetsBase = data->offsetsCur = (size_t *)(data->bufferBase + (size_t)tr->buffer_size);
    data->bufferLeft = (size_t)tr->buffer_size;
    data->offsetsLeft = (tr->offsets_size) / sizeof(size_t);
    data->flag = IPC_IO_INITIALIZED;
}

static int32_t MoveIpcToTransData(IpcIo *data, dbinder_transaction_data *transData, int status)
{
    if (data != NULL) {
        ToTransData(data, transData);
        if (memcpy_s(transData->buffer, transData->buffer_size, data->bufferBase, transData->buffer_size) != EOK) {
            RPC_LOG_ERROR("transData buffer memset failed");
            return ERR_FAILED;
        }
        uint32 offsetsSize = transData->sizeOfSelf - sizeof(dbinder_transaction_data) - transData->buffer_size;
        if (offsetsSize > 0) {
            if (memcpy_s(transData->buffer + transData->buffer_size, offsetsSize,
                data->offsetsBase, offsetsSize) != EOK) {
                RPC_LOG_ERROR("transData buffer memset failed");
                return ERR_FAILED;
            }
        }
    } else {
        transData->flags |= TF_OP_STATUS_CODE;
        transData->buffer_size = sizeof(size_t);
        transData->offsets_size = (size_t)status;
        transData->offsets = transData->buffer_size;
    }
    return ERR_NONE;
}

static int32_t ProcessNormalData(IpcIo *data, int32_t handle, int status, dbinder_transaction_data *transData)
{
    if (transData == NULL) {
        RPC_LOG_ERROR("ProcessNormalData transData is null");
        return ERR_FAILED;
    }

    uint32_t dataSize = (uint32_t)(data->offsetsCur - data->offsetsBase) +
        (uint32_t)(data->bufferCur - data->bufferBase);
    transData->buffer = (char *)malloc(dataSize);
    if (transData->buffer == NULL) {
        RPC_LOG_ERROR("transData buffer malloc failed");
        return ERR_FAILED;
    }
    transData->sizeOfSelf = sizeof(dbinder_transaction_data) + dataSize;

    if (handle == 0) {
        transData->cookie = 0;
    } else {
        HandleToIndexList *handleToIndex = QueryHandleToIndex(handle);
        if (handleToIndex == NULL) {
            RPC_LOG_ERROR("stubIndex not found for handle %d", handle);
            return ERR_FAILED;
        }
        transData->cookie = handleToIndex->index;
    }

    if (MoveIpcToTransData(data, transData, status) != ERR_NONE) {
        RPC_LOG_ERROR("move parcel to transData failed, handle = %d", handle);
        return ERR_FAILED;
    }

    return ERR_NONE;
}

static int32_t MoveTransData2Buffer(HandleSessionList *sessionObject, dbinder_transaction_data *transData)
{
    sessionObject->buffer = (char *)malloc((size_t)transData->sizeOfSelf);
    if (sessionObject->buffer == NULL) {
        RPC_LOG_ERROR("sessionObject buffer malloc failed");
        return ERR_FAILED;
    }
    sessionObject->len = transData->sizeOfSelf;

    if (memcpy_s(sessionObject->buffer, sizeof(dbinder_transaction_data),
        transData, sizeof(dbinder_transaction_data)) != EOK) {
        RPC_LOG_ERROR("sessionObject buffer memset failed");
        free(sessionObject->buffer);
        return ERR_FAILED;
    }

    if (memcpy_s(sessionObject->buffer + sizeof(dbinder_transaction_data),
        transData->buffer_size, transData->buffer, transData->buffer_size) != EOK) {
        RPC_LOG_ERROR("sessionObject buffer memset failed");
        free(sessionObject->buffer);
        return ERR_FAILED;
    }

    return ERR_NONE;
}

static HandleSessionList *WriteTransaction(int32_t cmd, MessageOption option, int32_t handle,
    int32_t sessionId, uint32_t code, IpcIo *data, uint64_t *seqNumber, int status)
{
    HandleSessionList *sessionObject = GetSessionObject(handle, sessionId);
    if (sessionObject == NULL) {
        RPC_LOG_ERROR("session is not exist for sessionId = %d, handle = %d", sessionId, handle);
        return NULL;
    }

    uint64_t seqNum = GetUniqueSeqNumber(cmd);
    if (seqNum == 0) {
        RPC_LOG_ERROR("seqNum invalid");
        if (sessionObject->buffer != NULL) {
            free(sessionObject->buffer);
        }
        return NULL;
    }
    *seqNumber = seqNum;

    dbinder_transaction_data transData = {
        .magic = DBINDER_MAGICWORD,
        .version = VERSION_NUM,
        .cmd = cmd,
        .code = code,
        .flags = option.flags,
        .seqNumber = *seqNumber,
        .buffer = NULL
    };

    if (ProcessNormalData(data, handle, status, &transData) != ERR_NONE) {
        RPC_LOG_ERROR("ProcessNormalData failed");
        if (transData.buffer != NULL) {
            free(transData.buffer);
            return NULL;
        }
    }

    if (MoveTransData2Buffer(sessionObject, &transData) != ERR_NONE) {
        RPC_LOG_ERROR("move transaction data to buffer failed");
        free(transData.buffer);
        return NULL;
    }

    free(transData.buffer);
    return sessionObject;
}

static int32_t OnSendMessage(HandleSessionList *sessionOfPeer)
{
    if (sessionOfPeer == NULL || sessionOfPeer->buffer == NULL) {
        RPC_LOG_ERROR("sessionOfPeer or buffer is null");
        return ERR_FAILED;
    }
    RpcSkeleton *rpcSkeleton = GetCurrentRpcSkeleton();
    if (rpcSkeleton == NULL) {
        RPC_LOG_ERROR("RpcSkeleton is null");
        return ERR_FAILED;
    }

    int32_t ret = rpcSkeleton->rpcTrans->Send((int)sessionOfPeer->sessionId,
        (void *)sessionOfPeer->buffer, (uint32_t)sessionOfPeer->len);

    free(sessionOfPeer->buffer);
    return ret;
}

static ThreadMessageInfo *MakeThreadMessageInfo(uint64_t seqNumber, uint32_t handle)
{
    ThreadMessageInfo *messageInfo = (ThreadMessageInfo *)malloc(sizeof(ThreadMessageInfo));
    if (messageInfo == NULL) {
        RPC_LOG_ERROR("messageInfo malloc failed");
        return NULL;
    }

    messageInfo->threadId = pthread_self();
    messageInfo->seqNumber = seqNumber;
    messageInfo->buffer = NULL;
    messageInfo->offsets = 0;
    messageInfo->sessionId = handle;
    return messageInfo;
}

static int32_t HandleReply(uint64_t seqNumber, IpcIo *reply, uintptr_t *buffer)
{
    if (reply == NULL) {
        RPC_LOG_ERROR("no need reply, free the buffer");
        return ERR_FAILED;
    }

    ThreadMessageInfo *messageInfo = QueryThreadBySeqNumber(seqNumber);
    if (messageInfo == NULL) {
        RPC_LOG_ERROR("receive buffer is nullptr");
        return ERR_NONE;
    }

    if (messageInfo->flags & TF_OP_STATUS_CODE) {
        int32_t err = messageInfo->offsetsSize;
        return err;
    }

    dbinder_transaction_data transData = {
        .buffer_size = messageInfo->bufferSize,
        .offsets_size = messageInfo->offsetsSize,
        .offsets = messageInfo->offsets,
        .buffer = messageInfo->buffer
    };
    ToIpcData(&transData, reply);
    *buffer = (uintptr_t)messageInfo->buffer;

    return ERR_NONE;
}

static int32_t WaitForReply(uint64_t seqNumber, IpcIo *reply, uint32_t handle, uint32_t userWaitTime, uintptr_t *buffer)
{
    if (reply == NULL || userWaitTime == 0) {
        return ERR_NONE;
    }

    ThreadMessageInfo *messageInfo = MakeThreadMessageInfo(seqNumber, handle);
    if (messageInfo == NULL) {
        RPC_LOG_ERROR("make thread message info failed, no memory");
        return ERR_FAILED;
    }
    if (AddSendThreadInWait(seqNumber, messageInfo, userWaitTime) != ERR_NONE) {
        RPC_LOG_ERROR("sender thread wait reply message time out");
        EraseThreadBySeqNumber(messageInfo);
        free(messageInfo);
        return ERR_FAILED;
    }
    int32_t result = HandleReply(seqNumber, reply, buffer);
    EraseThreadBySeqNumber(messageInfo);
    free(messageInfo);
    return result;
}

static int32_t SendOrWaitForCompletion(uint32_t userWaitTime, uint64_t seqNumber,
    HandleSessionList *sessionOfPeer, IpcIo *reply, uintptr_t *buffer)
{
    if (seqNumber == 0) {
        RPC_LOG_ERROR("seqNumber can not be zero");
        return ERR_FAILED;
    }
    if (sessionOfPeer == NULL) {
        RPC_LOG_ERROR("current session is invalid");
        return ERR_FAILED;
    }
    int32_t result = OnSendMessage(sessionOfPeer);
    if (result != ERR_NONE) {
        RPC_LOG_ERROR("fail to send to remote session with error = %d", result);
        // no return, for msg send failed maybe not mine
    }
    return WaitForReply(seqNumber, reply, sessionOfPeer->handle, userWaitTime, buffer);
}

static int32_t GetCallerSessionId(void)
{
    ThreadContext *threadContext = GetCurrentThreadContext();
    return threadContext->sessionId;
}

static int32_t SendReply(IpcIo *reply, uint32_t flags, int32_t result)
{
    uint64_t seqNumber = 0;
    MessageOption option = {
        .flags = flags
    };
    HandleSessionList *sessionObject = WriteTransaction(BC_REPLY, option, 0, GetCallerSessionId(),
        0, reply, &seqNumber, result);

    if (seqNumber == 0) {
        RPC_LOG_ERROR("seqNumber can not be zero");
        return ERR_FAILED;
    }
    SendOrWaitForCompletion(0, seqNumber, sessionObject, reply, NULL);
    return ERR_NONE;
}

static void ProcessTransaction(const dbinder_transaction_data *tr, uint32_t sessionId)
{
    if (tr == NULL || tr->cookie == 0) {
        return;
    }

    IpcIo data;
    IpcIo reply;
    uint8_t replyAlloc[RPC_IPC_LENGTH];
    IpcIoInit(&reply, replyAlloc, RPC_IPC_LENGTH, 0);
    MessageOption option = {
        .flags =  tr->flags
    };
    uint64_t senderSeqNumber = tr->seqNumber;

    ToIpcData(tr, &data);

    ThreadContext *threadContext = GetCurrentThreadContext();
    const pid_t oldPid = threadContext->callerPid;
    const pid_t oldUid = threadContext->callerUid;
    char oldDeviceId[DEVICEID_LENGTH];
    if (memcpy_s(oldDeviceId, DEVICEID_LENGTH, threadContext->callerDeviceID, DEVICEID_LENGTH) != EOK) {
        RPC_LOG_ERROR("oldDeviceId memcpy failed");
        return;
    }

    StubObject *stubObject = QueryStubByIndex(tr->cookie);
    if (stubObject == NULL) {
        RPC_LOG_ERROR("stubIndex is invalid");
        return;
    }

    int32_t result = stubObject->func(tr->code, &data, &reply, option);
    if (result != ERR_NONE) {
        RPC_LOG_ERROR("stub is invalid, has not OnReceive or Request");
    }
    if (!(option.flags & TF_OP_ASYNC)) {
        threadContext->sessionId = sessionId;
        threadContext->seqNumber = senderSeqNumber;
        SendReply(&reply, 0, result);
        threadContext->sessionId = 0;
        threadContext->seqNumber = 0;
    }

    threadContext->callerPid = oldPid;
    threadContext->callerUid = oldUid;
    if (memcpy_s(threadContext->callerDeviceID, DEVICEID_LENGTH, oldDeviceId, DEVICEID_LENGTH) != EOK) {
        RPC_LOG_ERROR("threadContext callerDeviceID memcpy failed");
    }
}

static void ProcessReply(const dbinder_transaction_data *tr, uint32_t sessionId)
{
    ThreadMessageInfo *messageInfo = QueryThreadBySeqNumber(tr->seqNumber);
    if (messageInfo == NULL) {
        RPC_LOG_ERROR("no thread waiting reply message of this seqNumber");
        /* messageInfo is null, no thread need to wakeup */
        return;
    }

    size_t bufferSize = tr->sizeOfSelf - sizeof(dbinder_transaction_data);
    messageInfo->buffer = (void *)malloc(bufferSize);
    if (messageInfo->buffer == NULL) {
        RPC_LOG_ERROR("some thread is waiting for reply message, but no memory");
        /* wake up sender thread */
        WakeUpThreadBySeqNumber(tr->seqNumber, sessionId);
        return;
    }

    if (memcpy_s(messageInfo->buffer, bufferSize, tr->buffer, bufferSize) != EOK) {
        RPC_LOG_ERROR("messageInfo buffer memset failed");
        free(messageInfo->buffer);
        WakeUpThreadBySeqNumber(tr->seqNumber, sessionId);
        return;
    }

    messageInfo->flags = tr->flags;
    messageInfo->bufferSize = tr->buffer_size;
    messageInfo->offsetsSize = tr->offsets_size;
    messageInfo->offsets = tr->offsets;
    messageInfo->sessionId = sessionId;

    /* wake up sender thread */
    WakeUpThreadBySeqNumber(tr->seqNumber, sessionId);
}

static void OnTransaction(ThreadProcessInfo *processInfo)
{
    if (processInfo == NULL) {
        return;
    }
    dbinder_transaction_data *tr = (dbinder_transaction_data *)processInfo->buffer;
    tr->buffer = (char *)(processInfo->buffer + sizeof(dbinder_transaction_data));

    if (tr->cmd == BC_TRANSACTION) {
        ProcessTransaction(tr, processInfo->sessionId);
    } else if (tr->cmd == BC_REPLY) {
        ProcessReply(tr, processInfo->sessionId);
    }
}

static ThreadProcessInfo *MakeThreadProcessInfo(uint32_t handle, const char *inBuffer, uint32_t size)
{
    if (inBuffer == NULL || size < sizeof(dbinder_transaction_data)) {
        RPC_LOG_ERROR("buffer is null or size invalid");
        return NULL;
    }

    ThreadProcessInfo *processInfo = (ThreadProcessInfo *)malloc(sizeof(ThreadProcessInfo));
    if (processInfo == NULL) {
        return NULL;
    }
    processInfo->buffer = (char *)malloc(size);
    if (processInfo->buffer == NULL) {
        free(processInfo);
        return NULL;
    }
    if (memcpy_s(processInfo->buffer, size, inBuffer, size) != EOK) {
        free(processInfo->buffer);
        free(processInfo);
        return NULL;
    }
    processInfo->sessionId = handle;
    processInfo->packageSize = size;

    return processInfo;
}

static int32_t CreateProcessThread(void)
{
    IpcSkeleton *current = GetCurrentSkeleton();
    if (current == NULL) {
        RPC_LOG_ERROR("current ipcskeleton is nullptr");
        return ERR_FAILED;
    }
    if (current->threadPool->idleSocketThreadNum > 0) {
        SpawnThread(SPAWN_PASSIVE, IF_PROT_DATABUS);
        RPC_LOG_INFO("create Process thread success");
        return ERR_NONE;
    }
    return ERR_FAILED;
}

static void StartProcessLoop(uint32_t handle, const void *buffer, uint32_t size)
{
    ThreadProcessInfo *processInfo = MakeThreadProcessInfo(handle, buffer, size);
    if (processInfo == NULL) {
        RPC_LOG_ERROR("MakeThreadProcessInfo failed");
        return;
    }

    IdleDataThread *idleDataThread = GetIdleDataThread();
    if (idleDataThread == NULL) {
        if (CreateProcessThread() != ERR_NONE) {
            RPC_LOG_ERROR("create IO thread failed");
        }
        do {
            /*  no IO thread in idle state, wait a monent */
            usleep(GET_IDLE_THREAD_WAIT_TIME);
            idleDataThread = GetIdleDataThread();
        } while (idleDataThread == NULL);
    }
    pthread_t threadId = idleDataThread->threadId;
    processInfo->threadId = threadId;
    AddDataInfoToThread(processInfo);
    WakeUpDataThread(threadId);
}

int32_t OnReceiveNewConnection(int sessionId)
{
    uint32_t handle = sessionId;
    IpcSkeleton *current = GetCurrentSkeleton();
    if (current == NULL) {
        RPC_LOG_ERROR("current ipcskeleton is nullptr");
        return ERR_FAILED;
    }

    HandleSessionList *stubSession = (HandleSessionList *)malloc(sizeof(HandleSessionList));
    if (stubSession == NULL) {
        RPC_LOG_ERROR("stubSession malloc failed");
        return ERR_FAILED;
    }
    stubSession->handle = handle;
    stubSession->sessionId = sessionId;
    if (AttachStubSession(stubSession) != ERR_NONE) {
        RPC_LOG_ERROR("AttachStubSession failed");
        free(stubSession);
        return ERR_FAILED;
    }
    return HandleNewConnection(RpcGetSessionIdList(), sessionId);
}

void OnDatabusSessionClosed(int sessionId)
{
    if (sessionId < 0) {
        return;
    }

    uint32_t handle = sessionId;
    HandleSessionList *handleSession = QueryStubSession(handle);
    if (handleSession != NULL) {
        DetachStubSession(handleSession);
        free(handleSession);
        RPC_LOG_INFO("OnDatabusSessionClosed called on rpc stub");
        return;
    }

    handleSession = QueryProxySessionBySessionId(sessionId);
    if (handleSession == NULL) {
        RPC_LOG_INFO("OnDatabusSessionClosed query session is null");
        return;
    }
    DetachProxySession(handleSession);

    HandleToIndexList *handeleIndex = QueryHandleToIndex(handleSession->handle);
    if (handeleIndex == NULL) {
        RPC_LOG_INFO("OnDatabusSessionClosed query stub index is null");
        return;
    }
    DetachHandleToIndex(handeleIndex);

    IpcSkeleton *ipcSkeleton  = GetCurrentSkeleton();
    if (ipcSkeleton == NULL) {
        RPC_LOG_ERROR("GetCurrentSkeleton return null");
        return;
    }

    DeathCallback *node = NULL;
    UTILS_DL_LIST_FOR_EACH_ENTRY(node, &ipcSkeleton->objects, DeathCallback, list)
    {
        if (node->handle == handleSession->handle) {
            RPC_LOG_INFO("OnDatabusSessionClosed SendObituary handle %d", node->handle);
            SendObituary(node);
            DeleteDeathCallback(node);
            break;
        }
    }
}

static uint32_t HasCompletePackage(const char *data, uint32_t readCursor, uint32_t len)
{
    const dbinder_transaction_data *tr = (const dbinder_transaction_data *)(data + readCursor);
    if ((tr->magic == DBINDER_MAGICWORD) &&
        (tr->sizeOfSelf <= SOCKET_MAX_BUFF_SIZE + sizeof(dbinder_transaction_data)) &&
        (readCursor + tr->sizeOfSelf <= len)) {
        return (uint32_t)tr->sizeOfSelf;
    }
    return 0;
}

void OnMessageAvailable(int sessionId, const void *data, uint32_t len)
{
    if (sessionId < 0 || data == NULL || len < sizeof(dbinder_transaction_data)) {
        RPC_LOG_ERROR("session has wrong inputs");
        return;
    }

    uint32_t handle = sessionId;
    uint32_t readSize = 0;
    while (readSize + sizeof(dbinder_transaction_data) < len) {
        uint32_t packageSize = HasCompletePackage(data, readSize, len);
        if (packageSize > 0) {
            StartProcessLoop(handle, data, packageSize);
            readSize += packageSize;
        } else {
            // If the current is abnormal, the subsequent is no longer processed.
            break;
        }
    }
}

void UpdateClientSession(int32_t handle, HandleSessionList *sessionObject,
    const char *serviceName, const char *deviceId)
{
    if (handle < 0 || sessionObject == NULL || serviceName == NULL || deviceId == NULL) {
        RPC_LOG_ERROR("UpdateClientSession params invalid");
        return;
    }

    RpcSkeleton *rpcSkeleton = GetCurrentRpcSkeleton();
    if (rpcSkeleton == NULL) {
        return;
    }
    int sessionId = rpcSkeleton->rpcTrans->Connect(serviceName, deviceId, NULL);
    if (sessionId < 0) {
        RPC_LOG_ERROR("UpdateClientSession connect failed");
        return;
    }
    if (WaitForSessionIdReady(RpcGetSessionIdList(), sessionId) != ERR_NONE) {
        RPC_LOG_ERROR("SendDataToRemote connect failed, sessionId=%d", sessionId);
        return;
    }

    sessionObject->handle = handle;
    sessionObject->sessionId = sessionId;
    if (AttachProxySession(sessionObject) != ERR_NONE) {
        RPC_LOG_ERROR("UpdateClientSession AttachProxySession failed");
    }
}

int32_t CreateTransServer(const char *sessionName)
{
    if (sessionName == NULL) {
        return ERR_FAILED;
    }
    RpcSkeleton *rpcSkeleton = GetCurrentRpcSkeleton();
    if (rpcSkeleton == NULL) {
        return ERR_FAILED;
    }

    if (rpcSkeleton->isServerCreated == 0) {
        return ERR_NONE;
    }

    pthread_mutex_lock(&rpcSkeleton->lock);
    if (rpcSkeleton->isServerCreated == -1) {
        if (rpcSkeleton->rpcTrans->StartListen(sessionName, GetRpcTransCallback()) != ERR_NONE) {
            RPC_LOG_ERROR("CreateTransServer failed");
            pthread_mutex_unlock(&rpcSkeleton->lock);
            return ERR_FAILED;
        }
        rpcSkeleton->isServerCreated = 0;
        pthread_mutex_unlock(&rpcSkeleton->lock);
        return SpawnThread(SPAWN_ACTIVE, IF_PROT_DATABUS);
    }
    pthread_mutex_unlock(&rpcSkeleton->lock);

    return ERR_NONE;
}

static int32_t RpcAcquireHandle(int32_t handle)
{
    (void)handle;
    return ERR_NONE;
}

static int32_t RpcReleaseHandle(int32_t handle)
{
    (void)handle;
    return ERR_NONE;
}

static int32_t RpcInvokerSendRequest(SvcIdentity target, uint32_t code, IpcIo *data, IpcIo *reply,
    MessageOption option, uintptr_t *buffer)
{
    RPC_LOG_INFO("RPCInvokerSendRequest called");
    int32_t result;
    uint64_t seqNumber = 0;

    uint32_t userWaitTime = option.waitTime;
    if (userWaitTime > RPC_MAX_SEND_WAIT_TIME) {
        userWaitTime = RPC_MAX_SEND_WAIT_TIME;
    }

    HandleSessionList *sessinoObject = WriteTransaction(BC_TRANSACTION, option, target.handle,
        0, code, data, &seqNumber, 0);
    if (sessinoObject == NULL) {
        return ERR_FAILED;
    }

    if (option.flags & TF_OP_ASYNC) {
        result = SendOrWaitForCompletion(userWaitTime, seqNumber, sessinoObject, NULL, buffer);
    } else {
        result = SendOrWaitForCompletion(userWaitTime, seqNumber, sessinoObject, reply, buffer);
    }

    return result;
}

static int32_t RpcFreeBuffer(void *ptr)
{
    if (ptr != NULL) {
        free(ptr);
    }
    return ERR_NONE;
}

static int32_t RpcSetMaxWorkThread(int32_t maxThreadNum)
{
    (void)maxThreadNum;
    return ERR_NONE;
}

static void RpcJoinThread(bool initiative)
{
    pthread_t threadId = pthread_self();

    ThreadContext *threadContext = GetCurrentThreadContext();
    if (threadContext == NULL) {
        return;
    }
    threadContext->stopWorkThread = false;

    while (threadContext->stopWorkThread == false) {
        AddDataThreadInWait(threadId);
        ThreadProcessInfo *processInfo = PopDataInfoFromThread(threadId);
        if (processInfo != NULL) {
            OnTransaction(processInfo);
            free(processInfo->buffer);
            free(processInfo);
        }
    }
}

void RpcStopWorkThread(void)
{
    IpcSkeleton *current = GetCurrentSkeleton();
    if (current == NULL) {
        return;
    }

    ThreadContext *threadContext = GetCurrentThreadContext();
    if (threadContext == NULL) {
        return;
    }
    threadContext->stopWorkThread = true;
}

static int32_t RpcSetRegistryObject(SvcIdentity target, SvcIdentity *samgr)
{
    (void)target;
    (void)samgr;
    return ERR_NONE;
}

static int32_t RpcAddDeathRecipient(int32_t handle, void *cookie)
{
    (void)handle;
    (void)cookie;
    return ERR_NONE;
}

static int32_t RpcRemoveDeathRecipient(int32_t handle, void *cookie)
{
    (void)handle;
    (void)cookie;
    return ERR_NONE;
}

RemoteInvoker *GetRpcInvoker(void)
{
    if (g_rpcInvoker == NULL) {
        g_rpcInvoker = (RemoteInvoker *)malloc(sizeof(RemoteInvoker));
        if (g_rpcInvoker != NULL) {
            g_rpcInvoker->AcquireHandle = RpcAcquireHandle;
            g_rpcInvoker->ReleaseHandle = RpcReleaseHandle;
            g_rpcInvoker->SendRequest = RpcInvokerSendRequest;
            g_rpcInvoker->FreeBuffer = RpcFreeBuffer;
            g_rpcInvoker->SetMaxWorkThread = RpcSetMaxWorkThread;
            g_rpcInvoker->JoinThread = RpcJoinThread;
            g_rpcInvoker->ExitCurrentThread = RpcStopWorkThread;
            g_rpcInvoker->SetRegistryObject = RpcSetRegistryObject;
            g_rpcInvoker->AddDeathRecipient = RpcAddDeathRecipient;
            g_rpcInvoker->RemoveDeathRecipient = RpcRemoveDeathRecipient;
        }
    }

    return g_rpcInvoker;
}