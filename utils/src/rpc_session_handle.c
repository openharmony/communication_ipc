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

#include "rpc_session_handle.h"

#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>

#include "rpc_log.h"
#include "rpc_errno.h"

static int32_t GetWaitTime(struct timespec *waitTime)
{
#define USECTONSEC 1000
    struct timeval now;
    if (gettimeofday(&now, NULL) != 0) {
        RPC_LOG_ERROR("gettimeofday failed");
        return ERR_FAILED;
    }
    waitTime->tv_sec = now.tv_sec + CONNECT_WAIT_TIME_SECONDS;
    waitTime->tv_nsec = now.tv_usec * USECTONSEC;

    return ERR_NONE;
}

static SessionIdList *FindOrNewSessionIdObject(SessionIdList *sessionIdList, int32_t sessionId)
{
    RPC_LOG_INFO("FindOrNewSessionIdObject sessionId=%d", sessionId);
    if (sessionIdList == NULL) {
        RPC_LOG_ERROR("FindOrNewSessionIdObject sessionIdList is null");
        return NULL;
    }
    pthread_mutex_lock(&sessionIdList->mutex);
    SessionIdList *node = NULL;
    UTILS_DL_LIST_FOR_EACH_ENTRY(node, &sessionIdList->idList, SessionIdList, idList)
    {
        if (node->sessionId == sessionId) {
            RPC_LOG_INFO("find sessionId in sessionIdList");
            pthread_mutex_unlock(&sessionIdList->mutex);
            return node;
        }
    }

    node = (SessionIdList *)malloc(sizeof(SessionIdList));
    if (node == NULL) {
        RPC_LOG_ERROR("FindOrNewSessionIdObject malloc failed");
        pthread_mutex_unlock(&sessionIdList->mutex);
        return NULL;
    }
    memset_s(node, sizeof(SessionIdList), 0, sizeof(SessionIdList));
    (void)pthread_mutex_init(&node->mutex, NULL);
    (void)pthread_cond_init(&node->condition, NULL);
    node->sessionId = sessionId;
    node->isReady = false;

    UtilsListAdd(&sessionIdList->idList, &node->idList);
    pthread_mutex_unlock(&sessionIdList->mutex);
    return node;
}

int32_t WaitForSessionIdReady(SessionIdList *sessionIdList, int32_t sessionId)
{
    if (sessionIdList == NULL) {
        RPC_LOG_ERROR("WaitForSessionIdReady sessionIdList is null");
        return ERR_FAILED;
    }
    if (sessionId <= 0) {
        RPC_LOG_ERROR("invalid sessionid %d", sessionId);
        return ERR_FAILED;
    }
    SessionIdList *sessionIdObject = FindOrNewSessionIdObject(sessionIdList, sessionId);
    if (sessionIdObject == NULL) {
        RPC_LOG_ERROR("FindOrNewSessionIdObject return null");
        return ERR_FAILED;
    }
    pthread_mutex_lock(&sessionIdObject->mutex);
    if (sessionIdObject->isReady) {
        pthread_mutex_unlock(&sessionIdObject->mutex);
        return ERR_NONE;
    }

    struct timespec waitTime;
    if (GetWaitTime(&waitTime) != ERR_NONE) {
        pthread_mutex_unlock(&sessionIdObject->mutex);
        return ERR_FAILED;
    }

    if (pthread_cond_timedwait(&sessionIdObject->condition,
        &sessionIdObject->mutex, &waitTime) == ETIMEDOUT) {
        RPC_LOG_ERROR("WaitForSessionIdReady timeout");
        pthread_mutex_unlock(&sessionIdObject->mutex);
        return ERR_FAILED;
    }

    RPC_LOG_INFO("WaitForSessionIdReady wakeup!");
    int32_t ret = sessionIdObject->isReady ? ERR_NONE : ERR_FAILED;
    pthread_mutex_unlock(&sessionIdObject->mutex);
    return ret;
}

int32_t HandleNewConnection(SessionIdList *sessionIdList, int32_t sessionId)
{
    if (sessionIdList == NULL) {
        RPC_LOG_ERROR("HandleNewConnection sessionIdList is null");
        return ERR_FAILED;
    }
    if (sessionId <= 0) {
        return ERR_FAILED;
    }

    SessionIdList *sessionIdObject = FindOrNewSessionIdObject(sessionIdList, sessionId);
    if (sessionIdObject == NULL) {
        RPC_LOG_ERROR("HandleNewConnection get sessionIdObject null");
        return ERR_FAILED;
    }

    pthread_mutex_lock(&sessionIdObject->mutex);
    if (!sessionIdObject->isReady) {
        sessionIdObject->isReady = true;
        pthread_cond_broadcast(&sessionIdObject->condition);
        RPC_LOG_INFO("HandleNewConnection broadcast thread, sessionId=%d", sessionId);
    }
    pthread_mutex_unlock(&sessionIdObject->mutex);
    return ERR_NONE;
}