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

#include "rpc_trans.h"

#include <stdbool.h>

#include "dbinder_service_inner.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "rpc_session_handle.h"


static int32_t OnConnected(int32_t sessionId, int32_t result)
{
    if (sessionId <= 0 || result != 0) {
        RPC_LOG_INFO("dbinder OnConnected failed, receive sessionId=%d, result=%d", sessionId, result);
        return ERR_FAILED;
    }
    RPC_LOG_INFO("dbinder OnConnected callback, receive sessionId: %d", sessionId);
    return HandleNewConnection(GetSessionIdList(), sessionId);
}

static int32_t OnDisconnected(int32_t sessionId)
{
    RPC_LOG_INFO("dbinder OnDisconnected callback, receive sessionId: %d", sessionId);
    return ERR_NONE;
}

static int32_t OnRecieved(int32_t sessionId, const void *data, uint32_t len)
{
    RPC_LOG_INFO("dbinder OnRecieved callback, receive sessionId: %d", sessionId);
    if (data == NULL) {
        RPC_LOG_ERROR("OnRecieved failed, data is null");
        return ERR_FAILED;
    }
    if (len != sizeof(DHandleEntryTxRx)) {
        RPC_LOG_ERROR("OnRecieved received data length %d, excepted length %d", len, sizeof(DHandleEntryTxRx));
        return ERR_FAILED;
    }

    DHandleEntryTxRx *handleEntry = (DHandleEntryTxRx *)data;
    if (OnRemoteMessageTask(handleEntry) != ERR_NONE) {
        RPC_LOG_ERROR("OnRemoteMessageTask failed");
        return ERR_FAILED;
    }

    return ERR_NONE;
}

static TransCallback g_sessionListener = {
    .OnConnected = OnConnected,
    .OnDisconnected = OnDisconnected,
    .OnRecieved = OnRecieved
};

TransCallback *GetDBinderTransCallback(void)
{
    RPC_LOG_INFO("GetTransCallback dbinder");
    return &g_sessionListener;
}