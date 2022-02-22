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

#include "rpc_trans_callback.h"

#include "dbinder_invoker.h"
#include "rpc_errno.h"
#include "rpc_log.h"

static int32_t OnConnected(int32_t sessionId, int32_t result)
{
    if (sessionId < 0 || result != 0) {
        RPC_LOG_ERROR("fail to open session because of wrong channel ID");
        return ERR_FAILED;
    }
    RPC_LOG_INFO("rpc OnConnected callback, receive sessionId: %d", sessionId);
    return OnReceiveNewConnection(sessionId);
}

static int32_t OnDisconnected(int32_t sessionId)
{
    RPC_LOG_INFO("rpc OnDisconnected callback, receive sessionId: %d", sessionId);
    OnDatabusSessionClosed(sessionId);
    return ERR_NONE;
}

static int32_t OnRecieved(int32_t sessionId, const void *data, uint32_t len)
{
    RPC_LOG_INFO("rpc OnRecieved callback, receive sessionId: %d", sessionId);
    OnMessageAvailable(sessionId, data, len);
    return ERR_NONE;
}

static TransCallback g_sessionListener = {
    .OnConnected = OnConnected,
    .OnDisconnected = OnDisconnected,
    .OnRecieved = OnRecieved
};

TransCallback *GetRpcTransCallback(void)
{
    RPC_LOG_INFO("GetTransCallback rpc");
    return &g_sessionListener;
}