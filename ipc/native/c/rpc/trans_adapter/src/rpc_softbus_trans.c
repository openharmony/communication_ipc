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

#include "rpc_softbus_trans.h"

#include <stddef.h>
#include <unistd.h>

#include "dbinder_types.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "securec.h"
#include "session.h"
#include "softbus_bus_center.h"

static SessionAttribute g_sessionAttr = {.dataType = TYPE_BYTES};

static int32_t StartListen(const char *saSessionName, void *cb)
{
    if (saSessionName == NULL) {
        RPC_LOG_ERROR("StartListen saSessionName is null");
        return ERR_FAILED;
    }
    if (cb == NULL) {
        RPC_LOG_ERROR("StartListen callback is null");
        return ERR_FAILED;
    }

    int ret = CreateSessionServer(saSessionName, saSessionName, (ISessionListener *)cb);
    if (ret != 0) {
        RPC_LOG_ERROR("CreateSessionServer failed, error=%d", ret);
        return ERR_FAILED;
    }
    return ERR_NONE;
}

static int32_t StopListen(const char *saSessionName)
{
    if (saSessionName == NULL) {
        RPC_LOG_ERROR("StopListen saSessionName is null");
        return ERR_FAILED;
    }

    int ret = RemoveSessionServer(saSessionName, saSessionName);
    if (ret != 0) {
        RPC_LOG_ERROR("RemoveSessionServer failed, error=%d", ret);
        return ERR_FAILED;
    }
    return ERR_NONE;
}

static int32_t Connect(const char *saSessionName, const char *peerDeviceId, void *args)
{
    if (saSessionName == NULL) {
        RPC_LOG_ERROR("Connect SaSessionName is null");
        return ERR_FAILED;
    }
    if (peerDeviceId == NULL) {
        RPC_LOG_ERROR("Connect peerDeviceId is null");
        return ERR_FAILED;
    }

    int ret = OpenSession(saSessionName, saSessionName, peerDeviceId, "", &g_sessionAttr);
    printf("SOFTBUS Connect deviceid %s\n", peerDeviceId);
    if (ret < 0) {
        RPC_LOG_ERROR("Connect OpenSession failed, error=%d", ret);
        return ERR_FAILED;
    }
    return (int32_t)ret;
}

static int32_t Disconnect(int32_t sessionId)
{
    if (sessionId < 0) {
        RPC_LOG_ERROR("Disconnect invalid sessionId=%d", sessionId);
        return ERR_FAILED;
    }

    CloseSession(sessionId);
    return ERR_NONE;
}

static int32_t Send(int32_t sessionId, const void *data, uint32_t len)
{
    if (sessionId < 0) {
        RPC_LOG_ERROR("Send invalid sessionId=%d", sessionId);
        return ERR_FAILED;
    }
    if (data == NULL) {
        RPC_LOG_ERROR("Send data is null");
        return ERR_FAILED;
    }

    int ret = SendBytes(sessionId, data, len);
    if (ret != 0) {
        RPC_LOG_ERROR("Send failed, error=%d", ret);
        return ERR_FAILED;
    }
    return ERR_NONE;
}

static int32_t GetLocalDeviceID(const char *saSessionName, char *deviceId)
{
    if (saSessionName == NULL) {
        RPC_LOG_ERROR("GetLocalDeviceID SaSessionName is null");
        return NULL;
    }
    NodeBasicInfo nodeInfo;
    int32_t ret = GetLocalNodeDeviceInfo(saSessionName, &nodeInfo);
    if (ret != 0) {
        RPC_LOG_ERROR("GetLocalDeviceID failed, error=%d", ret);
        return NULL;
    }
    if (memcpy_s(deviceId, DEVICEID_LENGTH + 1, nodeInfo.networkId, DEVICEID_LENGTH + 1) != EOK) {
        RPC_LOG_ERROR("GetLocalDeviceID memcpy failed");
        return ERR_FAILED;
    }
    return ERR_NONE;
}

static TransInterface g_softbusTrans = {
    .StartListen = StartListen,
    .StopListen = StopListen,
    .Connect = Connect,
    .Disconnect = Disconnect,
    .Send = Send,
    .GetLocalDeviceID = GetLocalDeviceID,
};

TransInterface *GetSoftbusTrans(void)
{
    return &g_softbusTrans;
}