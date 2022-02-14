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

#ifndef OHOS_RPC_TRANS_H
#define OHOS_RPC_TRANS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int32_t (*OnConnected)(int32_t sessionId, int32_t result);
    int32_t (*OnDisconnected)(int32_t sessionId);
    int32_t (*OnRecieved)(int32_t sessionId, const void *data, uint32_t len);
} TransCallback;

typedef struct {
    int32_t (*StartListen)(const char *SaSessionName, void *cb);
    int32_t (*StopListen)(const char *SaSessionName);
    int32_t (*Connect)(const char *SaSessionName, const char *peerDeviceId, void *args);
    int32_t (*Disconnect)(int32_t sessionId);
    int32_t (*Send)(int32_t sessionId, const void *data, uint32_t len);
    int32_t (*GetLocalDeviceID)(const char *SaSessionName, char *deviceId);
} TransInterface;

TransInterface *GetRpcTrans(void);

#ifdef __cplusplus
}
#endif
#endif // OHOS_RPC_TRANS_H