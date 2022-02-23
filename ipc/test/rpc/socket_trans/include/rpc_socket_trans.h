/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_RPC_SOCKET_TRANS_H
#define OHOS_RPC_SOCKET_TRANS_H

#include "rpc_trans.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_BACKLOG   4
#define DEFAULT_PACKET_SIZE 1024
#define DEFAULT_HASH_OFFSET 3
static char const *SOCKET_SERVER_ADDR = "0.0.0.0";
static char const *DEFAULT_NET_INTERFACE = "eth0";
static const uint16_t DEFAULT_HASH_SEED = 5381;
static const uint16_t DEFAULT_PORT_MIN = 10000;

TransInterface *GetSocketTrans(void);

#ifdef __cplusplus
}
#endif
#endif // OHOS_RPC_SOCKET_TRANS_H