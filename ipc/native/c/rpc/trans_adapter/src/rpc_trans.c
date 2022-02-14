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

#include <stddef.h>

#if defined(RPC_SOFTBUS_TRANS)
#include "rpc_softbus_trans.h"
#elif defined(RPC_SOCKET_TRANS)
#include "rpc_socket_trans.h"
#endif

TransInterface *GetRpcTrans(void)
{
#if defined(RPC_SOFTBUS_TRANS)
    return GetSoftbusTrans();
#elif defined(RPC_SOCKET_TRANS)
    return GetSocketTrans();
#endif

    return NULL;
}