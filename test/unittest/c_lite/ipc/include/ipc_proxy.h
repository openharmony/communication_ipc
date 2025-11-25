/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_IPC_PROXY_H
#define OHOS_IPC_PROXY_H

enum {
    GET_SYSTEM_ABILITY_TRANSACTION = 1,
    ADD_SYSTEM_ABILITY_TRANSACTION = 2,
};

enum {
    CLIENT_OP_ADD = 1,
    CLIENT_OP_SUB = 2,
    CLIENT_OP_PRINT = 3,
};

enum {
    SERVER_OP_ADD = 1,
    SERVER_OP_SUB = 2,
    SERVER_OP_MULTI = 3,
    SERVER_OP_ADD_SERVICE = 4,
};

#define IPC_MAX_SIZE 128

enum {
    SERVER_SA_ID1 = 15
};

#define OP_A 12
#define OP_B 17

#endif // OHOS_IPC_PROXY_H