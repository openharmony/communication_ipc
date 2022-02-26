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

#ifndef OHOS_IPC_RPC_TYPES_H
#define OHOS_IPC_RPC_TYPES_H

#define ZIPC_PACK_CHARS(c1, c2, c3, c4) ((((c1) << 24)) | (((c2) << 16)) | (((c3) << 8)) | (c4))
#define GET_IDLE_THREAD_WAIT_TIME 1000

enum {
    FIRST_CALL_TRANSACTION = 0x00000001,
    LAST_CALL_TRANSACTION = 0x00ffffff,
    PING_TRANSACTION = ZIPC_PACK_CHARS('_', 'P', 'N', 'G'),
    DUMP_TRANSACTION = ZIPC_PACK_CHARS('_', 'D', 'M', 'P'),
    SHELL_COMMAND_TRANSACTION = ZIPC_PACK_CHARS('_', 'C', 'M', 'D'),
    INTERFACE_TRANSACTION = ZIPC_PACK_CHARS('_', 'N', 'T', 'F'),
    SYSPROPS_TRANSACTION = ZIPC_PACK_CHARS('_', 'S', 'P', 'R'),
    SYNCHRONIZE_REFERENCE = ZIPC_PACK_CHARS('_', 'S', 'Y', 'C'),
    INVOKE_LISTEN_THREAD = ZIPC_PACK_CHARS('_', 'I', 'L', 'T'),
    GET_PROTO_INFO = ZIPC_PACK_CHARS('_', 'G', 'R', 'I'),
    GET_UIDPID_INFO = ZIPC_PACK_CHARS('_', 'G', 'U', 'I'),
    GRANT_DATABUS_NAME = ZIPC_PACK_CHARS('_', 'G', 'D', 'N'),
    DBINDER_OBITUARY_TRANSACTION = ZIPC_PACK_CHARS('_', 'D', 'O', 'T'),
    DBINDER_INCREFS_TRANSACTION = ZIPC_PACK_CHARS('_', 'D', 'I', 'T'),
    DBINDER_DECREFS_TRANSACTION = ZIPC_PACK_CHARS('_', 'D', 'D', 'T'),
    DBINDER_ADD_COMMAUTH = ZIPC_PACK_CHARS('_', 'D', 'A', 'C'),
    TRANS_SYNC = 0,
    TRANS_ASYNC = 1,
};

enum {
    IF_PROT_BINDER = 0,
    IF_PROT_DATABUS = 1,
};

#define SET_MAX_THREADS_DEFAULT 4
#define SET_MAX_THREADS_MAX     16
#define MAX_DEATH_CALLBACK_NUM  4

#define RPC_DEFAULT_SEND_WAIT_TIME 4
#define RPC_MAX_SEND_WAIT_TIME 3000

#if defined(__LITEOS_M__)
#define IF_PROT_DEFAULT IF_PROT_DATABUS
#else
#define IF_PROT_DEFAULT IF_PROT_BINDER
#endif

#endif /* OHOS_IPC_RPC_TYPES_H */