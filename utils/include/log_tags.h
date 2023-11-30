/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_COMMUNICATION_LOG_TAGS_H
#define OHOS_COMMUNICATION_LOG_TAGS_H

namespace OHOS {
const unsigned int LOG_ID_IPC_BASE = 0xD0057C0;
const unsigned int LOG_ID_TEST = 0xD000F00;

const unsigned int LOG_ID_IPC_COMMON = LOG_ID_IPC_BASE | 0x01;
const unsigned int LOG_ID_IPC_PROXY = LOG_ID_IPC_BASE | 0x02;
const unsigned int LOG_ID_IPC_STUB = LOG_ID_IPC_BASE | 0x03;
const unsigned int LOG_ID_IPC_THREAD_SKELETON = LOG_ID_IPC_BASE | 0x04;
const unsigned int LOG_ID_IPC_PROC_SKELETON = LOG_ID_IPC_BASE | 0x05;
const unsigned int LOG_ID_IPC_BINDER_INVOKER = LOG_ID_IPC_BASE | 0x06;
const unsigned int LOG_ID_IPC_BINDER_CONNECT = LOG_ID_IPC_BASE | 0x07;
const unsigned int LOG_ID_IPC_NAPI = LOG_ID_IPC_BASE | 0x08;
const unsigned int LOG_ID_IPC_OTHER = LOG_ID_IPC_BASE | 0x09;

const unsigned int LOG_ID_RPC = LOG_ID_IPC_BASE | 0x11;
const unsigned int LOG_ID_RPC_DBINDER_SER = LOG_ID_IPC_BASE | 0x12;
} // namespace OHOS
#endif // OHOS_COMMUNICATION_LOG_TAGS_H
