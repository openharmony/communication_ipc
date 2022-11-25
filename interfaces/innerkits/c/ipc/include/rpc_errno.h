/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_IPC_RPC_ERRNO_H
#define OHOS_IPC_RPC_ERRNO_H

enum IpcRpcErrNo {
    ERR_NONE = 0,
    ERR_FAILED = -1,
    ERR_INVALID_PARAM = -2,
    ERR_IPC_SKELETON_NOT_INIT = -3,
    ERR_THREAD_INVOKER_NOT_INIT = -4,
    ERR_NOT_RPC = -16,
    ERR_DEAD_OBJECT = -32,
    IPC_INVOKER_INVALID_DATA = -33,
    IPC_INVOKER_FAILED_REPLY = -34,
    IPC_INVOKER_UNKNOWN_CODE = -35,
    IPC_INVOKER_IOCTL_FAILED = -36,
};

#endif /* OHOS_IPC_RPC_ERRNO_H */

