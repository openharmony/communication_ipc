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

#include "binder_debug.h"
#include "sys_binder.h"

namespace OHOS {
const std::string &BinderDebug::ToString(int value)
{
    static BinderDebug instance;
    return instance.GetErrorDesc(value);
}

ErrorMap &BinderDebug::GetErrorMap()
{
    static ErrorMap errorMap = { { BR_ERROR, "BR_ERROR" },
                                 { BR_OK, "BR_OK" },
                                 { BR_TRANSACTION, "BR_TRANSACTION" },
                                 { BR_REPLY, "BR_REPLY" },
                                 { BR_ACQUIRE_RESULT, "BR_ACQUIRE_RESULT" },
                                 { BR_DEAD_REPLY, "BR_DEAD_REPLY" },
                                 { BR_TRANSACTION_COMPLETE, "BR_TRANSACTION_COMPLETE" },
                                 { BR_INCREFS, "BR_INCREFS" },
                                 { BR_ACQUIRE, "BR_ACQUIRE" },
                                 { BR_RELEASE, "BR_RELEASE" },
                                 { BR_DECREFS, "BR_DECREFS" },
                                 { BR_ATTEMPT_ACQUIRE, "BR_ATTEMPT_ACQUIRE" },
                                 { BR_NOOP, "BR_NOOP" },
                                 { BR_SPAWN_LOOPER, "BR_SPAWN_LOOPER" },
                                 { BR_FINISHED, "BR_FINISHED" },
                                 { BR_DEAD_BINDER, "BR_DEAD_BINDER" },
                                 { BR_CLEAR_DEATH_NOTIFICATION_DONE, "BR_CLEAR_DEATH_NOTIFICATION_DONE" },
                                 { BR_FAILED_REPLY, "BR_FAILED_REPLY" },
                                 { BC_TRANSACTION, "BC_TRANSACTION" },
                                 { BC_REPLY, "BC_REPLY" },
                                 { BC_ACQUIRE_RESULT, "BC_ACQUIRE_RESULT" },
                                 { BC_FREE_BUFFER, "BC_FREE_BUFFER" },
                                 { BC_INCREFS, "BC_INCREFS" },
                                 { BC_ACQUIRE, "BC_ACQUIRE" },
                                 { BC_RELEASE, "BC_RELEASE" },
                                 { BC_DECREFS, "BC_DECREFS" },
                                 { BC_INCREFS_DONE, "BC_INCREFS_DONE" },
                                 { BC_ACQUIRE_DONE, "BC_ACQUIRE_DONE" },
                                 { BC_ATTEMPT_ACQUIRE, "BC_ATTEMPT_ACQUIRE" },
                                 { BC_REGISTER_LOOPER, "BC_REGISTER_LOOPER" },
                                 { BC_ENTER_LOOPER, "BC_ENTER_LOOPER" },
                                 { BC_EXIT_LOOPER, "BC_EXIT_LOOPER" },
                                 { BC_REQUEST_DEATH_NOTIFICATION, "BC_REQUEST_DEATH_NOTIFICATION" },
                                 { BC_CLEAR_DEATH_NOTIFICATION, "BC_CLEAR_DEATH_NOTIFICATION" },
                                 { BC_DEAD_BINDER_DONE, "BC_DEAD_BINDER_DONE" } };
    return errorMap;
}
} // namespace OHOS