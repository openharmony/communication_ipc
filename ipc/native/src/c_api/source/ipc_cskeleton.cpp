/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "ipc_cskeleton.h"
#include "ipc_error_code.h"
#include "log_tags.h"
#include "ipc_debug.h"
#include "ipc_skeleton.h"
#include "ipc_thread_skeleton.h"

#include <securec.h>

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, OHOS::LOG_ID_IPC_CAPI, "IPCSkeleton" };

static constexpr int MIN_THREAD_NUM = 1;
static constexpr int MAX_THREAD_NUM = 32;

void OH_IPCSkeleton_JoinWorkThread(void)
{
    OHOS::IPCSkeleton::JoinWorkThread();
}

void OH_IPCSkeleton_StopWorkThread(void)
{
    OHOS::IPCSkeleton::StopWorkThread();
}

uint64_t OH_IPCSkeleton_GetCallingTokenId(void)
{
    return OHOS::IPCSkeleton::GetCallingFullTokenID();
}

uint64_t OH_IPCSkeleton_GetFirstTokenId(void)
{
    return OHOS::IPCSkeleton::GetFirstFullTokenID();
}

uint64_t OH_IPCSkeleton_GetSelfTokenId(void)
{
    return OHOS::IPCSkeleton::GetSelfTokenID();
}

uint64_t OH_IPCSkeleton_GetCallingPid(void)
{
    return static_cast<uint64_t>(OHOS::IPCSkeleton::GetCallingPid());
}

uint64_t OH_IPCSkeleton_GetCallingUid(void)
{
    return static_cast<uint64_t>(OHOS::IPCSkeleton::GetCallingUid());
}

int OH_IPCSkeleton_IsLocalCalling(void)
{
    return OHOS::IPCSkeleton::IsLocalCalling() ? 1 : 0;
}

int OH_IPCSkeleton_SetMaxWorkThreadNum(const int maxThreadNum)
{
    if (maxThreadNum < MIN_THREAD_NUM || maxThreadNum > MAX_THREAD_NUM) {
        ZLOGE(LOG_LABEL, "Check param error!");
        return OH_IPC_CHECK_PARAM_ERROR;
    }
    return OHOS::IPCSkeleton::SetMaxWorkThreadNum(maxThreadNum) ? OH_IPC_SUCCESS : OH_IPC_INNER_ERROR;
}

int OH_IPCSkeleton_SetCallingIdentity(const char *identity)
{
    if (identity == nullptr) {
        ZLOGE(LOG_LABEL, "Check param error!");
        return OH_IPC_CHECK_PARAM_ERROR;
    }
    std::string str = identity;
    return OHOS::IPCSkeleton::SetCallingIdentity(str) ? OH_IPC_SUCCESS : OH_IPC_INNER_ERROR;
}

int OH_IPCSkeleton_ResetCallingIdentity(char **identity, int32_t *len, OH_IPC_MemAllocator allocator)
{
    if (identity == nullptr || len == nullptr || allocator == nullptr) {
        ZLOGE(LOG_LABEL, "Check param error!");
        return OH_IPC_CHECK_PARAM_ERROR;
    }
    std::string str(OHOS::IPCSkeleton::ResetCallingIdentity());
    int length = static_cast<int>(str.length()) + 1;
    *identity = static_cast<char*>(allocator(length));
    if (*identity == nullptr) {
        ZLOGE(LOG_LABEL, "Memory allocator failed!");
        return OH_IPC_MEM_ALLOCATOR_ERROR;
    }
    if (memcpy_s(*identity, length, str.c_str(), length) != EOK) {
        ZLOGE(LOG_LABEL, "Memcpy string failed!");
        return OH_IPC_INNER_ERROR;
    }
    *len = length;
    return OH_IPC_SUCCESS;
}

int OH_IPCSkeleton_IsHandlingTransaction(void)
{
    return (OHOS::IPCThreadSkeleton::GetActiveInvoker() != nullptr) ? 1 : 0;
}
