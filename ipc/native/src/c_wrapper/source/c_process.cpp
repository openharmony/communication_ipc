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

#include "c_process.h"

#include <securec.h>
#include "c_remote_object_internal.h"
#include "log_tags.h"
#include "ipc_debug.h"
#include "ipc_skeleton.h"

using namespace OHOS;
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC, "CProcess" };

CRemoteObject *GetContextManager(void)
{
    sptr<IRemoteObject> saMgr = IPCSkeleton::GetContextObject();
    if (saMgr == nullptr) {
        return nullptr;
    }
    CRemoteObject *holder = new (std::nothrow) CRemoteObjectHolder();
    if (holder == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s: create samgr proxy holder failed\n", __func__);
        return nullptr;
    }
    holder->IncStrongRef(nullptr);
    holder->remote_ = saMgr;
    return holder;
}

void JoinWorkThread(void)
{
    IPCSkeleton::JoinWorkThread();
}

void StopWorkThread(void)
{
    IPCSkeleton::StopWorkThread();
}

uint64_t GetCallingTokenId(void)
{
    return IPCSkeleton::GetCallingFullTokenID();
}

uint64_t GetFirstToekenId(void)
{
    return IPCSkeleton::GetFirstFullTokenID();
}

uint64_t GetSelfToekenId(void)
{
    return IPCSkeleton::GetSelfTokenID();
}

uint64_t GetCallingPid(void)
{
    return static_cast<uint64_t>(IPCSkeleton::GetCallingPid());
}

uint64_t GetCallingUid(void)
{
    return static_cast<uint64_t>(IPCSkeleton::GetCallingUid());
}

bool SetMaxWorkThreadNum(int maxThreadNum)
{
    return IPCSkeleton::SetMaxWorkThreadNum(maxThreadNum);
}

bool IsLocalCalling(void)
{
    return IPCSkeleton::IsLocalCalling();
}

bool GetLocalDeviceID(void *value, OnCParcelBytesAllocator allocator)
{
    std::string str(IPCSkeleton::GetLocalDeviceID());
    char *buffer = nullptr;
    bool isSuccess = allocator(value, &buffer, str.length());
    if (!isSuccess) {
        ZLOGE(LOG_LABEL, "%{public}s: allocate string buffer is null\n", __func__);
        return false;
    }
    if (str.length() > 0 && memcpy_s(buffer, str.length(), str.data(), str.length()) != EOK) {
        ZLOGE(LOG_LABEL, "%{public}s: memcpy string failed\n", __func__);
        return false;
    }
    return true;
}
bool GetCallingDeviceID(void *value, OnCParcelBytesAllocator allocator)
{
    std::string str(IPCSkeleton::GetCallingDeviceID());
    char *buffer = nullptr;
    bool isSuccess = allocator(value, &buffer, str.length());
    if (!isSuccess) {
        ZLOGE(LOG_LABEL, "%{public}s: allocate string buffer is null\n", __func__);
        return false;
    }
    if (str.length() > 0 && memcpy_s(buffer, str.length(), str.data(), str.length()) != EOK) {
        ZLOGE(LOG_LABEL, "%{public}s: memcpy string failed\n", __func__);
        return false;
    }
    return true;
}

bool SetCallingIdentity(const char *identity)
{
    if (identity == nullptr) {
        return false;
    }
    std::string str = identity;
    return IPCSkeleton::SetCallingIdentity(str);
}

bool ResetCallingIdentity(void *value, OnCParcelBytesAllocator allocator)
{
    std::string str(IPCSkeleton::ResetCallingIdentity());
    char *buffer = nullptr;
    bool isSuccess = allocator(value, &buffer, str.length());
    if (!isSuccess) {
        ZLOGE(LOG_LABEL, "%{public}s: allocate string buffer is null\n", __func__);
        return false;
    }
    if (str.length() > 0 && memcpy_s(buffer, str.length(), str.data(), str.length()) != EOK) {
        ZLOGE(LOG_LABEL, "%{public}s: memcpy string failed\n", __func__);
        return false;
    }
    return true;
}