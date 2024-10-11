/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "skeleton_wrapper.h"

#include "ipc_skeleton.h"
#include "ipc_thread_skeleton.h"
namespace OHOS {
namespace IpcRust {
using namespace IPC_SINGLE;

bool SetMaxWorkThreadNum(int maxThreadNum)
{
    return OHOS::IPCSkeleton::SetMaxWorkThreadNum(maxThreadNum);
}

void JoinWorkThread()
{
    return OHOS::IPCSkeleton::JoinWorkThread();
}

void StopWorkThread()
{
    return OHOS::IPCSkeleton::StopWorkThread();
}

uint64_t GetCallingPid()
{
    return OHOS::IPCSkeleton::GetCallingPid();
}

uint64_t GetCallingRealPid()
{
    return OHOS::IPCSkeleton::GetCallingRealPid();
}

uint64_t GetCallingUid()
{
    return OHOS::IPCSkeleton ::GetCallingUid();
}

uint32_t GetCallingTokenID()
{
    return OHOS::IPCSkeleton ::GetCallingTokenID();
}

uint64_t GetCallingFullTokenID()
{
    return OHOS::IPCSkeleton ::GetCallingFullTokenID();
}

uint32_t GetFirstTokenID()
{
    return OHOS::IPCSkeleton ::GetFirstTokenID();
}

uint64_t GetFirstFullTokenID()
{
    return OHOS::IPCSkeleton ::GetFirstFullTokenID();
}

uint64_t GetSelfTokenID()
{
    return OHOS::IPCSkeleton::GetSelfTokenID();
}

rust::string GetLocalDeviceID()
{
    return OHOS::IPCSkeleton::GetLocalDeviceID();
}

rust::string GetCallingDeviceID()
{
    return OHOS::IPCSkeleton::GetCallingDeviceID();
}

bool IsLocalCalling()
{
    return OHOS::IPCSkeleton::IsLocalCalling();
}

std::unique_ptr<IRemoteObjectWrapper> GetContextObject()
{
    auto wrapper = std::make_unique<IRemoteObjectWrapper>();

    wrapper->is_raw_ = true;
    wrapper->raw_ = OHOS::IPCSkeleton::GetContextObject();

    return wrapper;
}

int FlushCommands(IRemoteObjectWrapper &object)
{
    return IPCSkeleton::FlushCommands(object.GetInner());
}

rust::string ResetCallingIdentity()
{
    return IPCSkeleton::ResetCallingIdentity();
}

bool SetCallingIdentity(rust::str identity)
{
    auto s = std::string(identity);
    return IPCSkeleton::SetCallingIdentity(s);
}

bool IsHandlingTransaction()
{
    if (IPCThreadSkeleton::GetActiveInvoker() != nullptr) {
        return true;
    }

    return false;
}

} // namespace IpcRust
} // namespace OHOS