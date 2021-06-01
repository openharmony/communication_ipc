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

#include "ipc_skeleton.h"
#include "ipc_process_skeleton.h"
#include "ipc_thread_skeleton.h"

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
using namespace IPC_SINGLE;
#endif

void IPCSkeleton::JoinWorkThread()
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    if (current != nullptr) {
        current->JoinWorkThread(IRemoteObject::IF_PROT_DEFAULT);
    }
}

void IPCSkeleton::StopWorkThread()
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    if (current != nullptr) {
        current->StopWorkThread(IRemoteObject::IF_PROT_DEFAULT);
    }
}

bool IPCSkeleton::SetContextObject(sptr<IRemoteObject> &object)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current != nullptr) {
        return current->SetRegistryObject(object);
    }
    return false;
}

sptr<IRemoteObject> IPCSkeleton::GetContextObject()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current != nullptr) {
        return current->GetRegistryObject();
    }
    return nullptr;
}

bool IPCSkeleton::SetMaxWorkThreadNum(int maxThreadNum)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current != nullptr) {
        // first thread have started at IPCProcessSkeleton instances
        return current->SetMaxWorkThread(maxThreadNum);
    }
    return false;
}

pid_t IPCSkeleton::GetCallingPid()
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetActiveInvoker();
    if (invoker != nullptr) {
        return invoker->GetCallerPid();
    }
    return getpid();
}

pid_t IPCSkeleton::GetCallingUid()
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetActiveInvoker();
    if (invoker != nullptr) {
        return invoker->GetCallerUid();
    }
    return getuid();
}

std::string IPCSkeleton::GetLocalDeviceID()
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetActiveInvoker();
    if (invoker != nullptr) {
        return invoker->GetLocalDeviceID();
    }
    return "";
}

std::string IPCSkeleton::GetCallingDeviceID()
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetActiveInvoker();
    if (invoker != nullptr) {
        return invoker->GetCallerDeviceID();
    }
    return "";
}

IPCSkeleton &IPCSkeleton::GetInstance()
{
    static IPCSkeleton skeleton;
    return skeleton;
}

bool IPCSkeleton::IsLocalCalling()
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetActiveInvoker();
    if (invoker != nullptr) {
        return invoker->IsLocalCalling();
    }
    return true;
}

int IPCSkeleton::FlushCommands(IRemoteObject *object)
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetProxyInvoker(object);
    if (invoker == nullptr) {
        return IPC_SKELETON_NULL_OBJECT_ERR;
    }

    return invoker->FlushCommands(object);
}

std::string IPCSkeleton::ResetCallingIdentity()
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetActiveInvoker();
    if (invoker != nullptr) {
        return invoker->ResetCallingIdentity();
    }
    return "";
}

bool IPCSkeleton::SetCallingIdentity(std::string &identity)
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetActiveInvoker();
    if (invoker != nullptr) {
        return invoker->SetCallingIdentity(identity);
    }

    return true;
}
}  // namespace OHOS
