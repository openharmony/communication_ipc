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

#include "iremote_broker.h"
#include "ipc_types.h"
#include "ipc_debug.h"
#include "ipc_object_proxy.h"
#include "ipc_thread_skeleton.h"

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
using namespace IPC_SINGLE;
#endif

bool IRemoteObject::CheckObjectLegality() const
{
    return false;
}

bool IRemoteObject::Marshalling(Parcel &parcel) const
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DEFAULT);

    if (invoker != nullptr) {
        return invoker->FlattenObject(parcel, this);
    }

    return false;
}

bool IRemoteObject::Marshalling(Parcel &parcel, const sptr<IRemoteObject> &object)
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DEFAULT);
    if (invoker != nullptr) {
        return invoker->FlattenObject(parcel, object);
    }

    return false;
}

IRemoteObject *IRemoteObject::Unmarshalling(Parcel &parcel)
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DEFAULT);

    if (invoker != nullptr) {
        return invoker->UnflattenObject(parcel);
    }

    return nullptr;
}

std::u16string IRemoteObject::GetObjectDescriptor() const
{
    return descriptor_;
}

sptr<IRemoteBroker> IRemoteObject::AsInterface()
{
    return nullptr;
}

bool IRemoteObject::IsProxyObject() const
{
    return true;
}

IRemoteObject::IRemoteObject(std::u16string descriptor) : descriptor_(descriptor)
{
    ExtendObjectLifetime();
    asRemote_ = true;
}
} // namespace OHOS
