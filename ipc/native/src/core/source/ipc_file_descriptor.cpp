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

#include "ipc_file_descriptor.h"

#include "ipc_debug.h"
#include "ipc_thread_skeleton.h"
#include "log_tags.h"

namespace OHOS {
using namespace OHOS::HiviewDFX;
#ifdef CONFIG_IPC_SINGLE
using namespace IPC_SINGLE;
#endif
static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "IPCFileDescriptor" };

IPCFileDescriptor::IPCFileDescriptor() : Parcelable(true), fd_(INVALID_FD) {}

IPCFileDescriptor::IPCFileDescriptor(int fd) : Parcelable(true)
{
    fd_ = fd;
}

IPCFileDescriptor::~IPCFileDescriptor()
{
    fd_ = INVALID_FD;
}

int IPCFileDescriptor::GetFd() const
{
    return fd_;
}

void IPCFileDescriptor::SetFd(int fd)
{
    fd_ = fd;
}

bool IPCFileDescriptor::Marshalling(Parcel &parcel) const
{
    if (fd_ < 0) {
        ZLOGE(LABEL, "%s:IPCFileDescriptor: fd %d is invalid", __func__, fd_);
        return false;
    }
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DEFAULT);
    if (invoker != nullptr) {
        return invoker->WriteFileDescriptor(parcel, fd_, false);
    }

    return false;
}

bool IPCFileDescriptor::Marshalling(Parcel &parcel, const sptr<IPCFileDescriptor> &object)
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DEFAULT);

    if (invoker != nullptr) {
        return invoker->WriteFileDescriptor(parcel, object->GetFd(), false);
    }

    return false;
}

IPCFileDescriptor *IPCFileDescriptor::Unmarshalling(Parcel &parcel)
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DEFAULT);
    int fd = -1;

    if (invoker != nullptr) {
        fd = invoker->ReadFileDescriptor(parcel);
    }

    if (fd < 0) {
        return nullptr;
    }

    return new IPCFileDescriptor(fd);
}
} // namespace OHOS
