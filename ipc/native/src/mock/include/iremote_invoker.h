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

#ifndef OHOS_IPC_IREMOTE_INVOKER_H
#define OHOS_IPC_IREMOTE_INVOKER_H

#include <unistd.h>
#include <sys/types.h>
#include "parcel.h"
#include "sys_binder.h"
#include "iremote_object.h"
#include "ipc_file_descriptor.h"

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
namespace IPC_SINGLE {
#endif

class IRemoteInvoker {
public:
    enum {
        IDLE_INVOKER,
        ACTIVE_INVOKER,
    };
    virtual ~IRemoteInvoker() = default;
    virtual bool AcquireHandle(int32_t handle) = 0;

    virtual bool ReleaseHandle(int32_t handle) = 0;

    virtual bool PingService(int32_t handle) = 0;

    virtual int SendReply(MessageParcel &reply, uint32_t flags, int32_t result) = 0;

    virtual int SendRequest(int handle, uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) = 0;

    virtual bool AddDeathRecipient(int32_t handle, void *cookie) = 0;

    virtual int GetObjectRefCount(const IRemoteObject *object) = 0;

    virtual bool RemoveDeathRecipient(int32_t handle, void *cookie) = 0;

    virtual bool SetMaxWorkThread(int maxThreadNum) = 0;

    virtual void JoinThread(bool initiative) = 0;

    virtual void JoinProcessThread(bool initiative) = 0;

    virtual void StopWorkThread() = 0;

    virtual void FreeBuffer(void *data) = 0;

    virtual bool SetRegistryObject(sptr<IRemoteObject> &object) = 0;

    virtual pid_t GetCallerPid() const = 0;

    virtual uid_t GetCallerUid() const = 0;

    virtual uint32_t GetStatus() const = 0;

    virtual bool IsLocalCalling() = 0;

    virtual std::string GetLocalDeviceID() = 0;

    virtual std::string GetCallerDeviceID() const = 0;

    virtual bool FlattenObject(Parcel &parcel, const IRemoteObject *object) const = 0;

    virtual IRemoteObject *UnflattenObject(Parcel &parcel) = 0;

    virtual int ReadFileDescriptor(Parcel &parcel) = 0;

    virtual bool WriteFileDescriptor(Parcel &parcel, int fd, bool takeOwnership) = 0;

    virtual int FlushCommands(IRemoteObject *object) = 0;

    virtual std::string ResetCallingIdentity() = 0;

    virtual bool SetCallingIdentity(std::string &identity) = 0;

#ifndef CONFIG_IPC_SINGLE
    virtual sptr<IRemoteObject> GetSAMgrObject() = 0;

    virtual int TranslateProxy(uint32_t handle, uint32_t flag) = 0;

    virtual int TranslateStub(binder_uintptr_t cookie, binder_uintptr_t ptr, uint32_t flag, int cmd) = 0;
#endif
};
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS
#endif // OHOS_IPC_IREMOTE_INVOKER_H
