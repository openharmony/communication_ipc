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

#ifndef OHOS_IPC_BINDER_INVOKER_H
#define OHOS_IPC_BINDER_INVOKER_H

#include <unistd.h>
#include <sys/types.h>
#include "binder_connector.h"
#include "iremote_invoker.h"
#include "invoker_factory.h"

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
namespace IPC_SINGLE {
#endif

class BinderInvoker : public IRemoteInvoker {
public:
    class BinderAllocator : public DefaultAllocator {
        void Dealloc(void *data) override;

        friend BinderInvoker;
    };

    BinderInvoker();

    ~BinderInvoker() = default;

    bool AcquireHandle(int32_t handle) override;

    bool ReleaseHandle(int32_t handle) override;

    bool PingService(int32_t handle) override;

    bool AddDeathRecipient(int32_t handle, void *cookie) override;

    bool RemoveDeathRecipient(int32_t handle, void *cookie) override;

    int GetObjectRefCount(const IRemoteObject *object) override;

    bool SetMaxWorkThread(int maxThreadNum) override;

    void JoinThread(bool initiative) override;

    void JoinProcessThread(bool initiative) override;

    void FreeBuffer(void *data) override;

    void StopWorkThread() override;

    bool SetRegistryObject(sptr<IRemoteObject> &object) override;

    int SendRequest(int handle, uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override;

    int SendReply(MessageParcel &reply, uint32_t flags, int32_t result) override;

    bool FlattenObject(Parcel &parcel, const IRemoteObject *object) const override;

    IRemoteObject *UnflattenObject(Parcel &parcel) override;

    int ReadFileDescriptor(Parcel &parcel) override;

    bool WriteFileDescriptor(Parcel &parcel, int fd, bool takeOwnership) override;

    pid_t GetCallerPid() const override;

    uid_t GetCallerUid() const override;

    uint32_t GetStatus() const override;

    bool IsLocalCalling() override;

    void SetStatus(uint32_t status);

    std::string GetLocalDeviceID() override;

    std::string GetCallerDeviceID() const override;

    int FlushCommands(IRemoteObject *object) override;

    std::string ResetCallingIdentity() override;

    bool SetCallingIdentity(std::string &identity) override;

    void ExitCurrentThread();

#ifndef CONFIG_IPC_SINGLE
    int TranslateProxy(uint32_t handle, uint32_t flag) override;

    int TranslateStub(binder_uintptr_t cookie, binder_uintptr_t ptr, uint32_t flag, int cmd) override;

    sptr<IRemoteObject> GetSAMgrObject() override;
#endif

protected:
    bool isMainWorkThread;
    bool stopWorkThread;
    pid_t callerPid_;
    pid_t callerUid_;

private:
    int TransactWithDriver(bool doRead = true);

    bool WriteTransaction(int cmd, uint32_t flags, int32_t handle, uint32_t code, const MessageParcel &data,
        const int *status);

    int WaitForCompletion(MessageParcel *reply = nullptr, int32_t *acquireResult = nullptr);

    void OnAttemptAcquire();

    void OnRemoveRecipientDone();

    void StartWorkLoop();

    void OnBinderDied();

    void OnAcquireObject(uint32_t cmd);

    void OnReleaseObject(uint32_t cmd);

    void OnTransaction(const uint8_t *);

    int HandleCommands(uint32_t cmd);

    int HandleReply(MessageParcel *reply);

private:
    DISALLOW_COPY_AND_MOVE(BinderInvoker);
    static constexpr int IPC_DEFAULT_PARCEL_SIZE = 256;
    Parcel input_;
    Parcel output_;
    BinderConnector *binderConnector_;
    uint32_t status_;
    static inline InvokerDelegator<BinderInvoker> delegator_ = { IRemoteObject::IF_PROT_BINDER };
};
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS
#endif // OHOS_IPC_BINDER_INVOKER_H
