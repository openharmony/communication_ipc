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
#include "process_skeleton.h"
#ifdef CONFIG_ACTV_BINDER
#include "actv_binder.h"
#endif

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

    ~BinderInvoker();

    bool AcquireHandle(int32_t handle) override;

    bool ReleaseHandle(int32_t handle) override;

    bool PingService(int32_t handle) override;

    bool AddDeathRecipient(int32_t handle, void *cookie) override;

    bool RemoveDeathRecipient(int32_t handle, void *cookie) override;

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

    sptr<IRemoteObject> UnflattenObject(Parcel &parcel) override;

    int ReadFileDescriptor(Parcel &parcel) override;

    bool WriteFileDescriptor(Parcel &parcel, int fd, bool takeOwnership) override;

    pid_t GetCallerPid() const override;

    pid_t GetCallerRealPid() const override;

    uid_t GetCallerUid() const override;

    uint64_t GetCallerTokenID() const override;

    uint64_t GetFirstCallerTokenID() const override;

    uint64_t GetSelfTokenID() const override;

    uint64_t GetSelfFirstCallerTokenID() const override;

    uint32_t GetStatus() override;

    bool IsLocalCalling() override;

    void SetStatus(uint32_t status);

    std::string GetLocalDeviceID() override;

    std::string GetCallerDeviceID() const override;

    int FlushCommands(IRemoteObject *object) override;

    std::string ResetCallingIdentity() override;

    bool SetCallingIdentity(std::string &identity) override;

    void ExitCurrentThread();

    uint32_t GetStrongRefCountForStub(uint32_t handle);

#ifndef CONFIG_IPC_SINGLE
    int TranslateIRemoteObject(int32_t cmd, const sptr<IRemoteObject> &obj) override;

    sptr<IRemoteObject> GetSAMgrObject() override;
#endif

#ifdef CONFIG_ACTV_BINDER
    static void JoinActvThread(bool initiative);

    static void SetActvHandlerInfo(uint32_t id);

    void LinkRemoteInvoker(void **data) override;

    void UnlinkRemoteInvoker(void **data) override;

    int SendRequest(int handle, uint32_t code,
                    MessageParcel &data, MessageParcel &reply,
                    MessageOption &option, void *invokerData) override;

    bool CheckActvBinderAvailable(int handle, uint32_t code,
                                  MessageOption &option, void *data);
#endif // CONFIG_ACTV_BINDER

protected:
    bool isMainWorkThread;
    bool stopWorkThread;
    pid_t callerPid_;
    pid_t callerRealPid_;
    pid_t callerUid_;
    uint64_t callerTokenID_;
    uint64_t firstTokenID_;

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

    void Transaction(const uint8_t *buffer);

    void OnTransaction(int32_t &error);

    void OnSpawnThread();

    int HandleCommands(uint32_t cmd);

    int HandleCommandsInner(uint32_t cmd);

    int HandleReply(MessageParcel *reply);

    bool TranslateDBinderProxy(int handle, MessageParcel &data);

    void GetAccessToken(uint64_t &callerTokenID, uint64_t &firstTokenID);

    void GetSenderInfo(uint64_t &callerTokenID, uint64_t &firstTokenID, pid_t &realPid);

    void PrintErrorMessage(uint64_t writeConsumed);

    void OnTransactionComplete(MessageParcel *reply,
        int32_t *acquireResult, bool &continueLoop, int32_t &error, uint32_t cmd);

    void OnDeadOrFailedReply(MessageParcel *reply,
        int32_t *acquireResult, bool &continueLoop, int32_t &error, uint32_t cmd);

    void OnAcquireResult(MessageParcel *reply,
        int32_t *acquireResult, bool &continueLoop, int32_t &error, uint32_t cmd);

    void OnReply(MessageParcel *reply,
        int32_t *acquireResult, bool &continueLoop, int32_t &error, uint32_t cmd);

    void OnTranslationComplete(MessageParcel *reply,
        int32_t *acquireResult, bool &continueLoop, int32_t &error, uint32_t cmd);

    void DealWithCmd(MessageParcel *reply,
        int32_t *acquireResult, bool &continueLoop, int32_t &error, uint32_t cmd);

#ifndef CONFIG_IPC_SINGLE
    bool AddCommAuth(int32_t handle, flat_binder_object *flat);
#endif

#ifdef CONFIG_ACTV_BINDER
    inline void SetUseActvBinder(bool useActvBinder)
    {
        if ((binderConnector_ != nullptr) && binderConnector_->IsActvBinderSupported()) {
            useActvBinder_ = useActvBinder;
        }
    }

    inline bool GetUseActvBinder()
    {
        return useActvBinder_;
    }

    inline uint32_t GetBWRCommand()
    {
        return useActvBinder_ ? ACTV_BINDER_WRITE_READ : BINDER_WRITE_READ;
    }
#endif // CONFIG_ACTV_BINDER

private:
    DISALLOW_COPY_AND_MOVE(BinderInvoker);
    using HandleFunction = void (BinderInvoker::*)(MessageParcel *reply,
        int32_t *acquireResult, bool &continueLoop, int32_t &error, uint32_t cmd);
    static constexpr int IPC_DEFAULT_PARCEL_SIZE = 256;
    static constexpr int IPC_CMD_PROCESS_WARN_TIME = 500;
    static constexpr int ACCESS_TOKEN_MAX_LEN = 10;
    Parcel input_;
    Parcel output_;
    BinderConnector *binderConnector_;
    uint32_t status_;
    static inline InvokerDelegator<BinderInvoker> delegator_ = { IRemoteObject::IF_PROT_BINDER };
    InvokerProcInfo invokerInfo_;
    int lastErr_ = 0;
    int lastErrCnt_ = 0;
    const std::unordered_set<int32_t> GET_HANDLE_CMD_SET = {BC_ACQUIRE, BC_RELEASE,
        BC_REQUEST_DEATH_NOTIFICATION, BC_REPLY, BC_CLEAR_DEATH_NOTIFICATION, BC_FREE_BUFFER, BC_TRANSACTION};
    const std::map<int32_t, std::function<void(int32_t cmd, int32_t &error)>> receiverCommandMap_ = {
        { BR_ERROR,           [&](int32_t cmd, int32_t &error) { error = input_.ReadInt32(); } },
        { BR_ACQUIRE,         [&](int32_t cmd, int32_t &error) { OnAcquireObject(cmd); } },
        { BR_INCREFS,         [&](int32_t cmd, int32_t &error) { OnAcquireObject(cmd); } },
        { BR_RELEASE,         [&](int32_t cmd, int32_t &error) { OnReleaseObject(cmd); } },
        { BR_DECREFS,         [&](int32_t cmd, int32_t &error) { OnReleaseObject(cmd); } },
        { BR_ATTEMPT_ACQUIRE, [&](int32_t cmd, int32_t &error) { OnAttemptAcquire(); } },
        { BR_TRANSACTION,     [&](int32_t cmd, int32_t &error) { OnTransaction(error); } },
        { BR_SPAWN_LOOPER,    [&](int32_t cmd, int32_t &error) { OnSpawnThread(); } },
        { BR_FINISHED,        [&](int32_t cmd, int32_t &error) { error = -ERR_TIMED_OUT; } },
        { BR_DEAD_BINDER,     [&](int32_t cmd, int32_t &error) { OnBinderDied(); } },
        { BR_OK,              [&](int32_t cmd, int32_t &error) { } },
        { BR_NOOP,            [&](int32_t cmd, int32_t &error) { } },
        { BR_CLEAR_DEATH_NOTIFICATION_DONE, [&](int32_t cmd, int32_t &error) { OnRemoveRecipientDone(); } },
    };
    const std::map<int32_t, HandleFunction> senderCommandMap_ = {
        { BR_TRANSACTION_COMPLETE,   &BinderInvoker::OnTransactionComplete },
        { BR_DEAD_REPLY,             &BinderInvoker::OnDeadOrFailedReply },
        { BR_FAILED_REPLY,           &BinderInvoker::OnDeadOrFailedReply },
        { BR_ACQUIRE_RESULT,         &BinderInvoker::OnAcquireResult },
        { BR_REPLY,                  &BinderInvoker::OnReply },
        { BR_TRANSLATION_COMPLETE,   &BinderInvoker::OnTranslationComplete },
    };
#ifdef CONFIG_ACTV_BINDER
    bool useActvBinder_ = false;
    ActvHandlerInfo *actvHandlerInfo_ = nullptr;
#endif
};
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS
#endif // OHOS_IPC_BINDER_INVOKER_H
