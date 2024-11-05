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

#include <atomic>
#include <unistd.h>
#include <sys/types.h>
#include <unordered_set>
#include "binder_connector.h"
#include "iremote_invoker.h"
#include "invoker_factory.h"
#include "process_skeleton.h"
#include <securec.h>
#ifdef CONFIG_ACTV_BINDER
#include "actv_binder.h"
#endif

namespace OHOS {

/* dfx interface,type is 0 for string */
extern "C" uintptr_t DFX_SetCrashObj(uint8_t type, uintptr_t addr);
extern "C" void DFX_ResetCrashObj(uintptr_t crashObj);

struct CrashObjDumper {
public:
    explicit CrashObjDumper(const char *str)
    {
        if (str == nullptr) {
            return;
        }
        ptr_ = DFX_SetCrashObj(0, reinterpret_cast<uintptr_t>(str));
    }
    ~CrashObjDumper()
    {
        DFX_ResetCrashObj(ptr_);
    }
private:
    uintptr_t ptr_ = 0;
};
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

    std::string GetCallerSid() const override;

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

    bool SetCallingIdentity(std::string &identity, bool flag) override;

    void ExitCurrentThread();

    uint32_t GetStrongRefCountForStub(uint32_t handle);

    bool IsSendRequesting();

#ifndef CONFIG_IPC_SINGLE
    int TranslateIRemoteObject(int32_t cmd, const sptr<IRemoteObject> &obj) override;

    sptr<IRemoteObject> GetSAMgrObject() override;
#endif

#ifdef CONFIG_ACTV_BINDER
    static void JoinActvThread(bool initiative);
    static bool IsActvBinderService();
#endif // CONFIG_ACTV_BINDER

protected:
    bool isMainWorkThread;
    bool stopWorkThread;
    pid_t callerPid_;
    pid_t callerRealPid_;
    pid_t callerUid_;
    uint64_t callerTokenID_;
    uint64_t firstTokenID_;
    std::string callerSid_;

private:
    int TransactWithDriver(bool doRead = true);

    bool WriteTransaction(int cmd, uint32_t flags, int32_t handle, uint32_t code, const MessageParcel &data,
        const int *status, size_t totalDBinderBufSize);

    int WaitForCompletion(MessageParcel *reply = nullptr, int32_t *acquireResult = nullptr);

    void OnAttemptAcquire();

    void OnRemoveRecipientDone();

    void StartWorkLoop();

    void OnBinderDied();

    void OnAcquireObject(uint32_t cmd);

    void OnReleaseObject(uint32_t cmd);

    void Transaction(binder_transaction_data_secctx& trSecctx);

    void OnTransaction(uint32_t cmd, int32_t &error);

    void OnSpawnThread();

    int HandleCommands(uint32_t cmd);

    int HandleCommandsInner(uint32_t cmd);

    int HandleReply(MessageParcel *reply, bool &isStubRet);

    bool TranslateDBinderProxy(int handle, MessageParcel &data);

    void GetAccessToken(uint64_t &callerTokenID, uint64_t &firstTokenID);

    void GetSenderInfo(uint64_t &callerTokenID, uint64_t &firstTokenID, pid_t &realPid);

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

    int32_t TargetStubSendRequest(const binder_transaction_data &tr,
        MessageParcel &data, MessageParcel &reply, MessageOption &option, uint32_t &flagValue);

    int32_t GeneralServiceSendRequest(
        const binder_transaction_data &tr, MessageParcel &data, MessageParcel &reply, MessageOption &option);

    int32_t SamgrServiceSendRequest(const binder_transaction_data &tr,
        MessageParcel &data, MessageParcel &reply, MessageOption &option);

    void AttachInvokerProcInfoWrapper();

    void RestoreInvokerProcInfo(const InvokerProcInfo &info);

    void PrintParcelData(Parcel &parcel, const std::string &parcelName);

    void UpdateConsumedData(const binder_write_read &bwr, const size_t outAvail);

    void PrintIdentity(bool isPrint, bool isBefore);

    void ProcDeferredDecRefs();

#ifndef CONFIG_IPC_SINGLE
    bool AddCommAuth(int32_t handle, flat_binder_object *flat);

    bool TranslateDBinderStub(int handle, MessageParcel &parcel, bool isReply, size_t &totalDBinderBufSize);

    bool GetDBinderCallingPidUid(int handle, bool isReply, pid_t &pid, uid_t &uid);

    bool UnFlattenDBinderObject(Parcel &parcel, dbinder_negotiation_data &dbinderData);
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
    static constexpr int IPC_DEFAULT_PARCEL_SIZE = 256;
    static constexpr int IPC_CMD_PROCESS_WARN_TIME = 500;
    static constexpr int ACCESS_TOKEN_MAX_LEN = 10;
    Parcel input_;
    Parcel output_;
    BinderConnector *binderConnector_;
    uint32_t status_;
    static inline InvokerDelegator<BinderInvoker> delegator_ = { IRemoteObject::IF_PROT_BINDER };
    InvokerProcInfo invokerInfo_;
    std::atomic<int> lastErr_ = 0;
    std::atomic<int> lastErrCnt_ = 0;
    std::atomic<int32_t> sendNestCount_ = 0;
    std::atomic<int32_t> sendRequestCount_ = 0;
    std::mutex strongRefMutex_;
    std::vector<IRemoteObject *> decStrongRefs_;
    std::mutex weakRefMutex_;
    std::vector<RefCounter *> decWeakRefs_;
#ifdef CONFIG_ACTV_BINDER
    bool useActvBinder_ = false;
#endif
};
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS
#endif // OHOS_IPC_BINDER_INVOKER_H
