/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_IPC_DBINDER_BASE_INVOKER_DEFINE_H
#define OHOS_IPC_DBINDER_BASE_INVOKER_DEFINE_H

#include <unistd.h>
#include <cinttypes>
#include <memory>
#include <sys/types.h>
#include "securec.h"
#include "sys_binder.h"
#include "iremote_invoker.h"
#include "invoker_factory.h"

#include "ipc_object_stub.h"
#include "ipc_object_proxy.h"
#include "ipc_process_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "ipc_skeleton.h"
#include "ipc_debug.h"
#include "hitrace_invoker.h"
#include "dbinder_error_code.h"
#include "log_tags.h"

namespace OHOS {
using namespace OHOS::HiviewDFX;

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_RPC_DBINDER_INVOKER,
    "DBinderBaseInvoker" };

template <class T> class DBinderBaseInvoker : public IRemoteInvoker {
public:
    class DBinderSendAllocator : public DefaultAllocator {
        void Dealloc(void *data) override;

        friend DBinderBaseInvoker;
    };

    class DBinderRecvAllocator : public DefaultAllocator {
        void Dealloc(void *data) override;

        friend DBinderBaseInvoker;
    };

    virtual ~DBinderBaseInvoker() = default;
    virtual std::shared_ptr<T> QueryServerSessionObject(uint32_t handle) = 0;
    virtual bool UpdateClientSession(std::shared_ptr<T> sessionObject) = 0;

    virtual int SendRequest(int32_t handle, uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override;
    virtual bool AddDeathRecipient(int32_t handle, void *cookie) override;
    virtual bool RemoveDeathRecipient(int32_t handle, void *cookie) override;
    virtual bool SetMaxWorkThread(int maxThreadNum) override;
    virtual int SendReply(MessageParcel &reply, uint32_t flags, int32_t result) override;
    virtual bool PingService(int32_t handle) override;
    virtual sptr<IRemoteObject> GetSAMgrObject() override;
    virtual bool SetRegistryObject(sptr<IRemoteObject> &object) override;
    virtual void FreeBuffer(void *data) override;
    virtual std::shared_ptr<T> WriteTransaction(int cmd, uint32_t flags, int32_t handle, int32_t socketId,
        uint32_t code, MessageParcel &data, uint64_t &seqNumber, int status);
    virtual int SendOrWaitForCompletion(int userWaitTime, uint64_t seqNumber, std::shared_ptr<T> sessionOfPeer,
        MessageParcel *reply = nullptr);
    virtual void OnTransaction(std::shared_ptr<ThreadProcessInfo> processInfo);
    virtual void StartProcessLoop(int32_t socketId, const char *buffer, uint32_t size);
    virtual uint32_t QueryHandleBySession(std::shared_ptr<T> session) = 0;
    virtual std::shared_ptr<T> QueryClientSessionObject(uint32_t databusHandle) = 0;
    virtual std::shared_ptr<T> NewSessionOfBinderProxy(uint32_t handle, std::shared_ptr<T> session) = 0;
    virtual std::shared_ptr<T> QuerySessionOfBinderProxy(uint32_t handle, std::shared_ptr<T> session) = 0;
    virtual std::shared_ptr<T> CreateServerSessionObject(binder_uintptr_t binder, std::shared_ptr<T> sessionObject) = 0;
    virtual uint32_t FlattenSession(char *sessionOffset, const std::shared_ptr<T> connectSession,
        uint32_t binderVersion) = 0;
    virtual std::shared_ptr<T> UnFlattenSession(char *sessionOffset, uint32_t binderVersion) = 0;
    virtual int OnSendMessage(std::shared_ptr<T> sessionOfPeer) = 0;
    virtual bool CreateProcessThread() = 0;
    virtual uint64_t GetSeqNum() const = 0;
    virtual void SetSeqNum(uint64_t seq) = 0;
    virtual int32_t GetClientFd() const = 0;
    virtual void SetClientFd(int32_t fd) = 0;
    virtual void SetCallerPid(pid_t pid) = 0;
    virtual void SetCallerUid(pid_t uid) = 0;
    virtual void SetStatus(uint32_t status) = 0;
    virtual void SetCallerDeviceID(const std::string &deviceId) = 0;
    virtual void SetCallerTokenID(const uint32_t tokenId) = 0;
    virtual int CheckAndSetCallerInfo(int32_t socketId, uint64_t stubIndex) = 0;
    virtual int OnSendRawData(std::shared_ptr<T> session, const void *data, size_t size) = 0;
    bool CheckTransactionData(const dbinder_transaction_data *tr) const;
    std::mutex &GetObjectMutex();
    void PrintDBinderTransaction(const char *funcName, const char *titleName, const dbinder_transaction_data *tr);
    void PrintBuffer(const char *funcName, const char *titleName, const uint8_t *data, size_t length);

private:
    uint32_t TranslateBinderType(flat_binder_object *binderObject, char *sessionOffset, std::shared_ptr<T> session);
    uint32_t TranslateHandleType(flat_binder_object *binderObject, char *sessionOffset, std::shared_ptr<T> session);
    void ClearBinderType(flat_binder_object *binderObject);
    void ClearHandleType(flat_binder_object *binderObject);
    bool TranslateRemoteHandleType(flat_binder_object *binderObject, char *sessionOffset, uint32_t binderVersion);
    int HandleReply(uint64_t seqNumber, MessageParcel *reply, std::shared_ptr<ThreadMessageInfo> messageInfo);
    int WaitForReply(uint64_t seqNumber, MessageParcel *reply, uint32_t handle, int userWaitTime);
    void ProcessTransaction(dbinder_transaction_data *tr, int32_t listenFd);
    void ProcessReply(dbinder_transaction_data *tr, int32_t listenFd);
    bool IRemoteObjectTranslateWhenSend(char *dataBuffer, binder_size_t bufferSize, MessageParcel &data,
        uint32_t socketId, std::shared_ptr<T> sessionObject);
    bool IRemoteObjectTranslateWhenRcv(char *dataBuffer, binder_size_t bufferSize, MessageParcel &data,
        uint32_t socketId, std::shared_ptr<T> sessionObject);
    bool TranslateRawData(char *dataBuffer, MessageParcel &data, uint32_t socketId);
    std::shared_ptr<T> GetSessionObject(uint32_t handle, uint32_t socketId);
    uint64_t GetUniqueSeqNumber(int cmd);
    void ConstructTransData(MessageParcel &data, dbinder_transaction_data &transData, size_t totalSize,
        uint64_t seqNum, int cmd, __u32 code, __u32 flags);
    bool ProcessRawData(std::shared_ptr<T> sessionObject, MessageParcel &data, uint64_t seqNum);
    std::shared_ptr<dbinder_transaction_data> ProcessNormalData(std::shared_ptr<T> sessionObject, MessageParcel &data,
        int32_t handle, int32_t socketId, uint64_t seqNum, int cmd, __u32 code, __u32 flags, int status);
    bool MoveTransData2Buffer(std::shared_ptr<T> sessionObject, std::shared_ptr<dbinder_transaction_data> transData);
    bool RemoveDBinderPtrData(std::shared_ptr<dbinder_transaction_data> transData, uint32_t &cutCount);
    void OverrideMessageParcelData(std::shared_ptr<dbinder_transaction_data> tr, MessageParcel &data);
    bool MoveMessageParcel2TransData(MessageParcel &data, std::shared_ptr<T> sessionObject,
        std::shared_ptr<dbinder_transaction_data> transData, int32_t socketId, int status);
    std::shared_ptr<ThreadProcessInfo> MakeThreadProcessInfo(int32_t socketId, const char *buffer, uint32_t size);
    std::shared_ptr<ThreadMessageInfo> MakeThreadMessageInfo(int32_t socketId);
    uint32_t MakeRemoteHandle(std::shared_ptr<T> session);

private:
    std::mutex objectMutex_;
    static constexpr int32_t REPLY_RETRY_COUNT = 5;
    static constexpr int32_t REPLY_RETRY_WAIT_MS = 10;
};
} // namespace OHOS
#endif // OHOS_IPC_DBINDER_BASE_INVOKER_DEFINE_H
