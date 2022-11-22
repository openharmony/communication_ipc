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

#ifndef OHOS_IPC_DBINDER_BASE_INVOKER_H
#define OHOS_IPC_DBINDER_BASE_INVOKER_H

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
#include "ipc_debug.h"
#include "hitrace_invoker.h"
#include "dbinder_error_code.h"
#include "log_tags.h"

namespace OHOS {
using namespace OHOS::HiviewDFX;

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_RPC, "DBinderBaseInvoker" };

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
    virtual bool UpdateClientSession(uint32_t handle, std::shared_ptr<T> sessionObject) = 0;

    int SendRequest(int32_t handle, uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override;
    bool AddDeathRecipient(int32_t handle, void *cookie) override;
    bool RemoveDeathRecipient(int32_t handle, void *cookie) override;
    int GetObjectRefCount(const IRemoteObject *object) override;
    bool SetMaxWorkThread(int maxThreadNum) override;
    int SendReply(MessageParcel &reply, uint32_t flags, int32_t result) override;
    bool PingService(int32_t handle) override;
    sptr<IRemoteObject> GetSAMgrObject() override;
    bool SetRegistryObject(sptr<IRemoteObject> &object) override;
    void FreeBuffer(void *data) override;
    virtual std::shared_ptr<T> WriteTransaction(int cmd, uint32_t flags, int32_t handle, int32_t socketId,
        uint32_t code, MessageParcel &data, uint64_t &seqNumber, int status);
    virtual int SendOrWaitForCompletion(int userWaitTime, uint64_t seqNumber, std::shared_ptr<T> sessionOfPeer,
        MessageParcel *reply = nullptr);
    virtual void OnTransaction(std::shared_ptr<ThreadProcessInfo> processInfo);
    virtual void StartProcessLoop(uint32_t handle, const char *buffer, uint32_t size);
    virtual uint32_t QueryHandleBySession(std::shared_ptr<T> session, uint64_t stubIndex) = 0;
    virtual std::shared_ptr<T> QueryClientSessionObject(uint32_t databusHandle) = 0;
    virtual std::shared_ptr<T> NewSessionOfBinderProxy(uint32_t handle, std::shared_ptr<T> session) = 0;
    virtual std::shared_ptr<T> QuerySessionOfBinderProxy(uint32_t handle, std::shared_ptr<T> session) = 0;
    virtual std::shared_ptr<T> CreateServerSessionObject(binder_uintptr_t binder, uint64_t &stubIndex,
        std::shared_ptr<T> sessionObject) = 0;
    virtual uint32_t FlattenSession(char *sessionOffset, const std::shared_ptr<T> connectSession,
        uint64_t stubIndex) = 0;
    virtual std::shared_ptr<T> UnFlattenSession(char *sessionOffset, uint64_t &stubIndex) = 0;
    virtual int OnSendMessage(std::shared_ptr<T> sessionOfPeer) = 0;
    virtual bool CreateProcessThread() = 0;
    virtual uint64_t GetSeqNum() const = 0;
    virtual void SetSeqNum(uint64_t seq) = 0;
    virtual uint32_t GetClientFd() const = 0;
    virtual void SetClientFd(uint32_t fd) = 0;
    virtual void SetCallerPid(pid_t pid) = 0;
    virtual void SetCallerUid(pid_t uid) = 0;
    virtual void SetStatus(uint32_t status) = 0;
    virtual void SetCallerDeviceID(const std::string &deviceId) = 0;
    virtual void SetCallerTokenID(const uint32_t tokenId) = 0;
    virtual int CheckAndSetCallerInfo(uint32_t listenFd, uint64_t stubIndex) = 0;
    virtual int OnSendRawData(std::shared_ptr<T> session, const void *data, size_t size) = 0;
    virtual bool SetTokenId(const dbinder_transaction_data *tr, std::shared_ptr<T> sessionObject) = 0;
    bool CheckTransactionData(const dbinder_transaction_data *tr) const;

private:
    uint32_t TranslateBinderType(flat_binder_object *binderObject, char *sessionOffset, std::shared_ptr<T> session);
    uint32_t TranslateHandleType(flat_binder_object *binderObject, char *sessionOffset, std::shared_ptr<T> session);
    bool TranslateRemoteHandleType(flat_binder_object *binderObject, char *sessionOffset, std::shared_ptr<T> session);
    int HandleReply(uint64_t seqNumber, MessageParcel *reply, std::shared_ptr<T> sessionObject);
    bool SetSenderStubIndex(std::shared_ptr<dbinder_transaction_data> transData, uint32_t handle);
    int WaitForReply(uint64_t seqNumber, MessageParcel *reply, std::shared_ptr<T> sessionObject, int userWaitTime);
    void ProcessTransaction(dbinder_transaction_data *tr, uint32_t listenFd);
    void ProcessReply(dbinder_transaction_data *tr, uint32_t listenFd);
    bool IRemoteObjectTranslate(char *dataBuffer, binder_size_t buffer_size, MessageParcel &data, uint32_t socketId,
        std::shared_ptr<T> sessionObject);
    bool TranslateRawData(char *dataBuffer, MessageParcel &data, uint32_t socketId);
    std::shared_ptr<T> GetSessionObject(uint32_t handle, uint32_t socketId);
    uint64_t GetUniqueSeqNumber(int cmd);
    void ConstructTransData(dbinder_transaction_data &TransData, size_t totalSize, uint64_t seqNum, int cmd, __u32 code,
        __u32 flags);
    bool ProcessRawData(std::shared_ptr<T> sessionObject, MessageParcel &data, uint64_t seqNum);
    std::shared_ptr<dbinder_transaction_data> ProcessNormalData(std::shared_ptr<T> sessionObject, MessageParcel &data,
        int32_t handle, int32_t socketId, uint64_t seqNum, int cmd, __u32 code, __u32 flags, int status);
    bool MoveTransData2Buffer(std::shared_ptr<T> sessionObject, std::shared_ptr<dbinder_transaction_data> transData);
    bool MoveMessageParcel2TransData(MessageParcel &data, std::shared_ptr<T> sessionObject,
        std::shared_ptr<dbinder_transaction_data> transData, int32_t socketId, int status);
    std::shared_ptr<ThreadProcessInfo> MakeThreadProcessInfo(uint32_t handle, const char *buffer, uint32_t size);
    std::shared_ptr<ThreadMessageInfo> MakeThreadMessageInfo(uint32_t handle);
    uint32_t MakeRemoteHandle(std::shared_ptr<T> session, uint64_t stubIndex);
};

template <class T>
uint32_t DBinderBaseInvoker<T>::TranslateBinderType(flat_binder_object *binderObject, char *sessionOffset,
    std::shared_ptr<T> session)
{
    uint64_t stubIndex = 0;
    std::shared_ptr<T> sessionOfPeer = CreateServerSessionObject(binderObject->binder, stubIndex, session);
    if (sessionOfPeer == nullptr) {
        ZLOGE(LOG_LABEL, "send an wrong stub object");
        return 0;
    }
    binderObject->hdr.type = BINDER_TYPE_REMOTE_HANDLE;
    binderObject->cookie = IRemoteObject::IF_PROT_DATABUS;
    binderObject->binder = 0;
    return FlattenSession(sessionOffset, sessionOfPeer, stubIndex);
}

template <class T>
uint32_t DBinderBaseInvoker<T>::TranslateHandleType(flat_binder_object *binderObject, char *sessionOffset,
    std::shared_ptr<T> session)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current ipc process skeleton is nullptr");
        return 0;
    }
    std::shared_ptr<T> sessionOfPeer = nullptr;
    if (binderObject->cookie == IRemoteObject::IF_PROT_DATABUS) {
        sessionOfPeer = QuerySessionOfBinderProxy(binderObject->handle, session);
    } else if (binderObject->cookie == IRemoteObject::IF_PROT_BINDER) {
        sessionOfPeer = NewSessionOfBinderProxy(binderObject->handle, session);
    }
    if (sessionOfPeer == nullptr) {
        ZLOGE(LOG_LABEL, "send an wrong dbinder object");
        return 0;
    }

    uint64_t stubIndex = current->QueryHandleToIndex(binderObject->handle);
    if (stubIndex == 0) {
        ZLOGE(LOG_LABEL, "stubIndex is zero");
        return 0;
    }
    binderObject->hdr.type = BINDER_TYPE_REMOTE_HANDLE;

    return FlattenSession(sessionOffset, sessionOfPeer, stubIndex);
}

template <class T> uint32_t DBinderBaseInvoker<T>::MakeRemoteHandle(std::shared_ptr<T> session, uint64_t stubIndex)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current ipc process skeleton is nullptr");
        return 0;
    }

    uint32_t handle = current->GetDBinderIdleHandle(stubIndex);
    ZLOGI(LOG_LABEL, "create new handle = %{public}d", handle);
    if (handle == 0) {
        ZLOGE(LOG_LABEL, "add stub index err stubIndex = %" PRIu64 ",\
            handle = %d", stubIndex, handle);
        return 0;
    }
    if (!UpdateClientSession(handle, session)) {
        ZLOGE(LOG_LABEL, "session create failed");
        return 0;
    }
    return handle;
}

template <class T>
bool DBinderBaseInvoker<T>::TranslateRemoteHandleType(flat_binder_object *binderObject, char *sessionOffset,
    std::shared_ptr<T> session)
{
    std::shared_ptr<T> sessionOfPeer = nullptr;
    uint64_t stubIndex = 0;

    if (binderObject->cookie == IRemoteObject::IF_PROT_DATABUS ||
        binderObject->cookie == IRemoteObject::IF_PROT_BINDER) {
        sessionOfPeer = UnFlattenSession(sessionOffset, stubIndex);
    }
    if (sessionOfPeer == nullptr) {
        ZLOGE(LOG_LABEL, "send a wrong dbinder object");
        return false;
    }
    sessionOfPeer->SetFeatureSet(session->GetFeatureSet());

    uint32_t handle = QueryHandleBySession(sessionOfPeer, stubIndex);
    if (handle == 0) {
        handle = MakeRemoteHandle(sessionOfPeer, stubIndex);
        ZLOGI(LOG_LABEL, "create new handle = %{public}u", handle);
        if (handle == 0) {
            ZLOGE(LOG_LABEL, "failed to create new handle");
            return false;
        }
    }
    binderObject->hdr.type = BINDER_TYPE_HANDLE;
    binderObject->handle = handle;
    return true;
}

/* check data parcel contains object, if yes, get its session as payload of socket packet */
template <class T>
bool DBinderBaseInvoker<T>::IRemoteObjectTranslate(char *dataBuffer, binder_size_t buffer_size, MessageParcel &data,
    uint32_t socketId, std::shared_ptr<T> sessionObject)
{
    if (data.GetOffsetsSize() <= 0 || dataBuffer == nullptr) {
        return true;
    }

    uint32_t totalSize = 0;
    binder_size_t *binderObjectsOffsets = reinterpret_cast<binder_size_t *>(data.GetObjectOffsets());
    uint32_t offsetOfSession = buffer_size + data.GetOffsetsSize() * sizeof(binder_size_t);
    char *flatOffset = dataBuffer + offsetOfSession;

    for (size_t i = 0; i < data.GetOffsetsSize(); i++) {
        auto binderObject = reinterpret_cast<flat_binder_object *>(dataBuffer + *(binderObjectsOffsets + i));
        switch (binderObject->hdr.type) {
            case BINDER_TYPE_BINDER: {
                uint32_t flatSize = TranslateBinderType(binderObject, flatOffset + totalSize, sessionObject);
                if (flatSize == 0) {
                    ZLOGE(LOG_LABEL, "send an wrong stub object");
                    return false;
                }
                totalSize += flatSize;
                break;
            }

            case BINDER_TYPE_HANDLE: {
                uint32_t flatSize = TranslateHandleType(binderObject, flatOffset + totalSize, sessionObject);
                if (flatSize == 0) {
                    ZLOGE(LOG_LABEL, "send an wrong dbinder object");
                    return false;
                }
                totalSize += flatSize;
                break;
            }

            case BINDER_TYPE_REMOTE_HANDLE: {
                if (TranslateRemoteHandleType(binderObject, flatOffset + i * T::GetFlatSessionLen(),
                    sessionObject) != true) {
                    ZLOGE(LOG_LABEL, "send a wrong dbinder object");
                    return false;
                }
                break;
            }

            case BINDER_TYPE_FD: {
                binderObject->hdr.type = BINDER_TYPE_FDR;
                binderObject->handle = -1;
                break;
            }

            case BINDER_TYPE_FDR: {
                if (!TranslateRawData(dataBuffer, data, socketId)) {
                    ZLOGE(LOG_LABEL, "fail to translate big raw data");
                    // do nothing
                }
                break;
            }
            default: {
                ZLOGE(LOG_LABEL, "do not support this type of translation");
                // do nothing
                break;
            }
        }
    }

    return true;
}

template <class T>
bool DBinderBaseInvoker<T>::TranslateRawData(char *dataBuffer, MessageParcel &data, uint32_t socketId)
{
    if (data.GetOffsetsSize() <= 0 || socketId == 0) {
        ZLOGI(LOG_LABEL, "no raw data to translate.");
        return true;
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current ipc process skeleton is nullptr");
        return false;
    }
    std::shared_ptr<InvokerRawData> receivedRawData = current->QueryRawData(socketId);
    if (receivedRawData == nullptr) {
        ZLOGE(LOG_LABEL, "cannot found rawData according to the socketId");
        return false;
    }
    std::shared_ptr<char> rawData = receivedRawData->GetData();
    size_t rawSize = receivedRawData->GetSize();
    current->DetachRawData(socketId);
    if (!data.RestoreRawData(rawData, rawSize)) {
        ZLOGE(LOG_LABEL, "found rawData, but cannot restore them");
        return false;
    }
    return true;
}

template <class T> std::shared_ptr<T> DBinderBaseInvoker<T>::GetSessionObject(uint32_t handle, uint32_t socketId)
{
    if (handle != 0) {
        /* transact case */
        return QueryServerSessionObject(handle);
    } else {
        /* reply case */
        return QueryClientSessionObject(socketId);
    }
}

template <class T> uint64_t DBinderBaseInvoker<T>::GetUniqueSeqNumber(int cmd)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current ipc process skeleton is nullptr");
        return 0;
    }

    if (cmd == BC_TRANSACTION) {
        return current->GetSeqNumber();
    } else if (cmd == BC_REPLY) {
        /* use sender sequence number */
        return GetSeqNum();
    } else {
        return 0;
    }
}

template <class T>
void DBinderBaseInvoker<T>::ConstructTransData(dbinder_transaction_data &TransData, size_t totalSize, uint64_t seqNum,
    int cmd, __u32 code, __u32 flags)
{
    TransData.sizeOfSelf = totalSize;
    TransData.magic = DBINDER_MAGICWORD;
    TransData.version = VERSION_NUM;
    TransData.cmd = cmd;
    TransData.code = code;
    TransData.flags = flags;
    TransData.cookie = 0;
    TransData.seqNumber = seqNum;
    TransData.buffer_size = 0;
    TransData.offsets_size = 0;
    TransData.offsets = 0;
}

template <class T>
bool DBinderBaseInvoker<T>::ProcessRawData(std::shared_ptr<T> sessionObject, MessageParcel &data, uint64_t seqNum)
{
    if (data.GetRawData() == nullptr || data.GetRawDataSize() == 0) {
        return true; // do nothing, return true
    }

    std::shared_ptr<dbinder_transaction_data> transData = nullptr;
    size_t totalSize = sizeof(dbinder_transaction_data) + data.GetRawDataSize();
    transData.reset(reinterpret_cast<dbinder_transaction_data *>(::operator new(totalSize)));
    if (transData == nullptr) {
        ZLOGE(LOG_LABEL, "fail to create raw buffer with length = %{public}zu", totalSize);
        return false;
    }

    ConstructTransData(*transData, totalSize, seqNum, BC_SEND_RAWDATA, 0, 0);
    int result = memcpy_s(reinterpret_cast<char *>(transData.get()) + sizeof(dbinder_transaction_data),
        totalSize - sizeof(dbinder_transaction_data), data.GetRawData(), data.GetRawDataSize());
    if (result != 0) {
        ZLOGE(LOG_LABEL, "memcpy data fail size = %{public}zu", data.GetRawDataSize());
        return false;
    }
    result = OnSendRawData(sessionObject, transData.get(), totalSize);
    if (result != 0) {
        ZLOGE(LOG_LABEL, "fail to send raw data");
        // do nothing, need send normal MessageParcel
    }
    return true;
}

template <class T>
bool DBinderBaseInvoker<T>::MoveMessageParcel2TransData(MessageParcel &data, std::shared_ptr<T> sessionObject,
    std::shared_ptr<dbinder_transaction_data> transData, int32_t socketId, int status)
{
    if (data.GetDataSize() > 0) {
        /* Send this parcel's data through the socket. */
        transData->buffer_size = data.GetDataSize();
        uint32_t useSize = transData->sizeOfSelf - sizeof(dbinder_transaction_data);
        int memcpyResult =
            memcpy_s(transData->buffer, useSize, reinterpret_cast<void *>(data.GetData()), transData->buffer_size);
        if (data.GetOffsetsSize() > 0) {
            memcpyResult += memcpy_s(transData->buffer + transData->buffer_size, useSize - transData->buffer_size,
                reinterpret_cast<void *>(data.GetObjectOffsets()), data.GetOffsetsSize() * sizeof(binder_size_t));
        }
        if (memcpyResult != 0) {
            ZLOGE(LOG_LABEL, "parcel data memcpy_s failed");
            return false;
        }
        transData->offsets_size = data.GetOffsetsSize() * sizeof(binder_size_t);
        transData->offsets = transData->buffer_size;

        if (!CheckTransactionData(transData.get())) {
            ZLOGE(LOG_LABEL, "check trans data fail");
            return false;
        }
        if (!IRemoteObjectTranslate(reinterpret_cast<char *>(transData->buffer), transData->buffer_size,
            data, (uint32_t)socketId, sessionObject)) {
            ZLOGE(LOG_LABEL, "translate object failed");
            return false;
        }
    } else {
        transData->flags |= TF_STATUS_CODE;
        transData->buffer_size = sizeof(binder_size_t);
        transData->offsets_size = static_cast<binder_size_t>(status);
        transData->offsets = transData->buffer_size;
    }
    return true;
}

template <class T>
std::shared_ptr<dbinder_transaction_data> DBinderBaseInvoker<T>::ProcessNormalData(std::shared_ptr<T> sessionObject,
    MessageParcel &data, int32_t handle, int32_t socketId, uint64_t seqNum, int cmd, __u32 code, __u32 flags,
    int status)
{
    uint32_t sendSize = ((data.GetDataSize() > 0) ? data.GetDataSize() : sizeof(binder_size_t)) +
        sizeof(struct dbinder_transaction_data) + data.GetOffsetsSize() * T::GetFlatSessionLen() +
        data.GetOffsetsSize() * sizeof(binder_size_t);
    std::shared_ptr<FeatureSetData> feature = sessionObject->GetFeatureSet();
    if (feature == nullptr) {
        ZLOGE(LOG_LABEL, "process normal data feature is null");
        return nullptr;
    }
    if (IsATEnable(feature->featureSet) == true) {
        sendSize += GetFeatureSize();
    }

    std::shared_ptr<dbinder_transaction_data> transData = nullptr;
    transData.reset(reinterpret_cast<dbinder_transaction_data *>(::operator new(sendSize)));
    if (transData == nullptr) {
        ZLOGE(LOG_LABEL, "new buffer failed of length = %{public}u", sendSize);
        return nullptr;
    }
    ConstructTransData(*transData, sendSize, seqNum, cmd, code, flags);

    if (SetSenderStubIndex(transData, (uint32_t)handle) != true) {
        ZLOGE(LOG_LABEL, "set stubIndex failed, handle = %{public}d", handle);
        return nullptr;
    }
    if (MoveMessageParcel2TransData(data, sessionObject, transData, socketId, status) != true) {
        ZLOGE(LOG_LABEL, "move parcel to transData failed, handle = %{public}d", handle);
        return nullptr;
    }
    if (IsATEnable(feature->featureSet) == true) {
        uint32_t bufferUseSize = transData->sizeOfSelf - sizeof(struct dbinder_transaction_data) - GetFeatureSize();
        FeatureTransData *featureAddr = (FeatureTransData *)(transData->buffer + bufferUseSize);
        if (SetFeatureTransData(featureAddr, GetFeatureSize()) == false) {
            ZLOGE(LOG_LABEL, "set feature trans data failed");
            return nullptr;
        }
        featureAddr->tokenId = feature->tokenId;
    }
    return transData;
}

template <class T>
bool DBinderBaseInvoker<T>::MoveTransData2Buffer(std::shared_ptr<T> sessionObject,
    std::shared_ptr<dbinder_transaction_data> transData)
{
    std::shared_ptr<BufferObject> sessionBuff = sessionObject->GetSessionBuff();
    if (sessionBuff == nullptr) {
        ZLOGE(LOG_LABEL, "get session buffer fail");
        return false;
    }

    uint32_t sendSize = transData->sizeOfSelf;
    char *sendBuffer = sessionBuff->GetSendBufferAndLock(sendSize);
    /* session buffer contain mutex, need release mutex */
    if (sendBuffer == nullptr) {
        ZLOGE(LOG_LABEL, "buffer alloc failed in session");
        return false;
    }

    sessionBuff->UpdateSendBuffer();
    ssize_t writeCursor = sessionBuff->GetSendBufferWriteCursor();
    ssize_t readCursor = sessionBuff->GetSendBufferReadCursor();
    if (writeCursor < 0 || readCursor < 0 || sendSize > sessionBuff->GetSendBufferSize() - (uint32_t)writeCursor) {
        sessionBuff->ReleaseSendBufferLock();
        ZLOGE(LOG_LABEL, "sender's data is large than idle buffer");
        return false;
    }
    if (memcpy_s(sendBuffer + writeCursor, sendSize, transData.get(), sendSize) != EOK) {
        sessionBuff->ReleaseSendBufferLock();
        ZLOGE(LOG_LABEL,
            "fail to copy from tr to sendBuffer, parcelSize = %{public}u", sendSize);
        return false;
    }

    writeCursor += static_cast<ssize_t>(sendSize);
    sessionBuff->SetSendBufferWriteCursor(writeCursor);
    sessionBuff->SetSendBufferReadCursor(readCursor);
    sessionBuff->ReleaseSendBufferLock();
    return true;
}

template <class T>
std::shared_ptr<T> DBinderBaseInvoker<T>::WriteTransaction(int cmd, uint32_t flags, int32_t handle, int32_t socketId,
    uint32_t code, MessageParcel &data, uint64_t &seqNumber, int status)
{
    std::shared_ptr<T> sessionObject = GetSessionObject(handle, socketId);
    if (sessionObject == nullptr) {
        ZLOGE(LOG_LABEL,
            "session is not exist for listenFd = %d, handle = %d", socketId, handle);
        return nullptr;
    }

    uint64_t seqNum = GetUniqueSeqNumber(cmd);
    if (seqNum == 0) {
        ZLOGE(LOG_LABEL, "seqNum invalid");
        return nullptr;
    }
    /* save seqNum for wait thread */
    seqNumber = seqNum;
    /* if MessageParcel has raw data, send raw data first, then send MessageParcel to peer */
    if (ProcessRawData(sessionObject, data, seqNum) != true) {
        ZLOGE(LOG_LABEL, "send rawdata failed");
        return nullptr;
    }
    std::shared_ptr<dbinder_transaction_data> transData =
        ProcessNormalData(sessionObject, data, handle, socketId, seqNum, cmd, code, flags, status);
    if (transData == nullptr) {
        ZLOGE(LOG_LABEL, "send normal data failed");
        return nullptr;
    }

    if (MoveTransData2Buffer(sessionObject, transData) != true) {
        ZLOGE(LOG_LABEL, "move transaction data to buffer failed");
        return nullptr;
    }
    return sessionObject;
}

template <class T> int DBinderBaseInvoker<T>::HandleReply(uint64_t seqNumber, MessageParcel *reply,
    std::shared_ptr<T> sessionObject)
{
    if (reply == nullptr) {
        ZLOGE(LOG_LABEL, "no need reply, free the buffer");
        return RPC_BASE_INVOKER_INVALID_REPLY_ERR;
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current ipc process skeleton is nullptr");
        return RPC_BASE_INVOKER_INVALID_REPLY_ERR;
    }
    std::shared_ptr<ThreadMessageInfo> messageInfo = current->QueryThreadBySeqNumber(seqNumber);
    if (messageInfo == nullptr) {
        ZLOGE(LOG_LABEL, "receive buffer is nullptr");
#ifndef BUILD_PUBLIC_VERSION
        ReportDriverEvent(DbinderErrorCode::COMMON_DRIVER_ERROR, DbinderErrorCode::ERROR_TYPE,
            DbinderErrorCode::RPC_DRIVER, DbinderErrorCode::ERROR_CODE, DbinderErrorCode::HANDLE_RECV_DATA_FAILURE);
#endif
        return RPC_BASE_INVOKER_INVALID_REPLY_ERR;
    }

    if (messageInfo->flags & MessageOption::TF_STATUS_CODE) {
        int32_t err = static_cast<int32_t>(messageInfo->offsetsSize);
        return err;
    }
    if (messageInfo->buffer == nullptr) {
        ZLOGE(LOG_LABEL, "need reply message, but buffer is nullptr");
        return RPC_BASE_INVOKER_INVALID_REPLY_ERR;
    }
    auto allocator = new (std::nothrow) DBinderRecvAllocator();
    if (allocator == nullptr) {
        ZLOGE(LOG_LABEL, "create DBinderRecvAllocator object failed");
        return RPC_BASE_INVOKER_INVALID_REPLY_ERR;
    }
    if (!reply->SetAllocator(allocator)) {
        ZLOGE(LOG_LABEL, "SetAllocator failed");
        delete allocator;
        return RPC_BASE_INVOKER_INVALID_REPLY_ERR;
    }
    reply->ParseFrom(reinterpret_cast<uintptr_t>(messageInfo->buffer), messageInfo->bufferSize);

    if (messageInfo->offsetsSize > 0) {
        reply->InjectOffsets(
            reinterpret_cast<binder_uintptr_t>(reinterpret_cast<char *>(messageInfo->buffer) + messageInfo->offsets),
            messageInfo->offsetsSize / sizeof(binder_size_t));
    }

    if (!IRemoteObjectTranslate(reinterpret_cast<char *>(messageInfo->buffer), messageInfo->bufferSize, *reply,
        messageInfo->socketId, sessionObject)) {
        ZLOGE(LOG_LABEL, "translate object failed");
        return RPC_BASE_INVOKER_INVALID_REPLY_ERR;
    }

    return ERR_NONE;
}

template <class T>
bool DBinderBaseInvoker<T>::SetSenderStubIndex(std::shared_ptr<dbinder_transaction_data> transData, uint32_t handle)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current ipc process skeleton is nullptr");
        return false;
    }
    transData->cookie = (handle == 0) ? 0 : current->QueryHandleToIndex(handle);
    return true;
}

template <class T> void DBinderBaseInvoker<T>::DBinderSendAllocator::Dealloc(void *data) {}

template <class T> void DBinderBaseInvoker<T>::DBinderRecvAllocator::Dealloc(void *data)
{
    delete[](unsigned char *) data;
}

template <class T>
int DBinderBaseInvoker<T>::WaitForReply(uint64_t seqNumber, MessageParcel *reply,
    std::shared_ptr<T> sessionObject, int userWaitTime)
{
    /* if reply == nullptr, this is a one way message */
    if (reply == nullptr) {
        return NO_ERROR;
    }

    std::shared_ptr<ThreadMessageInfo> messageInfo = MakeThreadMessageInfo(sessionObject->GetSessionHandle());
    if (messageInfo == nullptr) {
        ZLOGE(LOG_LABEL, "make thread message info failed, no memory");
        return RPC_BASE_INVOKER_WAIT_REPLY_ERR;
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current ipc process skeleton is nullptr");
        return RPC_BASE_INVOKER_WAIT_REPLY_ERR;
    }
    /* wait for reply */
    if (!current->AddSendThreadInWait(seqNumber, messageInfo, userWaitTime)) {
        ZLOGE(LOG_LABEL, "sender thread wait reply message time out");
        return RPC_BASE_INVOKER_WAIT_REPLY_ERR;
    }

    int32_t err = HandleReply(seqNumber, reply, sessionObject);
    current->EraseThreadBySeqNumber(seqNumber);
    messageInfo->buffer = nullptr;
    return err;
}

template <class T>
int DBinderBaseInvoker<T>::SendOrWaitForCompletion(int userWaitTime, uint64_t seqNumber,
    std::shared_ptr<T> sessionOfPeer, MessageParcel *reply)
{
    if (seqNumber == 0) {
        ZLOGE(LOG_LABEL, "seqNumber can not be zero");
        return RPC_BASE_INVOKER_INVALID_DATA_ERR;
    }
    if (sessionOfPeer == nullptr) {
        ZLOGE(LOG_LABEL, "current session is invalid");
        return RPC_BASE_INVOKER_INVALID_DATA_ERR;
    }
    int returnLen = OnSendMessage(sessionOfPeer);
    if (returnLen != 0) {
        ZLOGE(LOG_LABEL,
            "fail to send to remote session with error = %{public}d", returnLen);
        // no return, for msg send failed maybe not mine
    }
    return WaitForReply(seqNumber, reply, sessionOfPeer, userWaitTime);
}

template <class T>
int DBinderBaseInvoker<T>::SendRequest(int32_t handle, uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    uint64_t seqNumber = 0;
    int ret;

    uint32_t flags = (uint32_t)option.GetFlags();
    int userWaitTime = option.GetWaitTime();
    MessageParcel &newData = const_cast<MessageParcel &>(data);
    size_t oldWritePosition = newData.GetWritePosition();
    HiTraceId traceId = HiTraceChain::GetId();
    // set client send trace point if trace is enabled
    HiTraceId childId = HitraceInvoker::TraceClientSend(handle, code, newData, flags, traceId);
    std::shared_ptr<T> session = WriteTransaction(BC_TRANSACTION, flags, handle, 0, code, data, seqNumber, 0);
    if (session == nullptr) {
        newData.RewindWrite(oldWritePosition);
        ZLOGE(LOG_LABEL, "seqNumber can not be zero,handle=%d", handle);
#ifndef BUILD_PUBLIC_VERSION
        ReportDriverEvent(DbinderErrorCode::COMMON_DRIVER_ERROR, DbinderErrorCode::ERROR_TYPE,
            DbinderErrorCode::RPC_DRIVER, DbinderErrorCode::ERROR_CODE, DbinderErrorCode::TRANSACT_DATA_FAILURE);
#endif
        return RPC_BASE_INVOKER_WRITE_TRANS_ERR;
    }

    if (flags & TF_ONE_WAY) {
        ret = SendOrWaitForCompletion(userWaitTime, seqNumber, session, nullptr);
    } else {
        ret = SendOrWaitForCompletion(userWaitTime, seqNumber, session, &reply);
    }
    HitraceInvoker::TraceClientReceieve(handle, code, flags, traceId, childId);
    // restore Parcel data
    newData.RewindWrite(oldWritePosition);
    return ret;
}

template <class T> bool DBinderBaseInvoker<T>::AddDeathRecipient(int32_t handle, void *cookie)
{
    return true;
}

template <class T> bool DBinderBaseInvoker<T>::RemoveDeathRecipient(int32_t handle, void *cookie)
{
    return true;
}

template <class T> int DBinderBaseInvoker<T>::GetObjectRefCount(const IRemoteObject *object)
{
    return 0;
}

template <class T> bool DBinderBaseInvoker<T>::SetMaxWorkThread(int maxThreadNum)
{
    return true;
}

template <class T> int DBinderBaseInvoker<T>::SendReply(MessageParcel &reply, uint32_t flags, int32_t result)
{
    uint64_t seqNumber = 0;
    std::shared_ptr<T> sessionObject = WriteTransaction(BC_REPLY, flags, 0,
        GetClientFd(), 0, reply, seqNumber, result);

    if (seqNumber == 0) {
        ZLOGE(LOG_LABEL, "seqNumber can not be zero");
        return RPC_BASE_INVOKER_SEND_REPLY_ERR;
    }
    SendOrWaitForCompletion(0, seqNumber, sessionObject, nullptr);
    return 0;
}

template <class T> std::shared_ptr<ThreadMessageInfo> DBinderBaseInvoker<T>::MakeThreadMessageInfo(uint32_t handle)
{
    std::shared_ptr<ThreadMessageInfo> messageInfo = std::make_shared<struct ThreadMessageInfo>();
    if (messageInfo == nullptr) {
        ZLOGE(LOG_LABEL, "no memory");
        return nullptr;
    }

    messageInfo->threadId = std::this_thread::get_id();
    messageInfo->buffer = nullptr;
    messageInfo->offsets = 0;
    messageInfo->socketId = handle;
    return messageInfo;
}

template <class T>
std::shared_ptr<ThreadProcessInfo> DBinderBaseInvoker<T>::MakeThreadProcessInfo(uint32_t handle, const char *inBuffer,
    uint32_t size)
{
    if (inBuffer == nullptr || size < sizeof(dbinder_transaction_data) || size > SOCKET_MAX_BUFF_SIZE) {
        ZLOGE(LOG_LABEL, "buffer is null or size invalid");
        return nullptr;
    }

    std::shared_ptr<ThreadProcessInfo> processInfo = std::make_shared<ThreadProcessInfo>();
    if (processInfo == nullptr) {
        ZLOGE(LOG_LABEL, "make_shared processInfo fail");
        return nullptr;
    }
    std::shared_ptr<char> buffer(new (std::nothrow) char[size]);
    if (buffer == nullptr) {
        ZLOGE(LOG_LABEL, "new buffer failed of length = %{public}u", size);
        return nullptr;
    }

    int memcpyResult = memcpy_s(buffer.get(), size, inBuffer, size);
    if (memcpyResult != 0) {
        ZLOGE(LOG_LABEL, "memcpy_s failed , size = %{public}u", size);
        return nullptr;
    }

    processInfo->listenFd = handle;
    processInfo->packageSize = size;
    processInfo->buffer = buffer;
    return processInfo;
}

template <class T> void DBinderBaseInvoker<T>::StartProcessLoop(uint32_t handle, const char *buffer, uint32_t size)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current ipc process skeleton is nullptr");
        return;
    }
    std::shared_ptr<ThreadProcessInfo> processInfo = MakeThreadProcessInfo(handle, buffer, size);
    if (processInfo == nullptr) {
        ZLOGE(LOG_LABEL, "processInfo is nullptr");
        return;
    }
    std::thread::id threadId = current->GetIdleDataThread();
    if (threadId == std::thread::id()) {
        bool result = CreateProcessThread();
        if (!result) {
            int socketThreadNum = current->GetSocketTotalThreadNum();
            ZLOGE(LOG_LABEL,
                "create IO thread failed, current socket thread num=%d", socketThreadNum);
            /* thread create too much, wait some thread be idle */
        }
        do {
            /*  no IO thread in idle state, wait a monent */
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        } while ((threadId = current->GetIdleDataThread()) == std::thread::id());
    }

    current->AddDataInfoToThread(threadId, processInfo);
    current->WakeUpDataThread(threadId);
    return;
}

template <class T> void DBinderBaseInvoker<T>::ProcessTransaction(dbinder_transaction_data *tr, uint32_t listenFd)
{
    int error;
    MessageParcel data, reply;

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current ipc process skeleton is nullptr");
        return;
    }

    auto allocator = new (std::nothrow) DBinderSendAllocator();
    if (allocator == nullptr) {
        ZLOGE(LOG_LABEL, "DBinderSendAllocator Creation failed");
        return;
    }
    if (!data.SetAllocator(allocator)) {
        ZLOGE(LOG_LABEL, "SetAllocator failed");
        delete allocator;
        return;
    }
    data.ParseFrom(reinterpret_cast<uintptr_t>(tr->buffer), tr->buffer_size);
    if (!(tr->flags & MessageOption::TF_STATUS_CODE) && tr->offsets_size > 0) {
        data.InjectOffsets(reinterpret_cast<binder_uintptr_t>(reinterpret_cast<char *>(tr->buffer) + tr->offsets),
            tr->offsets_size / sizeof(binder_size_t));
    }
    uint32_t &newflags = const_cast<uint32_t &>(tr->flags);
    int isServerTraced = HitraceInvoker::TraceServerReceieve(tr->cookie, tr->code, data, newflags);

    const pid_t oldPid = GetCallerPid();
    const auto oldUid = static_cast<const uid_t>(GetCallerUid());
    const std::string oldDeviceId = GetCallerDeviceID();
    uint32_t oldStatus = GetStatus();
    const uint32_t oldTokenId = GetCallerTokenID();
    if (CheckAndSetCallerInfo(listenFd, tr->cookie) != ERR_NONE) {
        ZLOGE(LOG_LABEL, "set user info error, maybe cookie is NOT belong to current caller");
        return;
    }
    std::shared_ptr<T> sessionObject = QueryClientSessionObject(listenFd);
    if (sessionObject == nullptr) {
        ZLOGE(LOG_LABEL, "session is not exist for listenFd = %u", listenFd);
        return;
    }
    if (SetTokenId(tr, sessionObject) != true) {
        ZLOGE(LOG_LABEL, "set tokenid failed");
        return;
    }
    SetStatus(IRemoteInvoker::ACTIVE_INVOKER);

    const uint32_t flags = tr->flags;
    uint64_t senderSeqNumber = tr->seqNumber;
    if (tr->cookie == 0) {
        // maybe cookie is zero, discard this package
        return;
    }

    auto *stub = current->QueryStubByIndex(tr->cookie);
    if (stub == nullptr) {
        ZLOGE(LOG_LABEL, "stubIndex is invalid");
        return;
    }
    if (!IRemoteObjectTranslate(reinterpret_cast<char *>(tr->buffer), tr->buffer_size, data,
        listenFd, sessionObject)) {
        ZLOGE(LOG_LABEL, "translate object failed");
        return;
    }

    auto *stubObject = reinterpret_cast<IPCObjectStub *>(stub);
    MessageOption option;
    option.SetFlags(flags);
    error = stubObject->SendRequest(tr->code, data, reply, option);
    if (error != ERR_NONE) {
        ZLOGE(LOG_LABEL, "stub is invalid, has not OnReceive or Request");
        // can not return;
    }
    if (data.GetRawData() != nullptr) {
        ZLOGE(LOG_LABEL, "delete raw data in process skeleton");
        current->DetachRawData(listenFd);
    }
    HitraceInvoker::TraceServerSend(tr->cookie, tr->code, isServerTraced, newflags);
    if (!(flags & MessageOption::TF_ASYNC)) {
        SetClientFd(listenFd);
        SetSeqNum(senderSeqNumber);
        SendReply(reply, 0, error);
        SetClientFd(0);
        SetSeqNum(0);
    }

    SetCallerPid(oldPid);
    SetCallerUid(oldUid);
    SetCallerDeviceID(oldDeviceId);
    SetStatus(oldStatus);
    SetCallerTokenID(oldTokenId);
}

template <class T> void DBinderBaseInvoker<T>::ProcessReply(dbinder_transaction_data *tr, uint32_t listenFd)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current ipc process skeleton is nullptr, can not wakeup thread");
        return;
    }

    std::shared_ptr<ThreadMessageInfo> messageInfo = current->QueryThreadBySeqNumber(tr->seqNumber);
    if (messageInfo == nullptr) {
        ZLOGE(LOG_LABEL, "no thread waiting reply message of this seqNumber");
        /* messageInfo is null, no thread need to wakeup */
        return;
    }

    /* tr->sizeOfSelf > sizeof(dbinder_transaction_data) is checked in CheckTransactionData */
    messageInfo->buffer = new (std::nothrow) unsigned char[tr->sizeOfSelf - sizeof(dbinder_transaction_data)];
    if (messageInfo->buffer == nullptr) {
        ZLOGE(LOG_LABEL, "some thread is waiting for reply message, but no memory");
        /* wake up sender thread */
        current->WakeUpThreadBySeqNumber(tr->seqNumber, listenFd);
        return;
    }
    /* copy receive message to sender thread */
    int memcpyResult = memcpy_s(messageInfo->buffer, tr->sizeOfSelf - sizeof(dbinder_transaction_data), tr->buffer,
        tr->sizeOfSelf - sizeof(dbinder_transaction_data));
    if (memcpyResult != 0) {
        ZLOGE(LOG_LABEL, "memcpy_s failed");
        delete[](unsigned char *) messageInfo->buffer;
        messageInfo->buffer = nullptr;
        /* wake up sender thread even no memssage */
        current->WakeUpThreadBySeqNumber(tr->seqNumber, listenFd);
        return;
    }

    messageInfo->flags = tr->flags;
    messageInfo->bufferSize = tr->buffer_size;
    messageInfo->offsetsSize = tr->offsets_size;
    messageInfo->offsets = tr->offsets;
    messageInfo->socketId = listenFd;

    /* wake up sender thread */
    current->WakeUpThreadBySeqNumber(tr->seqNumber, listenFd);
}

template <class T> void DBinderBaseInvoker<T>::OnTransaction(std::shared_ptr<ThreadProcessInfo> processInfo)
{
    if (processInfo == nullptr) {
        ZLOGE(LOG_LABEL, "processInfo is error!");
        return;
    }
    uint32_t listenFd = processInfo->listenFd;
    char *package = processInfo->buffer.get();

    if (package == nullptr || listenFd == 0) {
        ZLOGE(LOG_LABEL, "package is null or listenFd invalid!");
        return;
    }

    dbinder_transaction_data *tr = reinterpret_cast<dbinder_transaction_data *>(package);
    if (tr->sizeOfSelf < sizeof(dbinder_transaction_data)) {
        ZLOGE(LOG_LABEL, "package is invalid");
        return;
    }

    if (tr->cmd == BC_TRANSACTION) {
        ProcessTransaction(tr, listenFd);
    } else if (tr->cmd == BC_REPLY) {
        ProcessReply(tr, listenFd);
    }
    return;
}

template <class T> bool DBinderBaseInvoker<T>::PingService(int32_t handle)
{
    return true;
}

template <class T> sptr<IRemoteObject> DBinderBaseInvoker<T>::GetSAMgrObject()
{
    return nullptr;
}


template <class T> bool DBinderBaseInvoker<T>::SetRegistryObject(sptr<IRemoteObject> &object)
{
    return true;
}

template <class T> void DBinderBaseInvoker<T>::FreeBuffer(void *data)
{
    return;
}

template <class T> bool DBinderBaseInvoker<T>::CheckTransactionData(const dbinder_transaction_data *tr) const
{
    if (tr->sizeOfSelf == 0 || tr->sizeOfSelf > SOCKET_MAX_BUFF_SIZE || tr->buffer_size > SOCKET_MAX_BUFF_SIZE ||
        tr->buffer_size == 0 || tr->offsets != tr->buffer_size ||
        tr->sizeOfSelf < sizeof(dbinder_transaction_data) + tr->buffer_size) {
        return false;
    }
    if ((tr->flags & MessageOption::TF_STATUS_CODE) && (tr->offsets != sizeof(binder_size_t))) {
        return false;
    }
    if (!(tr->flags & MessageOption::TF_STATUS_CODE)) {
        if (tr->offsets_size > (tr->sizeOfSelf - sizeof(dbinder_transaction_data) - tr->buffer_size)) {
            return false;
        }
        binder_size_t sessionSize =
            tr->sizeOfSelf - tr->buffer_size - sizeof(dbinder_transaction_data) - tr->offsets_size;
        if (sessionSize * sizeof(binder_size_t) < tr->offsets_size * T::GetFlatSessionLen()) {
            return false;
        }
    }

    return true;
}
} // namespace OHOS
#endif // OHOS_IPC_DBINDER_BASE_INVOKER_H
