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
    bool MoveMessageParcel2TransData(MessageParcel &data, std::shared_ptr<T> sessionObject,
        std::shared_ptr<dbinder_transaction_data> transData, int32_t socketId, int status);
    std::shared_ptr<ThreadProcessInfo> MakeThreadProcessInfo(int32_t socketId, const char *buffer, uint32_t size);
    std::shared_ptr<ThreadMessageInfo> MakeThreadMessageInfo(int32_t socketId);
    uint32_t MakeRemoteHandle(std::shared_ptr<T> session);

private:
    std::mutex objectMutex_;
};

template<class T>
uint32_t DBinderBaseInvoker<T>::TranslateBinderType(flat_binder_object *binderObject, char *sessionOffset,
    std::shared_ptr<T> session)
{
    std::shared_ptr<T> sessionOfPeer = CreateServerSessionObject(binderObject->cookie, session);
    if (sessionOfPeer == nullptr) {
        ZLOGE(LOG_LABEL, "send an wrong stub object");
        return 0;
    }
    binderObject->hdr.type = BINDER_TYPE_REMOTE_HANDLE;
    binderObject->cookie = IRemoteObject::IF_PROT_DATABUS;
    binderObject->binder = 0;
    return FlattenSession(sessionOffset, sessionOfPeer, SUPPORT_TOKENID_VERSION_NUM);
}

template<class T>
void DBinderBaseInvoker<T>::ClearBinderType(flat_binder_object *binderObject)
{
    binderObject->hdr.type = BINDER_TYPE_INVALID_BINDER;
    binderObject->cookie = IRemoteObject::IF_PROT_ERROR;
    binderObject->binder = 0;
}

template<class T>
uint32_t DBinderBaseInvoker<T>::TranslateHandleType(flat_binder_object *binderObject, char *sessionOffset,
    std::shared_ptr<T> session)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "IPCProcessSkeleton is nullptr");
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

    binderObject->hdr.type = BINDER_TYPE_REMOTE_HANDLE;
    return FlattenSession(sessionOffset, sessionOfPeer, SUPPORT_TOKENID_VERSION_NUM);
}

template<class T>
void DBinderBaseInvoker<T>::ClearHandleType(flat_binder_object *binderObject)
{
    binderObject->hdr.type = BINDER_TYPE_INVALID_HANDLE;
    binderObject->cookie = IRemoteObject::IF_PROT_ERROR;
    binderObject->binder = 0;
}

template<class T> uint32_t DBinderBaseInvoker<T>::MakeRemoteHandle(std::shared_ptr<T> session)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "IPCProcessSkeleton is nullptr");
        return 0;
    }

    if (!UpdateClientSession(session)) {
        ZLOGE(LOG_LABEL, "open session failed");
        return 0;
    }
    uint32_t handle = current->GetDBinderIdleHandle(session);
    if (handle == 0) {
        ZLOGE(LOG_LABEL, "get dbinder handle failed");
        if (current->QuerySessionByInfo(session->GetServiceName(), session->GetDeviceId()) == nullptr) {
            session->CloseDatabusSession();
        }
        return 0;
    }
    return handle;
}

template<class T>
bool DBinderBaseInvoker<T>::TranslateRemoteHandleType(flat_binder_object *binderObject, char *sessionOffset,
    uint32_t binderVersion)
{
    std::shared_ptr<T> sessionOfPeer = nullptr;
    if (binderObject->cookie == IRemoteObject::IF_PROT_DATABUS ||
        binderObject->cookie == IRemoteObject::IF_PROT_BINDER) {
        sessionOfPeer = UnFlattenSession(sessionOffset, binderVersion);
    }
    if (sessionOfPeer == nullptr) {
        ZLOGE(LOG_LABEL, "send a wrong dbinder object");
        return false;
    }

    // 1. If we find matched session, we need to first take its ownership in case of being erased
    // during proxy initialization
    // 2. If translate remote handle type concurrently, we may alloc two new handle, and open session
    // with the same sessionName and deviceId. thus get the same softbus session. this is OK because if
    // one proxy is reclaimed, we will close session when it is no longer used
    uint32_t handle = QueryHandleBySession(sessionOfPeer);
    if (handle == 0) {
        handle = MakeRemoteHandle(sessionOfPeer);
        ZLOGI(LOG_LABEL, "create new handle:%{public}u", handle);
        if (handle == 0) {
            ZLOGE(LOG_LABEL, "failed to create new handle");
            return false;
        }
    }
    // If any error occurred before, hdr.type was still BINDER_TYPE_REMOTE_HANDLE
    // Thus later UnFlattenObject will enter default case and return null
    binderObject->hdr.type = BINDER_TYPE_HANDLE;
    binderObject->handle = handle;
    return true;
}

/* check data parcel contains object, if yes, get its session as payload of socket packet
 * if translate any object failed, discard this parcel and do NOT send this parcel to remote
 */
template<class T>
bool DBinderBaseInvoker<T>::IRemoteObjectTranslateWhenSend(char *dataBuffer, binder_size_t bufferSize,
    MessageParcel &data, uint32_t socketId, std::shared_ptr<T> sessionObject)
{
    if (data.GetOffsetsSize() <= 0 || dataBuffer == nullptr) {
        return true;
    }

    uint32_t totalSize = 0;
    binder_size_t *binderObjectsOffsets = reinterpret_cast<binder_size_t *>(data.GetObjectOffsets());
    uint32_t offsetOfSession = bufferSize + data.GetOffsetsSize() * sizeof(binder_size_t);
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

            case BINDER_TYPE_FD: {
                binderObject->hdr.type = BINDER_TYPE_FDR;
                binderObject->handle = -1;
                break;
            }

            default: {
                ZLOGE(LOG_LABEL, "do not support this type:%{public}u of translation", binderObject->hdr.type);
                // do nothing
                break;
            }
        }
    }
    return true;
}

/* if translate any object failed, should translate next object flush it */
template<class T>
bool DBinderBaseInvoker<T>::IRemoteObjectTranslateWhenRcv(char *dataBuffer, binder_size_t bufferSize,
    MessageParcel &data, uint32_t socketId, std::shared_ptr<T> sessionObject)
{
    if (data.GetOffsetsSize() <= 0 || dataBuffer == nullptr) {
        return true;
    }
    binder_size_t *binderObjectsOffsets = reinterpret_cast<binder_size_t *>(data.GetObjectOffsets());
    uint32_t offsetOfSession = bufferSize + data.GetOffsetsSize() * sizeof(binder_size_t);
    char *flatOffset = dataBuffer + offsetOfSession;

    for (size_t i = 0; i < data.GetOffsetsSize(); i++) {
        auto binderObject = reinterpret_cast<flat_binder_object *>(dataBuffer + *(binderObjectsOffsets + i));
        switch (binderObject->hdr.type) {
            case BINDER_TYPE_BINDER: {
                ClearBinderType(binderObject);
                ZLOGE(LOG_LABEL, "receive an wrong stub object");
                break;
            }

            case BINDER_TYPE_HANDLE: {
                ClearHandleType(binderObject);
                ZLOGE(LOG_LABEL, "receive an wrong proxy object");
                break;
            }

            case BINDER_TYPE_REMOTE_HANDLE: {
                if (TranslateRemoteHandleType(binderObject, flatOffset + i * T::GetFlatSessionLen(),
                    SUPPORT_TOKENID_VERSION_NUM) != true) {
                    ZLOGE(LOG_LABEL, "receive an wrong dbiner object");
                    // do nothing, should translate other parcel object, such as fd should set to -1
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
                ZLOGE(LOG_LABEL, "do not support this type:%{public}u of translation", binderObject->hdr.type);
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
        ZLOGE(LOG_LABEL, "IPCProcessSkeleton is nullptr");
        return false;
    }
    std::shared_ptr<InvokerRawData> receivedRawData = current->QueryRawData(socketId);
    if (receivedRawData == nullptr) {
        ZLOGE(LOG_LABEL, "cannot found rawData according to the socketId:%{public}u", socketId);
        return false;
    }
    std::shared_ptr<char> rawData = receivedRawData->GetData();
    size_t rawSize = receivedRawData->GetSize();
    current->DetachRawData(socketId);
    if (!data.RestoreRawData(rawData, rawSize)) {
        ZLOGE(LOG_LABEL, "found rawData, but cannot restore them, socketId:%{public}u", socketId);
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
        ZLOGE(LOG_LABEL, "IPCProcessSkeleton is nullptr");
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
void DBinderBaseInvoker<T>::ConstructTransData(MessageParcel &data, dbinder_transaction_data &transData,
    size_t totalSize, uint64_t seqNum, int cmd, __u32 code, __u32 flags)
{
    transData.sizeOfSelf = totalSize;
    transData.magic = DBINDER_MAGICWORD;
    transData.version = SUPPORT_TOKENID_VERSION_NUM;
    transData.cmd = cmd;
    transData.code = code;
    transData.flags = flags;
    transData.cookie = 0;
    transData.seqNumber = seqNum;
    transData.buffer_size = 0;
    transData.offsets_size = 0;
    transData.offsets = 0;
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
        ZLOGE(LOG_LABEL, "fail to create raw buffer with length:%{public}zu", totalSize);
        return false;
    }

    ConstructTransData(data, *transData, totalSize, seqNum, BC_SEND_RAWDATA, 0, 0);
    int result = memcpy_s(reinterpret_cast<char *>(transData.get()) + sizeof(dbinder_transaction_data),
        totalSize - sizeof(dbinder_transaction_data), data.GetRawData(), data.GetRawDataSize());
    if (result != 0) {
        ZLOGE(LOG_LABEL, "memcpy data fail, size:%{public}zu", data.GetRawDataSize());
        return false;
    }
    result = OnSendRawData(sessionObject, transData.get(), totalSize);
    if (result != 0) {
        ZLOGE(LOG_LABEL, "fail to send raw data");
        return false;
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
            ZLOGE(LOG_LABEL, "parcel data memcpy_s failed, socketId:%{public}d", socketId);
            return false;
        }
        transData->offsets_size = data.GetOffsetsSize() * sizeof(binder_size_t);
        transData->offsets = transData->buffer_size;

        if (!CheckTransactionData(transData.get())) {
            ZLOGE(LOG_LABEL, "check trans data fail, socketId:%{public}d", socketId);
            return false;
        }
        if (!IRemoteObjectTranslateWhenSend(reinterpret_cast<char *>(transData->buffer), transData->buffer_size,
            data, socketId, sessionObject)) {
            ZLOGE(LOG_LABEL, "translate object failed, socketId:%{public}d", socketId);
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

    std::shared_ptr<dbinder_transaction_data> transData = nullptr;
    transData.reset(reinterpret_cast<dbinder_transaction_data *>(::operator new(sendSize)));
    if (transData == nullptr) {
        ZLOGE(LOG_LABEL, "new buffer failed of length:%{public}u", sendSize);
        return nullptr;
    }
    ConstructTransData(data, *transData, sendSize, seqNum, cmd, code, flags);
    transData->cookie = (handle == 0) ? 0 : sessionObject->GetStubIndex();
    if (MoveMessageParcel2TransData(data, sessionObject, transData, socketId, status) != true) {
        ZLOGE(LOG_LABEL, "move parcel to transData failed, handle:%{public}d socketId:%{public}d", handle, socketId);
        return nullptr;
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

    sessionBuff->UpdateSendBuffer(sendSize);
    ssize_t writeCursor = sessionBuff->GetSendBufferWriteCursor();
    ssize_t readCursor = sessionBuff->GetSendBufferReadCursor();
    if (writeCursor < 0 || readCursor < 0 || sendSize > sessionBuff->GetSendBufferSize() - writeCursor) {
        sessionBuff->ReleaseSendBufferLock();
        ZLOGE(LOG_LABEL, "sender's data is large than idle buffer, writecursor:%{public}zd readcursor:%{public}zd,\
            sendSize:%{public}u bufferSize:%{public}u",
            writeCursor, readCursor, sendSize, sessionBuff->GetSendBufferSize());
        return false;
    }
    if (memcpy_s(sendBuffer + writeCursor, sendSize, transData.get(), sendSize)) {
        sessionBuff->ReleaseSendBufferLock();
        ZLOGE(LOG_LABEL, "fail to copy from tr to sendBuffer, parcelSize:%{public}u", sendSize);
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
        ZLOGE(LOG_LABEL, "session is not exist for listenFd:%{public}d handle:%{public}d", socketId, handle);
        DfxReportFailListenEvent(DbinderErrorCode::RPC_DRIVER, socketId, RADAR_GET_SESSION_FAIL, __FUNCTION__);
        return nullptr;
    }

    uint64_t seqNum = GetUniqueSeqNumber(cmd);
    if (seqNum == 0) {
        ZLOGE(LOG_LABEL, "seqNum invalid, listenFd:%{public}d handle:%{public}d", socketId, handle);
        DfxReportFailListenEvent(DbinderErrorCode::RPC_DRIVER, socketId, RADAR_SEQ_INVALID, __FUNCTION__);
        return nullptr;
    }
    /* save seqNum for wait thread */
    seqNumber = seqNum;
    /* if MessageParcel has raw data, send raw data first, then send MessageParcel to peer */
    if (ProcessRawData(sessionObject, data, seqNum) != true) {
        ZLOGE(LOG_LABEL, "send rawdata failed, listenFd:%{public}d handle:%{public}d", socketId, handle);
        DfxReportFailListenEvent(DbinderErrorCode::RPC_DRIVER, socketId, RADAR_SEND_RAW_DATA_FAIL, __FUNCTION__);
        return nullptr;
    }
    std::shared_ptr<dbinder_transaction_data> transData =
        ProcessNormalData(sessionObject, data, handle, socketId, seqNum, cmd, code, flags, status);
    if (transData == nullptr) {
        ZLOGE(LOG_LABEL, "send normal data failed, listenFd:%{public}d handle:%{public}d", socketId, handle);
        DfxReportFailListenEvent(DbinderErrorCode::RPC_DRIVER, socketId, RADAR_SEND_NORMAL_DATA_FAIL, __FUNCTION__);
        return nullptr;
    }

    if (MoveTransData2Buffer(sessionObject, transData) != true) {
        ZLOGE(LOG_LABEL, "move transaction data to buffer failed, listenFd:%{public}d handle:%{public}d",
            socketId, handle);
        DfxReportFailListenEvent(DbinderErrorCode::RPC_DRIVER, socketId,
            RADAR_MOVE_TRANS_DATA_TO_BUFFER_FAIL, __FUNCTION__);
        return nullptr;
    }
    return sessionObject;
}

template <class T>
int DBinderBaseInvoker<T>::HandleReply(uint64_t seqNumber, MessageParcel *reply,
    std::shared_ptr<ThreadMessageInfo> messageInfo)
{
    if (reply == nullptr) {
        ZLOGE(LOG_LABEL, "no need reply, free the buffer");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_NO_NEED_REPLY, __FUNCTION__);
        return RPC_BASE_INVOKER_INVALID_REPLY_ERR;
    }

    if (messageInfo == nullptr) {
        ZLOGE(LOG_LABEL, "receive buffer is nullptr");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_RECEIVE_BUFFER_NULL, __FUNCTION__);
        return RPC_BASE_INVOKER_INVALID_REPLY_ERR;
    }

    if (messageInfo->flags & MessageOption::TF_STATUS_CODE) {
        int32_t err = static_cast<int32_t>(messageInfo->offsetsSize);
        return err;
    }
    if (messageInfo->buffer == nullptr) {
        ZLOGE(LOG_LABEL, "need reply message, but buffer is nullptr");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_BUFFER_NULL, __FUNCTION__);
        return RPC_BASE_INVOKER_INVALID_REPLY_ERR;
    }
    auto allocator = new (std::nothrow) DBinderRecvAllocator();
    if (allocator == nullptr) {
        ZLOGE(LOG_LABEL, "create DBinderRecvAllocator object failed");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_CREATE_RECV_ALLOCATOR_FAIL, __FUNCTION__);
        return RPC_BASE_INVOKER_INVALID_REPLY_ERR;
    }
    if (!reply->SetAllocator(allocator)) {
        ZLOGE(LOG_LABEL, "SetAllocator failed");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_SET_ALLOCATOR_FAIL, __FUNCTION__);
        delete allocator;
        return RPC_BASE_INVOKER_INVALID_REPLY_ERR;
    }
    reply->ParseFrom(reinterpret_cast<uintptr_t>(messageInfo->buffer), messageInfo->bufferSize);

    if (messageInfo->offsetsSize > 0) {
        reply->InjectOffsets(
            reinterpret_cast<binder_uintptr_t>(reinterpret_cast<char *>(messageInfo->buffer) + messageInfo->offsets),
            messageInfo->offsetsSize / sizeof(binder_size_t));
    }

    if (!IRemoteObjectTranslateWhenRcv(reinterpret_cast<char *>(messageInfo->buffer), messageInfo->bufferSize, *reply,
        messageInfo->socketId, nullptr)) {
        ZLOGE(LOG_LABEL, "translate object failed, socketId:%{public}u", messageInfo->socketId);
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_TRANSLATE_OBJECT_FAIL, __FUNCTION__);
        return RPC_BASE_INVOKER_INVALID_REPLY_ERR;
    }

    return ERR_NONE;
}

template <class T> void DBinderBaseInvoker<T>::DBinderSendAllocator::Dealloc(void *data) {}

template <class T> void DBinderBaseInvoker<T>::DBinderRecvAllocator::Dealloc(void *data)
{
    delete[](unsigned char *) data;
}

template <class T>
int DBinderBaseInvoker<T>::WaitForReply(uint64_t seqNumber, MessageParcel *reply, uint32_t handle, int userWaitTime)
{
    /* if reply == nullptr, this is a one way message */
    if (reply == nullptr) {
        return NO_ERROR;
    }

    std::shared_ptr<ThreadMessageInfo> messageInfo = MakeThreadMessageInfo(handle);
    if (messageInfo == nullptr) {
        ZLOGE(LOG_LABEL, "make thread message info failed, handle:%{public}u seq:%{public}" PRIu64,
            handle, seqNumber);
        return RPC_BASE_INVOKER_WAIT_REPLY_ERR;
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "IPCProcessSkeleton is nullptr, handle:%{public}u seq:%{public}" PRIu64,
            handle, seqNumber);
        return RPC_BASE_INVOKER_WAIT_REPLY_ERR;
    }
    /* wait for reply */
    if (!current->AddSendThreadInWait(seqNumber, messageInfo, userWaitTime)) {
        current->EraseThreadBySeqNumber(seqNumber);
        ZLOGE(LOG_LABEL, "sender thread wait reply message time out, "
            "waitTime:%{public}d handle:%{public}u seq:%{public}" PRIu64, userWaitTime, handle, seqNumber);
        return RPC_BASE_INVOKER_WAIT_REPLY_ERR;
    }

    int32_t err = HandleReply(seqNumber, reply, messageInfo);
    current->EraseThreadBySeqNumber(seqNumber);
    messageInfo->buffer = nullptr;
    messageInfo->ready = false;
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
        ZLOGE(LOG_LABEL, "current session is invalid, seq:%{public}" PRIu64, seqNumber);
        return RPC_BASE_INVOKER_INVALID_DATA_ERR;
    }
    int result = OnSendMessage(sessionOfPeer);
    if (result != 0) {
        ZLOGE(LOG_LABEL, "fail to send to remote session, error:%{public}d seq:%{public}" PRIu64, result, seqNumber);
        return RPC_BASE_INVOKER_INVALID_DATA_ERR;
    }
    result = WaitForReply(seqNumber, reply, sessionOfPeer->GetSocketId(), userWaitTime);
    if (result != ERR_NONE) {
        ZLOGE(LOG_LABEL, "dbinder wait for reply error:%{public}d seq:%{public}" PRIu64, result, seqNumber);
    }
    return result;
}

template <class T>
int DBinderBaseInvoker<T>::SendRequest(int32_t handle, uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    uint64_t seqNumber = 0;
    int ret;

    uint32_t flags = static_cast<uint32_t>(option.GetFlags());
    int userWaitTime = option.GetWaitTime();
    MessageParcel &newData = const_cast<MessageParcel &>(data);
    size_t oldWritePosition = newData.GetWritePosition();
    HiTraceId traceId = HiTraceChain::GetId();
    // set client send trace point if trace is enabled
    HiTraceId childId = HitraceInvoker::TraceClientSend(handle, code, newData, flags, traceId);
    std::shared_ptr<T> session = WriteTransaction(BC_TRANSACTION, flags, handle, 0, code, data, seqNumber, 0);
    if (session == nullptr) {
        newData.RewindWrite(oldWritePosition);
        ZLOGE(LOG_LABEL, "WriteTransaction fail, handle:%{public}d", handle);
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
        ZLOGE(LOG_LABEL, "WriteTransaction fail, seqNumber can not be zero");
        return RPC_BASE_INVOKER_SEND_REPLY_ERR;
    }
    SendOrWaitForCompletion(0, seqNumber, sessionObject, nullptr);
    return 0;
}

template <class T> std::shared_ptr<ThreadMessageInfo> DBinderBaseInvoker<T>::MakeThreadMessageInfo(int32_t socketId)
{
    std::shared_ptr<ThreadMessageInfo> messageInfo = std::make_shared<struct ThreadMessageInfo>();
    if (messageInfo == nullptr) {
        ZLOGE(LOG_LABEL, "make ThreadMessageInfo fail");
        return nullptr;
    }

    messageInfo->buffer = nullptr;
    messageInfo->offsets = 0;
    messageInfo->socketId = static_cast<uint32_t>(socketId);
    messageInfo->ready = false;
    return messageInfo;
}

template <class T>
std::shared_ptr<ThreadProcessInfo> DBinderBaseInvoker<T>::MakeThreadProcessInfo(int32_t socketId, const char *inBuffer,
    uint32_t size)
{
    if (inBuffer == nullptr || size < sizeof(dbinder_transaction_data) || size > SOCKET_MAX_BUFF_SIZE) {
        ZLOGE(LOG_LABEL, "buffer is null or size:%{public}u invalid, socketId:%{public}d", size, socketId);
        return nullptr;
    }

    std::shared_ptr<ThreadProcessInfo> processInfo(new ThreadProcessInfo, [](ThreadProcessInfo *ptr) {
        if (ptr != nullptr) {
            delete ptr;
            ptr = nullptr;
        }
    });
    if (processInfo == nullptr) {
        ZLOGE(LOG_LABEL, "make ThreadProcessInfo fail, socketId:%{public}d", socketId);
        return nullptr;
    }
    std::shared_ptr<char> buffer(new (std::nothrow) char[size]);
    if (buffer == nullptr) {
        ZLOGE(LOG_LABEL, "new buffer failed of length:%{public}u socketId:%{public}d", size, socketId);
        return nullptr;
    }

    int memcpyResult = memcpy_s(buffer.get(), size, inBuffer, size);
    if (memcpyResult != 0) {
        ZLOGE(LOG_LABEL, "memcpy_s failed , size:%{public}u socketId:%{public}d", size, socketId);
        return nullptr;
    }

    processInfo->listenFd = socketId;
    processInfo->packageSize = size;
    processInfo->buffer = buffer;
    return processInfo;
}

template <class T> void DBinderBaseInvoker<T>::StartProcessLoop(int32_t socketId, const char *buffer, uint32_t size)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "IPCProcessSkeleton is nullptr");
        return;
    }
    std::shared_ptr<ThreadProcessInfo> processInfo = MakeThreadProcessInfo(socketId, buffer, size);
    if (processInfo == nullptr) {
        ZLOGE(LOG_LABEL, "processInfo is nullptr");
        return;
    }
    std::thread::id threadId = current->GetIdleDataThread();
    if (threadId == std::thread::id()) {
        bool result = CreateProcessThread();
        if (!result) {
            int socketThreadNum = current->GetSocketTotalThreadNum();
            ZLOGE(LOG_LABEL, "create IO thread failed, current socket thread num:%{public}d socketId:%{public}d",
                socketThreadNum, socketId);
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

template <class T> void DBinderBaseInvoker<T>::ProcessTransaction(dbinder_transaction_data *tr, int32_t listenFd)
{
    MessageParcel data, reply;

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "IPCProcessSkeleton is nullptr");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_IPC_PROCESS_SKELETON_NULL, __FUNCTION__);
        return;
    }

    auto allocator = new (std::nothrow) DBinderSendAllocator();
    if (allocator == nullptr) {
        ZLOGE(LOG_LABEL, "DBinderSendAllocator failed, listenFd:%{public}d", listenFd);
        DfxReportFailListenEvent(DbinderErrorCode::RPC_DRIVER, listenFd, RADAR_SEND_ALLOCATOR_FAIL, __FUNCTION__);
        return;
    }
    if (!data.SetAllocator(allocator)) {
        ZLOGE(LOG_LABEL, "SetAllocator failed, listenFd:%{public}d", listenFd);
        DfxReportFailListenEvent(DbinderErrorCode::RPC_DRIVER, listenFd, RADAR_SET_ALLOCATOR_FAIL, __FUNCTION__);
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
    int32_t oldClientFd = GetClientFd();
    const uint32_t oldTokenId = GetCallerTokenID();
    if (CheckAndSetCallerInfo(listenFd, tr->cookie) != ERR_NONE) {
        ZLOGE(LOG_LABEL, "check and set caller info failed, cmd:%{public}u listenFd:%{public}d", tr->code, listenFd);
        DfxReportFailListenEvent(DbinderErrorCode::RPC_DRIVER, listenFd, RADAR_CHECK_AND_SET_CALLER_FAIL, __FUNCTION__);
        return;
    }
    SetStatus(IRemoteInvoker::ACTIVE_INVOKER);

    const uint32_t flags = tr->flags;
    uint64_t senderSeqNumber = tr->seqNumber;
    int error = ERR_NONE;
    {
        std::lock_guard<std::mutex> lockGuard(objectMutex_);
        auto *stub = current->QueryStubByIndex(tr->cookie);
        if (stub == nullptr) {
            ZLOGE(LOG_LABEL, "stubIndex is invalid, listenFd:%{public}d seq:%{public}" PRIu64,
                listenFd, senderSeqNumber);
            DfxReportFailListenEvent(DbinderErrorCode::RPC_DRIVER, listenFd, RADAR_STUB_INVALID, __FUNCTION__);
            return;
        }
        if (!IRemoteObjectTranslateWhenRcv(reinterpret_cast<char *>(tr->buffer), tr->buffer_size, data,
            listenFd, nullptr)) {
            ZLOGE(LOG_LABEL, "translate object failed, listenFd:%{public}d seq:%{public}" PRIu64,
                listenFd, senderSeqNumber);
            DfxReportFailListenEvent(DbinderErrorCode::RPC_DRIVER, listenFd, RADAR_TRANSLATE_FAIL, __FUNCTION__);
            return;
        }

        auto *stubObject = reinterpret_cast<IPCObjectStub *>(stub);
        MessageOption option;
        option.SetFlags(flags);
        // cannot use stub any more after SendRequest because this cmd may be
        // dbinder dec ref and thus stub will be destroyed
        int error = stubObject->SendRequest(tr->code, data, reply, option);
        if (error != ERR_NONE) {
            ZLOGW(LOG_LABEL, "stub sendrequest failed, cmd:%{public}u error:%{public}d "
                "listenFd:%{public}d seq:%{public}" PRIu64, tr->code, error, listenFd, senderSeqNumber);
            // can not return;
        }
    }

    if (data.GetRawData() != nullptr) {
        ZLOGW(LOG_LABEL, "delete raw data in process skeleton, listenFd:%{public}d seq:%{public}" PRIu64,
            listenFd, senderSeqNumber);
        current->DetachRawData(listenFd);
    }
    HitraceInvoker::TraceServerSend(tr->cookie, tr->code, isServerTraced, newflags);
    if (!(flags & MessageOption::TF_ASYNC)) {
        SetSeqNum(senderSeqNumber);
        SendReply(reply, 0, error);
        SetSeqNum(0);
    }

    SetCallerPid(oldPid);
    SetCallerUid(oldUid);
    SetCallerDeviceID(oldDeviceId);
    SetStatus(oldStatus);
    SetClientFd(oldClientFd);
    SetCallerTokenID(oldTokenId);
}

template <class T> void DBinderBaseInvoker<T>::ProcessReply(dbinder_transaction_data *tr, int32_t listenFd)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "IPCProcessSkeleton is nullptr, can not wakeup thread");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_IPC_PROCESS_SKELETON_NULL, __FUNCTION__);
        return;
    }

    std::shared_ptr<ThreadMessageInfo> messageInfo = current->QueryThreadBySeqNumber(tr->seqNumber);
    if (messageInfo == nullptr) {
        ZLOGE(LOG_LABEL, "no thread waiting reply message of this seqNumber:%{public}llu listenFd:%{public}d",
            tr->seqNumber, listenFd);
        DfxReportFailListenEvent(DbinderErrorCode::RPC_DRIVER, listenFd, RADAR_SEQ_MESSAGE_NULL, __FUNCTION__);
        /* messageInfo is null, no thread need to wakeup */
        return;
    }

    /* tr->sizeOfSelf > sizeof(dbinder_transaction_data) is checked in CheckTransactionData */
    messageInfo->buffer = new (std::nothrow) unsigned char[tr->sizeOfSelf - sizeof(dbinder_transaction_data)];
    if (messageInfo->buffer == nullptr) {
        ZLOGE(LOG_LABEL, "some thread is waiting for reply message, but no memory"
            ", seqNumber:%{public}llu listenFd:%{public}d", tr->seqNumber, listenFd);
        DfxReportFailListenEvent(DbinderErrorCode::RPC_DRIVER, listenFd, RADAR_SEQ_MESSAGE_BUFFER_NULL, __FUNCTION__);
        /* wake up sender thread */
        current->WakeUpThreadBySeqNumber(tr->seqNumber, listenFd);
        return;
    }
    /* copy receive message to sender thread */
    int memcpyResult = memcpy_s(messageInfo->buffer, tr->sizeOfSelf - sizeof(dbinder_transaction_data), tr->buffer,
        tr->sizeOfSelf - sizeof(dbinder_transaction_data));
    if (memcpyResult != 0) {
        ZLOGE(LOG_LABEL, "memcpy_s failed, error:%{public}d seqNumber:%{public}llu listenFd:%{public}d",
            memcpyResult, tr->seqNumber, listenFd);
        DfxReportFailListenEvent(DbinderErrorCode::RPC_DRIVER, listenFd, RADAR_ERR_MEMCPY_DATA, __FUNCTION__);
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
    messageInfo->socketId = static_cast<uint32_t>(listenFd);

    /* wake up sender thread */
    current->WakeUpThreadBySeqNumber(tr->seqNumber, listenFd);
}

template <class T> void DBinderBaseInvoker<T>::OnTransaction(std::shared_ptr<ThreadProcessInfo> processInfo)
{
    if (processInfo == nullptr) {
        ZLOGE(LOG_LABEL, "processInfo is error!");
        return;
    }
    int32_t listenFd = processInfo->listenFd;
    char *package = processInfo->buffer.get();

    if (package == nullptr || listenFd < 0) {
        ZLOGE(LOG_LABEL, "package is null or listenFd:%{public}d invalid!", listenFd);
        return;
    }

    dbinder_transaction_data *tr = reinterpret_cast<dbinder_transaction_data *>(package);
    if (tr->sizeOfSelf < sizeof(dbinder_transaction_data)) {
        ZLOGE(LOG_LABEL, "package size:%{public}u is invalid, expected size:%{public}zu",
            tr->sizeOfSelf, sizeof(dbinder_transaction_data));
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
        if (sessionSize * sizeof(binder_size_t) != tr->offsets_size * T::GetFlatSessionLen()) {
            return false;
        }
    }

    return true;
}

template <class T> std::mutex &DBinderBaseInvoker<T>::GetObjectMutex()
{
    return objectMutex_;
}

} // namespace OHOS
#endif // OHOS_IPC_DBINDER_BASE_INVOKER_H
