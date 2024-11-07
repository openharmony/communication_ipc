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

#ifndef OHOS_IPC_DBINDER_BASE_INVOKER_OBJECT_H
#define OHOS_IPC_DBINDER_BASE_INVOKER_OBJECT_H

#include "dbinder_base_invoker_define.h"

namespace OHOS {

template<class T> uint32_t DBinderBaseInvoker<T>::TranslateBinderType(
    flat_binder_object *binderObject, char *sessionOffset, std::shared_ptr<T> session)
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

template<class T> void DBinderBaseInvoker<T>::ClearBinderType(flat_binder_object *binderObject)
{
    binderObject->hdr.type = BINDER_TYPE_INVALID_BINDER;
    binderObject->cookie = IRemoteObject::IF_PROT_ERROR;
    binderObject->binder = 0;
}

template<class T> uint32_t DBinderBaseInvoker<T>::TranslateHandleType(
    flat_binder_object *binderObject, char *sessionOffset, std::shared_ptr<T> session)
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

template<class T> void DBinderBaseInvoker<T>::ClearHandleType(flat_binder_object *binderObject)
{
    binderObject->hdr.type = BINDER_TYPE_INVALID_HANDLE;
    binderObject->cookie = IRemoteObject::IF_PROT_ERROR;
    binderObject->binder = 0;
}

template<class T> bool DBinderBaseInvoker<T>::TranslateRemoteHandleType(
    flat_binder_object *binderObject, char *sessionOffset, uint32_t binderVersion)
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
                binderObject->handle = -1;
                break;
            }
            default: {
                ZLOGE(LOG_LABEL, "do not support this type:%{public}u of translation", binderObject->hdr.type);
                binderObject->hdr.type = BINDER_TYPE_INVALID_TYPE;
                // do nothing
                break;
            }
        }
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

template <class T>
bool DBinderBaseInvoker<T>::MoveTransData2Buffer(std::shared_ptr<T> sessionObject,
    std::shared_ptr<dbinder_transaction_data> transData)
{
    std::shared_ptr<BufferObject> sessionBuff = sessionObject->GetSessionBuff();
    if (sessionBuff == nullptr) {
        ZLOGE(LOG_LABEL, "get session buffer fail");
        return false;
    }
    if (transData == nullptr) {
        ZLOGE(LOG_LABEL, "transData is nullptr");
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
    if (writeCursor < 0 || readCursor < 0 || static_cast<uint32_t>(writeCursor) > sessionBuff->GetSendBufferSize() ||
        sendSize > sessionBuff->GetSendBufferSize() - static_cast<uint32_t>(writeCursor)) {
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

template <class T> bool DBinderBaseInvoker<T>::AddDeathRecipient(int32_t handle, void *cookie)
{
    return true;
}

template <class T> bool DBinderBaseInvoker<T>::RemoveDeathRecipient(int32_t handle, void *cookie)
{
    return true;
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

template<class T> uint32_t DBinderBaseInvoker<T>::MakeRemoteHandle(std::shared_ptr<T> session)
{
    if (session == nullptr) {
        ZLOGE(LOG_LABEL, "session is nullptr");
        return 0;
    }
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

} // namespace OHOS
#endif // OHOS_IPC_DBINDER_BASE_INVOKER_OBJECT_H