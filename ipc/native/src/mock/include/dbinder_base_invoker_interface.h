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

#ifndef OHOS_IPC_DBINDER_BASE_INVOKER_INTERFACE_H
#define OHOS_IPC_DBINDER_BASE_INVOKER_INTERFACE_H

#include "dbinder_base_invoker_object.h"
#include "dbinder_base_invoker_process.h"

namespace OHOS {

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
#endif // OHOS_IPC_DBINDER_BASE_INVOKER_INTERFACE_H