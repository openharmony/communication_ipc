/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_IPC_IPC_OBJECT_STUB_H
#define OHOS_IPC_IPC_OBJECT_STUB_H

#include <list>
#include "ipc_object_proxy.h"
#include "iremote_object.h"

namespace OHOS {
struct RefCountNode {
    int remotePid;
    std::string deviceId;
};

class IPCObjectStub : public IRemoteObject {
public:
    /**
     * @brief Enumerates object types.
     * @since 9
     */
    enum {
        OBJECT_TYPE_NATIVE,
        OBJECT_TYPE_JAVA,
        OBJECT_TYPE_JAVASCRIPT,
    };

    explicit IPCObjectStub(std::u16string descriptor = std::u16string(), bool serialInvokeFlag = false);
    ~IPCObjectStub();

    /**
     * @brief Determine whether it is a Proxy Object.
     * @return Returns <b>true</b> if it is a Proxy Object; returns <b>false</b> otherwise.
     * @since 9
     */
    bool IsProxyObject() const override
    {
        return false;
    };

    /**
     * @brief Determine the reference count of the object.
     * @return Returns the reference pointer count.
     * @since 9
     */
    int32_t GetObjectRefCount() override;

    /**
     * @brief Dump the contents.
     * @param fd Indicates the file descriptor.
     * @param args Indicates a vector containing u16string.
     * @return Returns {@link ERR_NONE} if the dump is successful; returns an error code
     * defined in {@link ipc_types.h} otherwise.
     * @since 9
     */
    int Dump(int fd, const std::vector<std::u16string> &args) override;

    /**
     * @brief Sets an entry for receiving requests.
     * @param code Indicates the service request code sent from the peer end.
     * @param data Indicates the object sent from the peer end.
     * @param reply Indicates the response message object sent from the remote service.
     * @param option Indicates whether the operation is synchronous or asynchronous.
     * @return Returns {@link ERR_NONE} if the operation is successful; returns an error code
     * defined in {@link ipc_types.h} otherwise.
     * @since 9
     */
    virtual int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

    /**
     * @brief Sends a request to the peer object.
     * @param code Indicates the message code of the request.
     * @param data Indicates the object storing the data to be sent.
     * @param reply Indicates the object receiving the response data.
     * @param option Indicates a synchronous (default) or asynchronous request.
     * @return Returns {@link ERR_NONE} if the operation is successful; returns an error code
     * defined in {@link ipc_types.h}otherwise.
     * @since 9
     */
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    /**
     * @brief The callback function that is strongly referenced for the first time.
     * @param objectId Indicates the object Id.
     * @return void
     * @since 9
     */
    void OnFirstStrongRef(const void *objectId) override;

    /**
     * @brief The callback function that is strongly referenced for the last time.
     * @param objectId Indicates the object Id.
     * @return void
     * @since 9
     */
    void OnLastStrongRef(const void *objectId) override;

    /**
     * @brief Register for callbacks to receive death notifications.
     * @param recipient Indicates the DeathRecipient pointer callback to register.
     * @return Returns <b>true</b> if register succeeds; returns <b>false</b> otherwise.
     * @since 9
     */
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override;

    /**
     * @brief Unregister for callbacks to receive death notifications.
     * @param recipient Indicates the DeathRecipient pointer callback to register.
     * @return Returns <b>true</b> if unregister succeeds; returns <b>false</b> otherwise.
     * @since 9
     */
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override;

    /**
     * @brief Obtains the PID of the object.
     * @return Returns the PID of the object.
     * @since 9
     */
    int GetCallingPid();

    /**
     * @brief Obtains the UID of the object.
     * @return Returns the UID of the object.
     * @since 9
     */
    int GetCallingUid();

    /**
     * @brief Obtains calling token ID of caller.
     * @return Returns the TokenId of caller.
     * @since 9
     */
    uint32_t GetCallingTokenID();

    /**
     * @brief Obtains full calling token ID of caller.
     * @return Returns the full TokenId of caller.
     * @since 9
     */
    uint64_t GetCallingFullTokenID();

    /**
     * @brief Obtains the first token ID.
     * @return Returns the first TokenId.
     * @since 9
     */
    uint32_t GetFirstTokenID();

    /**
     * @brief Obtains the first full token ID.
     * @return Returns the first full TokenId.
     * @since 9
     */
    uint64_t GetFirstFullTokenID();

    /**
     * @brief Take a remote dump.
     * @param code Indicates the service request code sent from the peer end.
     * @param data Indicates the object sent from the peer end.
     * @param reply Indicates the response message object sent from the remote service.
     * @param option Indicates whether the operation is synchronous or asynchronous.
     * @return Returns {@link ERR_NONE} if the operation is successful; returns an error code
     * defined in {@link ipc_types.h} otherwise.
     * @since 9
     */
    virtual int OnRemoteDump(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

    /**
     * @brief Obtains the process protocol.
     * @param code Indicates the service request code sent from the peer end.
     * @param data Indicates the object sent from the peer end.
     * @param reply Indicates the response message object sent from the remote service.
     * @param option Indicates whether the operation is synchronous or asynchronous.
     * @return Returns {@link ERR_NONE} if the operation is successful; returns an error code
     * defined in {@link ipc_types.h} otherwise.
     * @since 9
     */
    virtual int32_t ProcessProto(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

    /**
     * @brief Obtains the object type.
     * @return Returns an enumeration value that represents the type of object.
     * @since 9
     */
    virtual int GetObjectType() const;

    /**
     * @brief Obtains the last request time.
     * @return Returns the last request time.
     * @since 11
     */
    uint64_t GetLastRequestTime();

    /**
     * @brief Obtain the flag for sid.
     * @return Return the value of flag.
     * @since 12
     */
    bool GetRequestSidFlag() const;

    /**
     * @brief Set the value of the sid flag.
     * @return void.
     * @since 12
     */
    void SetRequestSidFlag(bool flag);

    /**
     * @brief Get and save the dbinder object data.
     * @param pid Indicates the sender pid.
     * @param uid Indicates the sender uid.
     * @return Returns {@link ERR_NONE} if the operation is successful; returns an error code
     * defined in {@link ipc_types.h} otherwise.
     * @since 12
     */
    virtual int GetAndSaveDBinderData(pid_t pid, uid_t uid);

#ifndef CONFIG_IPC_SINGLE
    /**
     * @brief Invoker the calling thread.
     * @param code Indicates the message code.
     * @param data Indicates the object sent to the peer process.
     * @param reply Indicates the object returned by the peer process.
     * @param option Indicates the synchronous or asynchronous mode to send messages.
     * @return Returns {@link ERR_NONE} if the operation is successful; returns an error code
     * defined in {@link ipc_types.h} otherwise.
     * @since 9
     */
    int32_t InvokerThread(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

    /**
     * @brief Notification service death.
     * @param data Indicates the object sent to the peer process.
     * @param reply Indicates the object returned by the peer process.
     * @param option Indicates the synchronous or asynchronous mode to send messages.
     * @return Returns {@link ERR_NONE} if the operation is successful; returns an error code
     * defined in {@link ipc_types.h} otherwise.
     * @since 9
     */
    int32_t NoticeServiceDie(MessageParcel &data, MessageParcel &reply, MessageOption &option);

    /**
     * @brief Invoke the data bus thread.
     * @param data Indicates the object sent to the peer process.
     * @param reply Indicates the object returned by the peer process.
     * @return Returns {@link ERR_NONE} if the operation is successful; returns an error code
     * defined in {@link ipc_types.h} otherwise.
     * @since 9
     */
    int32_t InvokerDataBusThread(MessageParcel &data, MessageParcel &reply);

    /**
     * @brief Add authentication information.
     * @param data Indicates the object sent to the peer process.
     * @param reply Indicates the object returned by the peer process.
     * @param code Indicates the message code of this request.
     * @return Returns {@link ERR_NONE} if the operation is successful; returns an error code
     * defined in {@link ipc_types.h} otherwise.
     * @since 9
     */
    int32_t AddAuthInfo(MessageParcel &data, MessageParcel &reply, uint32_t code);
#endif

private:
#ifndef CONFIG_IPC_SINGLE
    int GetPidUid(MessageParcel &data, MessageParcel &reply);
    std::string GetSessionName();
    int32_t GetSessionNameForPidUid(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int32_t GetGrantedSessionName(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    std::string CreateSessionName(int uid, int pid);
    int RemoveSessionName(MessageParcel &data);
    bool IsSamgrCall();
    int DBinderInvokeListenThread(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int DBinderIncRefsTransaction(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int DBinderDecRefsTransaction(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int DBinderAddCommAuth(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int DBinderGetSessionName(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int DBinderGetGrantedSessionName(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int DBinderGetSessionNameForPidUid(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int DBinderGetPidUid(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int DBinderRemoveSessionName(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
#endif

    bool IsDeviceIdIllegal(const std::string &deviceID);
    int DBinderPingTransaction(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int DBinderSearchDescriptor(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int DBinderSearchRefCount(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int DBinderDumpTransaction(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int SendRequestInner(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

    std::recursive_mutex serialRecursiveMutex_;
    bool serialInvokeFlag_;
    uint64_t lastRequestTime_;
    std::atomic<bool> requestSidFlag_ = false;
};
} // namespace OHOS
#endif // OHOS_IPC_IPC_OBJECT_STUB_H
