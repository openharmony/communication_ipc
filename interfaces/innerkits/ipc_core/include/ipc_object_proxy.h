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

#ifndef OHOS_IPC_IPC_OBJECT_PROXY_H
#define OHOS_IPC_IPC_OBJECT_PROXY_H

#include <dlfcn.h>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <vector>

#include "iremote_object.h"

namespace OHOS {
#define GET_FIRST_VIRTUAL_FUNC_ADDR(ptr) (*reinterpret_cast<uintptr_t *>(*reinterpret_cast<uintptr_t *>(ptr)))
#ifndef CONFIG_IPC_SINGLE
struct DBinderNegotiationData {
    pid_t peerPid;
    pid_t peerUid;
    uint32_t peerTokenId;
    uint64_t stubIndex;
    std::string peerServiceName;
    std::string peerDeviceId;
    std::string localServiceName;
    std::string localDeviceId;
};
#endif

class IPCObjectProxy : public IRemoteObject {
public:
    explicit IPCObjectProxy(int handle, std::u16string descriptor = std::u16string(),
        int proto = IRemoteObject::IF_PROT_DEFAULT);
    ~IPCObjectProxy();

   /**
    * @brief Sends message to the peer process in synchronous or asynchronous mode.
    * @param code Indicates the message code, which is determined by both sides of the communication.
    * @param data Indicates the object sent to the peer process.
    * @param reply Indicates the object returned by the peer process.
    * @param optionoption Indicates the synchronous or asynchronous mode to send messages.
    * @return Returns {@link ERR_NONE} if the operation is successful; returns an error code
    * defined in {@link ipc_types.h} otherwise.
    * @since 9
    */
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &optionoption) override;

    /**
     * @brief Determine whether it is a Proxy Object.
     * @return Returns <b>true</b> if it is Proxy Object; returns <b>false</b> otherwise.
     * @since 9
     */
    bool IsProxyObject() const override
    {
        return true;
    };

    /**
     * @brief Checks whether an object is dead.
     * @return Returns <b>true</b> if the object is dead; returns <b>false</b> otherwise.
     * @since 9
     */
    bool IsObjectDead() const override;

    /**
     * @brief Obtains the reference count of the object.
     * @return Returns the reference count.
     * @since 9
     */
    int32_t GetObjectRefCount() override;

    /**
     * @brief Dump the contents.
     * @param fd Indicates the file descriptor.
     * @param args Indicates a vector containing u16string.
     * @return Returns {@link ERR_NONE} if the operation is successful; returns an error code
     * defined in {@link ipc_types.h} otherwise.
     * @since 9
     */
    int Dump(int fd, const std::vector<std::u16string> &args) override;

    /**
     * @brief The first strong reference provided.
     * @param objectId Indicates the object Id.
     * @return void
     * @since 9
     */
    void OnFirstStrongRef(const void *objectId) override;

    /**
     * @brief The last strong reference provided.
     * @param objectId Indicates the object Id.
     * @return void
     * @since 9
     */
    void OnLastStrongRef(const void *objectId) override;

    /**
     * @brief Registered a death recipient.
     * @param recipient Indicates the recipient of the DeathRecipient pointer.
     * @return Returns <b>true</b> if the callback is registered successfully; returns <b>false</b> otherwise.
     * @since 9
     */
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override;

    /**
     * @brief Unregistered a death recipient.
     * @param recipient Indicates the recipient of the DeathRecipient pointer.
     * @return Returns <b>true</b> if the callback is registered successfully; returns <b>false</b> otherwise.
     * @since 9
     */
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override;

    /**
     * @brief Send Obituary to agents who have registered for death notices.
     * @return void
     * @since 9
     */
    void SendObituary();

    /**
     * @brief Check Subscribe to death notifications.
     * @return Returns <b>true</b> if the recipients exists; returns <b>false</b> otherwise.
     * @since 9
     */
    bool IsSubscribeDeathNotice() const
    {
        if (recipients_.empty()) {
            return false;
        }
        return true;
    };

    /**
     * @brief Obtains the handle.
     * @return Returns handle.
     * @since 9
     */
    uint32_t GetHandle() const
    {
        return handle_;
    };

    /**
     * @brief Call the listening thread.
     * @param data Indicates the object sent to the peer process.
     * @param reply Indicates the object returned by the peer process.
     * @return Returns {@link ERR_NONE} if the operation is successful; returns an error code
     * defined in {@link ipc_types.h} otherwise.
     * @since 9
     */
    int InvokeListenThread(MessageParcel &data, MessageParcel &reply);

    /**
     * @brief Notification service death.
     * @return Returns {@link ERR_NONE} if the operation is successful; returns an error code
     * defined in {@link ipc_types.h} otherwise.
     * @since 9
     */
    int32_t NoticeServiceDie();

    /**
     * @brief Obtains the corresponding PID and UID.
     * @param reply Indicates the object returned by the peer process.
     * @return Returns {@link ERR_NONE} if the operation is successful; returns an error code
     * defined in {@link ipc_types.h} otherwise.
     * @since 9
     */
    int GetPidUid(MessageParcel &reply);

    /**
     * @brief Obtains the session name.
     * @return Returns the session name of type string.
     * @since 9
     */
    std::string GetSessionName();

    /**
     * @brief Obtains the session name for PID and UID.
     * @param uid Indicates the UID value entered.
     * @param pid Indicates the PID value entered.
     * @return Returns the PID and UID session name of type string.
     * @since 9
     */
    std::string GetSessionNameForPidUid(uint32_t uid, uint32_t pid);

    /**
     * @brief Obtains the grant session name.
     * @return Returns the grant session name of type string.
     * @since 9
     */
    std::string GetGrantedSessionName();

    /**
     * @brief Remove the granted session name.
     * @param sessionName Indicates the session name that needs to remove.
     * @return Returns {@link ERR_NONE} if the operation is successful; returns an error code
     * @since 12
     */
    int RemoveSessionName(const std::string &sessionName);

    /**
     * @brief Obtains the proxy protocol.
     * @return Returns the obtained proxy protocol.
     * @since 9
     */
    int GetProto() const;

    /**
     * @brief Wait for initialization.
     * @param dbinderData dbinder object data.
     * @return void
     * @since 9
     */
    void WaitForInit(const void *dbinderData = nullptr);

    /**
     * @brief Obtains the interface descriptor.
     * @return Returns the corresponding interface descriptor.
     * @since 9
     */
    std::u16string GetInterfaceDescriptor() override;

    /**
     * @brief get the stub strong ref count.
     * @return 0 get failed; others the strong ref count of the stub.
     * @since 11
     */
    uint32_t GetStrongRefCountForStub();

#ifndef EMULATOR_PLATFORM
    bool CanPromote() override;
#endif

private:
    void SetObjectDied(bool isDied);
    int SendLocalRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &optionoption);
    int SendRequestInner(bool isLocal, uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    void ClearDeathRecipients();

#ifndef CONFIG_IPC_SINGLE
    /**
     * @brief Set the proxy protocol.
     * @param proto Indicates a proxy proto.
     * @return void
     * @since 9
     */
    void SetProto(int proto);

    /**
     * @brief Update the proxy protocol.
     * @return Returns the updated proxy protocol.
     * @since 9
     */
    int UpdateProto();

    /**
     * @brief Update the proxy protocol.
     * @param dbinderData Indicates a dbinder object data.
     * @return Returns <b>true</b> if the operation is successful; return <b>false</b> otherwise.
     * @since 12
     */
    bool UpdateProto(const void *dbinderData);

    /**
     * @brief Release the proxy protocol.
     * @return void
     * @since 9
     */
    void ReleaseProto();

    /**
     * @brief Increase a reference to remote.
     * @return Returns {@link ERR_NONE} if the operation is successful; returns an error code
     * defined in {@link ipc_types.h} otherwise.
     * @since 9
     */
    int32_t IncRefToRemote();

    /**
     * @brief Obtain proxy protocol information.
     * @return Returns the status code of the protocol.
     * @since 9
     */
    int GetProtoInfo();

    /**
     * @brief Register the Dbinder death recipient.
     * @return Returns <b>true</b> if the current recipient is not empty; return <b>false</b> otherwise.
     * @since 9
     */
    bool AddDbinderDeathRecipient();

    /**
     * @brief Unregister the Dbinder death recipient.
     * @return Returns <b>true</b> if the current recipient or callback result is not empty;
     * return <b>false</b> otherwise.
     * @since 9
     */
    bool RemoveDbinderDeathRecipient();

    /**
     * @brief Release the databus(Dbinder) protocol.
     * @return void
     * @since 9
     */
    void ReleaseDatabusProto();

    /**
     * @brief Release the binder protocol.
     * @return void
     * @since 9
     */
    void ReleaseBinderProto();

    /**
     * @brief Update the databus(Dbinder) client session name.
     * @param handle Indicates a handle that needs to update session information.
     * @param reply Indicates the object returned by the peer process.
     * @return Returns <b>true</b> if the update is successful; returns <b>false</b> Otherwise.
     * @since 9
     */
    bool UpdateDatabusClientSession(int handle, MessageParcel &reply);

    /**
     * @brief Update the databus(Dbinder) client session name.
     * @return Returns <b>true</b> if the update is successful; returns <b>false</b> Otherwise.
     * @since 12
     */
    bool UpdateDatabusClientSession();

    /**
     * @brief Check if there is a session.
     * @return Returns <b>true</b> if there is currently a session; returns <b>false</b> otherwise.
     * @since 9
     */
    bool CheckHaveSession();

    int GetDBinderNegotiationData(int handle, MessageParcel &reply, DBinderNegotiationData &dbinderData);

    int GetDBinderNegotiationData(DBinderNegotiationData &dbinderData);

    bool MakeDBinderTransSession(const DBinderNegotiationData &data);
#endif

    bool RegisterBinderDeathRecipient();
    bool UnRegisterBinderDeathRecipient();

    struct DeathRecipientAddrInfo : public virtual RefBase {
    public:
        explicit DeathRecipientAddrInfo(const sptr<DeathRecipient> &recipient);

        std::string GetNewSoPath();
        bool IsDlclosed();
    public:
        sptr<DeathRecipient> recipient_;
        void *soFuncAddr_;
        std::string soPath_;
    };

private:
    std::mutex initMutex_;
    std::recursive_mutex mutex_;
    std::shared_mutex descMutex_;

    std::vector<sptr<DeathRecipientAddrInfo>> recipients_;
    const uint32_t handle_;
    int proto_;
    bool isFinishInit_;
    std::atomic<bool> isRemoteDead_;
    std::u16string remoteDescriptor_;
    std::u16string interfaceDesc_;
    std::atomic<int> lastErr_ = 0;
    std::atomic<int> lastErrCnt_ = 0;
    std::unique_ptr<uint8_t[]> dbinderData_{nullptr};
};
} // namespace OHOS
#endif // OHOS_IPC_IPC_OBJECT_PROXY_H
