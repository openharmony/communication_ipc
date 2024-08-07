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

#ifndef OHOS_IPC_SERVICES_DBINDER_DBINDER_SERVICE_H
#define OHOS_IPC_SERVICES_DBINDER_DBINDER_SERVICE_H

#include <string>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <memory>
#include <list>
#include <thread>

#include "dbinder_service_stub.h"
#include "ipc_object_proxy.h"
#include "ipc_object_stub.h"
#include "rpc_system_ability_callback.h"

namespace OHOS {
class DBinderRemoteListener;

constexpr int DEVICEID_LENGTH = 64;
constexpr int SERVICENAME_LENGTH = 200;

/* version change history
 * a) 1 --> 2, support transfer tokenid to peer device
 */
constexpr int RPC_TOKENID_SUPPORT_VERSION = 2;
constexpr int ENCRYPT_HEAD_LEN = 28;
constexpr int ENCRYPT_LENGTH = 4;

// Description of the device identification information parameter.
struct DeviceIdInfo {
    uint32_t tokenId;
    char fromDeviceId[DEVICEID_LENGTH + 1];
    char toDeviceId[DEVICEID_LENGTH + 1];
};

// Description of the DHandle entry head parameter.
struct DHandleEntryHead {
    uint32_t len;
    uint32_t version;
};

// Description of the DHandle entry TxRx parameter.
struct DHandleEntryTxRx {
    struct DHandleEntryHead head;
    uint32_t transType;
    uint32_t dBinderCode;
    uint16_t fromPort;
    uint16_t toPort;
    uint64_t stubIndex;
    uint32_t seqNumber;
    binder_uintptr_t binderObject;
    struct DeviceIdInfo deviceIdInfo;
    binder_uintptr_t stub;
    uint16_t serviceNameLength;
    char serviceName[SERVICENAME_LENGTH + 1];
    uint32_t pid;
    uint32_t uid;
};

// SessionInfo parameter description.
struct SessionInfo {
    uint32_t seqNumber;
    uint32_t type;
    uint16_t toPort;
    uint16_t fromPort;
    uint64_t stubIndex;
    uint32_t socketFd;
    std::string serviceName;
    struct DeviceIdInfo deviceIdInfo;
};

// Enumerate DBinder message codes.
enum DBinderCode {
    MESSAGE_AS_INVOKER          = 1,
    MESSAGE_AS_REPLY            = 2,
    MESSAGE_AS_OBITUARY         = 3,
    MESSAGE_AS_REMOTE_ERROR     = 4,
    MESSAGE_AS_REPLY_TOKENID    = 5,
};

// Enumerate the returned DBinder error codes.
enum DBinderErrorCode {
    DBINDER_OK                  = 100,
    STUB_INVALID                = 101,
    SEND_MESSAGE_FAILED         = 102,
    MAKE_THREADLOCK_FAILED      = 103,
    WAIT_REPLY_TIMEOUT          = 104,
    QUERY_REPLY_SESSION_FAILED  = 105,
    SA_NOT_FOUND                = 106,
    SA_INVOKE_FAILED            = 107,
    DEVICEID_INVALID            = 108,
    SESSION_NAME_NOT_FOUND      = 109,
    WRITE_PARCEL_FAILED         = 110,
    INVOKE_STUB_THREAD_FAILED   = 111,
    SESSION_NAME_INVALID        = 112,
    SA_NOT_AVAILABLE            = 113,
    SAID_INVALID_ERR            = 114,
    SA_NOT_DISTRUBUTED_ERR      = 115,
};

// Description of thread locking information parameters.
struct ThreadLockInfo {
    std::mutex mutex;
    std::string networkId;
    std::condition_variable condition;
    bool ready = false;
};

class DBinderService : public virtual RefBase {
public:
    DBinderService();
    virtual ~DBinderService();
public:

    /**
     * @brief Obtains an instance.
     * @return Returns a DBinderService type pointer object.
     * @since 9
     */
    static sptr<DBinderService> GetInstance();

    /**
     * @brief Convert device ID to security string for printing.
     * @param deviceID Indicates the device ID to be converted.
     * @return Returns the converted security device ID.
     * @since 9
     */
    static std::string ConvertToSecureDeviceID(const std::string &str);

    /**
     * @brief Start the DBinder service.
     * @param callbackImpl Indicates a callback of type RpcSystemAbilityCallback.
     * @return Returns <b>true</b> if the service started successfully; returns <b>false</b> otherwise.
     * @since 9
     */
    bool StartDBinderService(std::shared_ptr<RpcSystemAbilityCallback> &callbackImpl);

    /**
     * @brief Make a remote binding.
     * @param serviceName Indicates the service name.
     * @param deviceID Indicates the device ID.
     * @param binderObject Indicates the object to be binder.
     * @param pid Indicates the value of pid.
     * @param uid Indicates the value of uid.
     * @return Returns the DBinderServiceStuble pointer object.
     * @since 9
     */
    sptr<DBinderServiceStub> MakeRemoteBinder(const std::u16string &serviceName,
        const std::string &deviceID, int32_t binderObject, uint32_t pid = 0, uint32_t uid = 0);

    /**
     * @brief Register the remote agent.
     * @param serviceName Indicates the service name.
     * @param binderObject Indicates the IRemoteObject pointer object to be binder.
     * @return Returns <b>true</b> if the registration successful; returns <b>false</b> otherwise.
     * @since 9
     */
    bool RegisterRemoteProxy(std::u16string serviceName, sptr<IRemoteObject> binderObject);

    /**
     * @brief Register the remote agent.
     * @param serviceName Indicates the service name.
     * @param systemAbilityId Indicatesthe system ability ID.
     * @return Returns <b>true</b> if the registration successful; returns <b>false</b> otherwise.
     * @since 9
     */
    bool RegisterRemoteProxy(std::u16string serviceName, int32_t systemAbilityId);

    /**
     * @brief Processing remote messaging tasks.
     * @param message Indicates the delivered message belongs to the DHandleEntryTxR structure.
     * @return Returns <b>true</b> if the processing is successful; returns <b>false</b> otherwise.
     * @since 9
     */
    bool OnRemoteMessageTask(std::shared_ptr<struct DHandleEntryTxRx> message);

    /**
     * @brief Register an asynchronous message task.
     * @param message Indicates the delivered message belongs to the DHandleEntryTxR structure.
     * @return void
     * @since 9
     */
    void AddAsynMessageTask(std::shared_ptr<struct DHandleEntryTxRx> message);

    /**
     * @brief Query the session object.
     * @param stub Indicates a stub that can be used to query a session object.
     * @return The returned result belongs to the SessionInfo structure.
     * @since 9
     */
    std::shared_ptr<struct SessionInfo> QuerySessionObject(binder_uintptr_t stub);

    /**
     * @brief Detach the remote object death notification.
     * @param object Indicates the IRemoteObject pointer object.
     * @return Returns <b>true</b> if the registration successful; returns <b>false</b> otherwise.
     * @since 9
     */
    bool DetachDeathRecipient(sptr<IRemoteObject> object);

    /**
     * @brief Attach the remote object death notification.
     * @param object Indicates the IRemoteObject pointer object.
     * @param deathRecipient Indicates the the callback to attach.
     * @return Returns <b>true</b> if the operation succeeds; returns <b>false</b> otherwise.
     * @since 9
     */
    bool AttachDeathRecipient(sptr<IRemoteObject> object, sptr<IRemoteObject::DeathRecipient> deathRecipient);

    /**
     * @brief Query the remote object death notification.
     * @param object Indicates the IRemoteObject pointer object.
     * @return Returns the results of the found death notice.
     * @since 9
     */
    sptr<IRemoteObject::DeathRecipient> QueryDeathRecipient(sptr<IRemoteObject> object);

    /**
     * @brief Detach the callback proxy object.
     * @param object Indicates the IRemoteObject pointer object.
     * @return Returns <b>true</b> if the operation succeeds; returns <b>false</b> otherwise.
     * @since 9
     */
    bool DetachCallbackProxy(sptr<IRemoteObject> object);

    /**
     * @brief Attach the callback proxy object.
     * @param object Indicates the IRemoteObject pointer object.
     * @param dbStub Indicates a service communication stub across devices.
     * @return Returns <b>true</b> if the operation succeeds; returns <b>false</b> otherwise.
     * @since 9
     */
    bool AttachCallbackProxy(sptr<IRemoteObject> object, DBinderServiceStub *dbStub);

    /**
     * @brief Notification service death.
     * @param serviceName Indicates the service name.
     * @param deviceID Indicates the device ID.
     * @return Returns {@code ERR_NONE} if valid notifications; returns an error code if the operation fails.
     * @since 9
     */
    int32_t NoticeServiceDie(const std::u16string &serviceName, const std::string &deviceID);

    /**
     * @brief Notification device death.
     * @param deviceID Indicates the device ID.
     * @return Returns {@code ERR_NONE} if valid notifications; returns an error code if the operation fails.
     * @since 9
     */
    int32_t NoticeDeviceDie(const std::string &deviceID);

    /**
     * @brief Create a databus(Dbinder) name.
     * @param uid Indicates the UID of databus(Dbinder).
     * @param pid Indicates the PID of databus(Dbinder).
     * @return Returns the corresponding sessionName.
     * @since 9
     */
    std::string CreateDatabusName(int uid, int pid);

    /**
     * @brief Detach the proxy object.
     * @param binderObject Indicates the object to which it is bound.
     * @return Returns <b>true</b> if the operation succeeds; returns <b>false</b> otherwise.
     * @since 9
     */
    bool DetachProxyObject(binder_uintptr_t binderObject);

    /**
     * @brief A callback when a system ability is loaded completely.
     * @param srcNetworkId Indicates The network ID of the path.
     * @param systemAbilityId Indicates system capability ID.
     * @param remoteObject Indicates a remote object.
     * @return void
     * @since 9
     */
    void LoadSystemAbilityComplete(const std::string& srcNetworkId, int32_t systemAbilityId,
        const sptr<IRemoteObject>& remoteObject);

    /**
     * @brief Close the process session.
     * @param session Indicates the session to close.
     * @return Returns <b>true</b> if the shutdown is successful; returns <b>false</b> otherwise.
     * @since 9
     */
    bool ProcessOnSessionClosed(const std::string &networkId);

private:
    static std::shared_ptr<DBinderRemoteListener> GetRemoteListener();
    static bool StartRemoteListener();
    static void StopRemoteListener();
    std::u16string GetRegisterService(binder_uintptr_t binderObject);
    int32_t InvokerRemoteDBinder(const sptr<DBinderServiceStub> stub, uint32_t seqNumber, uint32_t pid, uint32_t uid);
    bool CheckAndAmendSaId(std::shared_ptr<struct DHandleEntryTxRx> replyMessage);
    bool OnRemoteReplyMessage(std::shared_ptr<struct DHandleEntryTxRx> replyMessage);
    bool OnRemoteErrorMessage(std::shared_ptr<struct DHandleEntryTxRx> replyMessage);
    void MakeSessionByReplyMessage(std::shared_ptr<struct DHandleEntryTxRx> replyMessage);
    bool OnRemoteInvokerMessage(std::shared_ptr<struct DHandleEntryTxRx> message);
    void WakeupThreadByStub(uint32_t seqNumber);
    void DetachThreadLockInfo(uint32_t seqNumber);
    bool AttachThreadLockInfo(uint32_t seqNumber, const std::string &networkId,
        std::shared_ptr<struct ThreadLockInfo> object);
    std::shared_ptr<struct ThreadLockInfo> QueryThreadLockInfo(uint32_t seqNumber);
    bool AttachProxyObject(sptr<IRemoteObject> object, binder_uintptr_t binderObject);
    sptr<IRemoteObject> QueryProxyObject(binder_uintptr_t binderObject);
    bool DetachSessionObject(binder_uintptr_t stub);
    bool AttachSessionObject(std::shared_ptr<struct SessionInfo> object, binder_uintptr_t stub);
    sptr<IRemoteObject> FindOrNewProxy(binder_uintptr_t binderObject, int32_t systemAbilityId);
    bool CheckDeviceIDsInvalid(const std::string &deviceID, const std::string &localDevID);
    bool CopyDeviceIDsToMessage(std::shared_ptr<struct DHandleEntryTxRx> message,
        const std::string &localDevID, const std::string &deviceID);
    std::shared_ptr<struct DHandleEntryTxRx> CreateMessage(const sptr<DBinderServiceStub> &stub, uint32_t seqNumber,
        uint32_t pid, uint32_t uid);
    bool SendEntryToRemote(const sptr<DBinderServiceStub> stub, uint32_t seqNumber, uint32_t pid, uint32_t uid);
    bool IsInvalidStub(std::shared_ptr<struct DHandleEntryTxRx> replyMessage);
    bool CopyDeviceIdInfo(std::shared_ptr<struct SessionInfo> &session,
        std::shared_ptr<struct DHandleEntryTxRx> replyMessage);
    void InitializeSession(std::shared_ptr<struct SessionInfo> &session,
        std::shared_ptr<struct DHandleEntryTxRx> replyMessage);
    uint16_t AllocFreeSocketPort();
    std::string GetLocalDeviceID();
    binder_uintptr_t AddStubByTag(binder_uintptr_t stub);
    binder_uintptr_t QueryStubPtr(binder_uintptr_t stub);
    bool CheckBinderObject(const sptr<DBinderServiceStub> &stub, binder_uintptr_t binderObject);
    bool HasDBinderStub(binder_uintptr_t binderObject);
    bool IsSameStubObject(const sptr<DBinderServiceStub> &stub, const std::u16string &service,
        const std::string &device);
    sptr<DBinderServiceStub> FindDBinderStub(const std::u16string &service, const std::string &device);
    bool DeleteDBinderStub(const std::u16string &service, const std::string &device);
    sptr<DBinderServiceStub> FindOrNewDBinderStub(const std::u16string &service,
        const std::string &device, binder_uintptr_t binderObject);
    void ProcessCallbackProxy(sptr<DBinderServiceStub> dbStub);
    bool NoticeCallbackProxy(sptr<DBinderServiceStub> dbStub);
    std::list<std::u16string> FindServicesByDeviceID(const std::string &deviceID);
    int32_t NoticeServiceDieInner(const std::u16string &serviceName, const std::string &deviceID);
    uint32_t GetRemoteTransType();
    bool CheckDeviceIdIllegal(const std::string &remoteDeviceId);
    bool CheckSessionNameIsEmpty(const std::string &sessionName);
    bool CheckInvokeListenThreadIllegal(IPCObjectProxy *proxy, MessageParcel &data, MessageParcel &reply);
    bool CheckStubIndexAndSessionNameIllegal(uint64_t stubIndex, const std::string &serverSessionName,
        const std::string &deviceId, IPCObjectProxy *proxy);
    bool SetReplyMessage(std::shared_ptr<struct DHandleEntryTxRx> replyMessage, uint64_t stubIndex,
        const std::string &serverSessionName, uint32_t selfTokenId, IPCObjectProxy *proxy);
    uint32_t OnRemoteInvokerDataBusMessage(IPCObjectProxy *proxy, std::shared_ptr<struct DHandleEntryTxRx> replyMessage,
        std::string &remoteDeviceId, int pid, int uid, uint32_t tokenId);
    bool IsDeviceIdIllegal(const std::string &deviceID);
    std::string GetDatabusNameByProxy(IPCObjectProxy *proxy);
    uint32_t GetSeqNumber();
    bool IsSameSession(std::shared_ptr<struct SessionInfo> oldSession, std::shared_ptr<struct SessionInfo> newSession);
    bool RegisterRemoteProxyInner(std::u16string serviceName, binder_uintptr_t binder);
    bool CheckSystemAbilityId(int32_t systemAbilityId);
    bool HandleInvokeListenThread(IPCObjectProxy *proxy, uint64_t stubIndex, std::string serverSessionName,
        std::shared_ptr<struct DHandleEntryTxRx> replyMessage);
    bool ReStartRemoteListener();
    bool IsSameLoadSaItem(const std::string& srcNetworkId, int32_t systemAbilityId,
        std::shared_ptr<DHandleEntryTxRx> loadSaItem);
    std::shared_ptr<struct DHandleEntryTxRx> PopLoadSaItem(const std::string& srcNetworkId, int32_t systemAbilityId);
    void SendReplyMessageToRemote(uint32_t dBinderCode, uint32_t reason,
        std::shared_ptr<struct DHandleEntryTxRx> replyMessage);

private:
    DISALLOW_COPY_AND_MOVE(DBinderService);
    static std::mutex instanceMutex_;
    static constexpr int WAIT_FOR_REPLY_MAX_SEC = 8;
    static constexpr int RETRY_TIMES = 2;
    static std::shared_ptr<DBinderRemoteListener> remoteListener_;
    static bool mainThreadCreated_;
    static sptr<DBinderService> instance_;

    std::shared_mutex remoteBinderMutex_;
    std::shared_mutex proxyMutex_;
    std::shared_mutex deathRecipientMutex_;
    std::shared_mutex sessionMutex_;
    std::shared_mutex loadSaMutex_;

    std::mutex handleEntryMutex_;
    std::mutex threadLockMutex_;
    std::mutex callbackProxyMutex_;
    std::mutex deathNotificationMutex_;

    uint32_t seqNumber_ = 0; /* indicate make remote binder message sequence number, and can be overflow */

    /* indicate the stub flag used for negotiation with the peer end, and can be overflow */
    binder_uintptr_t stubTagNum_ = 1;
    std::map<binder_uintptr_t, binder_uintptr_t> mapDBinderStubRegisters_;
    std::list<sptr<DBinderServiceStub>> DBinderStubRegisted_;
    std::map<std::u16string, binder_uintptr_t> mapRemoteBinderObjects_;
    std::map<uint32_t, std::shared_ptr<struct ThreadLockInfo>> threadLockInfo_;
    std::map<int, sptr<IRemoteObject>> proxyObject_;
    std::map<binder_uintptr_t, std::shared_ptr<struct SessionInfo>> sessionObject_;
    std::map<sptr<IRemoteObject>, DBinderServiceStub *> noticeProxy_;
    std::map<sptr<IRemoteObject>, sptr<IRemoteObject::DeathRecipient>> deathRecipients_;
    std::list<std::shared_ptr<struct DHandleEntryTxRx>> loadSaReply_;
    static constexpr int32_t FIRST_SYS_ABILITY_ID = 0x00000001;
    static constexpr int32_t LAST_SYS_ABILITY_ID = 0x00ffffff;

    std::shared_ptr<RpcSystemAbilityCallback> dbinderCallback_;
};
} // namespace OHOS
#endif // OHOS_IPC_SERVICES_DBINDER_DBINDER_SERVICE_H
