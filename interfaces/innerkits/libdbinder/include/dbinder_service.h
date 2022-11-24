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
#include "Session.h"
#include "thread_pool.h"

using Communication::SoftBus::Session;

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

struct DeviceIdInfo {
    uint32_t tokenId;
    char fromDeviceId[DEVICEID_LENGTH + 1];
    char toDeviceId[DEVICEID_LENGTH + 1];
};

struct DHandleEntryHead {
    uint32_t len;
    uint32_t version;
};

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

enum DBinderCode {
    MESSAGE_AS_INVOKER          = 1,
    MESSAGE_AS_REPLY            = 2,
    MESSAGE_AS_OBITUARY         = 3,
    MESSAGE_AS_REMOTE_ERROR     = 4,
    MESSAGE_AS_REPLY_TOKENID    = 5,
};

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
};

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
    static sptr<DBinderService> GetInstance();
    static std::string ConvertToSecureDeviceID(const std::string &deviceID);
    bool StartDBinderService(std::shared_ptr<RpcSystemAbilityCallback> &callbackImpl);
    sptr<DBinderServiceStub> MakeRemoteBinder(const std::u16string &serviceName,
        const std::string &deviceID, int32_t binderObject, uint32_t pid = 0, uint32_t uid = 0);
    bool RegisterRemoteProxy(std::u16string serviceName, sptr<IRemoteObject> binderObject);
    bool RegisterRemoteProxy(std::u16string serviceName, int32_t systemAbilityId);
    bool OnRemoteMessageTask(std::shared_ptr<struct DHandleEntryTxRx> message);
    void AddAsynMessageTask(std::shared_ptr<struct DHandleEntryTxRx> message);
    std::shared_ptr<struct SessionInfo> QuerySessionObject(binder_uintptr_t stub);
    bool DetachDeathRecipient(sptr<IRemoteObject> object);
    bool AttachDeathRecipient(sptr<IRemoteObject> object, sptr<IRemoteObject::DeathRecipient> deathRecipient);
    sptr<IRemoteObject::DeathRecipient> QueryDeathRecipient(sptr<IRemoteObject> object);
    bool DetachCallbackProxy(sptr<IRemoteObject> object);
    bool AttachCallbackProxy(sptr<IRemoteObject> object, DBinderServiceStub *dbStub);
    int32_t NoticeServiceDie(const std::u16string &serviceName, const std::string &deviceID);
    int32_t NoticeDeviceDie(const std::string &deviceID);
    std::string CreateDatabusName(int uid, int pid);
    bool DetachProxyObject(binder_uintptr_t binderObject);
    void LoadSystemAbilityComplete(const std::string& srcNetworkId, int32_t systemAbilityId,
        const sptr<IRemoteObject>& remoteObject);
    bool ProcessOnSessionClosed(std::shared_ptr<Session> session);

private:
    static std::shared_ptr<DBinderRemoteListener> GetRemoteListener();
    static bool StartRemoteListener();
    static void StopRemoteListener();
    std::u16string GetRegisterService(binder_uintptr_t binderObject);
    int32_t InvokerRemoteDBinder(const sptr<DBinderServiceStub> stub, uint32_t seqNumber, uint32_t pid, uint32_t uid);
    bool OnRemoteReplyMessage(const struct DHandleEntryTxRx *replyMessage);
    bool OnRemoteErrorMessage(const struct DHandleEntryTxRx *replyMessage);
    void MakeSessionByReplyMessage(const struct DHandleEntryTxRx *replyMessage);
    bool OnRemoteInvokerMessage(const struct DHandleEntryTxRx *message);
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
    bool SendEntryToRemote(const sptr<DBinderServiceStub> stub, uint32_t seqNumber, uint32_t pid, uint32_t uid);
    uint16_t AllocFreeSocketPort();
    std::string GetLocalDeviceID();
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
    uint32_t OnRemoteInvokerDataBusMessage(IPCObjectProxy *proxy, struct DHandleEntryTxRx *replyMessage,
        std::string &remoteDeviceId, int pid, int uid, uint32_t tokenId);
    bool IsDeviceIdIllegal(const std::string &deviceID);
    std::string GetDatabusNameByProxy(IPCObjectProxy *proxy);
    uint32_t GetSeqNumber();
    bool StartThreadPool();
    bool StopThreadPool();
    bool AddAsynTask(const ThreadPool::Task &f);
    bool IsSameSession(std::shared_ptr<struct SessionInfo> oldSession, std::shared_ptr<struct SessionInfo> newSession);
    bool RegisterRemoteProxyInner(std::u16string serviceName, binder_uintptr_t binder);
    bool CheckSystemAbilityId(int32_t systemAbilityId);
    bool HandleInvokeListenThread(IPCObjectProxy *proxy, uint64_t stubIndex, std::string serverSessionName,
        struct DHandleEntryTxRx *replyMessage);
    bool ReStartRemoteListener();
    bool IsSameLoadSaItem(const std::string& srcNetworkId, int32_t systemAbilityId,
        std::shared_ptr<DHandleEntryTxRx> loadSaItem);
    std::shared_ptr<struct DHandleEntryTxRx> PopLoadSaItem(const std::string& srcNetworkId, int32_t systemAbilityId);
    void SendMessageToRemote(uint32_t dBinderCode, uint32_t reason,
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
    std::mutex threadPoolMutex_;

    uint32_t seqNumber_ = 0; /* indicate make remote binder message sequence number, and can be overflow */
    std::list<sptr<DBinderServiceStub>> DBinderStubRegisted_;
    std::map<std::u16string, binder_uintptr_t> mapRemoteBinderObjects_;
    std::map<uint32_t, std::shared_ptr<struct ThreadLockInfo>> threadLockInfo_;
    std::map<int, sptr<IRemoteObject>> proxyObject_;
    std::map<binder_uintptr_t, std::shared_ptr<struct SessionInfo>> sessionObject_;
    std::map<sptr<IRemoteObject>, DBinderServiceStub *> noticeProxy_;
    std::map<sptr<IRemoteObject>, sptr<IRemoteObject::DeathRecipient>> deathRecipients_;
    bool threadPoolStarted_ = false;
    int32_t threadPoolNumber_ = 4;
    std::unique_ptr<ThreadPool> threadPool_ = nullptr;
    std::list<std::shared_ptr<struct DHandleEntryTxRx>> loadSaReply_;
    static constexpr int32_t FIRST_SYS_ABILITY_ID = 0x00000001;
    static constexpr int32_t LAST_SYS_ABILITY_ID = 0x00ffffff;

    std::shared_ptr<RpcSystemAbilityCallback> dbinderCallback_;
};
} // namespace OHOS
#endif // OHOS_IPC_SERVICES_DBINDER_DBINDER_SERVICE_H
