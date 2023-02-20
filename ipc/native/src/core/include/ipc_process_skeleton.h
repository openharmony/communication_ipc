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

#ifndef OHOS_IPC_IPC_PROCESS_SKELETON_H
#define OHOS_IPC_IPC_PROCESS_SKELETON_H

#include <list>
#include <map>
#include <shared_mutex>

#include "invoker_rawdata.h"
#include "ipc_object_proxy.h"
#include "ipc_object_stub.h"
#include "ipc_thread_pool.h"
#include "iremote_object.h"
#include "nocopyable.h"
#include "refbase.h"
#include "sys_binder.h"

#ifndef CONFIG_IPC_SINGLE
#include "comm_auth_info.h"
#include "dbinder_callback_stub.h"
#include "dbinder_session_object.h"
#include "ISessionService.h"
#include "Session.h"
#include "stub_refcount_object.h"

using Communication::SoftBus::ISessionService;
using Communication::SoftBus::Session;
#endif

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
namespace IPC_SINGLE {
#endif

#ifndef CONFIG_IPC_SINGLE
struct SocketThreadLockInfo {
    std::mutex mutex;
    std::condition_variable condition;
    bool ready = false;
};

struct ThreadMessageInfo {
    uint32_t flags;
    binder_size_t bufferSize;
    binder_size_t offsetsSize;
    binder_uintptr_t offsets;
    uint32_t socketId;
    void *buffer;
    std::mutex mutex;
    std::condition_variable condition;
    bool ready;
};

struct ThreadProcessInfo {
    uint32_t listenFd;
    uint32_t packageSize;
    std::shared_ptr<char> buffer;
};
#endif

class IPCProcessSkeleton : public virtual RefBase {
public:
    enum {
        LISTEN_THREAD_CREATE_OK, // Invoker family.
        LISTEN_THREAD_CREATE_FAILED,
        LISTEN_THREAD_CREATED_ALREADY,
        LISTEN_THREAD_CREATED_TIMEOUT
    };
    ~IPCProcessSkeleton() override;

    static IPCProcessSkeleton *GetCurrent();
    static std::string ConvertToSecureString(const std::string &deviceId);

#ifndef CONFIG_IPC_SINGLE
    static uint32_t ConvertChannelID2Int(int64_t databusChannelId);
    static bool IsHandleMadeByUser(uint32_t handle);
#endif
    bool SetMaxWorkThread(int maxThreadNum);

    sptr<IRemoteObject> GetRegistryObject();

    bool SpawnThread(int policy = IPCWorkThread::SPAWN_PASSIVE, int proto = IRemoteObject::IF_PROT_DEFAULT);

    std::u16string MakeHandleDescriptor(int handle);

    sptr<IRemoteObject> FindOrNewObject(int handle);
    bool IsContainsObject(IRemoteObject *object);
    sptr<IRemoteObject> QueryObject(const std::u16string &descriptor);
    bool AttachObject(IRemoteObject *object);
    bool DetachObject(IRemoteObject *object);

    bool OnThreadTerminated(const std::string &threadName);

    bool SetRegistryObject(sptr<IRemoteObject> &object);
    bool AttachRawData(uint32_t fd, std::shared_ptr<InvokerRawData> rawData);
    bool DetachRawData(uint32_t fd);
    std::shared_ptr<InvokerRawData> QueryRawData(uint32_t fd);

#ifndef CONFIG_IPC_SINGLE
    sptr<IRemoteObject> GetSAMgrObject();
    std::shared_ptr<DBinderSessionObject> ProxyDetachDBinderSession(uint32_t handle, IPCObjectProxy *proxy);
    bool ProxyAttachDBinderSession(uint32_t handle, std::shared_ptr<DBinderSessionObject> object);
    std::shared_ptr<DBinderSessionObject> ProxyQueryDBinderSession(uint32_t handle);
    bool ProxyMoveDBinderSession(uint32_t handle, IPCObjectProxy *proxy);
    bool QueryProxyBySessionHandle(uint32_t handle, std::vector<uint32_t> &proxyHandle);
    std::shared_ptr<DBinderSessionObject> QuerySessionByInfo(const std::string &name, const std::string &deviceId);

    bool DetachThreadLockInfo(const std::thread::id &threadId);
    bool AttachThreadLockInfo(std::shared_ptr<SocketThreadLockInfo> object, const std::thread::id &threadId);
    std::shared_ptr<SocketThreadLockInfo> QueryThreadLockInfo(const std::thread::id &threadId);
    void EraseThreadBySeqNumber(uint64_t seqNumber);
    bool AddThreadBySeqNumber(uint64_t seqNumber, std::shared_ptr<ThreadMessageInfo> messageInfo);
    std::shared_ptr<ThreadMessageInfo> QueryThreadBySeqNumber(uint64_t seqNumber);
    bool AddSendThreadInWait(uint64_t seqNumber, std::shared_ptr<ThreadMessageInfo> messageInfo, int userWaitTime);

    std::thread::id GetIdleSocketThread();
    int GetSocketIdleThreadNum() const;
    int GetSocketTotalThreadNum() const;
    int PopSocketIdFromThread(const std::thread::id &threadId);
    void WakeUpSocketIOThread(const std::thread::id &threadID);
    void WakeUpThreadBySeqNumber(uint64_t seqNumber, uint32_t handle);
    IRemoteObject *QueryStubByIndex(uint64_t stubIndex);
    uint64_t QueryStubIndex(IRemoteObject *stubObject);
    uint64_t AddStubByIndex(IRemoteObject *stubObject);
    uint64_t EraseStubIndex(IRemoteObject *stubObject);
    uint64_t GetSeqNumber();
    uint32_t GetDBinderIdleHandle(std::shared_ptr<DBinderSessionObject> session);
    std::string GetLocalDeviceID();

    bool AttachCallbackStub(IPCObjectProxy *ipcProxy, sptr<IPCObjectStub> callbackStub);
    sptr<IPCObjectStub> QueryCallbackStub(IPCObjectProxy *ipcProxy);
    sptr<IPCObjectProxy> QueryCallbackProxy(IPCObjectStub *callbackStub);
    sptr<IPCObjectStub> DetachCallbackStub(IPCObjectProxy *ipcProxy);
    uint32_t QueryHandleByDatabusSession(const std::string &name, const std::string &deviceId, uint64_t stubIndex);
    bool StubDetachDBinderSession(uint32_t handle, uint32_t &tokenId);
    std::shared_ptr<DBinderSessionObject> StubQueryDBinderSession(uint32_t handle);
    bool StubAttachDBinderSession(uint32_t handle, std::shared_ptr<DBinderSessionObject> object);
    std::string GetDatabusName();
    bool CreateSoftbusServer(const std::string &name);

    bool AttachCommAuthInfo(IRemoteObject *stub, int pid, int uid, uint32_t tokenId, const std::string &deviceId);
    bool DetachCommAuthInfo(IRemoteObject *stub, int pid, int uid, uint32_t tokenId, const std::string &deviceId);
    void DetachCommAuthInfoByStub(IRemoteObject *stub);
    bool QueryCommAuthInfo(int pid, int uid, uint32_t &tokenId, const std::string &deviceId);
    bool AddDataThreadToIdle(const std::thread::id &threadId);
    bool DeleteDataThreadFromIdle(const std::thread::id &threadId);
    std::thread::id GetIdleDataThread();
    void AddDataInfoToThread(const std::thread::id &threadId, std::shared_ptr<ThreadProcessInfo> processInfo);
    std::shared_ptr<ThreadProcessInfo> PopDataInfoFromThread(const std::thread::id &threadId);
    void WakeUpDataThread(const std::thread::id &threadID);
    void AddDataThreadInWait(const std::thread::id &threadId);
    bool IsSameRemoteObject(IRemoteObject *stub, int pid, int uid, uint32_t tokenId, const std::string &deviceId,
        const std::shared_ptr<CommAuthInfo> &auth);
    bool IsSameRemoteObject(int pid, int uid, const std::string &deviceId, const std::shared_ptr<CommAuthInfo> &auth);
    bool DetachAppInfoToStubIndex(uint32_t pid, uint32_t uid, uint32_t tokenId, const std::string &deviceId,
        uint64_t stubIndex, uint32_t listenFd);
    std::list<uint64_t> DetachAppInfoToStubIndex(uint32_t pid, uint32_t uid, uint32_t tokenId,
        const std::string &deviceId, uint32_t listenFd);
    void DetachAppInfoToStubIndex(uint64_t stubIndex);
    bool AttachAppInfoToStubIndex(uint32_t pid, uint32_t uid, uint32_t tokenId, const std::string &deviceId,
        uint64_t stubIndex, uint32_t listenFd);
    bool AttachAppInfoToStubIndex(uint32_t pid, uint32_t uid, uint32_t tokenId, const std::string &deviceId,
        uint32_t listenFd);
    bool QueryAppInfoToStubIndex(uint32_t pid, uint32_t uid, uint32_t tokenId, const std::string &deviceId,
        uint64_t stubIndex, uint32_t listenFd);
    std::string UIntToString(uint32_t input);
    bool AttachDBinderCallbackStub(sptr<IRemoteObject> rpcProxy, sptr<DBinderCallbackStub> stub);
    bool DetachDBinderCallbackStubByProxy(sptr<IRemoteObject> rpcProxy);
    void DetachDBinderCallbackStub(DBinderCallbackStub *stub);
    sptr<DBinderCallbackStub> QueryDBinderCallbackStub(sptr<IRemoteObject> rpcProxy);
    sptr<IRemoteObject> QueryDBinderCallbackProxy(sptr<IRemoteObject> stub);
#endif

public:
    static constexpr int DEFAULT_WORK_THREAD_NUM = 16;
    static constexpr uint32_t DBINDER_HANDLE_BASE = 100000;
    static constexpr uint32_t DBINDER_HANDLE_RANG = 100;
    static constexpr int ENCRYPT_LENGTH = 4;
private:
    DISALLOW_COPY_AND_MOVE(IPCProcessSkeleton);
    IPCProcessSkeleton();
    static IPCProcessSkeleton *instance_;
    static std::mutex procMutex_;
    std::shared_mutex mutex_;
    std::shared_mutex rawDataMutex_;
    std::map<std::u16string, wptr<IRemoteObject>> objects_;
    std::map<IRemoteObject *, bool> isContainStub_;
    std::map<uint32_t, std::shared_ptr<InvokerRawData>> rawData_;
    IPCWorkThreadPool *threadPool_ = nullptr;

#ifndef CONFIG_IPC_SINGLE
    std::mutex databusProcMutex_;
    std::mutex sessionNameMutex_;
    std::mutex seqNumberMutex_;
    std::mutex idleDataMutex_;
    std::mutex dataQueueMutex_;
    std::mutex findThreadMutex_;

    std::recursive_mutex proxyToSessionMutex_;

    std::shared_mutex databusSessionMutex_;
    std::shared_mutex threadLockMutex_;
    std::shared_mutex callbackStubMutex_;
    std::shared_mutex stubObjectsMutex_;
    std::shared_mutex appInfoToIndexMutex_;
    std::shared_mutex commAuthMutex_;
    std::shared_mutex dbinderSentMutex_;

    std::map<uint64_t, std::shared_ptr<ThreadMessageInfo>> seqNumberToThread_;
    std::map<uint64_t, IRemoteObject *> stubObjects_;
    std::map<std::thread::id, std::shared_ptr<SocketThreadLockInfo>> threadLockInfo_;
    std::map<uint32_t, std::shared_ptr<DBinderSessionObject>> proxyToSession_;
    std::map<uint32_t, std::shared_ptr<DBinderSessionObject>> dbinderSessionObjects_;
    std::map<IPCObjectProxy *, sptr<IPCObjectStub>> noticeStub_;
    std::map<std::thread::id, std::vector<std::shared_ptr<ThreadProcessInfo>>> dataInfoQueue_; // key is threadId
    std::map<std::string, std::map<uint64_t, uint32_t>> appInfoToStubIndex_;
    std::map<sptr<IRemoteObject>, wptr<DBinderCallbackStub>> dbinderSentCallback;

    std::list<std::thread::id> idleDataThreads_;
    std::list<std::shared_ptr<CommAuthInfo>> commAuth_;

    uint32_t dBinderHandle_ = DBINDER_HANDLE_BASE; /* dbinder handle start at 100000 */
    uint64_t seqNumber_ = 0;
    std::string sessionName_ = std::string("");
    uint64_t randNum_;
#endif
};
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS
#endif // OHOS_IPC_IPC_PROCESS_SKELETON_H
