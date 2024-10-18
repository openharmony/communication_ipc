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

#ifndef OHOS_IPC_IPC_PROCESS_SKELETON_H
#define OHOS_IPC_IPC_PROCESS_SKELETON_H

#include <list>
#include <map>
#include <atomic>
#include <shared_mutex>

#include "invoker_rawdata.h"
#include "ipc_object_proxy.h"
#include "ipc_object_stub.h"
#include "ipc_thread_pool.h"
#include "iremote_object.h"
#include "nocopyable.h"
#include "sys_binder.h"

#ifndef CONFIG_IPC_SINGLE
#include "comm_auth_info.h"
#include "dbinder_callback_stub.h"
#include "dbinder_session_object.h"
#include "dbinder_softbus_client.h"
#include "stub_refcount_object.h"
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
    int32_t listenFd;
    uint32_t packageSize;
    std::shared_ptr<char> buffer;
};

struct AppAuthInfo {
    uint32_t pid;
    uint32_t uid;
    uint32_t tokenId;
    int32_t socketId;
    uint64_t stubIndex;
    IRemoteObject *stub;
    std::string deviceId;
};
#endif

class IPCProcessSkeleton {
public:
    enum {
        LISTEN_THREAD_CREATE_OK, // Invoker family.
        LISTEN_THREAD_CREATE_FAILED,
        LISTEN_THREAD_CREATED_ALREADY,
        LISTEN_THREAD_CREATED_TIMEOUT
    };
    ~IPCProcessSkeleton();

    static IPCProcessSkeleton *GetCurrent();
    static std::string ConvertToSecureString(const std::string &str);
    static inline const char *GetIPCRuntimeInfo()
    {
#ifndef CONFIG_IPC_SINGLE
        return "ipc_core";
#else
        return "ipc_single";
#endif
    };

#ifndef CONFIG_IPC_SINGLE
    static uint32_t ConvertChannelID2Int(int64_t databusChannelId);
    static bool IsHandleMadeByUser(uint32_t handle);
#endif
    bool SetIPCProxyLimit(uint64_t num, std::function<void (uint64_t num)> callback);
    bool SetMaxWorkThread(int maxThreadNum);
    std::u16string MakeHandleDescriptor(int handle);

    bool OnThreadTerminated(const std::string &threadName);
    bool SpawnThread(int policy = IPCWorkThread::SPAWN_PASSIVE, int proto = IRemoteObject::IF_PROT_DEFAULT);

    sptr<IRemoteObject> FindOrNewObject(int handle, const dbinder_negotiation_data *dbinderData = nullptr);
    bool IsContainsObject(IRemoteObject *object);
    sptr<IRemoteObject> QueryObject(const std::u16string &descriptor, bool lockFlag = true);
    bool AttachObject(IRemoteObject *object, bool lockFlag = true);
    bool DetachObject(IRemoteObject *object);
    sptr<IRemoteObject> GetProxyObject(int handle, bool &newFlag);

    sptr<IRemoteObject> GetRegistryObject();
    bool SetRegistryObject(sptr<IRemoteObject> &object);
    void BlockUntilThreadAvailable();
    void LockForNumExecuting();
    void UnlockForNumExecuting();

#ifndef CONFIG_IPC_SINGLE
    bool AttachRawData(int32_t socketId, std::shared_ptr<InvokerRawData> rawData);
    bool DetachRawData(int32_t socketId);
    std::shared_ptr<InvokerRawData> QueryRawData(int32_t socketId);

    sptr<IRemoteObject> GetSAMgrObject();
    std::shared_ptr<DBinderSessionObject> ProxyDetachDBinderSession(uint32_t handle, IPCObjectProxy *proxy);
    bool ProxyAttachDBinderSession(uint32_t handle, std::shared_ptr<DBinderSessionObject> object);
    std::shared_ptr<DBinderSessionObject> ProxyQueryDBinderSession(uint32_t handle);
    bool ProxyMoveDBinderSession(uint32_t handle, IPCObjectProxy *proxy);
    bool QueryProxyBySocketId(int32_t socketId, std::vector<uint32_t> &proxyHandle);
    std::shared_ptr<DBinderSessionObject> QuerySessionByInfo(const std::string &name, const std::string &deviceId);

    bool DetachThreadLockInfo(const std::thread::id &threadId);
    bool AttachThreadLockInfo(std::shared_ptr<SocketThreadLockInfo> object, const std::thread::id &threadId);
    std::shared_ptr<SocketThreadLockInfo> QueryThreadLockInfo(const std::thread::id &threadId);
    void EraseThreadBySeqNumber(uint64_t seqNumber);
    bool AddThreadBySeqNumber(uint64_t seqNumber, std::shared_ptr<ThreadMessageInfo> messageInfo);
    std::shared_ptr<ThreadMessageInfo> QueryThreadBySeqNumber(uint64_t seqNumber);
    bool AddSendThreadInWait(uint64_t seqNumber, std::shared_ptr<ThreadMessageInfo> messageInfo, int userWaitTime);

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
    void DetachCommAuthInfoBySocketId(int32_t socketId);
    bool QueryCommAuthInfo(int pid, int uid, uint32_t &tokenId, const std::string &deviceId);
    void UpdateCommAuthSocketInfo(int pid, int uid, uint32_t &tokenId, const std::string &deviceId,
        const int32_t socketId);
    bool AttachOrUpdateAppAuthInfo(const AppAuthInfo &appAuthInfo);
    bool DetachAppAuthInfo(const AppAuthInfo &appAuthInfo);
    void DetachAppAuthInfoByStub(IRemoteObject *stub, uint64_t stubIndex);
    std::list<uint64_t> DetachAppAuthInfoBySocketId(int32_t socketId);
    bool QueryCommAuthInfo(AppAuthInfo &appAuthInfo);
    bool QueryAppInfoToStubIndex(const AppAuthInfo &appAuthInfo);
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
        uint64_t stubIndex, int32_t listenFd);
    std::list<uint64_t> DetachAppInfoToStubIndex(uint32_t pid, uint32_t uid, uint32_t tokenId,
        const std::string &deviceId, int32_t listenFd);
    void DetachAppInfoToStubIndex(uint64_t stubIndex);
    std::list<uint64_t> DetachAppInfoToStubIndex(int32_t listenFd);
    bool AttachAppInfoToStubIndex(uint32_t pid, uint32_t uid, uint32_t tokenId, const std::string &deviceId,
        uint64_t stubIndex, int32_t listenFd);
    bool AttachAppInfoToStubIndex(uint32_t pid, uint32_t uid, uint32_t tokenId, const std::string &deviceId,
        int32_t listenFd);
    bool QueryAppInfoToStubIndex(uint32_t pid, uint32_t uid, uint32_t tokenId, const std::string &deviceId,
        uint64_t stubIndex, int32_t listenFd);
    std::string UIntToString(uint32_t input);
    bool AttachDBinderCallbackStub(sptr<IRemoteObject> rpcProxy, sptr<DBinderCallbackStub> stub);
    bool DetachDBinderCallbackStubByProxy(sptr<IRemoteObject> rpcProxy);
    void DetachDBinderCallbackStub(DBinderCallbackStub *stub);
    sptr<DBinderCallbackStub> QueryDBinderCallbackStub(sptr<IRemoteObject> rpcProxy);
    sptr<IRemoteObject> QueryDBinderCallbackProxy(sptr<IRemoteObject> stub);
#endif

public:
    static constexpr int DEFAULT_WORK_THREAD_NUM = 16;
#ifdef CONFIG_ACTV_BINDER
    /* The actv binder handle needs to be encoded with at least 31 bits */
    static constexpr uint32_t DBINDER_HANDLE_BASE = 0x80000000;
#else
    static constexpr uint32_t DBINDER_HANDLE_MAGIC = 6872; // 'D'(Binder) 'H'(andle)
    static constexpr uint32_t DBINDER_HANDLE_BASE = 100000 * DBINDER_HANDLE_MAGIC;
#endif
    static constexpr uint32_t DBINDER_HANDLE_COUNT = 100000;
    static constexpr uint32_t DBINDER_HANDLE_RANG = 100;
    static constexpr int32_t FOUNDATION_UID = 5523;
    static constexpr int ENCRYPT_LENGTH = 4;
private:
    DISALLOW_COPY_AND_MOVE(IPCProcessSkeleton);
    IPCProcessSkeleton();
#ifndef CONFIG_IPC_SINGLE
    void ClearDataResource();
#endif

    class DestroyInstance {
    public:
        ~DestroyInstance();
    };

    static IPCProcessSkeleton *instance_;
    static std::mutex procMutex_;
    static DestroyInstance destroyInstance_;
    static std::atomic<bool> exitFlag_;
    std::atomic<int> lastErrHandle_ = -1;
    std::atomic<int> lastErrCnt_ = 0;

    // for DFX
    std::mutex mutex_;
    std::condition_variable cv_;
    int numExecuting_ = 0;
    int numWaitingForThreads_ = 0;

    IPCWorkThreadPool *threadPool_ = nullptr;

#ifndef CONFIG_IPC_SINGLE
    std::mutex databusProcMutex_;
    std::mutex sessionNameMutex_;
    std::mutex seqNumberMutex_;
    std::mutex idleDataMutex_;
    std::mutex dataQueueMutex_;
    std::mutex findThreadMutex_;

    std::recursive_mutex proxyToSessionMutex_;
    std::shared_mutex rawDataMutex_;
    std::shared_mutex databusSessionMutex_;
    std::shared_mutex threadLockMutex_;
    std::shared_mutex callbackStubMutex_;
    std::shared_mutex stubObjectsMutex_;
    std::shared_mutex appInfoToIndexMutex_;
    std::shared_mutex commAuthMutex_;
    std::shared_mutex dbinderSentMutex_;
    std::shared_mutex appAuthMutex_;

    std::map<uint32_t, std::shared_ptr<InvokerRawData>> rawData_;
    std::map<uint64_t, std::shared_ptr<ThreadMessageInfo>> seqNumberToThread_;
    std::unordered_map<uint64_t, IRemoteObject *> stubObjects_;
    std::map<std::thread::id, std::shared_ptr<SocketThreadLockInfo>> threadLockInfo_;
    std::map<uint32_t, std::shared_ptr<DBinderSessionObject>> proxyToSession_;
    std::map<uint32_t, std::shared_ptr<DBinderSessionObject>> dbinderSessionObjects_;
    std::map<IPCObjectProxy *, sptr<IPCObjectStub>> noticeStub_;
    std::map<std::thread::id, std::vector<std::shared_ptr<ThreadProcessInfo>>> dataInfoQueue_; // key is threadId
    std::map<std::string, std::map<uint64_t, int32_t>> appInfoToStubIndex_;
    std::map<sptr<IRemoteObject>, wptr<DBinderCallbackStub>> dbinderSentCallback_;

    std::list<std::thread::id> idleDataThreads_;
    std::list<std::shared_ptr<CommAuthInfo>> commAuth_;

    uint32_t dBinderHandle_ = DBINDER_HANDLE_BASE; /* dbinder handle start at 687200000 */
    uint64_t seqNumber_ = 0;
    std::string sessionName_ = std::string("");
    std::atomic<int32_t> listenSocketId_ = 0;
    uint64_t randNum_;
#endif
};
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS
#endif // OHOS_IPC_IPC_PROCESS_SKELETON_H
