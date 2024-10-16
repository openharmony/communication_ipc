/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_IPC_PROCESS_SKELETON_H
#define OHOS_IPC_PROCESS_SKELETON_H

#include <map>
#include <mutex>
#include <atomic>
#include <shared_mutex>
#include <unordered_map>

#include "iremote_object.h"
#include "sys_binder.h"

namespace OHOS {

struct InvokerProcInfo {
    pid_t pid;
    pid_t realPid;
    pid_t uid;
    uint64_t tokenId;
    uint64_t firstTokenId;
    std::string sid;
    uint32_t invoker;
};

class ProcessSkeleton {
public:
    static std::string ConvertToSecureDesc(const std::string &str);
    static bool IsPrint(int err, std::atomic<int> &lastErr, std::atomic<int> &lastErrCnt);
    static uint32_t ConvertAddr(const void *ptr);
    static ProcessSkeleton* GetInstance();
    static bool FlattenDBinderData(Parcel &parcel, const dbinder_negotiation_data *&dbinderData);
    static bool UnFlattenDBinderData(Parcel &parcel, dbinder_negotiation_data *&dbinderData);
    static bool GetSubStr(const std::string &str, std::string &substr, size_t offset, size_t length);
    static bool IsNumStr(const std::string &str);

    bool SetIPCProxyLimit(uint64_t num, std::function<void (uint64_t num)> callback);
    sptr<IRemoteObject> GetRegistryObject();
    void SetRegistryObject(sptr<IRemoteObject> &object);
    void SetSamgrFlag(bool flag);
    bool GetSamgrFlag();

    bool IsContainsObject(IRemoteObject *object);
    sptr<IRemoteObject> QueryObject(const std::u16string &descriptor, bool lockFlag);
    bool AttachObject(IRemoteObject *object, const std::u16string &descriptor, bool lockFlag);
    bool DetachObject(IRemoteObject *object, const std::u16string &descriptor);
    bool LockObjectMutex();
    bool UnlockObjectMutex();
    bool AttachValidObject(IRemoteObject *object, const std::u16string &desc);
    bool DetachValidObject(IRemoteObject *object);
    bool IsValidObject(IRemoteObject *object, std::u16string &desc);
    bool AttachInvokerProcInfo(bool isLocal, InvokerProcInfo &invokeInfo);
    bool QueryInvokerProcInfo(bool isLocal, InvokerProcInfo &invokeInfo);
    bool DetachInvokerProcInfo(bool isLocal);

    bool GetThreadStopFlag();
    void IncreaseThreadCount();
    void DecreaseThreadCount();
    void NotifyChildThreadStop();

private:
    DISALLOW_COPY_AND_MOVE(ProcessSkeleton);
    ProcessSkeleton() = default;
    ~ProcessSkeleton();

    class DestroyInstance {
    public:
        ~DestroyInstance()
        {
            if (instance_ != nullptr) {
                delete instance_;
                instance_ = nullptr;
            }
        }
    };

    static ProcessSkeleton* instance_;
    static std::mutex mutex_;
    static DestroyInstance destroyInstance_;
    static std::atomic<bool> exitFlag_;

    std::shared_mutex objMutex_;
    sptr<IRemoteObject> registryObject_ = nullptr;
    bool isSamgr_ = false;

    std::unordered_map<std::u16string, wptr<IRemoteObject>> objects_;
    std::unordered_map<IRemoteObject *, bool> isContainStub_;

    std::shared_mutex validObjectMutex_;
    std::unordered_map<IRemoteObject *, std::u16string> validObjectRecord_;
    uint64_t ipcProxyLimitNum_ = 20000; // default maximun ipc proxy number
    std::atomic<uint64_t> proxyObjectCountNum_ = 0;
    std::function<void (uint64_t num)> ipcProxyCallback_ {nullptr};

    std::shared_mutex invokerProcMutex_;
    std::unordered_map<std::string, InvokerProcInfo> invokerProcInfo_;

    static constexpr size_t MAIN_THREAD_MAX_WAIT_TIME = 3;
    std::atomic_bool stopThreadFlag_ = false;
    std::mutex threadCountMutex_;
    std::condition_variable threadCountCon_;
    std::atomic_size_t runningChildThreadNum_ = 0;
};
} // namespace OHOS
#endif // OHOS_IPC_PROCESS_SKELETON_H
