/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include <shared_mutex>

#include "iremote_object.h"

namespace OHOS {
struct DeadObjectInfo {
    int32_t handle;
    uint64_t deadTime;
    uint64_t agingTime;
    std::u16string desc;
};

struct InvokerProcInfo {
    pid_t pid;
    pid_t realPid;
    pid_t uid;
    uint64_t tokenId;
    uint64_t firstTokenId;
    uintptr_t invoker;
};

class ProcessSkeleton {
public:
    static std::string ConvertToSecureDesc(const std::string &str);
    static bool IsPrint(int err, int &lastErr, int &lastErrCnt);
    static ProcessSkeleton* GetInstance();
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
    bool AttachDeadObject(IRemoteObject *object, DeadObjectInfo &objInfo);
    bool DetachDeadObject(IRemoteObject *object);
    bool IsDeadObject(IRemoteObject *object, DeadObjectInfo &deadInfo);
    bool AttachInvokerProcInfo(bool isLocal, InvokerProcInfo &invokeInfo);
    bool QueryInvokerProcInfo(bool isLocal, InvokerProcInfo &invokeInfo);

private:
    DISALLOW_COPY_AND_MOVE(ProcessSkeleton);
    ProcessSkeleton() = default;
    ~ProcessSkeleton();
    void DetachTimeoutDeadObject();

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

    std::map<std::u16string, wptr<IRemoteObject>> objects_;
    std::map<IRemoteObject *, bool> isContainStub_;

    std::shared_mutex deadObjectMutex_;
    std::map<IRemoteObject *, DeadObjectInfo> deadObjectRecord_;
    uint64_t deadObjectClearTime_ = 0;

    std::shared_mutex invokerProcMutex_;
    std::map<std::string, InvokerProcInfo> invokerProcInfo_;
};
} // namespace OHOS
#endif // OHOS_IPC_PROCESS_SKELETON_H
