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

#ifndef OHOS_IPC_BINDER_CONNECTOR_H
#define OHOS_IPC_BINDER_CONNECTOR_H

#include <string>
#include <mutex>
#ifdef CONFIG_ACTV_BINDER
#include <unordered_set>
#include <unordered_map>
#endif

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
namespace IPC_SINGLE {
#endif

#ifdef CONFIG_ACTV_BINDER
typedef void (*ActvBinderJoinThreadFunc)(bool initiative);

class ActvBinderConnector {
public:
    static void *ActvThreadEntry(void *arg);
    static char *GetProcName(char *buf, size_t len);

    static void JoinActvThread(bool initiative);
    static void SetJoinActvThreadFunc(ActvBinderJoinThreadFunc func);

    ActvBinderConnector();

    int InitActvBinder(int fd);
    void InitActvBinderConfig(uint64_t featureSet);

    bool isActvMgr_;
    std::unordered_map<std::string, std::unordered_set<uint32_t> > actvBlockedCodes_;

private:
    static std::mutex skeletonMutex_;
    static ActvBinderJoinThreadFunc joinActvThreadFunc_;
};
#endif

class BinderConnector {
public:
    static BinderConnector *GetInstance();
    BinderConnector(const std::string &deviceName);
    ~BinderConnector();

    int WriteBinder(unsigned long request, void *value);
    void ExitCurrentThread(unsigned long request);
    bool IsDriverAlive();
    bool IsAccessTokenSupported();
    uint64_t GetSelfTokenID();
    uint64_t GetSelfFirstCallerTokenID();
#ifdef CONFIG_ACTV_BINDER
    bool IsActvBinderSupported();
    const std::unordered_set<uint32_t> *GetActvBinderBlockedCodes(const std::string &desc);
#endif
private:
    static BinderConnector *instance_;
    static std::mutex skeletonMutex;
    bool OpenDriver();
    int driverFD_;
    void *vmAddr_;
    const std::string deviceName_;
    int32_t version_;
    uint64_t featureSet_;
    uint64_t selfTokenID_;
#ifdef CONFIG_ACTV_BINDER
    size_t vmSize_;
    ActvBinderConnector actvBinder_;
#endif
};
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS
#endif // OHOS_IPC_BINDER_CONNECTOR_H
