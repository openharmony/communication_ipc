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

#ifndef OHOS_IPC_BINDER_CONNECTOR_H
#define OHOS_IPC_BINDER_CONNECTOR_H

#include <string>
#include <mutex>

namespace OHOS {
#ifdef CONFIG_ACTV_BINDER
class ActvBinderConnector {
public:
    ActvBinderConnector();

    int InitActvBinder(int fd);
    void InitActvBinderConfig(uint64_t featureSet);

    bool isActvMgr_;
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
    bool IsRealPidSupported();
    uint64_t GetSelfTokenID();
    uint64_t GetSelfFirstCallerTokenID();
    void CloseDriverFd();
#ifdef CONFIG_ACTV_BINDER
    bool IsActvBinderSupported();
    bool IsActvBinderService();
#endif
private:
    static BinderConnector *instance_;
    static std::mutex skeletonMutex;
    bool OpenDriver();
    bool MapMemory(uint64_t featureSet);
    int driverFD_;
    void *vmAddr_;
    const std::string deviceName_;
    int32_t version_;
    uint64_t featureSet_;
    uint64_t selfTokenID_;
#ifdef CONFIG_ACTV_BINDER
    ActvBinderConnector actvBinder_;
#endif
};
} // namespace OHOS
#endif // OHOS_IPC_BINDER_CONNECTOR_H
