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

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
namespace IPC_SINGLE {
#endif

class BinderConnector {
public:
    static BinderConnector *GetInstance();
    BinderConnector(const std::string &deviceName);
    ~BinderConnector();

    int WriteBinder(unsigned long request, void *value);
    void ExitCurrentThread(unsigned long request);
    bool IsDriverAlive();
private:
    static BinderConnector *instance_;
    static std::mutex skeletonMutex;
    bool OpenDriver();
    int driverFD_;
    void *vmAddr_;
    const std::string deviceName_;
};
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS
#endif // OHOS_IPC_BINDER_CONNECTOR_H
