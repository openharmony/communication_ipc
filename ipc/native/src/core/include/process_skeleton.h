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

#include <mutex>
#include <refbase.h>

#include "iremote_object.h"

namespace OHOS {

class ProcessSkeleton : public virtual RefBase {
public:

    static sptr<ProcessSkeleton> GetInstance();
    sptr<IRemoteObject> GetRegistryObject();
    void SetRegistryObject(sptr<IRemoteObject> &object);
    void SetSamgrFlag(bool flag);
    bool GetSamgrFlag();

private:
    DISALLOW_COPY_AND_MOVE(ProcessSkeleton);
    ProcessSkeleton() = default;
    ~ProcessSkeleton() = default;

    static sptr<ProcessSkeleton> instance_;
    static std::mutex mutex_;
    sptr<IRemoteObject> registryObject_ = nullptr;
    bool isSamgr_ = false;
};
} // namespace OHOS
#endif // OHOS_IPC_PROCESS_SKELETON_H
