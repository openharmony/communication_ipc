/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NAPI_REMOTE_OBJECT_HOLDER_H
#define NAPI_REMOTE_OBJECT_HOLDER_H

#include <refbase.h>
#include <mutex>

#include "napi_remote_object_internal.h"

#include "napi/native_api.h"

namespace OHOS {
class NAPIRemoteObjectHolder : public RefBase {
public:
    explicit NAPIRemoteObjectHolder(napi_env env, const std::u16string &descriptor, napi_value thisVar);
    ~NAPIRemoteObjectHolder();
    sptr<IRemoteObject> Get();
    void Set(sptr<IRemoteObject> object);
    void attachLocalInterface(napi_value localInterface, std::string &descriptor);
    napi_value queryLocalInterface(std::string &descriptor);
    napi_ref GetJsObjectRef() const;
    napi_env GetJsObjectEnv() const;
    void CleanJsEnv();
    void Lock()
    {
        mutex_.lock();
    };

    void Unlock()
    {
        mutex_.unlock();
    };

    void IncAttachCount()
    {
        ++attachCount_;
    };

    int32_t DecAttachCount()
    {
        if (attachCount_ > 0) {
            --attachCount_;
        }
        return attachCount_;
    };

    std::u16string GetDescriptor()
    {
        return descriptor_;
    };

private:
    void DeleteJsObjectRefInUvWork();

    std::mutex mutex_;
    napi_env env_ = nullptr;
    std::thread::id jsThreadId_;
    std::u16string descriptor_;
    sptr<IRemoteObject> sptrCachedObject_;
    wptr<IRemoteObject> wptrCachedObject_;
    napi_ref localInterfaceRef_;
    int32_t attachCount_;
    napi_ref jsObjectRef_;
};
} // namespace OHOS
#endif // NAPI_REMOTE_OBJECT_HOLDER_H