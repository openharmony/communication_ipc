/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef REMOTE_OBJECT_HOLDER_IMPL_H
#define REMOTE_OBJECT_HOLDER_IMPL_H

#include <mutex>

#include "ffi_remote_data.h"
#include "remote_object_internal_impl.h"

namespace OHOS {
class RemoteObjectHolderImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(RemoteObjectHolderImpl, OHOS::FFI::FFIData)
public:
    explicit RemoteObjectHolderImpl(const std::u16string& descriptor);
    ~RemoteObjectHolderImpl();
    sptr<IRemoteObject> Get();
    void Set(sptr<IRemoteObject> object);
    void attachLocalInterface(std::string& descriptor);
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
    std::mutex mutex_;
    std::thread::id jsThreadId_;
    std::u16string descriptor_;
    sptr<IRemoteObject> sptrCachedObject_;
    wptr<IRemoteObject> wptrCachedObject_;
    int32_t attachCount_;
};
} // namespace OHOS
#endif // REMOTE_OBJECT_HOLDER_IMPL_H