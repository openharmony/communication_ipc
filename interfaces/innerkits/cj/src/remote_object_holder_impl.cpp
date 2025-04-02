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

#include "remote_object_holder_impl.h"

#include <string_ex.h>

#include "ipc_utils_ffi.h"

namespace OHOS {
RemoteObjectHolderImpl::RemoteObjectHolderImpl(const std::u16string& descriptor)
    : descriptor_(descriptor), sptrCachedObject_(nullptr), wptrCachedObject_(nullptr), attachCount_(1)
{
    jsThreadId_ = std::this_thread::get_id();
}

RemoteObjectHolderImpl::~RemoteObjectHolderImpl() {}

sptr<IRemoteObject> RemoteObjectHolderImpl::Get()
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    if (sptrCachedObject_ != nullptr) {
        return sptrCachedObject_;
    }
    sptr<IRemoteObject> tmp = wptrCachedObject_.promote();
    if (tmp == nullptr) {
        tmp = new (std::nothrow) RemoteObjectImpl(jsThreadId_, descriptor_);
        if (tmp == nullptr) {
            ZLOGE(LOG_LABEL, "new RemoteObjectImpl failed");
            return nullptr;
        }
        wptrCachedObject_ = tmp;
    }
    return tmp;
}

void RemoteObjectHolderImpl::Set(sptr<IRemoteObject> object)
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    IPCObjectStub* tmp = static_cast<IPCObjectStub*>(object.GetRefPtr());
    if (tmp->GetObjectType() == IPCObjectStub::OBJECT_TYPE_JAVASCRIPT) {
        wptrCachedObject_ = object;
    } else {
        sptrCachedObject_ = object;
    }
}

void RemoteObjectHolderImpl::attachLocalInterface(std::string& descriptor)
{
    descriptor_ = Str8ToStr16(descriptor);
}
} // namespace OHOS