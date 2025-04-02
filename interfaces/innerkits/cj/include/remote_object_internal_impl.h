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

#ifndef REMOTE_OBJECT_INTERNAL_IMPL_H
#define REMOTE_OBJECT_INTERNAL_IMPL_H

#include <thread>

#include "ipc_object_stub.h"
#include "napi_remote_object.h"
#include "napi_remote_object_internal.h"

namespace OHOS {
struct CJCallbackParam {
    int64_t id;
    uint32_t code;
    int64_t data;
    int64_t reply;
    MessageOption* option;
    CallingInfo callingInfo;
    CallingInfo oldCallingInfo;
    ThreadLockInfo* lockInfo;
    int result;
};

class RemoteObjectImpl : public IPCObjectStub {
public:
    RemoteObjectImpl(std::thread::id jsThreadId, const std::u16string& descriptor);

private:
    std::thread::id jsThreadId_;
};

struct CJSendRequestParam {
    sptr<IRemoteObject> target;
    uint32_t code;
    std::shared_ptr<MessageParcel> data;
    std::shared_ptr<MessageParcel> reply;
    MessageOption& option;
    int errCode;
    int64_t cjDataRef;
    int64_t cjReplyRef;
    int64_t callback;
    std::string traceValue;
    int32_t traceId;
};
} // namespace OHOS
#endif // REMOTE_OBJECT_INTERNAL_IMPL_H