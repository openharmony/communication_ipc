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

#ifndef REMOTE_OBJECT_IMPL_H
#define REMOTE_OBJECT_IMPL_H

#include "cj_common_ffi.h"
#include "ffi_remote_data.h"
#include "message_sequence_impl.h"
#include "remote_object_holder_impl.h"

namespace OHOS {
class CjRemoteObjectImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(CjRemoteObjectImpl, OHOS::FFI::FFIData)
public:
    explicit CjRemoteObjectImpl(RemoteObjectHolderImpl* holder);
    ~CjRemoteObjectImpl();
    char* GetDescriptor(int32_t* errCode);
    int32_t ModifyLocalInterface(char* stringValue);
    int32_t SendMessageRequest(uint32_t code, int64_t dataId, int64_t replyId, MessageOption option, int64_t funcId);
    RemoteObjectHolderImpl* GetHolder();

private:
    RemoteObjectHolderImpl* holder_;
};

RetDataI64 CreateStubRemoteObject(const sptr<IRemoteObject> target);
RetDataI64 CreateProxyRemoteObject(const sptr<IRemoteObject> target);
RetDataI64 CJ_rpc_CreateRemoteObject(const sptr<IRemoteObject> target);
sptr<IRemoteObject> CJ_rpc_getNativeRemoteObject(RetDataI64 object);
} // namespace OHOS
#endif // REMOTE_OBJECT_IMPL_H