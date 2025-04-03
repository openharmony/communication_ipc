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
#include "ipc_skeleton_imp.h"

#include "ipc_skeleton.h"
#include "ipc_utils_ffi.h"
#include "iremote_invoker.h"
#include "remote_object_impl.h"

namespace OHOS {
// 0:remoteObject 1:remoteProxy
RetDataI64 GetContextObject()
{
    sptr<IRemoteObject> object = IPCSkeleton::GetContextObject();
    if (object == nullptr) {
        ZLOGE(LOG_LABEL, "fatal error, could not get registry object");
        return RetDataI64 { 0, 0 };
    }
    int32_t type = object->IsProxyObject() ? 1 : 0;
    return RetDataI64{type, CJ_rpc_CreateRemoteObject(object)};
}

uint32_t GetCallingTokenId()
{
    uint64_t tokenId = IPCSkeleton::GetSelfTokenID();
    return static_cast<uint32_t>(tokenId);
}

char* GetCallingDeviceID()
{
    return MallocCString("");
}

char* GetLocalDeviceID()
{
    return MallocCString("");
}

bool IsLocalCalling()
{
    return true;
}

void FlushCmdBuffer(int64_t object)
{
    sptr<IRemoteObject> target = CJ_rpc_getNativeRemoteObject(object);
    IPCSkeleton::FlushCommands(target);
}
} // namespace OHOS