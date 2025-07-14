/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_IPC_TAIHE_ANI_REMOTE_OBJECT_H
#define OHOS_IPC_TAIHE_ANI_REMOTE_OBJECT_H

#include "ohos.rpc.rpc.proj.hpp"
#include "ohos.rpc.rpc.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

#include <cinttypes>
#include <set>
#include <string>
#include <unistd.h>
#include <vector>

#include "message_parcel.h"
#include "ipc_object_stub.h"

namespace OHOS {

class ANIRemoteObject : public OHOS::IPCObjectStub {
public:
    ANIRemoteObject(const std::u16string &descriptor, ::ohos::rpc::rpc::weak::RemoteObject jsObj);
    ~ANIRemoteObject();

    int OnRemoteRequest(uint32_t code, OHOS::MessageParcel &data, OHOS::MessageParcel &reply,
        OHOS::MessageOption &option) override;

    int GetObjectType() const override;

    ::ohos::rpc::rpc::RemoteObject GetJsObject();

private:
    std::optional<::ohos::rpc::rpc::RemoteObject> jsObjRef_;
};
} // namespace

#endif // OHOS_IPC_TAIHE_ANI_REMOTE_OBJECT_H