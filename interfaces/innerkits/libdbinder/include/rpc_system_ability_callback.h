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

#ifndef INTERFACES_RPC_SERVICES_CALLBACK_H
#define INTERFACES_RPC_SERVICES_CALLBACK_H

#include "iremote_object.h"

namespace OHOS {
class RpcSystemAbilityCallback {
public:
    virtual sptr<IRemoteObject> GetSystemAbilityFromRemote(int32_t systemAbilityId) = 0;
    virtual bool LoadSystemAbilityFromRemote(const std::string& srcNetworkId, int32_t systemAbilityId)
    {
        return false;
    };
    
    RpcSystemAbilityCallback() = default;
    virtual ~RpcSystemAbilityCallback() = default;
};
} // namespace OHOS
#endif // INTERFACES_RPC_SERVICES_CALLBACK_H