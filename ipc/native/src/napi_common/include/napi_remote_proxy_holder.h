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

#ifndef NAPI_REMOTE_PROXY_HOLDER_H
#define NAPI_REMOTE_PROXY_HOLDER_H

#include <mutex>
#include <refbase.h>
#include <set>
#include <uv.h>

#include "napi_remote_object_internal.h"

#include "napi/native_api.h"

namespace OHOS {
class NAPIDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit NAPIDeathRecipient(napi_env env, napi_value jsDeathRecipient);

    void OnRemoteDied(const wptr<IRemoteObject> &object) override;

    bool Matches(napi_value object);

protected:
    virtual ~NAPIDeathRecipient() = default;

private:
    static void AfterWorkCallback(uv_work_t *work, int status);

    struct OnRemoteDiedParam {
        napi_env env;
        napi_ref deathRecipientRef;
    };
    napi_env env_ = nullptr;
    napi_ref deathRecipientRef_ = nullptr;
};

class NAPIDeathRecipientList : public RefBase {
public:
    NAPIDeathRecipientList();

    ~NAPIDeathRecipientList();

    bool Add(const sptr<NAPIDeathRecipient> &recipient);

    bool Remove(const sptr<NAPIDeathRecipient> &recipient);

    sptr<NAPIDeathRecipient> Find(napi_value jsRecipient);

private:
    std::mutex mutex_;
    std::set<sptr<NAPIDeathRecipient>> set_;
};

class NAPIRemoteProxyHolder {
public:
    NAPIRemoteProxyHolder();
    ~NAPIRemoteProxyHolder();
    sptr<NAPIDeathRecipientList> list_;
    sptr<IRemoteObject> object_;
};

NAPIRemoteProxyHolder *NAPI_ohos_rpc_getRemoteProxyHolder(napi_env env, napi_value jsRemoteProxy);
} // namespace OHOS
#endif // NAPI_REMOTE_PROXY_HOLDER_H