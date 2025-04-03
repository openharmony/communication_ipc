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

#include "napi_remote_proxy_holder.h"

#include "ipc_debug.h"
#include "log_tags.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "native_engine/native_value.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_NAPI, "NapiRemoteProxyHolder" };

NAPIDeathRecipient::NAPIDeathRecipient(napi_env env, napi_value jsDeathRecipient)
{
    env_ = env;
    napi_status status = napi_create_reference(env_, jsDeathRecipient, 1, &deathRecipientRef_);
    NAPI_ASSERT_RETURN_VOID(env_, status == napi_ok, "failed to create ref to js death recipient");
}

void NAPIDeathRecipient::AfterWorkCallback(OnRemoteDiedParam *param)
{
    ZLOGD(LOG_LABEL, "start to call onRemoteDied");
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(param->env, &scope);

    auto CleanUp = [&param, &scope]() {
        napi_close_handle_scope(param->env, scope);
        delete param;
    };

    napi_value jsDeathRecipient = nullptr;
    napi_get_reference_value(param->env, param->deathRecipient->GetDeathRecipientRef(), &jsDeathRecipient);
    if (jsDeathRecipient == nullptr) {
        ZLOGE(LOG_LABEL, "failed to get js death recipient");
        CleanUp();
        return;
    }

    napi_value onRemoteDied = nullptr;
    napi_get_named_property(param->env, jsDeathRecipient, "onRemoteDied", &onRemoteDied);
    if (onRemoteDied == nullptr) {
        ZLOGE(LOG_LABEL, "failed to get property onRemoteDied");
        CleanUp();
        return;
    }

    napi_value returnVal = nullptr;
    napi_call_function(param->env, jsDeathRecipient, onRemoteDied, 0, nullptr, &returnVal);
    if (returnVal == nullptr) {
        ZLOGE(LOG_LABEL, "failed to call function onRemoteDied");
    }

    napi_status napiStatus = napi_delete_reference(param->env, param->deathRecipient->GetDeathRecipientRef());
    if (napiStatus != napi_ok) {
        ZLOGE(LOG_LABEL, "failed to delete ref to js death recipient");
    }
    param->deathRecipient->CleanDeathRecipientRef();

    CleanUp();
}

void NAPIDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    if (deathRecipientRef_ == nullptr) {
        ZLOGE(LOG_LABEL, "js death recipient has already removed");
        return;
    }

    if (env_ == nullptr) {
        ZLOGE(LOG_LABEL, "js env has been destructed");
        return;
    }

    OnRemoteDiedParam *param = new (std::nothrow) OnRemoteDiedParam {
        .env = env_,
        .deathRecipient = this
    };
    NAPI_ASSERT_RETURN_VOID(env_, param != nullptr, "new OperateJsRefParam failed");

    auto task = [param]() {
        AfterWorkCallback(param);
    };
    napi_status sendRet = napi_send_event(env_, task, napi_eprio_high);
    if (sendRet != napi_ok) {
        ZLOGE(LOG_LABEL, "napi_send_event failed, ret:%{public}d", sendRet);
        delete param;
    }
}

bool NAPIDeathRecipient::Matches(napi_value object)
{
    bool result = false;
    if (object != nullptr && deathRecipientRef_ != nullptr) {
        napi_value jsDeathRecipient = nullptr;
        napi_get_reference_value(env_, deathRecipientRef_, &jsDeathRecipient);
        napi_status status = napi_strict_equals(env_, object, jsDeathRecipient, &result);
        if (status != napi_ok) {
            ZLOGI(LOG_LABEL, "compares death recipients failed");
        }
    }
    return result;
}

napi_ref NAPIDeathRecipient::GetDeathRecipientRef() const
{
    return deathRecipientRef_;
}

void NAPIDeathRecipient::CleanDeathRecipientRef()
{
    deathRecipientRef_ = nullptr;
}

NAPIDeathRecipientList::NAPIDeathRecipientList() {}

NAPIDeathRecipientList::~NAPIDeathRecipientList()
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    set_.clear();
}

bool NAPIDeathRecipientList::Add(const sptr<NAPIDeathRecipient> &recipient)
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    auto ret = set_.insert(recipient);
    return ret.second;
}

bool NAPIDeathRecipientList::Remove(const sptr<NAPIDeathRecipient> &recipient)
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    return (set_.erase(recipient) > 0);
}

sptr<NAPIDeathRecipient> NAPIDeathRecipientList::Find(napi_value jsRecipient)
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    for (auto it = set_.begin(); it != set_.end(); it++) {
        if ((*it)->Matches(jsRecipient)) {
            return *it;
        }
    }
    return nullptr;
}

NAPIRemoteProxyHolder::NAPIRemoteProxyHolder() : list_(nullptr), object_(nullptr) {}

NAPIRemoteProxyHolder::~NAPIRemoteProxyHolder()
{
    list_ = nullptr;
    object_ = nullptr;
}

NAPIRemoteProxyHolder *NAPI_ohos_rpc_getRemoteProxyHolder(napi_env env, napi_value jsRemoteProxy)
{
    NAPIRemoteProxyHolder *proxyHolder = nullptr;
    napi_unwrap(env, jsRemoteProxy, (void **)&proxyHolder);
    NAPI_ASSERT(env, proxyHolder != nullptr, "failed to get napi remote proxy holder");
    return proxyHolder;
}
} // namespace OHOS