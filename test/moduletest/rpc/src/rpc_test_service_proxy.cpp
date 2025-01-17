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

#include "rpc_test_service_proxy.h"
#include "dbinder_log.h"

namespace OHOS {
using namespace OHOS::HiviewDFX;

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_TEST, "RpcTestServiceProxy" };

RpcTestServiceProxy::RpcTestServiceProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IRpcTestService>(impl)
{
}

int32_t RpcTestServiceProxy::TestGetProto()
{
    auto object = Remote();
    if (object == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "The obtained proxy is a null pointer");
        return IRemoteObject::IF_PROT_ERROR;
    }
    sptr<IPCObjectProxy> proxy = reinterpret_cast<IPCObjectProxy *>(object.GetRefPtr());
    return proxy->GetProto();
}

bool RpcTestServiceProxy::TestAddDeathRecipient(const sptr<IRemoteObject::DeathRecipient> &recipient)
{
    bool ret = Remote()->AddDeathRecipient(recipient);
    if (!ret) {
        DBINDER_LOGE(LOG_LABEL, "Add death recipient failed");
    }
    return ret;
}

int32_t RpcTestServiceProxy::TestGetServiceName(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int ret = Remote()->SendRequest(GET_SERVICE_NAME, data, reply, option);
    if (ret != ERR_NONE) {
        DBINDER_LOGE(LOG_LABEL, "Send request failed ret = %{public}d", ret);
    }
    return ret;
}

int32_t RpcTestServiceProxy::TestAccessToken(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int32_t ret = Remote()->SendRequest(GET_TOKENID, data, reply, option);
    if (ret != ERR_NONE) {
        DBINDER_LOGE(LOG_LABEL, "Send request failed ret = %{public}d", ret);
    }
    return ret;
}

int32_t RpcTestServiceProxy::TestSyncAdd(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int32_t ret = Remote()->SendRequest(TEST_SYNC_ADD, data, reply, option);
    if (ret != ERR_NONE) {
        DBINDER_LOGE(LOG_LABEL, "Send request failed ret = %{public}d", ret);
    }
    return ret;
}
} // namespace OHOS