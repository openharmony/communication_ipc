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

#include "rpc_test_service_stub.h"

#include "dbinder_log.h"
#include "ipc_skeleton.h"

namespace OHOS {
using namespace OHOS::HiviewDFX;

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_TEST, "RpcTestServiceProxy" };
static constexpr uint32_t INVAL_TOKEN_ID = 0x0;

int32_t RpcTestServiceStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    int result = ERR_NONE;
    switch (code) {
        case GET_SERVICE_NAME: {
            result = TestGetServiceName(data, reply, option);
            break;
        }
        case GET_TOKENID: {
            result = TestAccessToken(data, reply, option);
            break;
        }
        case TEST_SYNC_ADD: {
            result = TestSyncAdd(data, reply, option);
            break;
        }
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return result;
}

int32_t RpcTestServiceStub::TestGetServiceName(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    reply.WriteString(GetServiceName());
    return ERR_NONE;
}

int32_t RpcTestServiceStub::TestAccessToken(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
    if (tokenId == INVAL_TOKEN_ID) {
        DBINDER_LOGW(LOG_LABEL, "tokenId = %{public}u", tokenId);
    }
    reply.WriteUint32(tokenId);
    return ERR_NONE;
}

int32_t RpcTestServiceStub::TestSyncAdd(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int32_t value1 = data.ReadInt32();
    int32_t value2 = data.ReadInt32();
    reply.WriteInt32(value1 + value2);
    return ERR_NONE;
}
} // namespace OHOS