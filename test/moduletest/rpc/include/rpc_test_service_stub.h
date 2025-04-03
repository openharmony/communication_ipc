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

#ifndef OHOS_RPC_TEST_SERVICE_STUB_H
#define OHOS_RPC_TEST_SERVICE_STUB_H

#include <map>
#include "rpc_test_service_base.h"

namespace OHOS {
class RpcTestServiceStub : public IRemoteStub<IRpcTestService> {
public:
    int OnRemoteRequest(uint32_t code,
        MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    int32_t TestGetServiceName(MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    int32_t TestAccessToken(MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    int32_t TestSyncAdd(MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    void InitMessageProcessMap();
};
} // namespace OHOS
#endif // OHOS_RPC_TEST_SERVICE_STUB_H

