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

#ifndef OHOS_RPC_TESST_SERVICE_BASE_H
#define OHOS_RPC_TESST_SERVICE_BASE_H

#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"
#include "message_parcel.h"

namespace OHOS {
class IRpcTestService : public IRemoteBroker {
public:
    enum {
        GET_SERVICE_NAME    = 0,
        GET_TOKENID         = 1,
        TEST_SYNC_ADD       = 2,
    };
    std::string GetServiceName()
    {
        return serviceName_;
    }
    virtual int32_t TestGetServiceName(MessageParcel &data, MessageParcel &reply, MessageOption &option) = 0;
    virtual int32_t TestAccessToken(MessageParcel &data, MessageParcel &reply, MessageOption &option) = 0;
    virtual int32_t TestSyncAdd(MessageParcel &data, MessageParcel &reply, MessageOption &option) = 0;
    DECLARE_INTERFACE_DESCRIPTOR(u"test.rpc.IRpcTestService");
private:
    std::string serviceName_ = "IRpcTestService";
};
} // namespace OHOS
#endif // OHOS_RPC_TESST_SERVICE_BASE_H

