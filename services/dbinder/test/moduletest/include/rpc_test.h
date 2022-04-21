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

#ifndef OHOS_RPC_FOO_TEST_H
#define OHOS_RPC_FOO_TEST_H

#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"

namespace OHOS {
class IRpcFooTest : public IRemoteBroker {
public:
    enum FooInterFaceId {
        GET_FOO_NAME = 0,
        SEND_ASYNC_REPLY = 1,
        SEND_WRONG_REPLY = 2,
        GET_TOKENID = 3,
    };
    std::string GetFooName(void);
    virtual std::string TestGetFooName(void) = 0;
    virtual uint32_t TestAccessToken(void) = 0;
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"test.rpc.IRpcFooTest");
private:
    std::string fooName_ = "IRpcFooTest";
};

class RpcFooStub : public IRemoteStub<IRpcFooTest> {
public:
    int OnRemoteRequest(uint32_t code,
        MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    std::string TestGetFooName(void) override;
    uint32_t TestAccessToken(void) override;
};

class RpcFooProxy : public IRemoteProxy<IRpcFooTest> {
public:
    explicit RpcFooProxy(const sptr<IRemoteObject> &impl);
    ~RpcFooProxy() = default;
    std::string TestGetFooName(void) override;
    uint32_t TestAccessToken(void) override;
private:
    static inline BrokerDelegator<RpcFooProxy> delegator_;
};
} // namespace OHOS
#endif // OHOS_RPC_FOO_TEST_H

