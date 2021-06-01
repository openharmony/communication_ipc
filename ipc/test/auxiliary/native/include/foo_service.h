/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_IPC_FOO_SERVICE_H
#define OHOS_IPC_FOO_SERVICE_H

#include <mutex>
#include <condition_variable>
#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"
#include "hilog/log.h"
#include "log_tags.h"

namespace OHOS {

class IFoo : public IRemoteBroker {
public:
    enum FooInterFaceId {
        GET_FOO_NAME = 0,
        SEND_ASYNC_REPLY = 1,
        SEND_WRONG_REPLY = 2,
    };
    virtual std::string GetFooName() = 0;
    virtual void SendAsyncReply(int &reply) = 0;
    virtual int TestNestingSend(int sendCode) = 0;
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"test.ipc.IFoo");
};

class FooStub : public IRemoteStub<IFoo> {
public:
    virtual ~FooStub();
    virtual int OnRemoteRequest(uint32_t code,
        MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    std::string GetFooName() override;
    void SendAsyncReply(int &reply) override;
    int WaitForAsyncReply(int timeout);
    static void CleanDecTimes();
    static int GetDecTimes();
    int TestNestingSend(int sendCode) override;
public:
    static std::mutex decTimeMutex_;
    static int decTimes_;
private:
    int asyncReply_ = { 0 };
    std::mutex mutex_;
    std::condition_variable cv_;
    static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "FooStub" };
};

class FooProxy : public IRemoteProxy<IFoo> {
public:
    explicit FooProxy(const sptr<IRemoteObject> &impl);
    ~FooProxy() = default;
    std::string GetFooName() override;
    void SendAsyncReply(int &reply) override;
    int TestNestingSend(int sendCode) override;
private:
    static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "FooProxy" };
    static inline BrokerDelegator<FooProxy> delegator_;
};
} // namespace OHOS
#endif // OHOS_IPC_FOO_SERVICE_H

