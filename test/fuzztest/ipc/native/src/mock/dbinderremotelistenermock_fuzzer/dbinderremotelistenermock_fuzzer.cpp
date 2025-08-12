/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "dbinderremotelistenermock_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "dbinder_remote_listener.h"
#include "dbinder_softbus_client.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

static constexpr size_t MAX_STR_LEN = 100;

class DBinderRemoteListenerInterface {
public:
    DBinderRemoteListenerInterface() {};
    virtual ~DBinderRemoteListenerInterface() {};

    virtual int32_t Socket(SocketInfo info) = 0;
    virtual int32_t Bind(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener) = 0;
    virtual int32_t SendBytes(int32_t socket, const void *data, uint32_t len) = 0;
};

class DBinderRemoteListenerInterfaceMock : public DBinderRemoteListenerInterface {
public:
    DBinderRemoteListenerInterfaceMock();
    ~DBinderRemoteListenerInterfaceMock() override;

    MOCK_METHOD(int32_t, Socket, (SocketInfo info), (override));
    MOCK_METHOD(int32_t, Bind, (int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener),
                (override));
    MOCK_METHOD(int32_t, SendBytes, (int32_t socket, const void *data, uint32_t len), (override));
};

static void *g_interface = nullptr;

DBinderRemoteListenerInterfaceMock::DBinderRemoteListenerInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

DBinderRemoteListenerInterfaceMock::~DBinderRemoteListenerInterfaceMock()
{
    g_interface = nullptr;
}

static DBinderRemoteListenerInterface *GetDBinderRemoteListenerInterface()
{
    return reinterpret_cast<DBinderRemoteListenerInterface *>(g_interface);
}

extern "C" {
int32_t DBinderSoftbusClient::Socket(SocketInfo info)
{
    if (g_interface == nullptr) {
        return SOFTBUS_OK;
    }
    return GetDBinderRemoteListenerInterface()->Socket(info);
}

int32_t DBinderSoftbusClient::Bind(int32_t socket, const QosTV qos[], uint32_t qosCount,
    const ISocketListener *listener)
{
    if (g_interface == nullptr) {
        return 0;
    }
    return GetDBinderRemoteListenerInterface()->Bind(socket, qos, qosCount, listener);
}

int32_t DBinderSoftbusClient::SendBytes(int32_t socket, const void *data, uint32_t len)
{
    if (g_interface == nullptr) {
        return 0;
    }
    return GetDBinderRemoteListenerInterface()->SendBytes(socket, data, len);
}
}

void CreateClientSocketFuzzTest001(FuzzedDataProvider &provider)
{
    std::string networkId = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    auto dBinderRemoteListener = std::make_shared<DBinderRemoteListener>();
    if (dBinderRemoteListener == nullptr) {
        return;
    }
    NiceMock<DBinderRemoteListenerInterfaceMock> mock;
    EXPECT_CALL(mock, Socket).WillRepeatedly(Return(1));
    EXPECT_CALL(mock, Bind).WillRepeatedly(Return(0));
    dBinderRemoteListener->CreateClientSocket(networkId);
}

void CreateClientSocketFuzzTest002(FuzzedDataProvider &provider)
{
    std::string networkId = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    auto dBinderRemoteListener = std::make_shared<DBinderRemoteListener>();
    if (dBinderRemoteListener == nullptr) {
        return;
    }
    NiceMock<DBinderRemoteListenerInterfaceMock> mock;
    EXPECT_CALL(mock, Socket).WillRepeatedly(Return(1));
    EXPECT_CALL(mock, Bind).WillRepeatedly(Return(-1));
    dBinderRemoteListener->CreateClientSocket(networkId);
}

void SendDataToRemoteFuzzTest001(FuzzedDataProvider &provider)
{
    std::string networkId = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    DHandleEntryTxRx msg;
    auto dBinderRemoteListener = std::make_shared<DBinderRemoteListener>();
    if (dBinderRemoteListener == nullptr) {
        return;
    }
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    if (socketId <= 0) {
        return;
    }
    dBinderRemoteListener->clientSocketInfos_[networkId] = socketId;
    NiceMock<DBinderRemoteListenerInterfaceMock> mock;
    EXPECT_CALL(mock, SendBytes).WillRepeatedly(Return(0));
    dBinderRemoteListener->SendDataToRemote(networkId, &msg);
}

void SendDataToRemoteFuzzTest002(FuzzedDataProvider &provider)
{
    std::string networkId = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    DHandleEntryTxRx msg;
    auto dBinderRemoteListener = std::make_shared<DBinderRemoteListener>();
    if (dBinderRemoteListener == nullptr) {
        return;
    }
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    if (socketId <= 0) {
        return;
    }
    dBinderRemoteListener->clientSocketInfos_[networkId] = socketId;
    NiceMock<DBinderRemoteListenerInterfaceMock> mock;
    EXPECT_CALL(mock, SendBytes).WillRepeatedly(Return(-1));
    dBinderRemoteListener->SendDataToRemote(networkId, &msg);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::CreateClientSocketFuzzTest001(provider);
    OHOS::CreateClientSocketFuzzTest002(provider);
    OHOS::SendDataToRemoteFuzzTest001(provider);
    OHOS::SendDataToRemoteFuzzTest002(provider);
    return 0;
}
