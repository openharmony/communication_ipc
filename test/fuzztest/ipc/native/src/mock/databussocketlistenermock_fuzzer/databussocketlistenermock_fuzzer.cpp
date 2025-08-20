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

#include "databussocketlistenermock_fuzzer.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "databus_socket_listener.h"
#include "dbinder_softbus_client.h"
#include "ipc_process_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "string_ex.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
const static size_t MAX_STRING_PARAM_LEN = 100;

class DataBusSocketListenerInterface {
public:
    DataBusSocketListenerInterface() {};
    virtual ~DataBusSocketListenerInterface() {};

    virtual int32_t Socket(SocketInfo info) = 0;
    virtual int32_t Listen(int32_t socket, const QosTV qos[], uint32_t qosCount,
        const ISocketListener *listener) = 0;
    virtual IPCProcessSkeleton *GetCurrent();
    virtual int32_t Bind(int32_t socket, const QosTV qos[], uint32_t qosCount,
        const ISocketListener *listener) = 0;
    virtual IRemoteInvoker *GetRemoteInvoker(int proto);
};

class DataBusSocketListenerInterfaceMock : public DataBusSocketListenerInterface {
public:
    DataBusSocketListenerInterfaceMock();
    ~DataBusSocketListenerInterfaceMock() override;
    MOCK_METHOD1(Socket, int32_t(SocketInfo));
    MOCK_METHOD4(Listen, int32_t(int32_t, const QosTV*, uint32_t, const ISocketListener *));
    MOCK_METHOD0(GetCurrent, IPCProcessSkeleton*());
    MOCK_METHOD4(Bind, int32_t(int32_t, const QosTV*, uint32_t, const ISocketListener *));
    MOCK_METHOD1(GetRemoteInvoker, IRemoteInvoker *(int));
};

static void *g_interface = nullptr;

DataBusSocketListenerInterfaceMock::DataBusSocketListenerInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

DataBusSocketListenerInterfaceMock::~DataBusSocketListenerInterfaceMock()
{
    g_interface = nullptr;
}

static DataBusSocketListenerInterface *GetDataBusSocketListenerInterface()
{
    return reinterpret_cast<DataBusSocketListenerInterfaceMock *>(g_interface);
}

extern "C" {
    int32_t DBinderSoftbusClient::Socket(SocketInfo info)
    {
        if (g_interface == nullptr) {
            return -1;
        }
        return GetDataBusSocketListenerInterface()->Socket(info);
    }

    int32_t DBinderSoftbusClient::Listen(
        int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener)
    {
        if (g_interface == nullptr) {
            return -1;
        }
        return GetDataBusSocketListenerInterface()->Listen(socket, qos, qosCount, listener);
    }

    IPCProcessSkeleton *IPCProcessSkeleton::GetCurrent()
    {
        if (g_interface == nullptr) {
            return nullptr;
        }
        return GetDataBusSocketListenerInterface()->GetCurrent();
    }

    int32_t DBinderSoftbusClient::Bind(int32_t socket, const QosTV qos[], uint32_t qosCount,
        const ISocketListener *listener)
    {
        if (g_interface == nullptr) {
            return -1;
        }
        return GetDataBusSocketListenerInterface()->Bind(socket, qos, qosCount, listener);
    }

    IRemoteInvoker *IPCThreadSkeleton::GetRemoteInvoker(int proto)
    {
        if (g_interface == nullptr) {
            return nullptr;
        }
        return GetDataBusSocketListenerInterface()->GetRemoteInvoker(proto);
    }
}

static void CreateClientSocketFuzzTest001(FuzzedDataProvider &provider)
{
    std::shared_ptr<DatabusSocketListener> listener = DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        return;
    }
    std::string ownName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::string peerName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::string networkId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    listener->CreateClientSocket(ownName, peerName, networkId);

    NiceMock<DataBusSocketListenerInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, Socket).WillRepeatedly(testing::Return(1));
    EXPECT_CALL(mockClient, Bind).WillRepeatedly(testing::Return(-1));
    listener->CreateClientSocket(ownName, peerName, networkId);
}

static void CreateClientSocketFuzzTest002(FuzzedDataProvider &provider)
{
    std::shared_ptr<DatabusSocketListener> listener = DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        return;
    }
    std::string ownName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::string peerName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::string networkId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    NiceMock<DataBusSocketListenerInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, Socket).WillRepeatedly(testing::Return(1));
    EXPECT_CALL(mockClient, Bind).WillRepeatedly(testing::Return(0));
    listener->CreateClientSocket(ownName, peerName, networkId);
}

static void StartServerListenerFuzzTest001(FuzzedDataProvider &provider)
{
    std::shared_ptr<DatabusSocketListener> listener = DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        return;
    }
    std::string ownName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    listener->StartServerListener(ownName);

    NiceMock<DataBusSocketListenerInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, Socket).WillRepeatedly(testing::Return(1));
    EXPECT_CALL(mockClient, Listen).WillRepeatedly(testing::Return(-1));
    listener->StartServerListener(ownName);
}

static void StartServerListenerFuzzTest002(FuzzedDataProvider &provider)
{
    std::shared_ptr<DatabusSocketListener> listener = DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        return;
    }
    std::string ownName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    NiceMock<DataBusSocketListenerInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, Socket).WillRepeatedly(testing::Return(1));
    EXPECT_CALL(mockClient, Listen).WillRepeatedly(testing::Return(0));
    listener->StartServerListener(ownName);
}

static void RemoveSessionNameFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<DatabusSocketListener> listener = DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        return;
    }
    NiceMock<DataBusSocketListenerInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, GetCurrent).WillRepeatedly(testing::Return(nullptr));
    listener->RemoveSessionName();
}

static void ShutdownSocketFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<DatabusSocketListener> listener = DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        return;
    }
    std::string ownName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::string peerName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::string networkId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    NiceMock<DataBusSocketListenerInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, Socket).WillRepeatedly(testing::Return(1));
    EXPECT_CALL(mockClient, Bind).WillRepeatedly(testing::Return(0));
    listener->CreateClientSocket(ownName, peerName, networkId);
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    listener->ShutdownSocket(socketId);
    socketId = 1;
    listener->ShutdownSocket(socketId);
}

static void ClientOnShutdownFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<DatabusSocketListener> listener = DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        return;
    }
    int32_t reason = provider.ConsumeIntegral<int32_t>();
    std::string ownName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::string peerName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::string networkId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    NiceMock<DataBusSocketListenerInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, Socket).WillRepeatedly(testing::Return(1));
    EXPECT_CALL(mockClient, Bind).WillRepeatedly(testing::Return(0));
    listener->CreateClientSocket(ownName, peerName, networkId);
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    listener->ClientOnShutdown(socketId, static_cast<ShutdownReason>(reason));
    socketId = 1;
    listener->ClientOnShutdown(socketId, static_cast<ShutdownReason>(reason));
}

static void ServerOnBindFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<DatabusSocketListener> listener = DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        return;
    }
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    std::string name = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::string networkId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::string pkgName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    int32_t dataType = provider.ConsumeIntegral<int32_t>();
    PeerSocketInfo info = {
        .name = const_cast<char *>(name.c_str()),
        .networkId = const_cast<char *>(networkId.c_str()),
        .pkgName = const_cast<char *>(pkgName.c_str()),
        .dataType = static_cast<TransDataType>(dataType),
    };
    NiceMock<DataBusSocketListenerInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, GetRemoteInvoker).WillRepeatedly(testing::Return(nullptr));
    listener->ServerOnBind(socketId, info);
}

static void ServerOnShutdownFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<DatabusSocketListener> listener = DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        return;
    }
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    int32_t reason = provider.ConsumeIntegral<int32_t>();
    NiceMock<DataBusSocketListenerInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, GetRemoteInvoker).WillRepeatedly(testing::Return(nullptr));
    listener->ServerOnShutdown(socketId, static_cast<ShutdownReason>(reason));
}

static void OnBytesReceivedFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<DatabusSocketListener> listener = DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        return;
    }
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    std::string recivedData = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    uint32_t recivedLen = recivedData.size();
    NiceMock<DataBusSocketListenerInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, GetRemoteInvoker).WillRepeatedly(testing::Return(nullptr));
    listener->OnBytesReceived(socketId, static_cast<const void*>(recivedData.c_str()), recivedLen);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::CreateClientSocketFuzzTest001(provider);
    OHOS::CreateClientSocketFuzzTest002(provider);
    OHOS::StartServerListenerFuzzTest001(provider);
    OHOS::StartServerListenerFuzzTest002(provider);
    OHOS::RemoveSessionNameFuzzTest(provider);
    OHOS::ShutdownSocketFuzzTest(provider);
    OHOS::ClientOnShutdownFuzzTest(provider);
    OHOS::ServerOnBindFuzzTest(provider);
    OHOS::ServerOnShutdownFuzzTest(provider);
    OHOS::OnBytesReceivedFuzzTest(provider);
    return 0;
}