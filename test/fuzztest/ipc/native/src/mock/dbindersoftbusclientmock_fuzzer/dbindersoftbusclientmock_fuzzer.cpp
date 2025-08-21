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

#include "dbindersoftbusclientmock_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "dbinder_softbus_client.h"
#include "message_parcel.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
const static size_t MAX_STRING_PARAM_LEN = 100;

class DbinderSoftBusClientInterface {
public:
    DbinderSoftBusClientInterface() {};
    virtual ~DbinderSoftBusClientInterface() {};

    virtual bool OpenSoftbusClientSo() = 0;
};

class DbinderSoftBusClientInterfaceMock : public DbinderSoftBusClientInterface {
public:
    DbinderSoftBusClientInterfaceMock();
    ~DbinderSoftBusClientInterfaceMock() override;
    MOCK_METHOD0(OpenSoftbusClientSo, bool());
};

static void *g_interface = nullptr;

DbinderSoftBusClientInterfaceMock::DbinderSoftBusClientInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

DbinderSoftBusClientInterfaceMock::~DbinderSoftBusClientInterfaceMock()
{
    g_interface = nullptr;
}

static DbinderSoftBusClientInterface *GetDbinderSoftBusClientInterface()
{
    return reinterpret_cast<DbinderSoftBusClientInterfaceMock *>(g_interface);
}

extern "C" {
    bool DBinderSoftbusClient::OpenSoftbusClientSo()
    {
        DbinderSoftBusClientInterface* interface = GetDbinderSoftBusClientInterface();
        if (interface == nullptr) {
            return false;
        }
        return interface->OpenSoftbusClientSo();
    }
}

static void DBinderGrantPermissionFuzzTest(FuzzedDataProvider &provider)
{
    int32_t uid = provider.ConsumeIntegral<int32_t>();
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    std::string socketName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    NiceMock<DbinderSoftBusClientInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, OpenSoftbusClientSo).WillOnce(Return(false));
    DBinderSoftbusClient::GetInstance().DBinderGrantPermission(uid, pid, socketName);

    EXPECT_CALL(mockClient, OpenSoftbusClientSo).WillOnce(Return(true));
    DBinderSoftbusClient::GetInstance().DBinderGrantPermission(uid, pid, socketName);
}

static void DBinderRemovePermissionFuzzTest(FuzzedDataProvider &provider)
{
    std::string socketName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    NiceMock<DbinderSoftBusClientInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, OpenSoftbusClientSo).WillOnce(Return(false));
    DBinderSoftbusClient::GetInstance().DBinderRemovePermission(socketName);

    EXPECT_CALL(mockClient, OpenSoftbusClientSo).WillOnce(Return(true));
    DBinderSoftbusClient::GetInstance().DBinderRemovePermission(socketName);
}

static void GetLocalNodeDeviceIdFuzzTest(FuzzedDataProvider &provider)
{
    std::string pkgName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::string devId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    NiceMock<DbinderSoftBusClientInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, OpenSoftbusClientSo).WillOnce(Return(false));
    DBinderSoftbusClient::GetInstance().GetLocalNodeDeviceId(pkgName, devId);

    EXPECT_CALL(mockClient, OpenSoftbusClientSo).WillOnce(Return(true));
    DBinderSoftbusClient::GetInstance().GetLocalNodeDeviceId(pkgName, devId);
}

static void SocketFuzzTest(FuzzedDataProvider &provider)
{
    SocketInfo info;
    std::string name = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::string peerNetworkId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::string pkgName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::string peerName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    info.name = const_cast<char *>(name.c_str());
    info.peerNetworkId = const_cast<char *>(peerNetworkId.c_str());
    info.pkgName = const_cast<char *>(pkgName.c_str());
    info.dataType = DATA_TYPE_MESSAGE;
    info.peerName = const_cast<char *>(peerName.c_str());
    NiceMock<DbinderSoftBusClientInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, OpenSoftbusClientSo).WillOnce(Return(false));
    DBinderSoftbusClient::GetInstance().Socket(info);

    EXPECT_CALL(mockClient, OpenSoftbusClientSo).WillOnce(Return(true));
    DBinderSoftbusClient::GetInstance().Socket(info);
}

static void ListenFuzzTest(FuzzedDataProvider &provider)
{
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    int32_t qosType = provider.ConsumeIntegralInRange<int32_t>(0, static_cast<int>(QOS_TYPE_BUTT));
    int32_t value = provider.ConsumeIntegral<int32_t>();
    QosTV qos[1] = {{static_cast<QosType>(qosType), value}};
    ISocketListener serverListener{};
    NiceMock<DbinderSoftBusClientInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, OpenSoftbusClientSo).WillOnce(Return(false));
    DBinderSoftbusClient::GetInstance().Listen(socketId, qos, sizeof(qos) / sizeof(qos[0]), &serverListener);

    EXPECT_CALL(mockClient, OpenSoftbusClientSo).WillOnce(Return(true));
    DBinderSoftbusClient::GetInstance().Listen(socketId, qos, sizeof(qos) / sizeof(qos[0]), &serverListener);
}

static void BindFuzzTest(FuzzedDataProvider &provider)
{
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    int32_t qosType = provider.ConsumeIntegralInRange<int32_t>(0, static_cast<int>(QOS_TYPE_BUTT));
    int32_t value = provider.ConsumeIntegral<int32_t>();
    QosTV qos[1] = {{static_cast<QosType>(qosType), value}};
    ISocketListener serverListener{};
    NiceMock<DbinderSoftBusClientInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, OpenSoftbusClientSo).WillOnce(Return(false));
    DBinderSoftbusClient::GetInstance().Bind(socketId, qos, sizeof(qos) / sizeof(qos[0]), &serverListener);

    EXPECT_CALL(mockClient, OpenSoftbusClientSo).WillOnce(Return(true));
    DBinderSoftbusClient::GetInstance().Bind(socketId, qos, sizeof(qos) / sizeof(qos[0]), &serverListener);
}

static void SendBytesTest(FuzzedDataProvider &provider)
{
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    std::string data = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    NiceMock<DbinderSoftBusClientInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, OpenSoftbusClientSo).WillOnce(Return(false));
    DBinderSoftbusClient::GetInstance().SendBytes(socketId, static_cast<const void*>(data.data()), data.size());

    EXPECT_CALL(mockClient, OpenSoftbusClientSo).WillOnce(Return(true));
    DBinderSoftbusClient::GetInstance().SendBytes(socketId, static_cast<const void*>(data.data()), data.size());
}

static void SendMessageTest(FuzzedDataProvider &provider)
{
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    std::string data = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    NiceMock<DbinderSoftBusClientInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, OpenSoftbusClientSo).WillOnce(Return(false));
    DBinderSoftbusClient::GetInstance().SendMessage(socketId, static_cast<const void*>(data.data()), data.size());

    EXPECT_CALL(mockClient, OpenSoftbusClientSo).WillOnce(Return(true));
    DBinderSoftbusClient::GetInstance().SendMessage(socketId, static_cast<const void*>(data.data()), data.size());
}

static void ShutdownFuzzTest(FuzzedDataProvider &provider)
{
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    NiceMock<DbinderSoftBusClientInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, OpenSoftbusClientSo).WillOnce(Return(false));
    DBinderSoftbusClient::GetInstance().Shutdown(socketId);

    EXPECT_CALL(mockClient, OpenSoftbusClientSo).WillOnce(Return(true));
    DBinderSoftbusClient::GetInstance().Shutdown(socketId);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::DBinderGrantPermissionFuzzTest(provider);
    OHOS::DBinderRemovePermissionFuzzTest(provider);
    OHOS::GetLocalNodeDeviceIdFuzzTest(provider);
    OHOS::SocketFuzzTest(provider);
    OHOS::ListenFuzzTest(provider);
    OHOS::BindFuzzTest(provider);
    OHOS::SendBytesTest(provider);
    OHOS::SendMessageTest(provider);
    OHOS::ShutdownFuzzTest(provider);
    return 0;
}
