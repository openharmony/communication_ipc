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

#include <algorithm>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "databus_socket_listener.h"
#include "ipc_thread_skeleton.h"
#include "iremote_invoker.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
class DatabusSocketListenerInterface {
public:
    DatabusSocketListenerInterface() {};
    virtual ~DatabusSocketListenerInterface() {};
    virtual int32_t Socket(SocketInfo info) = 0;
    virtual int32_t Listen(int32_t socket, const QosTV qos[], uint32_t qosCount,
        const ISocketListener *listener) = 0;
    virtual int32_t Bind(int32_t socket, const QosTV qos[], uint32_t qosCount,
        const ISocketListener *listener) = 0;
    virtual IRemoteInvoker *GetRemoteInvoker(int proto) = 0;
};

class DatabusSocketListenerInterfaceMock : public DatabusSocketListenerInterface {
public:
    DatabusSocketListenerInterfaceMock();
    ~DatabusSocketListenerInterfaceMock() override;
    MOCK_METHOD1(Socket, int32_t(SocketInfo));
    MOCK_METHOD4(Listen, int32_t(int32_t, const QosTV *, uint32_t, const ISocketListener *));
    MOCK_METHOD1(GetRemoteInvoker, IRemoteInvoker *(int));
    MOCK_METHOD4(Bind, int32_t(int32_t, const QosTV *, uint32_t, const ISocketListener *));
};

class DatabusSocketListenerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() const;
    void TearDown() const;
};

void DatabusSocketListenerTest::SetUpTestCase()
{
}

void DatabusSocketListenerTest::TearDownTestCase()
{
}

void DatabusSocketListenerTest::SetUp() const
{
}

void DatabusSocketListenerTest::TearDown() const
{
}

static void *g_interface = nullptr;

DatabusSocketListenerInterfaceMock::DatabusSocketListenerInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

DatabusSocketListenerInterfaceMock::~DatabusSocketListenerInterfaceMock()
{
    g_interface = nullptr;
}

static DatabusSocketListenerInterfaceMock *GetDatabusSocketListenerInterface()
{
    return reinterpret_cast<DatabusSocketListenerInterfaceMock *>(g_interface);
}

extern "C" {
    IRemoteInvoker *IPCThreadSkeleton::GetRemoteInvoker(int proto)
    {
        if (GetDatabusSocketListenerInterface() == nullptr) {
            return nullptr;
        }
        return GetDatabusSocketListenerInterface()->GetRemoteInvoker(proto);
    }

    int32_t DBinderSoftbusClient::Socket(SocketInfo info)
    {
        return GetDatabusSocketListenerInterface()->Socket(info);
    }

    int32_t DBinderSoftbusClient::Listen(
        int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener)
    {
        return GetDatabusSocketListenerInterface()->Listen(socket, qos, qosCount, listener);
    }

    int32_t Bind(int32_t socket, const QosTV qos[], uint32_t qosCount,
        const ISocketListener *listener)
    {
        return GetDatabusSocketListenerInterface()->Bind(socket, qos, qosCount, listener);
    }
}

/**
 * @tc.name: ServerOnBindTest001
 * @tc.desc: Verify the ServerOnBind function when peerUid.length() > INT_STRING_MAX_LEN
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, ServerOnBindTest001, TestSize.Level1)
{
    DatabusSocketListener listener;
    int32_t socket = 1;
    std::string infoName = DBINDER_SOCKET_NAME_PREFIX + "01234567890123456789" + "_" + "012345";
    std::string infoNetworkId = "1234567890abcdefg";
    std::string infoPkgName = "1234567asd";
    PeerSocketInfo info = {
        .dataType = DATA_TYPE_BYTES,
        .name = const_cast<char *>(infoName.c_str()),
        .networkId = const_cast<char *>(infoNetworkId.c_str()),
        .pkgName = const_cast<char *>(infoPkgName.c_str()),
    };
    ASSERT_NO_FATAL_FAILURE(listener.ServerOnBind(socket, info));
}

/**
 * @tc.name: ServerOnBindTest002
 * @tc.desc: Verify the ServerOnBind function when peerPid.length() > INT_STRING_MAX_LEN)
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, ServerOnBindTest002, TestSize.Level1)
{
    DatabusSocketListener listener;
    int32_t socket = 1;
    std::string infoName = DBINDER_SOCKET_NAME_PREFIX + "01234567890123456789" + "_" + "012345";
    std::string infoNetworkId = "1234567890abcdefg";
    std::string infoPkgName = "1234567asd";
    PeerSocketInfo info = {
        .dataType = DATA_TYPE_BYTES,
        .name = const_cast<char *>(infoName.c_str()),
        .networkId = const_cast<char *>(infoNetworkId.c_str()),
        .pkgName = const_cast<char *>(infoPkgName.c_str()),
    };
    ASSERT_NO_FATAL_FAILURE(listener.ServerOnBind(socket, info));
}

/**
 * @tc.name: ServerOnBindTest003
 * @tc.desc: Verify the ServerOnBind function when !ProcessSkeleton::IsNumStr(peerUid)
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, ServerOnBindTest003, TestSize.Level1)
{
    DatabusSocketListener listener;
    int32_t socket = 1;
    std::string infoName = DBINDER_SOCKET_NAME_PREFIX + "peerUid" + "_" + "012345";
    std::string infoNetworkId = "1234567890abcdefg";
    std::string infoPkgName = "1234567asd";
    PeerSocketInfo info = {
        .dataType = DATA_TYPE_BYTES,
        .name = const_cast<char *>(infoName.c_str()),
        .networkId = const_cast<char *>(infoNetworkId.c_str()),
        .pkgName = const_cast<char *>(infoPkgName.c_str()),
    };
    ASSERT_NO_FATAL_FAILURE(listener.ServerOnBind(socket, info));
}

/**
 * @tc.name: ServerOnBindTest004
 * @tc.desc: Verify the ServerOnBind function when !ProcessSkeleton::IsNumStr(peerPid)
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, ServerOnBindTest004, TestSize.Level1)
{
    DatabusSocketListener listener;
    int32_t socket = 1;
    std::string infoName = DBINDER_SOCKET_NAME_PREFIX + "012345" + "_" + "peerPid";
    std::string infoNetworkId = "1234567890abcdefg";
    std::string infoPkgName = "1234567asd";
    PeerSocketInfo info = {
        .dataType = DATA_TYPE_BYTES,
        .name = const_cast<char *>(infoName.c_str()),
        .networkId = const_cast<char *>(infoNetworkId.c_str()),
        .pkgName = const_cast<char *>(infoPkgName.c_str())
    };
    ASSERT_NO_FATAL_FAILURE(listener.ServerOnBind(socket, info));
}

/**
 * @tc.name: ClientOnShutdown001
 * @tc.desc: Verify the ClientOnShutdown function when invoker == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, ClientOnShutdown001, TestSize.Level1)
{
    DatabusSocketListener listener;
    int32_t socket = 1;
    ShutdownReason reason = SHUTDOWN_REASON_LINK_DOWN;
    NiceMock<DatabusSocketListenerInterfaceMock> mock;

    EXPECT_CALL(mock, GetRemoteInvoker).WillOnce(Return(nullptr));
    ASSERT_NO_FATAL_FAILURE(listener.ClientOnShutdown(socket, reason));
}

/**
 * @tc.name: ClientOnShutdown002
 * @tc.desc: Verify the ClientOnShutdown function when it->second == socket in iter socketInfoMap_
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, ClientOnShutdown002, TestSize.Level1)
{
    DatabusSocketListener listener;
    int32_t socket = 100;
    ShutdownReason reason = SHUTDOWN_REASON_LINK_DOWN;
    std::string ownName = "ownName";
    std::string peerName = "peerName";
    std::string networkId = "networkId";
    DBinderSocketInfo info(ownName, peerName, networkId);
    listener.socketInfoMap_[info] = socket;
    ASSERT_NO_FATAL_FAILURE(listener.ClientOnShutdown(socket, reason));
    listener.socketInfoMap_.clear();
}

/**
 * @tc.name: StartServerListener001
 * @tc.desc: Verify the StartServerListener function when socketId <= 0
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, StartServerListener001, TestSize.Level1)
{
    DatabusSocketListener listener;
    std::string ownName = "ownName";
    NiceMock<DatabusSocketListenerInterfaceMock> mock;
    int32_t socketId = -1;

    EXPECT_CALL(mock, Socket).WillOnce(Return(socketId));
    int32_t result = listener.StartServerListener(ownName);
    EXPECT_EQ(result, SOCKET_ID_INVALID);
}

/**
 * @tc.name: StartServerListener002
 * @tc.desc: Verify the StartServerListener function when ret != SOFTBUS_OK && ret != SOFTBUS_TRANS_SOCKET_IN_USE
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, StartServerListener002, TestSize.Level1)
{
    DatabusSocketListener listener;
    std::string ownName = "ownName";
    NiceMock<DatabusSocketListenerInterfaceMock> mock;
    int32_t socketId = 100;

    EXPECT_CALL(mock, Socket).WillOnce(Return(socketId));
    EXPECT_CALL(mock, Listen).WillOnce(Return(SOFTBUS_DISCOVER_ACTION_HAD_PRELINK));
    int32_t result = listener.StartServerListener(ownName);
    EXPECT_EQ(result, SOCKET_ID_INVALID);
}

/**
 * @tc.name: StartServerListener003
 * @tc.desc: Verify the StartServerListener function when ret == SOFTBUS_TRANS_SOCKET_IN_USE
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, StartServerListener003, TestSize.Level1)
{
    DatabusSocketListener listener;
    std::string ownName = "ownName";
    NiceMock<DatabusSocketListenerInterfaceMock> mock;
    int32_t socketId = 1;

    EXPECT_CALL(mock, Socket).WillOnce(Return(socketId));
    EXPECT_CALL(mock, Listen).WillOnce(Return(SOFTBUS_TRANS_SOCKET_IN_USE));
    int32_t result = listener.StartServerListener(ownName);
    EXPECT_EQ(result, socketId);
}

/**
 * @tc.name: StartServerListener004
 * @tc.desc: Verify the StartServerListener function when ret == SOFTBUS_OK
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, StartServerListener004, TestSize.Level1)
{
    DatabusSocketListener listener;
    std::string ownName = "ownName";
    NiceMock<DatabusSocketListenerInterfaceMock> mock;
    int32_t socketId = 1;

    EXPECT_CALL(mock, Socket).WillOnce(Return(socketId));
    EXPECT_CALL(mock, Listen).WillOnce(Return(SOFTBUS_OK));
    int32_t result = listener.StartServerListener(ownName);
    EXPECT_EQ(result, socketId);
}
}  // namespace OHOS