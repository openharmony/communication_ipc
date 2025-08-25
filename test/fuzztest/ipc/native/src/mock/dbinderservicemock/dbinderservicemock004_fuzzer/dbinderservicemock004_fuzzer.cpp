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

#include "dbinderservicemock_fuzzer.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <condition_variable>
#include <fuzzer/FuzzedDataProvider.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mutex>
#include <random>
#include <thread>

#include "dbinder_service.h"
#include "dbinder_service_stub.h"
#include "dbinder_remote_listener.h"
#include "dbinder_softbus_client.h"
#include "string_ex.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

class DBinderServiceInterface {
public:
    DBinderServiceInterface() {};
    virtual ~DBinderServiceInterface() {};

    virtual int32_t DBinderGrantPermission(int32_t uid, int32_t pid, const std::string &socketName) = 0;
    virtual std::string GetSessionName() = 0;
    virtual bool WriteString(const std::string &value) = 0;
    virtual int InvokeListenThread(MessageParcel &data, MessageParcel &reply) = 0;
    virtual uint64_t ReadUint64() = 0;
    virtual const std::string ReadString() = 0;
};

class DBinderServiceInterfaceMock : public DBinderServiceInterface {
public:
    DBinderServiceInterfaceMock();
    ~DBinderServiceInterfaceMock() override;
    MOCK_METHOD3(DBinderGrantPermission, int32_t(int32_t uid, int32_t pid, const std::string &socketName));
    MOCK_METHOD0(GetSessionName, std::string());
    MOCK_METHOD1(WriteString, bool(const std::string &value));
    MOCK_METHOD2(InvokeListenThread, int(MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD0(ReadUint64, uint64_t());
    MOCK_METHOD0(ReadString, const std::string());
};

static void *g_interface = nullptr;

DBinderServiceInterfaceMock::DBinderServiceInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

DBinderServiceInterfaceMock::~DBinderServiceInterfaceMock()
{
    g_interface = nullptr;
}

static DBinderServiceInterfaceMock *GetDBinderServiceInterfaceMock()
{
    return reinterpret_cast<DBinderServiceInterfaceMock *>(g_interface);
}

extern "C" {
    int32_t DBinderSoftbusClient::DBinderGrantPermission(int32_t uid, int32_t pid, const std::string &socketName)
    {
        if (g_interface == nullptr) {
            return -1;
        }
        return GetDBinderServiceInterfaceMock()->DBinderGrantPermission(uid, pid, socketName);
    }

    std::string IPCObjectProxy::GetSessionName()
    {
        if (g_interface == nullptr) {
            return "";
        }
        return GetDBinderServiceInterfaceMock()->GetSessionName();
    }

    bool Parcel::WriteString(const std::string &value)
    {
        if (g_interface == nullptr) {
            return false;
        }
        return GetDBinderServiceInterfaceMock()->WriteString(value);
    }

    int IPCObjectProxy::InvokeListenThread(MessageParcel &data, MessageParcel &reply)
    {
        if (g_interface == nullptr) {
            return 0;
        }
        return GetDBinderServiceInterfaceMock()->InvokeListenThread(data, reply);
    }

    uint64_t Parcel::ReadUint64()
    {
        if (g_interface == nullptr) {
            return -1;
        }
        return GetDBinderServiceInterfaceMock()->ReadUint64();
    }

    const std::string Parcel::ReadString()
    {
        if (g_interface == nullptr) {
            return "";
        }
        return GetDBinderServiceInterfaceMock()->ReadString();
    }
}

static void RandomString(std::string &str)
{
    const std::string charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const size_t length = 250;

    std::mt19937 rng(static_cast<unsigned int>(std::time(nullptr)));
    std::uniform_int_distribution<size_t> dist(0, charset.size() - 1);

    str.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        str += charset[dist(rng)];
    }
}

void GetDatabusNameByProxyTest(FuzzedDataProvider &provider)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        return;
    }
    sptr<IPCObjectProxy> callbackProxy = nullptr;
    dBinderService->GetDatabusNameByProxy(callbackProxy);

    int32_t handle = provider.ConsumeIntegral<int32_t>();
    callbackProxy = new (std::nothrow) IPCObjectProxy(handle);
    if (callbackProxy == nullptr) {
        return;
    }
    NiceMock<DBinderServiceInterfaceMock> mock;
    EXPECT_CALL(mock, GetSessionName).WillRepeatedly(testing::Return(""));
    dBinderService->GetDatabusNameByProxy(callbackProxy);

    EXPECT_CALL(mock, GetSessionName).WillRepeatedly(testing::Return("abc"));
    dBinderService->GetDatabusNameByProxy(callbackProxy);
}

void CreateDatabusNameTest(FuzzedDataProvider &provider)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        return;
    }

    int32_t pid = provider.ConsumeIntegral<int32_t>();
    int32_t uid = provider.ConsumeIntegral<int32_t>();
    NiceMock<DBinderServiceInterfaceMock> mock;
    EXPECT_CALL(mock, DBinderGrantPermission).WillRepeatedly(testing::Return(ERR_NONE));
    dBinderService->CreateDatabusName(pid, uid);
}

void SetReplyMessageTest(FuzzedDataProvider &provider)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    std::shared_ptr<struct DHandleEntryTxRx> message = std::make_shared<DHandleEntryTxRx>();
    if (message == nullptr || dBinderService == nullptr) {
        return;
    }
    int32_t handle = provider.ConsumeIntegral<int32_t>();
    sptr<IPCObjectProxy> proxy = new (std::nothrow) IPCObjectProxy(handle);
    if (proxy == nullptr) {
        return;
    }
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    std::string serverSessionName = "";
    RandomString(serverSessionName);
    uint32_t selfTokenId = provider.ConsumeIntegral<uint32_t>();
    message->head.version = RPC_TOKENID_SUPPORT_VERSION + 1;
    dBinderService->SetReplyMessage(message, stubIndex, serverSessionName, selfTokenId, proxy);

    message->head.version = 1;
    dBinderService->SetReplyMessage(message, stubIndex, serverSessionName, selfTokenId, proxy);
}

void OnRemoteInvokerDataBusMessageTest001(FuzzedDataProvider &provider)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<DHandleEntryTxRx>();
    if (replyMessage == nullptr || dBinderService == nullptr) {
        return;
    }
    int32_t handle = provider.ConsumeIntegral<int32_t>();
    sptr<IPCObjectProxy> proxy = new (std::nothrow) IPCObjectProxy(handle);
    if (proxy == nullptr) {
        return;
    }

    std::string remoteDeviceId = provider.ConsumeRandomLengthString(DEVICEID_LENGTH);
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    int32_t uid = provider.ConsumeIntegral<int32_t>();
    uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
    NiceMock<DBinderServiceInterfaceMock> mock;
    EXPECT_CALL(mock, GetSessionName).WillRepeatedly(testing::Return(""));
    dBinderService->OnRemoteInvokerDataBusMessage(proxy, replyMessage, remoteDeviceId, pid, uid, tokenId);

    EXPECT_CALL(mock, GetSessionName).WillRepeatedly(testing::Return("123"));
    dBinderService->OnRemoteInvokerDataBusMessage(proxy, replyMessage, remoteDeviceId, pid, uid, tokenId);

    EXPECT_CALL(mock, WriteString).WillRepeatedly(testing::Return(false));
    dBinderService->OnRemoteInvokerDataBusMessage(proxy, replyMessage, remoteDeviceId, pid, uid, tokenId);

    EXPECT_CALL(mock, WriteString).WillRepeatedly(testing::Return(true));
    dBinderService->OnRemoteInvokerDataBusMessage(proxy, replyMessage, remoteDeviceId, pid, uid, tokenId);

    EXPECT_CALL(mock, InvokeListenThread).WillRepeatedly(testing::Return(1));
    dBinderService->OnRemoteInvokerDataBusMessage(proxy, replyMessage, remoteDeviceId, pid, uid, tokenId);

    EXPECT_CALL(mock, InvokeListenThread).WillRepeatedly(testing::Return(ERR_NONE));
    dBinderService->OnRemoteInvokerDataBusMessage(proxy, replyMessage, remoteDeviceId, pid, uid, tokenId);
}

void OnRemoteInvokerDataBusMessageTest002(FuzzedDataProvider &provider)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<DHandleEntryTxRx>();
    if (replyMessage == nullptr || dBinderService == nullptr) {
        return;
    }
    int32_t handle = provider.ConsumeIntegral<int32_t>();
    sptr<IPCObjectProxy> proxy = new (std::nothrow) IPCObjectProxy(handle);
    if (proxy == nullptr) {
        return;
    }

    std::string remoteDeviceId = provider.ConsumeRandomLengthString(DEVICEID_LENGTH);
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    int32_t uid = provider.ConsumeIntegral<int32_t>();
    uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();

    NiceMock<DBinderServiceInterfaceMock> mock;
    EXPECT_CALL(mock, GetSessionName).WillRepeatedly(testing::Return("123"));
    EXPECT_CALL(mock, WriteString).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, InvokeListenThread).WillRepeatedly(testing::Return(ERR_NONE));
    EXPECT_CALL(mock, ReadString).WillRepeatedly(testing::Return("123"));
    EXPECT_CALL(mock, ReadUint64).WillRepeatedly(testing::Return(0));
    dBinderService->OnRemoteInvokerDataBusMessage(proxy, replyMessage, remoteDeviceId, pid, uid, tokenId);

    EXPECT_CALL(mock, ReadUint64).WillRepeatedly(testing::Return(1));
    dBinderService->OnRemoteInvokerDataBusMessage(proxy, replyMessage, remoteDeviceId, pid, uid, tokenId);

    std::string serverSessionName = "";
    RandomString(serverSessionName);
    EXPECT_CALL(mock, ReadString).WillRepeatedly(testing::Return(serverSessionName));
    dBinderService->OnRemoteInvokerDataBusMessage(proxy, replyMessage, remoteDeviceId, pid, uid, tokenId);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::GetDatabusNameByProxyTest(provider);
    OHOS::CreateDatabusNameTest(provider);
    OHOS::SetReplyMessageTest(provider);
    OHOS::OnRemoteInvokerDataBusMessageTest001(provider);
    OHOS::OnRemoteInvokerDataBusMessageTest002(provider);
    return 0;
}