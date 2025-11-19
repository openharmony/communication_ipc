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
const static size_t MAX_STRING_PARAM_LEN = 100;

class DBinderServiceInterface {
public:
    DBinderServiceInterface() {};
    virtual ~DBinderServiceInterface() {};
    virtual int32_t DBinderGrantPermission(int32_t uid, int32_t pid, const std::string &socketName) = 0;
    virtual int32_t Socket(SocketInfo info) = 0;
    virtual int32_t Listen(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener) = 0;
};

class DBinderServiceInterfaceMock : public DBinderServiceInterface {
public:
    DBinderServiceInterfaceMock();
    ~DBinderServiceInterfaceMock() override;
    MOCK_METHOD3(DBinderGrantPermission, int32_t(int32_t uid, int32_t pid, const std::string &socketName));
    MOCK_METHOD1(Socket, int32_t(SocketInfo));
    MOCK_METHOD4(Listen, int32_t(int32_t, const QosTV*, uint32_t, const ISocketListener *));
};

class TestRpcSystemAbilityCallback : public RpcSystemAbilityCallback {
public:
    sptr<IRemoteObject> GetSystemAbilityFromRemote(int32_t systemAbilityId) override
    {
        return nullptr;
    }

    bool LoadSystemAbilityFromRemote(const std::string& srcNetworkId, int32_t systemAbilityId) override
    {
        return isLoad_;
    }
    bool IsDistributedSystemAbility(int32_t systemAbilityId) override
    {
        return isSystemAbility_;
    }
    void SetSystemAbility(bool value)
    {
        isSystemAbility_ = value;
    }
    void SetLoad(bool value)
    {
        isLoad_ = value;
    }

private:
    bool isSystemAbility_ = true;
    bool isLoad_ = true;
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

    int32_t DBinderSoftbusClient::Socket(SocketInfo info)
    {
        if (g_interface == nullptr) {
            return -1;
        }
        return GetDBinderServiceInterfaceMock()->Socket(info);
    }

    int32_t DBinderSoftbusClient::Listen(
        int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener)
    {
        if (g_interface == nullptr) {
            return -1;
        }
        return GetDBinderServiceInterfaceMock()->Listen(socket, qos, qosCount, listener);
    }
}

void StartDBinderServiceTest(FuzzedDataProvider &provider)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        return;
    }
    std::shared_ptr<RpcSystemAbilityCallback> callbackImpl = nullptr;
    callbackImpl = std::make_shared<TestRpcSystemAbilityCallback>();
    if (callbackImpl == nullptr) {
        return;
    }
    dBinderService->StartDBinderService(callbackImpl);

    NiceMock<DBinderServiceInterfaceMock> mock;
    EXPECT_CALL(mock, DBinderGrantPermission).WillRepeatedly(testing::Return(ERR_NONE));
    EXPECT_CALL(mock, Socket).WillRepeatedly(testing::Return(1));
    EXPECT_CALL(mock, Listen).WillRepeatedly(testing::Return(0));
    dBinderService->StartDBinderService(callbackImpl);
    dBinderService->StartDBinderService(callbackImpl);
    dBinderService->StartRemoteListener();
    dBinderService->StopRemoteListener();
}

void AddStubByTagTest(FuzzedDataProvider &provider)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        return;
    }
    std::string name = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    const std::u16string serviceName = Str8ToStr16(name);
    const std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
    sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
    if (stub == nullptr) {
        return;
    }
    binder_uintptr_t binderObjectPtr = reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr());

    dBinderService->AddStubByTag(binderObjectPtr);
    dBinderService->QueryStubPtr(binderObjectPtr);
    dBinderService->AddStubByTag(binderObjectPtr);
}

void CheckBinderObjectTest(FuzzedDataProvider &provider)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        return;
    }
    std::string name = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    const std::u16string serviceName = Str8ToStr16(name);
    const std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
    sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
    if (stub == nullptr) {
        return;
    }
    binder_uintptr_t binderObjectPtr = reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr());

    sptr<DBinderServiceStub> stub1 = nullptr;
    dBinderService->CheckBinderObject(stub1, binderObjectPtr);
}

void FindOrNewDBinderStubTest(FuzzedDataProvider &provider)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        return;
    }
    std::string name = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::u16string serviceName = Str8ToStr16(name);
    std::string device = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
    uint32_t pid = provider.ConsumeIntegral<uint32_t>();
    uint32_t uid = provider.ConsumeIntegral<uint32_t>();
    bool isNew = false;

    dBinderService->FindOrNewDBinderStub(serviceName, device, binderObject, pid, uid, isNew);
    dBinderService->HasDBinderStub(binderObject);
    dBinderService->FindDBinderStub(serviceName, device);
    dBinderService->DeleteDBinderStub(serviceName, device, pid, uid);

    dBinderService->FindOrNewDBinderStub(serviceName, device, binderObject, pid, uid, isNew);
    dBinderService->FindOrNewDBinderStub(serviceName, device, binderObject, pid, uid, isNew);
    dBinderService->DeleteDBinderStub(serviceName, device);
}

void OnRemoteInvokerMessageTest(FuzzedDataProvider &provider)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    std::shared_ptr<struct DHandleEntryTxRx> message = std::make_shared<DHandleEntryTxRx>();
    if (message == nullptr || dBinderService == nullptr) {
        return;
    }

    std::shared_ptr<TestRpcSystemAbilityCallback> callback = std::make_shared<TestRpcSystemAbilityCallback>();
    if (callback == nullptr) {
        return;
    }

    message->stubIndex = provider.ConsumeIntegralInRange<int32_t>(DBinderService::FIRST_SYS_ABILITY_ID,
        DBinderService::LAST_SYS_ABILITY_ID);
    message->binderObject = provider.ConsumeIntegralInRange<int32_t>(DBinderService::FIRST_SYS_ABILITY_ID,
        DBinderService::LAST_SYS_ABILITY_ID);

    std::string localDevID = provider.ConsumeRandomLengthString(DEVICEID_LENGTH);
    std::string deviceID = provider.ConsumeRandomLengthString(DEVICEID_LENGTH);
    NiceMock<DBinderServiceInterfaceMock> mock;
    EXPECT_CALL(mock, DBinderGrantPermission).WillRepeatedly(testing::Return(ERR_NONE));
    EXPECT_CALL(mock, Socket).WillRepeatedly(testing::Return(1));
    EXPECT_CALL(mock, Listen).WillRepeatedly(testing::Return(0));
    auto temp = std::static_pointer_cast<OHOS::RpcSystemAbilityCallback>(callback);
    dBinderService->mainThreadCreated_ = false;
    bool ret = dBinderService->StartDBinderService(temp);
    if (!ret) {
        return;
    }
    dBinderService->CopyDeviceIDsToMessage(message, localDevID, deviceID);
    dBinderService->OnRemoteInvokerMessage(message);

    callback->SetSystemAbility(true);
    dBinderService->OnRemoteInvokerMessage(message);

    callback->SetLoad(true);
    dBinderService->OnRemoteInvokerMessage(message);
    dBinderService->StopRemoteListener();
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::StartDBinderServiceTest(provider);
    OHOS::AddStubByTagTest(provider);
    OHOS::CheckBinderObjectTest(provider);
    OHOS::FindOrNewDBinderStubTest(provider);
    OHOS::OnRemoteInvokerMessageTest(provider);
    return 0;
}