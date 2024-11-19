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

#include "test_service_client.h"
#include <iostream>
#include <unistd.h>
#include <map>
#include "ipc_debug.h"
#include "ipc_skeleton.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {

constexpr int PARCEL_MAX_CAPACITY = 200 * 1024;

bool TestServiceClient::ConnectService()
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        ZLOGE(LABEL, "get registry fail");
        return false;
    }

    sptr<IRemoteObject> object = saMgr->GetSystemAbility(IPC_TEST_SERVICE);

    if (object != nullptr) {
        ZLOGI(LABEL, "Got test Service object");
        sptr<IRemoteObject::DeathRecipient> death(new TestDeathRecipient());
        object->AddDeathRecipient(death.GetRefPtr());
        testService_ = iface_cast<ITestService>(object);
    }

    if (testService_ == nullptr) {
        ZLOGE(LABEL, "Could not find Test Service!");
        return false;
    }
    return true;
}

bool TestServiceClient::StartSyncTransaction()
{
    if (testService_ == nullptr) {
        ZLOGE(LABEL, "The testService_ object is an empty object");
        return false;
    }

    ZLOGI(LABEL, "StartSyncTransaction");
    int result = 0;
    int originalValue = 2019;
    int reversalValue = 9102;
    int ret = testService_->TestSyncTransaction(originalValue, result);
    if (ret != 0) {
        ZLOGE(LABEL, "TestSyncTransaction function call failed");
        return false;
    }

    if (result != reversalValue) {
        return false;
    }
    return true;
}

bool TestServiceClient::StartPingService()
{
    if (testService_ == nullptr) {
        ZLOGE(LABEL, "The testService_ object is an empty object");
        return false;
    }

    ZLOGI(LABEL, "StartPingService");
    const std::u16string descriptor = ITestService::GetDescriptor();
    int ret = testService_->TestPingService(descriptor);
    if (ret != 0) {
        ZLOGE(LABEL, "TestPingService function call failed");
        return false;
    }
    return true;
}

bool TestServiceClient::StartGetFooService()
{
    if (testService_ == nullptr) {
        ZLOGE(LABEL, "The testService_ object is an empty object");
        return false;
    }

    ZLOGI(LABEL, "StartGetFooService");
    sptr<IFoo> foo = testService_->TestGetFooService();
    if (foo == nullptr) {
        ZLOGE(LABEL, "TestGetFooService function call failed");
        return false;
    }
    return true;
}

bool TestServiceClient::StartDumpService()
{
    if (testService_ == nullptr) {
        ZLOGE(LABEL, "The testService_ object is an empty object");
        return false;
    }

    ZLOGI(LABEL, "StartDumpService");
    int ret = testService_->TestDumpService();
    if (ret != 0) {
        ZLOGE(LABEL, "TestDumpService function call failed");
        return false;
    }
    return true;
}

bool TestServiceClient::StartTestFileDescriptor()
{
    if (testService_ == nullptr) {
        ZLOGE(LABEL, "The testService_ object is an empty object");
        return false;
    }

    ZLOGI(LABEL, "StartTestFileDescriptor");
    int fd = testService_->TestGetFileDescriptor();
    if (fd == INVALID_FD) {
        ZLOGE(LABEL, "TestGetFileDescriptor function call failed");
        return false;
    }
    if (write(fd, "client write!\n", strlen("client write!\n")) < 0) {
        ZLOGE(LABEL, "write fd error");
        return false;
    }
    close(fd);
    return true;
}

bool TestServiceClient::StartLoopTest(int maxCount)
{
    if (testService_ == nullptr) {
        ZLOGE(LABEL, "The testService_ object is an empty object");
        return false;
    }

    ZLOGI(LABEL, "StartLoopTest");
    int count = 0;
    std::string testString;
    // start loop test, test times is 10240
    for (count = 0; count < maxCount; count++) {
        testString += "0123456789!";
        int ret = testService_->TestStringTransaction(testString);
        if (ret > PARCEL_MAX_CAPACITY) {
            return false;
        }
    }

    return true;
}

bool TestServiceClient::TestEnableSerialInvokeFlag()
{
    ZLOGI(LABEL, "TestEnableSerialInvokeFlag");
    if (testService_ == nullptr) {
        ZLOGE(LABEL, "The testService_ object is an empty object");
        return false;
    }
    int result = testService_->TestEnableSerialInvokeFlag();
    if (result != 0) {
        ZLOGE(LABEL, "TestEnableSerialInvokeFlag function call failed");
        return false;
    }

    return true;
}

bool TestServiceClient::TestNativeIPCSendRequests(int subCmd)
{
    if (testService_ == nullptr) {
        ZLOGE(LABEL, "The testService_ object is an empty object");
        return false;
    }

    auto remoteProxy = std::make_shared<NativeRemoteProxyTest>(testService_);
    if (remoteProxy == nullptr) {
        ZLOGE(LABEL, "Create remote proxy test failed!");
        return false;
    }

    static std::map<int, std::function<int()>> commandMap = {
        { NATIVE_TEST_CMD_SYNC_ADD,               [remoteProxy]() { return remoteProxy->SyncAdd(); }},
        { NATIVE_TEST_CMD_ASYNC_ADD,              [remoteProxy]() { return remoteProxy->ASyncAdd(); }},
        { NATIVE_TEST_CMD_SYNC_ADD_REPEAT,        [remoteProxy]() { return remoteProxy->AddParallel(true); }},
        { NATIVE_TEST_CMD_ASYNC_ADD_REPEAT,       [remoteProxy]() { return remoteProxy->AddParallel(false); }},
        { NATIVE_TEST_CMD_SEND_AND_ECHO_BASE,     [remoteProxy]() { return remoteProxy->SendAndEchoBase(); }},
        { NATIVE_TEST_CMD_SEND_AND_ECHO_SRING,    [remoteProxy]() { return remoteProxy->SendAndEchoString(); }},
        { NATIVE_TEST_CMD_SEND_AND_ECHO_BUFFER,   [remoteProxy]() { return remoteProxy->SendAndEchoBuffer(); }},
        { NATIVE_TEST_CMD_SEND_FILE_DESCRIPTOR,   [remoteProxy]() { return remoteProxy->SendAndEchoFileDescriptor(); }},
        { NATIVE_TEST_CMD_SEND_ERROR_CODE,        [remoteProxy]() { return remoteProxy->SendErrorCode(); }},
    };
    auto it = commandMap.find(subCmd);
    if (it == commandMap.end()) {
        ZLOGE(LABEL, "Error sub cmd:%{public}d", subCmd);
        return false;
    }
    if (it->second() != 0) {
        ZLOGE(LABEL, "Test sub cmd:%{public}d failed!", subCmd);
        return false;
    }

    ZLOGI(LABEL, "Test sub cmd:%{public}d success!", subCmd);
    return true;
}

bool TestServiceClient::TestRegisterRemoteStub()
{
    if (testService_ == nullptr) {
        ZLOGE(LABEL, "The testService_ object is an empty object");
        return false;
    }

    if (remoteStub_ == nullptr) {
        remoteStub_ = std::make_shared<NativeRemoteStubTest>(testService_);
        if (remoteStub_ == nullptr) {
            ZLOGE(LABEL, "Create remote stub test failed!");
            return false;
        }
    }
    int ret = remoteStub_->RegisterRemoteStub();
    if (ret != 0) {
        ZLOGE(LABEL, "RegisterRemoteStub function call failed");
        return false;
    }
    ZLOGI(LABEL, "RegisterRemoteStub function success");
    return true;
}

bool TestServiceClient::TestUnRegisterRemoteStub()
{
    if (testService_ == nullptr) {
        ZLOGE(LABEL, "The testService_ object is an empty object");
        return false;
    }

    if (remoteStub_ == nullptr) {
        remoteStub_ = std::make_shared<NativeRemoteStubTest>(testService_);
        if (remoteStub_ == nullptr) {
            ZLOGE(LABEL, "create remote stub test failed!");
            return false;
        }
    }
    int ret = remoteStub_->UnRegisterRemoteStub();
    if (ret != 0) {
        ZLOGE(LABEL, "UnRegisterRemoteStub function call failed");
        return false;
    }
    ZLOGI(LABEL, "TestUnRegisterRemoteStub function call success");
    return true;
}

bool TestServiceClient::TestSendTooManyRequest()
{
    if (testService_ == nullptr) {
        ZLOGE(LABEL, "The testService_ object is an empty object");
        return false;
    }

    ZLOGI(LABEL, "TestSendTooManyRequest");
    int res = 0;
    int data = 2024;
    int ret = testService_->TestSendTooManyRequest(data, res);
    if (ret != 0) {
        ZLOGE(LABEL, "TestSendTooManyRequest function call failed");
        return false;
    }
    return true;
}

bool TestServiceClient::TestMultiThreadSendRequest()
{
    if (testService_ == nullptr) {
        ZLOGE(LABEL, "The testService_ object is an empty object");
        return false;
    }

    int res = 0;
    int value = 2024;
    int ret = testService_->TestMultiThreadSendRequest(value, res);
    if (ret != 0) {
        ZLOGE(LABEL, "TestMultiThreadSendRequest function call failed");
        return false;
    }
    return true;
}

} // namespace OHOS
