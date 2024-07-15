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

int TestServiceClient::ConnectService()
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        ZLOGE(LABEL, "get registry fail");
        return -1;
    }

    sptr<IRemoteObject> object = saMgr->GetSystemAbility(IPC_TEST_SERVICE);

    if (object != nullptr) {
        ZLOGD(LABEL, "Got test Service object");
        sptr<IRemoteObject::DeathRecipient> death(new TestDeathRecipient());
        object->AddDeathRecipient(death.GetRefPtr());
        testService_ = iface_cast<ITestService>(object);
    }

    if (testService_ == nullptr) {
        ZLOGE(LABEL, "Could not find Test Service!");
        return -1;
    }
    return 0;
}

void TestServiceClient::StartSyncTransaction()
{
    if (testService_ != nullptr) {
        ZLOGD(LABEL, "StartSyncTransaction");
        [[maybe_unused]] int result = 0;
        testService_->TestSyncTransaction(2019, result);
    }
}

void TestServiceClient::StartSyncDelayReply()
{
    if (testService_ != nullptr) {
        ZLOGD(LABEL, "StartSyncDelayReply");
        [[maybe_unused]] int result = 0;
        testService_->TestSyncTransaction(2019, result, 2);
    }
}

void TestServiceClient::StartAsyncTransaction()
{
    if (testService_ != nullptr) {
        ZLOGD(LABEL, "StartAsyncTransaction");
        [[maybe_unused]] int result = 0;
        testService_->TestAsyncTransaction(2019, result);
    }
}

void TestServiceClient::StartPingService()
{
    if (testService_ != nullptr) {
        ZLOGD(LABEL, "StartPingService");
        const std::u16string descriptor = ITestService::GetDescriptor();
        testService_->TestPingService(descriptor);
    }
}

void TestServiceClient::StartGetFooService()
{
    if (testService_ != nullptr) {
        ZLOGD(LABEL, "StartGetFooService");
        sptr<IFoo> foo = testService_->TestGetFooService();
        if (foo == nullptr) {
            ZLOGD(LABEL, "Fail to get foo service");
        }
    }
}

void TestServiceClient::StartDumpService()
{
    if (testService_ != nullptr) {
        ZLOGD(LABEL, "StartDumpService");
        testService_->TestDumpService();
    }
}

void TestServiceClient::StartAsyncDumpService()
{
    if (testService_ != nullptr) {
        ZLOGD(LABEL, "StartAsyncDumpService");
        testService_->TestAsyncDumpService();
    }
}

void TestServiceClient::StartTestFileDescriptor()
{
    if (testService_ != nullptr) {
        ZLOGD(LABEL, "StartTestFileDescriptor");
        int fd = testService_->TestGetFileDescriptor();
        if (fd != INVALID_FD) {
            if (write(fd, "client write!\n", strlen("client write!\n")) < 0) {
                ZLOGE(LABEL, "write fd error");
            }
            close(fd);
        }
    }
}

int TestServiceClient::StartLoopTest(int maxCount)
{
    if (testService_ != nullptr) {
        ZLOGD(LABEL, "StartLoopTest");
        int count = 0;
        std::string testString;
        // start loop test, test times is 1000
        for (count = 0; count < maxCount; count++) {
            testString += "0123456789abcdefghijklmnopqrstuvwxyz~!@#$%^&*()_+{}?/[]<>-='|~";
            testService_->TestStringTransaction(testString);
        }
        return count;
    }
    return 0;
}

void TestServiceClient::TestEnableSerialInvokeFlag()
{
    ZLOGD(LABEL, "TestEnableSerialInvokeFlag");
    if (testService_ == nullptr) {
        ZLOGE(LABEL, "Member variable testService_ Is a null pointer");
        return;
    }
    int result = testService_->TestEnableSerialInvokeFlag();
    if (result != 0) {
        std::cout << "TestServiceClient::TestEnableSerialInvokeFlag function call failed" << std::endl;
        return;
    }
    std::cout << "TestServiceClient::TestEnableSerialInvokeFlag function call successful" << std::endl;
}

void TestServiceClient::TestNativeIPCSendRequests(int subCmd)
{
    auto remoteProxy = std::make_shared<NativeRemoteProxyTest>(testService_);
    if (remoteProxy == nullptr) {
        ZLOGE(LABEL, "create remote proxy test failed!");
        return;
    }
    static std::map<int, std::function<int()>> commandMap = {
        { NATIVE_TEST_CMD_SYNC_ADD, [&]() { return remoteProxy->SyncAdd(); }},
        { NATIVE_TEST_CMD_ASYNC_ADD, [&]() { return remoteProxy->ASyncAdd(); }},
        { NATIVE_TEST_CMD_SYNC_ADD_REPEAT, [&]() { return remoteProxy->AddParallel(true); }},
        { NATIVE_TEST_CMD_ASYNC_ADD_REPEAT, [&]() { return remoteProxy->AddParallel(false); }},
        { NATIVE_TEST_CMD_SEND_AND_ECHO_BASE, [&]() { return remoteProxy->SendAndEchoBase(); }},
        { NATIVE_TEST_CMD_SEND_AND_ECHO_SRING, [&]() { return remoteProxy->SendAndEchoString(); }},
        { NATIVE_TEST_CMD_SEND_AND_ECHO_BUFFER, [&]() { return remoteProxy->SendAndEchoBuffer(); }},
        { NATIVE_TEST_CMD_SEND_FILE_DESCRIPTOR, [&]() { return remoteProxy->SendAndEchoFileDescriptor(); }},
        { NATIVE_TEST_CMD_SEND_ERROR_CODE, [&]() { return remoteProxy->SendErrorCode(); }},
    };
    auto it = commandMap.find(subCmd);
    if (it != commandMap.end()) {
        if (it->second() != 0) {
            ZLOGE(LABEL, "Test sub cmd:%{public}d failed!", subCmd);
        } else {
            ZLOGD(LABEL, "Test sub cmd:%{public}d success!", subCmd);
        }
    } else {
        ZLOGD(LABEL, "error sub cmd:%{public}d", subCmd);
        return;
    }
}

void TestServiceClient::TestRegisterRemoteStub()
{
    if (remoteStub_ == nullptr) {
        remoteStub_ = std::make_shared<NativeRemoteStubTest>(testService_);
        if (remoteStub_ == nullptr) {
            ZLOGE(LABEL, "create remote stub test failed!");
            return;
        }
    }
    int ret = remoteStub_->RegisterRemoteStub();
    if (ret != 0) {
        ZLOGE(LABEL, "function call failed");
        return;
    }
    ZLOGD(LABEL, "function call success");
}

void TestServiceClient::TestUnRegisterRemoteStub()
{
    if (remoteStub_ == nullptr) {
        remoteStub_ = std::make_shared<NativeRemoteStubTest>(testService_);
        if (remoteStub_ == nullptr) {
            ZLOGE(LABEL, "create remote stub test failed!");
            return;
        }
    }
    int ret = remoteStub_->UnRegisterRemoteStub();
    if (ret != 0) {
        ZLOGE(LABEL, "function call failed");
        return;
    }
    ZLOGD(LABEL, "function call success");
}

void TestServiceClient::TestSendTooManyRequest()
{
    if (testService_ != nullptr) {
        ZLOGD(LABEL, "TestSendTooManyRequest");
        int ret = 0;
        int data = 2024;
        testService_->TestSendTooManyRequest(data, ret);
    }
}

void TestServiceClient::TestMultiThreadSendRequest()
{
    if (testService_ != nullptr) {
        ZLOGD(LABEL, "TestMultiThreadSendRequest");
        int ret = 0;
        int value = 2024;
        testService_->TestMultiThreadSendRequest(value, ret);
    }
}

} // namespace OHOS
