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
#include <fcntl.h>
#include <unistd.h>
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
        ZLOGE(LABEL, "Got test Service object");
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
        ZLOGI(LABEL, "StartSyncTransaction");
        [[maybe_unused]] int result = 0;
        testService_->TestSyncTransaction(2019, result);
    }
}

void TestServiceClient::StartSyncDelayReply()
{
    if (testService_ != nullptr) {
        ZLOGI(LABEL, "StartSyncDelayReply");
        [[maybe_unused]] int result = 0;
        testService_->TestSyncTransaction(2019, result, 2);
    }
}

void TestServiceClient::StartAsyncTransaction()
{
    if (testService_ != nullptr) {
        ZLOGI(LABEL, "StartAsyncTransaction");
        [[maybe_unused]] int result = 0;
        testService_->TestAsyncTransaction(2019, result);
    }
}

void TestServiceClient::StartPingService()
{
    if (testService_ != nullptr) {
        ZLOGI(LABEL, "StartPingService");
        const std::u16string descriptor = ITestService::GetDescriptor();
        testService_->TestPingService(descriptor);
    }
}

void TestServiceClient::StartGetFooService()
{
    if (testService_ != nullptr) {
        ZLOGI(LABEL, "StartGetFooService");
        sptr<IFoo> foo = testService_->TestGetFooService();
        if (foo == nullptr) {
            ZLOGI(LABEL, "Fail to get foo service");
        }
    }
}

void TestServiceClient::StartDumpService()
{
    if (testService_ != nullptr) {
        ZLOGI(LABEL, "StartDumpService");
        testService_->TestDumpService();
    }
}

void TestServiceClient::StartAsyncDumpService()
{
    if (testService_ != nullptr) {
        ZLOGI(LABEL, "StartAsyncDumpService");
        testService_->TestAsyncDumpService();
    }
}

void TestServiceClient::StartTestFileDescriptor()
{
    if (testService_ != nullptr) {
        ZLOGI(LABEL, "StartTestFileDescriptor");
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
        ZLOGI(LABEL, "StartLoopTest");
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
} // namespace OHOS
