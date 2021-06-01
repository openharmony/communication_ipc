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

#include "test_service.h"
#include <unistd.h>
#include <fcntl.h>
#include "ipc_skeleton.h"
#include "ipc_debug.h"
#include "string_ex.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
using namespace OHOS::HiviewDFX;

static int Reverse(int x)
{
    int result = 0;
    int decimal = 10; // decimal value.

    while (x != 0) {
        result = result * decimal + x % decimal;
        x = x / decimal;
    }

    return result;
}

int TestService::Instantiate()
{
    ZLOGI(LABEL, "%{public}s call in", __func__);
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        ZLOGE(LABEL, "%{public}s:fail to get Registry", __func__);
        return -ENODEV;
    }

    sptr<IRemoteObject> newInstance = new TestService();
#ifdef IPCSERVERTESTEXTRA
    int result = saMgr->AddSystemAbility(IPC_EXTRA_TEST_SERVICE, newInstance);
    ZLOGI(LABEL, "%{public}s: IPC_EXTRA_TEST_SERVICE result = %{public}d", __func__, result);
#else
    int result = saMgr->AddSystemAbility(IPC_TEST_SERVICE, newInstance);
    ZLOGI(LABEL, "%{public}s: IPC_TEST_SERVICE result = %{public}d", __func__, result);
#endif

    ZLOGI(LABEL, "TestService: strong = %d", newInstance->GetSptrRefCount());
    return result;
}

TestService::TestService() : testFd_(INVALID_FD)
{
}

TestService::~TestService()
{
    if (testFd_ != INVALID_FD) {
        close(testFd_);
    }
}

int TestService::TestSyncTransaction(int data, int &rep, int delayTime)
{
    rep = Reverse(data);

    if (delayTime > 0) {
        sleep(delayTime);
    }

    ZLOGE(LABEL, "TestServiceStub:read from client data = %{public}d", data);
    return ERR_NONE;
}

int TestService::TestAsyncTransaction(int data, int timeout)
{
    ZLOGE(LABEL, "TestServiceStub:read from client data = %{public}d", data);

    if (timeout > 0) {
        sleep(timeout);
    }

    return Reverse(data);
}

int TestService::TestAsyncCallbackTrans(int data, int &reply, int timeout)
{
    if (timeout > 0) {
        timeout = 0;
    }

    return Reverse(data);
}

int TestService::TestZtraceTransaction(std::string &send, std::string &receive, int len)
{
    receive = send;
    transform(receive.begin(), receive.end(), receive.begin(), ::tolower);
    return 0;
}
int TestService::TestPingService(const std::u16string &serviceName)
{
    std::u16string localServiceName = GetObjectDescriptor();
    if (localServiceName.compare(serviceName) != 0) {
        ZLOGE(LABEL, "local name is ""%s, passing is %s",
            Str16ToStr8(localServiceName).c_str(), Str16ToStr8(serviceName).c_str());
        return -1;
    }

    return 0;
}

sptr<IFoo> TestService::TestGetFooService()
{
    return new FooStub();
}

int TestService::TestGetFileDescriptor()
{
    if (testFd_ != INVALID_FD) {
        close(testFd_);
    }

    testFd_ = open("/data/test/test.txt",
        O_RDWR | O_APPEND | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);

    if (testFd_ == INVALID_FD) {
        ZLOGE(LABEL, "%s(%d):open failed.", __func__, __LINE__);
        return !INVALID_FD;
    }

    ssize_t writeLen = write(testFd_, "Sever write!\n", strlen("Sever write!\n"));
    if (writeLen < 0) {
        ZLOGE(LABEL, "%s(%d): server write file failed.", __func__, __LINE__);
        close(testFd_);
        return INVALID_FD;
    } else {
        ZLOGI(LABEL, "%s(%d): server write file success.", __func__, __LINE__);
    }

    return testFd_;
}

int TestService::TestStringTransaction(const std::string &data)
{
    return data.size();
}

void TestService::TestDumpService()
{
    // use for proxy only.
}

void TestService::TestAsyncDumpService()
{
    // use for proxy only.
}

int TestService::TestRawDataTransaction(int length, int &reply)
{
    return 0;
}

int TestService::TestRawDataReply(int length)
{
    return 0;
}

int TestService::TestCallingUidPid()
{
    return 0;
}

int TestService::TestFlushAsyncCalls(int count, int length)
{
    return 0;
}

int TestService::TestMultipleProcesses(int data, int &rep, int delayTime)
{
    return 0;
}

int TestService::Dump(int fd, const std::vector<std::u16string> &args)
{
    ssize_t writeCount = 0;
    if (fd > 0) {
        std::u16string argsParam = args.front();
        std::string context;
        context.append(Str16ToStr8(argsParam));
        context.append(1, '\r');
        writeCount = write(fd, context.data(), context.size());
    }

    return writeCount > 0 ? ERR_NONE : ERR_TRANSACTION_FAILED;
}

std::u16string TestService::TestAshmem(sptr<Ashmem> ashmem, int32_t contentSize)
{
    return u"";
}

int TestService::TestNestingSend(int sendCode, int &replyCode)
{
    return 0;
}
} // namespace OHOS
