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

#include <iostream>
#include <string>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <thread>
#include <nativetoken_kit.h>
#include <token_setproc.h>

#include "log_tags.h"
#include "if_system_ability_manager.h"
#include "ipc_debug.h"
#include "ipc_skeleton.h"
#include "test_service_client.h"

using namespace OHOS;
using namespace OHOS::HiviewDFX;
static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_TEST, "IPCTestClient" };
static std::shared_ptr<TestServiceClient> gTestClient{ nullptr };
static void InitTokenId(void)
{
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 0,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = NULL,
        .acls = NULL,
        .processName = "com.ipc.test",
        .aplStr = "normal",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
}

void ThreadFunc(std::shared_ptr<TestServiceClient> testClient)
{
    testClient->TestEnableSerialInvokeFlag();
}

void SignalHandler(int signum)
{
    ZLOGI(LABEL, "Caught signal %{public}d", signum);
    if (gTestClient != nullptr) {
        ZLOGE(LABEL, "UnRegister RemoteStub before application exit");
        gTestClient->TestUnRegisterRemoteStub();
        gTestClient = nullptr;
    }
    if (signum == SIGINT) {
        ZLOGI(LABEL, "SIGINT");
        IPCSkeleton::StopWorkThread();
    }
}

void TestCaseSyncTrans(std::shared_ptr<TestServiceClient> &testClient)
{
    bool ret = testClient->StartSyncTransaction();
    if (!ret) {
        std::cout << "[FAILED] Execution of TestCaseSyncTrans case failed" <<std::endl;
    } else {
        std::cout << "[PASS] Execution of TestCaseSyncTrans case Successful" <<std::endl;
    }
}

#ifdef FREEZE_PROCESS_ENABLED
void TestCaseFreezeProcess(std::shared_ptr<TestServiceClient> &testClient)
{
    bool ret = testClient->TestFreezeProcess();
    std::cout << (ret ? "[PASS] Execution of TestFreezeProcess case Successful" :
        "[FAILED] Execution of TestFreezeProcess case failed") << std::endl;
}

int GetPidOfTestProcess()
{
    std::string command = "pidof com.samples.ipc_service";
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        return -1;
    }

    char buffer[128];
    std::string result;

    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }

    pclose(pipe);
    if (!result.empty()) {
        return std::stoi(result);
    }
    return -1;
}

int TestFreezeAsyncProcess()
{
    int pid = GetPidOfTestProcess();
    if (pid <= 0) {
        ZLOGE(LABEL, "get test process pid fail!");
        return -1;
    }

    int timeout = 1000;
    auto res = IPCSkeleton::Freeze(pid, true, timeout);
    if (res != ERR_NONE) {
        ZLOGE(LABEL, "Freeze binder fail, err code = %{public}d", res);
        return res;
    }

    bool isFrozen = false;
    res = IPCSkeleton::GetProcessFreezeInfo(pid, isFrozen);
    if (res != ERR_NONE || !isFrozen) {
        ZLOGE(LABEL, "GetProcessFreezeInfo failed, err code = %{public}d, isFrozen = %{public}d", res, isFrozen);
        return -1;
    }
    ZLOGI(LABEL, "Freeze binder success");

    int  waitTime = 20;
    sleep(waitTime);

    res = IPCSkeleton::Freeze(pid, false, timeout);
    if (res != ERR_NONE) {
        ZLOGE(LABEL, "Unfreeze binder fail, err code = %{public}d", res);
        return res;
    }
    ZLOGI(LABEL, "Unfreeze binder success");

    return 0;
}

void TestCaseFreezeAsyncProcess()
{
    bool ret = TestFreezeAsyncProcess();
    std::cout << ((ret == 0) ? "[PASS] Execution of TestFreezeAsyncProcess case Successful" :
        "[FAILED] Execution of TestFreezeAsyncProcess case failed") << std::endl;
}
#endif // FREEZE_PROCESS_ENABLED

void TestCasePingService(std::shared_ptr<TestServiceClient> &testClient)
{
    bool ret = testClient->StartPingService();
    if (!ret) {
        std::cout << "[FAILED] Execution of TestCasePingService case failed" <<std::endl;
    } else {
        std::cout << "[PASS] Execution of TestCasePingService case Successful" <<std::endl;
    }
}

void TestCaseGetFooService(std::shared_ptr<TestServiceClient> &testClient)
{
    bool ret = testClient->StartGetFooService();
    if (!ret) {
        std::cout << "[FAILED] Execution of TestCaseGetFooService case failed" <<std::endl;
    } else {
        std::cout << "[PASS] Execution of TestCaseGetFooService case Successful" <<std::endl;
    }
}

void TestCaseGetFileDescriptor(std::shared_ptr<TestServiceClient> &testClient)
{
    bool ret = testClient->StartTestFileDescriptor();
    if (!ret) {
        std::cout << "[FAILED] Execution of TestCaseGetFileDescriptor case failed" <<std::endl;
    } else {
        std::cout << "[PASS] Execution of TestCaseGetFileDescriptor case Successful" <<std::endl;
    }
}

void TestCaseLoopTest(std::shared_ptr<TestServiceClient> &testClient)
{
    constexpr int maxTestCount = 10240;
    bool ret = testClient->StartLoopTest(maxTestCount);
    if (!ret) {
        std::cout << "[FAILED] Execution of TestCaseLoopTest case failed" <<std::endl;
    } else {
        std::cout << "[PASS] Execution of TestCaseLoopTest case Successful" <<std::endl;
    }
}

void TestCaseDumpService(std::shared_ptr<TestServiceClient> &testClient)
{
    bool ret = testClient->StartDumpService();
    if (!ret) {
        std::cout << "[FAILED] Execution of TestCaseDumpService case failed" <<std::endl;
    } else {
        std::cout << "[PASS] Execution of TestCaseDumpService case Successful" <<std::endl;
    }
}
void TestCaseEnableSerialInvokeFlag(std::shared_ptr<TestServiceClient> &testClient)
{
    std::thread temp(ThreadFunc, testClient);
    bool ret = testClient->TestEnableSerialInvokeFlag();
    temp.join();
    if (!ret) {
        std::cout << "[FAILED] Execution of TestCaseEnableSerialInvokeFlag case failed" <<std::endl;
    } else {
        std::cout << "[PASS] Execution of TestCaseEnableSerialInvokeFlag case Successful" <<std::endl;
    }
}

void TestCaseNativeIPCSendRequests(std::shared_ptr<TestServiceClient> &testClient)
{
    bool ret = testClient->TestRegisterRemoteStub();
    if (!ret) {
        std::cout << "[FAILED] Execution of TestRegisterRemoteStub case failed" <<std::endl;
        return;
    }
    ret = testClient->TestNativeIPCSendRequests(1);
    if (!ret) {
        std::cout << "[FAILED] Execution of TestCaseNativeIPCSendRequests case failed" <<std::endl;
        return;
    }
    std::cout << "[PASS] Execution of TestCaseNativeIPCSendRequests case Successful" <<std::endl;
}

void TestCaseRegisterRemoteStub(std::shared_ptr<TestServiceClient> &testClient)
{
    bool ret = testClient->TestRegisterRemoteStub();
    if (!ret) {
        std::cout << "[FAILED] Execution of TestRegisterRemoteStub case failed" <<std::endl;
        return;
    }
    gTestClient = testClient;
    if (signal(SIGINT, SignalHandler) == SIG_ERR) {
        ZLOGE(LABEL, "Failed to caught signal");
        std::cout << "[FAILED] Execution of TestRegisterRemoteStub case failed" <<std::endl;
        return;
    }
    std::cout << "[PASS] Execution of TestRegisterRemoteStub case Successful" <<std::endl;
}

void TestCaseTooManyRequests(std::shared_ptr<TestServiceClient> &testClient)
{
    bool ret = testClient->TestSendTooManyRequest();
    if (!ret) {
        std::cout << "[FAILED] Execution of TestCaseTooManyRequests case failed" <<std::endl;
    }
    ret = testClient->StartSyncTransaction();
    if (!ret) {
        std::cout << "[FAILED] Execution of TestCaseTooManyRequests case failed" <<std::endl;
        return;
    }
    std::cout << "[PASS] Execution of TestCaseTooManyRequests case Successful" <<std::endl;
}

void TestCaseMultiThreadSendRequest(std::shared_ptr<TestServiceClient> &testClient)
{
    bool ret = testClient->TestMultiThreadSendRequest();
    if (!ret) {
        std::cout << "[FAILED] Execution of TestCaseMultiThreadSendRequest case failed" <<std::endl;
    } else {
        std::cout << "[PASS] Execution of TestCaseMultiThreadSendRequest case Successful" <<std::endl;
    }
}

void TestCaseQueryThreadInvocationState(std::shared_ptr<TestServiceClient> &testClient)
{
    bool ret = testClient->TestQueryThreadInvocationState();
    if (!ret) {
        std::cout << "[FAILED] Execution of TestCaseQueryThreadInvocationState case failed" <<std::endl;
    } else {
        std::cout << "[PASS] Execution of TestCaseQueryThreadInvocationState case Successful" <<std::endl;
    }
}

void ExecuteAllTestCase()
{
    std::shared_ptr<TestServiceClient> testClient = std::make_shared<TestServiceClient>();
    int ret = testClient->ConnectService();
    if (!ret) {
        ZLOGE(LABEL, "ConnectService failed");
        return;
    }
    TestCaseQueryThreadInvocationState(testClient);
    TestCaseSyncTrans(testClient);
    TestCasePingService(testClient);
    TestCaseGetFooService(testClient);
    TestCaseGetFileDescriptor(testClient);
    TestCaseLoopTest(testClient);
    TestCaseDumpService(testClient);
    TestCaseEnableSerialInvokeFlag(testClient);
    TestCaseNativeIPCSendRequests(testClient);
    TestCaseRegisterRemoteStub(testClient);
    TestCaseTooManyRequests(testClient);
    TestCaseMultiThreadSendRequest(testClient);
#ifdef FREEZE_PROCESS_ENABLED
    TestCaseFreezeProcess(testClient);
    TestCaseFreezeAsyncProcess();
#endif // FREEZE_PROCESS_ENABLED
    ZLOGI(LABEL, "All test cases have been executed");
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    if (fork() == 0) {
        system("/system/bin/ipc_server_test");
        return 0;
    }

    sleep(1);
    std::cout << "Start executing the client" <<std::endl;
    InitTokenId();
    ExecuteAllTestCase();

    // The non IPC context obtains one's own sid
    std::string selfSid = IPCSkeleton::GetCallingSid();
    ZLOGI(LABEL, "Get from service: sid = %{public}s", selfSid.c_str());
    system("kill -9 $(pidof /system/bin/ipc_server_test)");

    return 0;
}
