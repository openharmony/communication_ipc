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

#include <unistd.h>
#include <sys/time.h>
#include <iostream>
#include <string>
#include <sstream>
#include <regex>
#include <chrono>
#include <securec.h>
#include <gtest/gtest.h>
#include "ipc_debug.h"
#include "hitrace/trace.h"
#include "ipc_skeleton.h"
#include "ipc_object_proxy.h"
#include "test_service_skeleton.h"
#include "test_service.h"
#include "ipc_test_helper.h"
#include "binder_connector.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "log_tags.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HiviewDFX;

static constexpr HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC, "BinderTraceUnitTest" };

class BinderTraceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);

private:
    static IPCTestHelper *g_helper;
};
IPCTestHelper *BinderTraceTest::g_helper = nullptr;
void BinderTraceTest::SetUpTestCase()
{
    if (g_helper == nullptr) {
        g_helper = new IPCTestHelper();
        bool res = g_helper->PrepareTestSuite();
        ASSERT_TRUE(res);
    }
}

void BinderTraceTest::TearDownTestCase()
{
    if (g_helper != nullptr) {
        bool res = g_helper->TearDownTestSuite();
        ASSERT_TRUE(res);
        delete g_helper;
        g_helper = nullptr;
    }
}

static std::string HitraceLongToString(unsigned long data)
{
    std::string result;
    constexpr int BUFFER_SIZE = 16;
    char str[BUFFER_SIZE] = {0};

    if (sprintf_s(str, sizeof(str), "%lx", data) <= 0) {
        return result;
    }

    result = str;
    return result;
}

static std::string BinderTraceGetRemainLog(const std::string &tag)
{
    std::string logMsgs;
    std::string remainLogMsgs;
    constexpr int BUFFER_SIZE = 1024;
    FILE *fp = popen("/system/bin/hilog -x -z 4096", "re");
    bool findTag = false;

    if (fp != nullptr) {
        char buf[BUFFER_SIZE] = {0};
        size_t n;
        n = fread(buf, 1, sizeof(buf), fp);
        while (n > 0) {
            logMsgs.append(buf, n);
            n = fread(buf, 1, sizeof(buf), fp);
        }
        pclose(fp);
    } else {
        return remainLogMsgs;
    }

    std::stringstream ss(logMsgs);
    std::string str;
    while (!ss.eof()) {
        getline(ss, str);

        if (findTag == false && str.find(tag) != std::string::npos) {
            findTag = true;
        }

        if (findTag == true) {
            remainLogMsgs.append(str);
        }
    }

    return remainLogMsgs;
}
static int BinderTraceCheckLog(const std::string &remainLogMsgs, const std::string &checkItem,
    const std::string &chainId)
{
    std::stringstream rss(remainLogMsgs);
    std::string str;
    std::regex re(checkItem);

    while (!rss.eof()) {
        getline(rss, str);
        if (std::regex_search(str, re) == true && str.find(chainId) != std::string::npos) {
            return 1;
        }
    }

    return 0;
}

static std::string PrintTagLog(const std::string &tag)
{
    struct timeval tv = {};
    constexpr int SEC_TO_USEC = 1000000;
    gettimeofday(&tv, nullptr);
    long long timeStamp = tv.tv_sec * SEC_TO_USEC + tv.tv_usec;
    std::string strTimeStamp;
    std::stringstream ss;
    ss << timeStamp;
    ss >> strTimeStamp;
    std::string logTag = strTimeStamp + tag;
    HiLog::Info(LOG_LABEL, "%s\n", logTag.c_str());
    return logTag;
}

HWTEST_F(BinderTraceTest, Sync001, TestSize.Level1)
{
    HiTraceId getId = HiTrace::GetId();
    EXPECT_EQ(0, getId.IsValid());
    HiTraceId traceId = HiTrace::Begin("ipc hitrace", 0);
    std::string chainId = HitraceLongToString(traceId.GetChainId());
    EXPECT_NE(0UL, chainId.size());
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();

    ASSERT_TRUE(saMgr != nullptr);

    sptr<IRemoteObject> service = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    sptr<ITestService> testService = iface_cast<ITestService>(service);

    ASSERT_TRUE(testService != nullptr);
    HiLog::Info(LOG_LABEL, "Get test.service OK\n");
    std::string logTag = PrintTagLog(":BinderTraceTest_Sync001");

    if (service->IsProxyObject()) {
        HiLog::Info(LOG_LABEL, "Got Proxy node\n");
        TestServiceProxy *proxy = static_cast<TestServiceProxy *>(testService.GetRefPtr());
        int reply = 0;
        int ret = proxy->TestSyncTransaction(2019, reply);
        EXPECT_EQ(ret, NO_ERROR);
        EXPECT_EQ(reply, 9102);
    } else {
        HiLog::Info(LOG_LABEL, "Got Stub node\n");
    }

    getId = HiTrace::GetId();
    EXPECT_EQ(1, getId.IsValid());
    HiTrace::End(traceId);
    getId = HiTrace::GetId();
    EXPECT_EQ(0, getId.IsValid());
    std::string remainLogMsgs = BinderTraceGetRemainLog(logTag);
    EXPECT_EQ(0, BinderTraceCheckLog(remainLogMsgs, "HITRACE_TP_CS", chainId));
    EXPECT_EQ(0, BinderTraceCheckLog(remainLogMsgs, "HITRACE_TP_SR", chainId));
    EXPECT_EQ(0, BinderTraceCheckLog(remainLogMsgs, "HITRACE_TP_SS", chainId));
    EXPECT_EQ(0, BinderTraceCheckLog(remainLogMsgs, "HITRACE_TP_CR", chainId));
}

HWTEST_F(BinderTraceTest, Sync002, TestSize.Level1)
{
    const std::string HITRACE_TP_CS_LOG =
        "\\[[a-f0-9]{1,16}, 0, 0\\] <HITRACE_TP_CS,chain=[0-9a-f]{1,16},span=[0-9a-f]{1,16},pspan=";
    const std::string HITRACE_TP_SR_LOG =
        "\\[[a-f0-9]{1,16}, [a-f0-9]{1,16}, 0\\] <HITRACE_TP_SR,chain=[0-9a-f]{1,16},span=[0-9a-f]{1,16},pspan=";
    const std::string HITRACE_TP_SS_LOG =
        "\\[[a-f0-9]{1,16}, [a-f0-9]{1,16}, 0\\] <HITRACE_TP_SS,chain=[0-9a-f]{1,16},span=[0-9a-f]{1,16},pspan=";
    const std::string HITRACE_TP_CR_LOG =
        "\\[[a-f0-9]{1,16}, 0, 0\\] <HITRACE_TP_CR,chain=[0-9a-f]{1,16},span=[0-9a-f]{1,16},pspan=";
    HiTraceId getId = HiTrace::GetId();
    EXPECT_EQ(0, getId.IsValid());
    HiTraceId traceId = HiTrace::Begin("ipc hitrace", HITRACE_FLAG_TP_INFO);
    std::string chainId = HitraceLongToString(traceId.GetChainId());
    EXPECT_NE(0UL, chainId.size());
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();

    ASSERT_TRUE(saMgr != nullptr);

    sptr<IRemoteObject> service = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    sptr<ITestService> testService = iface_cast<ITestService>(service);

    ASSERT_TRUE(testService != nullptr);
    HiLog::Info(LOG_LABEL, "Get test.service OK\n");
    std::string logTag = PrintTagLog(":BinderTraceTest_Sync002");

    if (service->IsProxyObject()) {
        HiLog::Info(LOG_LABEL, "Got Proxy node\n");
        TestServiceProxy *proxy = static_cast<TestServiceProxy *>(testService.GetRefPtr());
        int reply = 0;
        int ret = proxy->TestSyncTransaction(2019, reply);
        EXPECT_EQ(ret, NO_ERROR);
        EXPECT_EQ(reply, 9102);
    } else {
        HiLog::Info(LOG_LABEL, "Got Stub node\n");
    }

    getId = HiTrace::GetId();
    EXPECT_EQ(1, getId.IsValid());
    HiTrace::End(traceId);
    getId = HiTrace::GetId();
    EXPECT_EQ(0, getId.IsValid());
}

HWTEST_F(BinderTraceTest, Sync003, TestSize.Level1)
{
    const std::string HITRACE_TP_CS_LOG = "\\[[a-f0-9]{1,16}\\] <HITRACE_TP_CS,chain=[0-9a-f]{1,16},span=0,pspan=";
    const std::string HITRACE_TP_SR_LOG = "\\[[a-f0-9]{1,16}\\] <HITRACE_TP_SR,chain=[0-9a-f]{1,16},span=0,pspan=";
    const std::string HITRACE_TP_SS_LOG = "\\[[a-f0-9]{1,16}\\] <HITRACE_TP_SS,chain=[0-9a-f]{1,16},span=0,pspan=";
    const std::string HITRACE_TP_CR_LOG = "\\[[a-f0-9]{1,16}\\] <HITRACE_TP_CR,chain=[0-9a-f]{1,16},span=0,pspan=";
    HiTraceId getId = HiTrace::GetId();
    EXPECT_EQ(0, getId.IsValid());
    HiTraceId traceId = HiTrace::Begin("ipc hitrace", HITRACE_FLAG_TP_INFO | HITRACE_FLAG_DONOT_CREATE_SPAN);
    std::string chainId = HitraceLongToString(traceId.GetChainId());
    EXPECT_NE(0UL, chainId.size());
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saMgr != nullptr);

    sptr<IRemoteObject> service = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    sptr<ITestService> testService = iface_cast<ITestService>(service);
    ASSERT_TRUE(testService != nullptr);

    HiLog::Info(LOG_LABEL, "Get test.service OK\n");
    std::string logTag = PrintTagLog(":BinderTraceTest_Sync003");
    if (service->IsProxyObject()) {
        HiLog::Info(LOG_LABEL, "Got Proxy node\n");
        TestServiceProxy *proxy = static_cast<TestServiceProxy *>(testService.GetRefPtr());
        int reply = 0;
        int ret = proxy->TestSyncTransaction(2019, reply);
        EXPECT_EQ(ret, NO_ERROR);
        EXPECT_EQ(reply, 9102);
    } else {
        HiLog::Info(LOG_LABEL, "Got Stub node\n");
    }

    getId = HiTrace::GetId();
    EXPECT_EQ(1, getId.IsValid());
    HiTrace::End(traceId);
    getId = HiTrace::GetId();
    EXPECT_EQ(0, getId.IsValid());
}

HWTEST_F(BinderTraceTest, Async001, TestSize.Level1)
{
    HiTraceId getId = HiTrace::GetId();
    EXPECT_EQ(0, getId.IsValid());
    HiTraceId traceId = HiTrace::Begin("ipc hitrace", HITRACE_FLAG_INCLUDE_ASYNC);
    std::string chainId = HitraceLongToString(traceId.GetChainId());
    EXPECT_NE(0UL, chainId.size());
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();

    ASSERT_TRUE(saMgr != nullptr);

    sptr<IRemoteObject> service = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    sptr<ITestService> testService = iface_cast<ITestService>(service);

    ASSERT_TRUE(testService != nullptr);
    HiLog::Info(LOG_LABEL, "Get test.service OK\n");
    std::string logTag = PrintTagLog(":BinderTraceTest_Async001");

    if (service->IsProxyObject()) {
        HiLog::Info(LOG_LABEL, "Got Proxy node\n");
        TestServiceProxy *proxy = static_cast<TestServiceProxy *>(testService.GetRefPtr());
        int ret = proxy->TestAsyncTransaction(2019);
        EXPECT_EQ(ret, ERR_NONE);
    } else {
        HiLog::Info(LOG_LABEL, "Got Stub node\n");
    }

    getId = HiTrace::GetId();
    EXPECT_EQ(1, getId.IsValid());
    HiTrace::End(traceId);
    getId = HiTrace::GetId();
    EXPECT_EQ(0, getId.IsValid());
    std::string remainLogMsgs = BinderTraceGetRemainLog(logTag);
    EXPECT_EQ(0, BinderTraceCheckLog(remainLogMsgs, "HITRACE_TP_CS", chainId));
    EXPECT_EQ(0, BinderTraceCheckLog(remainLogMsgs, "HITRACE_TP_SR", chainId));
    EXPECT_EQ(0, BinderTraceCheckLog(remainLogMsgs, "HITRACE_TP_SS", chainId));
    EXPECT_EQ(0, BinderTraceCheckLog(remainLogMsgs, "HITRACE_TP_CR", chainId));
}

HWTEST_F(BinderTraceTest, Async002, TestSize.Level1)
{
    const std::string HITRACE_TP_CS_LOG =
        "\\[[a-f0-9]{1,16}, 0, 0\\] <HITRACE_TP_CS,chain=[0-9a-f]{1,16},span=[0-9a-f]{1,16},pspan=";
    const std::string HITRACE_TP_SR_LOG =
        "\\[[a-f0-9]{1,16}, [a-f0-9]{1,16}, 0\\] <HITRACE_TP_SR,chain=[0-9a-f]{1,16},span=[0-9a-f]{1,16},pspan=";
    HiTraceId getId = HiTrace::GetId();
    EXPECT_EQ(0, getId.IsValid());
    HiTraceId traceId = HiTrace::Begin("ipc hitrace", HITRACE_FLAG_TP_INFO | HITRACE_FLAG_INCLUDE_ASYNC);
    std::string chainId = HitraceLongToString(traceId.GetChainId());
    EXPECT_NE(0UL, chainId.size());
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();

    ASSERT_TRUE(saMgr != nullptr);

    sptr<IRemoteObject> service = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    sptr<ITestService> testService = iface_cast<ITestService>(service);

    ASSERT_TRUE(testService != nullptr);
    HiLog::Info(LOG_LABEL, "Get test.service OK\n");
    std::string logTag = PrintTagLog(":BinderTraceTest_Async002");

    if (service->IsProxyObject()) {
        HiLog::Info(LOG_LABEL, "Got Proxy node\n");
        TestServiceProxy *proxy = static_cast<TestServiceProxy *>(testService.GetRefPtr());
        int ret = proxy->TestAsyncTransaction(2019, 1);
        EXPECT_EQ(ret, ERR_NONE);
    } else {
        HiLog::Info(LOG_LABEL, "Got Stub node\n");
    }

    getId = HiTrace::GetId();
    EXPECT_EQ(1, getId.IsValid());
    HiTrace::End(traceId);
    getId = HiTrace::GetId();
    EXPECT_EQ(0, getId.IsValid());
}

HWTEST_F(BinderTraceTest, Async003, TestSize.Level1)
{
    const std::string HITRACE_TP_CS_LOG = "\\[[a-f0-9]{1,16}\\] <HITRACE_TP_CS,chain=[0-9a-f]{1,16},span=0,pspan=";
    const std::string HITRACE_TP_SR_LOG = "\\[[a-f0-9]{1,16}\\] <HITRACE_TP_SR,chain=[0-9a-f]{1,16},span=0,pspan=";
    HiTraceId getId = HiTrace::GetId();
    EXPECT_EQ(0, getId.IsValid());
    HiTraceId traceId = HiTrace::Begin("ipc hitrace",
        HITRACE_FLAG_TP_INFO | HITRACE_FLAG_INCLUDE_ASYNC | HITRACE_FLAG_DONOT_CREATE_SPAN);
    std::string chainId = HitraceLongToString(traceId.GetChainId());
    EXPECT_NE(0UL, chainId.size());
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();

    ASSERT_TRUE(saMgr != nullptr);

    sptr<IRemoteObject> service = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    sptr<ITestService> testService = iface_cast<ITestService>(service);

    ASSERT_TRUE(testService != nullptr);
    HiLog::Info(LOG_LABEL, "Get test.service OK\n");
    std::string logTag = PrintTagLog(":BinderTraceTest_Async003");

    if (service->IsProxyObject()) {
        HiLog::Info(LOG_LABEL, "Got Proxy node\n");
        TestServiceProxy *proxy = static_cast<TestServiceProxy *>(testService.GetRefPtr());
        int ret = proxy->TestAsyncTransaction(2019, 1);
        EXPECT_EQ(ret, ERR_NONE);
    } else {
        HiLog::Info(LOG_LABEL, "Got Stub node\n");
    }

    getId = HiTrace::GetId();
    EXPECT_EQ(1, getId.IsValid());
    HiTrace::End(traceId);
    getId = HiTrace::GetId();
    EXPECT_EQ(0, getId.IsValid());
}
