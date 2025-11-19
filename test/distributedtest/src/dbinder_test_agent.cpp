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
#include "dbinder_test_service.h"
#include "ipc_skeleton.h"
#include "distributed_agent.h"
#include "dbinder_service_test_helper.h"
#include "dbinder_log.h"
#include "dsoftbus_interface.h"

using namespace testing;
using namespace OHOS;
using namespace OHOS::DistributeSystemTest;
using namespace OHOS::HiviewDFX;

static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_TEST, "DBinderTestAgent" };

class DBinderTestAgent : public DistributedAgent {
public:
    DBinderTestAgent();
    ~DBinderTestAgent();
    virtual bool SetUp();
    virtual bool TearDown();
    virtual int OnProcessMsg(const std::string &strMsg, int len, std::string &strReturnValue, int returnValueLen);
    virtual int OnProcessCmd(const std::string &strCommand, int cmdLen, const std::string &strArgs, int argsLen,
        const std::string &strExpectValue, int expectValueLen);

private:
    std::string localUdid;
    void KillService() const;
    void RestartService() const;
};

DBinderTestAgent::DBinderTestAgent()
{
    std::string pkgName = "dbinderService";
    NodeBasicInfo nodeBasicInfo;
    if (GetLocalNodeDeviceInfo(pkgName.c_str(), &nodeBasicInfo) != 0) {
        DBINDER_LOGE(LABEL, "Get local node device info failed");
        return;
    }
    std::string networkId(nodeBasicInfo.networkId);
    localUdid = networkId;
}

DBinderTestAgent::~DBinderTestAgent() {}

bool DBinderTestAgent::SetUp()
{
    DBINDER_LOGI(LABEL, "enter SetUp");
    StartDBinderServiceTestService();
    return true;
}

bool DBinderTestAgent::TearDown()
{
    DBINDER_LOGI(LABEL, "enter TearDown");
    KillService();
    return true;
}

// from test framework
int DBinderTestAgent::OnProcessMsg(const std::string &strMsg, int len, std::string &strReturnValue,
    int returnValueLen)
{
    std::string msg = "Ask Device ID";
    if (strncmp(msg.c_str(), strMsg.c_str(), len) == 0) {
        strReturnValue = localUdid;
        returnValueLen = strlen(localUdid.c_str());
        return returnValueLen;
    } else {
        return DistributedAgent::OnProcessMsg(strMsg, len, strReturnValue, returnValueLen);
    }
}

// from test framework
int DBinderTestAgent::OnProcessCmd(const std::string &strCommand, int cmdLen, const std::string &strArgs, int argsLen,
    const std::string &strExpectValue, int expectValueLen)
{
    DBINDER_LOGI(LABEL, "enter OnProcessCmd");
    if (strCommand == "KILL") {
        DBINDER_LOGI(LABEL, "strCommand = %{public}s, strArgs = %{public}s", strCommand.c_str(), strArgs.c_str());
        KillService();
    } else if (strCommand == "RESTART") {
        DBINDER_LOGI(LABEL, "strCommand = %{public}s, strArgs = %{public}s", strCommand.c_str(), strArgs.c_str());
        RestartService();
    } else {
        return DistributedAgent::OnProcessCmd(strCommand, cmdLen, strArgs, argsLen, strExpectValue, expectValueLen);
    }

    return 0;
}

void DBinderTestAgent::KillService() const
{
    DBINDER_LOGI(LABEL, "enter KillService");
    StopDBinderServiceTestService();
}

void DBinderTestAgent::RestartService() const
{
    DBINDER_LOGI(LABEL, "enter RestartService");
    StartDBinderServiceTestService();
}

int main()
{
    // Test agent main function
    DBinderTestAgent obj;
    if (obj.SetUp()) {
        obj.Start("agent.desc");
        obj.Join();
    } else {
        DBINDER_LOGE(LABEL, "Init environment failed.");
    }
    if (obj.TearDown()) {
        return 0;
    } else {
        DBINDER_LOGE(LABEL, "Clear environment failed.");
        return -1;
    }
}
