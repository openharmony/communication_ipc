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

#include "dbinder_test_service.h"
#include <unistd.h>
#include <string>
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "log_tags.h"

static std::string g_dbinderTestServerName = "dbinderTestServer";

namespace OHOS {
using namespace OHOS::HiviewDFX;
int DBinderTestService::destructTimes_ = 0;
std::mutex DBinderTestService::destructTimesMutex_;

#ifndef TITLE
#define TITLE __PRETTY_FUNCTION__
#endif

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_RPC, "DbinderTest" };
#define DBINDER_LOGE(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Error(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)
#define DBINDER_LOGI(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Info(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)

static int Reverse(int x)
{
    int result = 0;
    while (x != 0) {
        result = result * 10 + x % 10;
        x = x / 10;
    }
    return result;
}

DBinderTestService::~DBinderTestService()
{
    DBINDER_LOGI("DBinderTestService finish");
    std::lock_guard<std::mutex> lockGuard(destructTimesMutex_);

    destructTimes_++;
}

int DBinderTestService::Instantiate()
{
    DBINDER_LOGI("enter %{public}s", __func__);
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        DBINDER_LOGE("%{public}s:fail to instantiate", __func__);
        return -ENODEV;
    }

    ISystemAbilityManager::SAExtraProp saExtra;
    saExtra.isDistributed = true;
#ifdef DBINDER_TEST_SECOND
    int result = saMgr->AddSystemAbility(RPC_TEST_SERVICE2, new DBinderTestService(), saExtra);
#else
    int result = saMgr->AddSystemAbility(RPC_TEST_SERVICE, new DBinderTestService(), saExtra);
#endif
    DBINDER_LOGE("%{public}s: add TestService result=%{public}d", __func__, result);

    return result;
}

int DBinderTestService::ReverseInt(int data, int &rep)
{
    DBINDER_LOGI("enter %{public}s", __func__);
    rep = Reverse(data);
    DBINDER_LOGI("%{public}s:read from client data = %{public}d", __func__, data);
    return ERR_NONE;
}

int DBinderTestService::ReverseIntDelay(int data, int &rep)
{
    DBINDER_LOGI("enter %{public}s", __func__);
    rep = Reverse(data);
    DBINDER_LOGI("%{public}s:read from client data = %{public}d", __func__, data);
    return ERR_NONE;
}

int DBinderTestService::Delay(int data, int &rep)
{
    DBINDER_LOGI("enter %{public}s", __func__);
    rep = data;
    int i = 1;
    while (i <= data) {
        sleep(1);
        DBINDER_LOGI("sleep loop : %{public}d", i);
        i++;
    }
    DBINDER_LOGE("%{public}s:read from client data = %{public}d", __func__, data);
    return ERR_NONE;
}

int DBinderTestService::PingService(std::u16string &serviceName)
{
    std::u16string localServiceName = GetDescriptor();
    if (localServiceName.compare(serviceName) != 0) {
        DBINDER_LOGE("ServiceName is not equal");
        return -1;
    }
    return ERR_NONE;
}

int DBinderTestService::TransProxyObject(int data, sptr<IRemoteObject> &transObject, int operation, int &rep,
    int &withdrawRes)
{
    DBINDER_LOGI("enter %{public}s", __func__);
    return 0;
}

int DBinderTestService::TransStubObject(int data, sptr<IRemoteObject> &transObject, int &rep, int &stubRep)
{
    DBINDER_LOGI("enter %{public}s", __func__);
    return 0;
}

int DBinderTestService::TransOversizedPkt(const std::string &dataStr, std::string &repStr)
{
    DBINDER_LOGI("enter %{public}s", __func__);
    return 0;
}

int DBinderTestService::ProxyTransRawData(int length)
{
    DBINDER_LOGI("enter %{public}s", __func__);
    return 0;
}

int DBinderTestService::StubTransRawData(int length)
{
    DBINDER_LOGI("enter %{public}s", __func__);
    return 0;
}

#ifndef CONFIG_STANDARD_SYSTEM
int DBinderTestService::GetChildId(uint64_t &rep)
{
    DBINDER_LOGI("enter %{public}s", __func__);
    return 0;
}
#endif

int DBinderTestService::FlushAsyncCommands(int count, int length)
{
    DBINDER_LOGI("enter %{public}s", __func__);
    return 0;
}

sptr<IRemoteObject> DBinderTestService::GetRemoteObject(int type)
{
    DBINDER_LOGI("DBinderTestService GetRemoteObject");
    if (type == IDBinderTestService::FIRST_OBJECT) {
        return new DBinderTestService();
    }

    if (object_ == nullptr) {
        object_ = new DBinderTestService();
        return object_;
    } else {
        sptr<IRemoteObject> node = object_;
        object_ = nullptr;
        return node;
    }
}

int DBinderTestService::GetRemoteDecTimes()
{
    std::lock_guard<std::mutex> lockGuard(destructTimesMutex_);

    DBINDER_LOGI("DBinderTestService GetDestructTimes");
    return destructTimes_;
}

void DBinderTestService::ClearRemoteDecTimes()
{
    std::lock_guard<std::mutex> lockGuard(destructTimesMutex_);

    DBINDER_LOGI("DBinderTestService ClearRemoteDecTimes");
    destructTimes_ = 0;
}
} // namespace OHOS
