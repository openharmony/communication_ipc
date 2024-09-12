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

#include <fcntl.h>
#include <iostream>
#include <unistd.h>

#include "ipc_skeleton.h"
#include "ipc_debug.h"
#include "ipc_payload_statistics.h"
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

int TestService::Instantiate(bool isEnableSerialInvokeFlag)
{
    ZLOGD(LABEL, "%{public}s call in", __func__);
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        ZLOGE(LABEL, "%{public}s:fail to get Registry", __func__);
        return -ENODEV;
    }

    sptr<IRemoteObject> newInstance = new TestService(isEnableSerialInvokeFlag);
    IPCObjectStub *stub = reinterpret_cast<IPCObjectStub *>(newInstance.GetRefPtr());
    stub->SetRequestSidFlag(true);

#ifdef IPCSERVERTESTEXTRA
    int result = saMgr->AddSystemAbility(IPC_EXTRA_TEST_SERVICE, newInstance);
    ZLOGD(LABEL, "%{public}s: IPC_EXTRA_TEST_SERVICE result = %{public}d", __func__, result);
#else
    int result = saMgr->AddSystemAbility(IPC_TEST_SERVICE, newInstance);
    ZLOGD(LABEL, "%{public}s: IPC_TEST_SERVICE result = %{public}d", __func__, result);
#endif

    ZLOGD(LABEL, "TestService: strong = %d", newInstance->GetSptrRefCount());
    return result;
}

TestService::TestService(bool serialInvokeFlag) : TestServiceStub(serialInvokeFlag), testFd_(INVALID_FD)
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
        sleep((uint32_t)delayTime);
    }

    std::string sid = IPCSkeleton::GetCallingSid();
    ZLOGI(LABEL, "TestServiceStub:read from client data = %{public}d, Caller sid = %{public}s", data, sid.c_str());

    return ERR_NONE;
}

int TestService::TestAsyncTransaction(int data, int timeout)
{
    ZLOGE(LABEL, "TestServiceStub:read from client data = %{public}d", data);

    if (timeout > 0) {
        sleep((uint32_t)timeout);
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

    testFd_ = open("/data/test.txt",
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
        ZLOGD(LABEL, "%s(%d): server write file success.", __func__, __LINE__);
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
    (void)length;
    (void)reply;
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

int TestService::TestAccessTokenID(int32_t ftoken_expected)
{
    (void)ftoken_expected;
    return 0;
}

int TestService::TestAccessTokenID64(uint64_t token_expected, uint64_t ftoken_expected)
{
    (void)token_expected;
    (void)ftoken_expected;
    return 0;
}

int TestService::TestMessageParcelAppend(MessageParcel &dst, MessageParcel &src)
{
    (void)dst;
    (void)src;
    return 0;
}

int TestService::TestMessageParcelAppendWithIpc(MessageParcel &dst, MessageParcel &src,
    MessageParcel &reply, bool withObject)
{
    (void)dst;
    (void)src;
    (void)reply;
    (void)withObject;
    return 0;
}

int TestService::TestFlushAsyncCalls(int count, int length)
{
    return 0;
}

int TestService::TestMultipleProcesses(int data, int &rep, int delayTime)
{
    (void)data;
    (void)rep;
    (void)delayTime;
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

    if (!IPCPayloadStatistics::GetStatisticsStatus()) {
        IPCPayloadStatistics::StartStatistics();
    }

    std::cout << " ---------------------------------------- "<< std::endl;
    std::cout << " TotalCount = " << IPCPayloadStatistics::GetTotalCount();
    std::cout << " TotalCost = " << IPCPayloadStatistics::GetTotalCost() << std::endl;
    std::vector<int32_t> pidVec = IPCPayloadStatistics::GetPids();
    for (int32_t &val : pidVec) {
        std::cout << " Pid = " << val << std::endl;
        std::cout << " PidCount = " << IPCPayloadStatistics::GetCount(val)
            << " PidCost = " << IPCPayloadStatistics::GetCost(val) << std::endl;
        std::vector<IPCInterfaceInfo> infoVec = IPCPayloadStatistics::GetDescriptorCodes(val);
        for (auto &info : infoVec) {
            std::cout << " desc = " << Str16ToStr8(info.desc) << " code = " << info.code;
            std::cout << " DescCount = " << IPCPayloadStatistics::GetDescriptorCodeCount(val, info.desc, info.code);
            IPCPayloadCost payloadCost = IPCPayloadStatistics::GetDescriptorCodeCost(val, info.desc, info.code);
            std::cout << " DescTotalCost = " << payloadCost.totalCost;
            std::cout << " DescMaxCost = " << payloadCost.maxCost;
            std::cout << " DescMinCost = " << payloadCost.minCost;
            std::cout << " DescAverCost = " << payloadCost.averCost << std::endl;
        }
    }
    std::cout << " ---------------------------------------- "<< std::endl;

    return writeCount > 0 ? ERR_NONE : ERR_TRANSACTION_FAILED;
}

std::u16string TestService::TestAshmem(sptr<Ashmem> ashmem, int32_t contentSize)
{
    (void)contentSize;
    return u"";
}

int TestService::TestNestingSend(int sendCode, int &replyCode)
{
    (void)sendCode;
    return 0;
}

int TestService::TestEnableSerialInvokeFlag()
{
    return 0;
}

int TestService::TestRegisterRemoteStub(const char *descriptor, const sptr<IRemoteObject> object)
{
    if (descriptor == nullptr || strlen(descriptor) < 1 || object == nullptr) {
        return -1;
    }
    std::lock_guard<std::mutex> lockGuard(remoteObjectsMutex_);
    remoteObjects_.emplace(descriptor, object);
    return 0;
}

int TestService::TestUnRegisterRemoteStub(const char *descriptor)
{
    if (descriptor == nullptr || strlen(descriptor) < 1) {
        return -1;
    }
    std::lock_guard<std::mutex> lockGuard(remoteObjectsMutex_);
    remoteObjects_.erase(descriptor);
    return 0;
}

sptr<IRemoteObject> TestService::TestQueryRemoteProxy(const char *descriptor)
{
    if (descriptor == nullptr || strlen(descriptor) < 1) {
        return nullptr;
    }
    auto data = remoteObjects_.find(descriptor);
    if (data != remoteObjects_.end()) {
        return data->second;
    }
    return nullptr;
}

int TestService::TestSendTooManyRequest(int data, int &reply)
{
    (void)data;
    (void)reply;
    return 0;
}
int TestService::TestMultiThreadSendRequest(int data, int &reply)
{
    (void)data;
    (void)reply;
    return 0;
}
} // namespace OHOS
