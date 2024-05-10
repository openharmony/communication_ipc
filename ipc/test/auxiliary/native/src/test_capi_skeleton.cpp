/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include <cinttypes>
#include <thread>
#include <chrono>
#include <sstream>
#include <string>
#include <fcntl.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <securec.h>
#include <unistd.h>
#include <random>
#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "ipc_kit.h"
#include "test_capi_skeleton.h"
#include "ipc_debug.h"
#include "ipc_inner_object.h"
#include "test_service_command.h"

namespace OHOS {

static constexpr int MAX_MEMORY_SIZE = 204800;
static constexpr int8_t TEST_VAL_INT8 = 121;
static constexpr int16_t TEST_VAL_INT16 = 1234;
static constexpr int32_t TEST_VAL_INT32 = 12345678;
static constexpr int64_t TEST_VAL_INT64 = 1234567890123L;
static constexpr float TEST_VAL_FLOAT = 123.456f;
static constexpr double TEST_VAL_DOUBLE = 123.456789;
static const std::string TEST_VAL_STRING = "0123456789abcdefghijklmnopqrstuvwxyz~!@#$%^&*()_+{}?/[]<>-='|~";
static constexpr uint8_t TEST_VAL_BUFFER[] = { 0xA1, 0xB2, 0xC3, 0xD4, 0xE5 };
static const std::string TEST_VAL_INTERFACE_TOKEN = "interface_token: test capi skeleton!";

static void* LocalMemAllocator(int32_t len)
{
    if (len <= 0 || len > MAX_MEMORY_SIZE) {
        return nullptr;
    }
    void *buffer = malloc(len);
    if (buffer != nullptr) {
        if (memset_s(buffer, len, 0, len) != EOK) {
            ZLOGE(NativeRemoteProxyTest::LABEL, "memset_s failed!");
        }
    }

    return buffer;
}

NativeRemoteBase::NativeRemoteBase(const sptr<ITestService> &testService)
    : testService_(testService)
{
}

NativeRemoteProxyTest::NativeRemoteProxyTest(const sptr<ITestService> &testService)
    : NativeRemoteBase(testService)
{
    if (testService_ == nullptr) {
        ZLOGE(LABEL, "test service is nullptr");
        return;
    }

    sptr<IRemoteObject> remote = testService_->TestQueryRemoteProxy(NATIVEREMOTESTUBTEST_DESCRIPTOR.c_str());
    proxy_ = CreateIPCRemoteProxy(remote);
    if (proxy_ == nullptr) {
        ZLOGE(LABEL, "CreateNativeRemoteProxy failed!");
        return;
    }
    stubCallBack_ = OH_IPCRemoteStub_Create(NATIVEREMOTESTUBCALLBACKTEST_DESCRIPTOR.c_str(),
        OnRemoteRequestStubCallBack, nullptr, this);
}

NativeRemoteProxyTest::~NativeRemoteProxyTest()
{
    if (stubCallBack_ != nullptr) {
        OH_IPCRemoteStub_Destroy(stubCallBack_);
    }
    if (proxy_ != nullptr) {
        OH_IPCRemoteProxy_Destroy(proxy_);
    }
}

int NativeRemoteProxyTest::SyncAdd()
{
    if (proxy_ == nullptr) {
        return -1;
    }
    OHIPCParcel *data = OH_IPCParcel_Create();
    if (data == nullptr) {
        return -1;
    }
    OHIPCParcel *reply = OH_IPCParcel_Create();
    if (reply == nullptr) {
        OH_IPCParcel_Destroy(data);
        return -1;
    }
    OH_IPC_MessageOption option{ OH_IPC_REQUEST_MODE_SYNC, 0 };
    int ret = OH_IPCParcel_WriteInterfaceToken(data, NATIVEREMOTESTUBTEST_DESCRIPTOR.c_str());
    if (ret != OH_IPC_SUCCESS) {
        ZLOGE(LABEL, "OH_IPCParcel_WriteInterfaceToken failed! ret:%{public}d", ret);
        OH_IPCParcel_Destroy(data);
        OH_IPCParcel_Destroy(reply);
        return -1;
    }
    int a = randomDistribution_(randomDevice_);
    int b = randomDistribution_(randomDevice_);
    OH_IPCParcel_WriteInt32(data, a);
    OH_IPCParcel_WriteInt32(data, b);
    ret = OH_IPCRemoteProxy_SendRequest(proxy_, NATIVE_TEST_CMD_SYNC_ADD, data, reply, &option);
    if (ret != OH_IPC_SUCCESS) {
        ZLOGE(LABEL, "OH_IPCRemoteProxy_SendRequest failed! ret:%{public}d", ret);
        OH_IPCParcel_Destroy(data);
        OH_IPCParcel_Destroy(reply);
        return -1;
    }
    int result = 0;
    OH_IPCParcel_ReadInt32(reply, &result);
    OH_IPCParcel_Destroy(data);
    OH_IPCParcel_Destroy(reply);
    if ((a + b) == result) {
        ZLOGD(LABEL, "SyncAdd success! %{public}d + %{public}d = %{public}d", a, b, result);
        return 0;
    }
    ZLOGE(LABEL, "SyncAdd failed! %{public}d + %{public}d = %{public}d", a, b, result);
    return -1;
}

int NativeRemoteProxyTest::ASyncAdd()
{
    if (proxy_ == nullptr) {
        return -1;
    }
    OHIPCParcel *data = OH_IPCParcel_Create();
    if (data == nullptr) {
        return -1;
    }

    OH_IPC_MessageOption option{ OH_IPC_REQUEST_MODE_ASYNC, 0 };
    if (OH_IPCParcel_WriteInterfaceToken(data, NATIVEREMOTESTUBTEST_DESCRIPTOR.c_str()) != OH_IPC_SUCCESS) {
        OH_IPCParcel_Destroy(data);
        ZLOGE(LABEL, "OH_IPCParcel_WriteInterfaceToken failed!");
        return -1;
    }
    int a = randomDistribution_(randomDevice_);
    int b = randomDistribution_(randomDevice_);
    OH_IPCParcel_WriteInt32(data, a);
    OH_IPCParcel_WriteInt32(data, b);
    OH_IPCParcel_WriteRemoteStub(data, stubCallBack_);
    int ret = OH_IPCRemoteProxy_SendRequest(proxy_, NATIVE_TEST_CMD_ASYNC_ADD, data, nullptr, &option);
    OH_IPCParcel_Destroy(data);
    if (ret != OH_IPC_SUCCESS) {
        ZLOGE(LABEL, "ipc sendRequest return=%{public}d ", ret);
        return -1;
    }
    static constexpr int TIMEOUT = 3;
    WaitForAsyncReply(TIMEOUT);
    if ((a + b) == asyncReply_) {
        ZLOGD(LABEL, "ASyncAdd success! %{public}d + %{public}d = %{public}d", a, b, asyncReply_);
        return 0;
    }
    ZLOGE(LABEL, "ASyncAdd failed! %{public}d + %{public}d = %{public}d", a, b, asyncReply_);
    return -1;
}

int NativeRemoteProxyTest::OnRemoteRequestStubCallBack(uint32_t code,
    const OHIPCParcel *data, OHIPCParcel *reply, void *userData)
{
    ZLOGD(LABEL, "start %{public}u", code);
    auto *proxyTest = reinterpret_cast<NativeRemoteProxyTest *>(userData);
    if (code != NATIVE_TEST_CMD_ASYNC_ADD || proxyTest == nullptr) {
        ZLOGE(LABEL, "check params or init failed!");
        return OH_IPC_CHECK_PARAM_ERROR;
    }

    int32_t val = 0;
    int ret = OH_IPCParcel_ReadInt32(data, &val);
    if (ret != OH_IPC_SUCCESS) {
        ZLOGE(LABEL, "OH_IPCParcel_ReadInt32 failed!");
        return ret;
    }

    switch (code) {
        case NATIVE_TEST_CMD_ASYNC_ADD: {
            proxyTest->SendAsyncReply(val);
            return OH_IPC_SUCCESS;
        }
        default:
            break;
    }
    return OH_IPC_SUCCESS;
}

int NativeRemoteProxyTest::WaitForAsyncReply(int timeout)
{
    asyncReply_ = 0;
    std::unique_lock<std::mutex> lck(mutex_);
    cv_.wait_for(lck, std::chrono::seconds(timeout), [&]() {
        return asyncReply_ != 0;
    });
    return asyncReply_;
}

void NativeRemoteProxyTest::SendAsyncReply(int &replyValue)
{
    std::unique_lock<std::mutex> lck(mutex_);
    asyncReply_ = replyValue;
    cv_.notify_all();
}

void NativeRemoteProxyTest::SendBasicDataType(OHIPCParcel *data)
{
    if (data != nullptr) {
        OH_IPCParcel_WriteInt8(data, TEST_VAL_INT8);
        OH_IPCParcel_WriteInt16(data, TEST_VAL_INT16);
        OH_IPCParcel_WriteInt32(data, TEST_VAL_INT32);
        OH_IPCParcel_WriteInt64(data, TEST_VAL_INT64);
        OH_IPCParcel_WriteFloat(data, TEST_VAL_FLOAT);
        OH_IPCParcel_WriteDouble(data, TEST_VAL_DOUBLE);
    }
}

template <typename T>
static int CheckBaseDataReply(const OHIPCParcel *data, T checkValue,
    int (*readFunc)(const OHIPCParcel *data, T *value))
{
    int ret = OH_IPC_SUCCESS;
    T value = 0;
    ret = readFunc(data, &value);
    if (value != checkValue) {
        ZLOGE(NativeRemoteProxyTest::LABEL, "CheckBaseDataReply failed! expect value:%{public}" PRId64
            ", real value:%{public}" PRId64, static_cast<int64_t>(checkValue), static_cast<int64_t>(value));
        return -1;
    }
    return 0;
}

int NativeRemoteProxyTest::TestBasicDataTypeReply(const OHIPCParcel *reply)
{
    static const double ESP = 1e-6;
    if (reply == nullptr) {
        return -1;
    }
    if (CheckBaseDataReply<int8_t>(reply, TEST_VAL_INT8, OH_IPCParcel_ReadInt8) != 0) {
        return -1;
    }
    if (CheckBaseDataReply<int16_t>(reply, TEST_VAL_INT16, OH_IPCParcel_ReadInt16) != 0) {
        return -1;
    }
    if (CheckBaseDataReply<int32_t>(reply, TEST_VAL_INT32, OH_IPCParcel_ReadInt32) != 0) {
        return -1;
    }
    if (CheckBaseDataReply<int64_t>(reply, TEST_VAL_INT64, OH_IPCParcel_ReadInt64) != 0) {
        return -1;
    }
    float valFloat = 0.0f;
    int ret = OH_IPCParcel_ReadFloat(reply, &valFloat);
    if (abs(valFloat - TEST_VAL_FLOAT) > ESP) {
        ZLOGE(LABEL, "CheckBaseDataReply failed! expect value:%{public}f, real value:%{public}f",
            TEST_VAL_FLOAT, valFloat);
        return -1;
    }

    double valDouble = 0.0;
    ret = OH_IPCParcel_ReadDouble(reply, &valDouble);
    if (abs(valDouble - TEST_VAL_DOUBLE) > ESP) {
        ZLOGE(LABEL, "CheckBaseDataReply failed! expect value:%{public}f, real value:%{public}f",
            TEST_VAL_DOUBLE, valDouble);
        return -1;
    }
    return 0;
}

int NativeRemoteProxyTest::SendAndEchoBase()
{
    if (proxy_ == nullptr) {
        return -1;
    }
    OHIPCParcel *data = OH_IPCParcel_Create();
    if (data == nullptr) {
        return -1;
    }
    OHIPCParcel *reply = OH_IPCParcel_Create();
    if (reply == nullptr) {
        OH_IPCParcel_Destroy(data);
        return -1;
    }
    OH_IPC_MessageOption option{ OH_IPC_REQUEST_MODE_SYNC, 0 };
    if (OH_IPCParcel_WriteInterfaceToken(data, NATIVEREMOTESTUBTEST_DESCRIPTOR.c_str()) != OH_IPC_SUCCESS) {
        OH_IPCParcel_Destroy(data);
        OH_IPCParcel_Destroy(reply);
        return -1;
    }

    SendBasicDataType(data);

    int ret = OH_IPCRemoteProxy_SendRequest(proxy_, NATIVE_TEST_CMD_SEND_AND_ECHO_BASE, data, reply, &option);
    if (ret != OH_IPC_SUCCESS) {
        OH_IPCParcel_Destroy(data);
        OH_IPCParcel_Destroy(reply);
        ZLOGE(LABEL, "SendAndEchoBase SendRequest ret:%{public}d", ret);
        return -1;
    }
    OH_IPCParcel_Destroy(data);
    if (TestBasicDataTypeReply(reply) != 0) {
        OH_IPCParcel_Destroy(reply);
        return -1;
    }

    OH_IPCParcel_Destroy(reply);
    return 0;
}

int NativeRemoteProxyTest::SendAndEchoString()
{
    if (proxy_ == nullptr) {
        return -1;
    }
    OHIPCParcel *data = OH_IPCParcel_Create();
    if (data == nullptr) {
        return -1;
    }
    OHIPCParcel *reply = OH_IPCParcel_Create();
    if (reply == nullptr) {
        OH_IPCParcel_Destroy(data);
        return -1;
    }
    OH_IPC_MessageOption option{ OH_IPC_REQUEST_MODE_SYNC, 0 };
    if (OH_IPCParcel_WriteInterfaceToken(data, NATIVEREMOTESTUBTEST_DESCRIPTOR.c_str()) != OH_IPC_SUCCESS) {
        OH_IPCParcel_Destroy(data);
        OH_IPCParcel_Destroy(reply);
        return -1;
    }
    if (OH_IPCParcel_WriteString(data, TEST_VAL_STRING.c_str()) != OH_IPC_SUCCESS) {
        ZLOGE(LABEL, "OH_IPCParcel_WriteString failed!");
        OH_IPCParcel_Destroy(data);
        OH_IPCParcel_Destroy(reply);
        return -1;
    }
    int ret = OH_IPCRemoteProxy_SendRequest(proxy_, NATIVE_TEST_CMD_SEND_AND_ECHO_SRING,
        data, reply, &option);
    if (ret != OH_IPC_SUCCESS) {
        ZLOGE(LABEL, "SendAndEchoString SendRequest ret:%{public}d", ret);
        OH_IPCParcel_Destroy(data);
        OH_IPCParcel_Destroy(reply);
        return -1;
    }

    const char *readStr = OH_IPCParcel_ReadString(reply);
    if (readStr == nullptr || TEST_VAL_STRING != readStr) {
        ZLOGE(LABEL, "OH_IPCParcel_ReadString failed!");
        OH_IPCParcel_Destroy(data);
        OH_IPCParcel_Destroy(reply);
        return -1;
    }
    OH_IPCParcel_Destroy(data);
    OH_IPCParcel_Destroy(reply);
    return 0;
}

int NativeRemoteProxyTest::SendAndEchoBuffer()
{
    if (proxy_ == nullptr) {
        return -1;
    }
    OHIPCParcel *data = OH_IPCParcel_Create();
    if (data == nullptr) {
        return -1;
    }
    OHIPCParcel *reply = OH_IPCParcel_Create();
    if (reply == nullptr) {
        OH_IPCParcel_Destroy(data);
        return -1;
    }
    OH_IPC_MessageOption option{ OH_IPC_REQUEST_MODE_SYNC, 0 };
    if (OH_IPCParcel_WriteInterfaceToken(data, NATIVEREMOTESTUBTEST_DESCRIPTOR.c_str()) != OH_IPC_SUCCESS) {
        OH_IPCParcel_Destroy(data);
        OH_IPCParcel_Destroy(reply);
        return -1;
    }
    OH_IPCParcel_WriteInt32(data, sizeof(TEST_VAL_BUFFER));
    OH_IPCParcel_WriteBuffer(data, TEST_VAL_BUFFER, sizeof(TEST_VAL_BUFFER));

    int ret = OH_IPCRemoteProxy_SendRequest(proxy_, NATIVE_TEST_CMD_SEND_AND_ECHO_BUFFER,
        data, reply, &option);
    if (ret != OH_IPC_SUCCESS) {
        ZLOGE(LABEL, "SendAndEchoBuffer SendRequest ret:%{public}d", ret);
        OH_IPCParcel_Destroy(data);
        OH_IPCParcel_Destroy(reply);
        return -1;
    }

    const uint8_t *readBuff = OH_IPCParcel_ReadBuffer(reply, sizeof(TEST_VAL_BUFFER));
    if (readBuff == nullptr) {
        OH_IPCParcel_Destroy(data);
        OH_IPCParcel_Destroy(reply);
        return -1;
    }
    int cmpResult = memcmp(readBuff, TEST_VAL_BUFFER, sizeof(TEST_VAL_BUFFER));
    if (cmpResult != 0) {
        ZLOGE(LABEL, "SendAndEchoBuffer check echo buffer faield!");
        OH_IPCParcel_Destroy(data);
        OH_IPCParcel_Destroy(reply);
        return -1;
    }
    OH_IPCParcel_Destroy(data);
    OH_IPCParcel_Destroy(reply);
    return 0;
}

int NativeRemoteProxyTest::SendAndEchoFileDescriptor()
{
    if (proxy_ == nullptr) {
        return -1;
    }
    OHIPCParcel *data = OH_IPCParcel_Create();
    if (data == nullptr) {
        return -1;
    }
    OHIPCParcel *reply = OH_IPCParcel_Create();
    if (reply == nullptr) {
        OH_IPCParcel_Destroy(data);
        return -1;
    }
    OH_IPC_MessageOption option{ OH_IPC_REQUEST_MODE_SYNC, 0 };
    if (OH_IPCParcel_WriteInterfaceToken(data, NATIVEREMOTESTUBTEST_DESCRIPTOR.c_str()) != OH_IPC_SUCCESS) {
        OH_IPCParcel_Destroy(data);
        OH_IPCParcel_Destroy(reply);
        return -1;
    }
    int32_t fd = open("/data/capiTest.txt", O_RDWR | O_CREAT);
    if (fd == INVALID_FD) {
        OH_IPCParcel_Destroy(data);
        OH_IPCParcel_Destroy(reply);
        ZLOGE(LABEL, "open file failed!");
        return -1;
    }
    OH_IPCParcel_WriteFileDescriptor(data, fd);
    int ret = OH_IPCRemoteProxy_SendRequest(proxy_, NATIVE_TEST_CMD_SEND_FILE_DESCRIPTOR, data, reply, &option);
    if (ret != OH_IPC_SUCCESS) {
        ZLOGE(LABEL, "SendAndEchoFileDescriptor SendRequest ret:%{public}d", ret);
        OH_IPCParcel_Destroy(data);
        OH_IPCParcel_Destroy(reply);
        close(fd);
        return -1;
    }
    close(fd);
    OH_IPCParcel_Destroy(data);
    OH_IPCParcel_Destroy(reply);
    return 0;
}

int NativeRemoteProxyTest::SendErrorCode()
{
    static std::map<int, int> vec = {
        { OH_IPC_USER_ERROR_CODE_MIN, OH_IPC_USER_ERROR_CODE_MIN },
        { OH_IPC_USER_ERROR_CODE_MAX, OH_IPC_USER_ERROR_CODE_MAX },
        { OH_IPC_USER_ERROR_CODE_MIN - 1, OH_IPC_INVALID_USER_ERROR_CODE },
        { OH_IPC_USER_ERROR_CODE_MAX + 1, OH_IPC_INVALID_USER_ERROR_CODE }
    };

    if (proxy_ == nullptr) {
        return -1;
    }
    auto func = [&, this](int val, int expect) -> int {
        OHIPCParcel *data = OH_IPCParcel_Create();
        if (data == nullptr) {
            return -1;
        }
        OHIPCParcel *reply = OH_IPCParcel_Create();
        if (reply == nullptr) {
            OH_IPCParcel_Destroy(data);
            return -1;
        }
        OH_IPC_MessageOption option{ OH_IPC_REQUEST_MODE_SYNC, 0 };
        if (OH_IPCParcel_WriteInterfaceToken(data, NATIVEREMOTESTUBTEST_DESCRIPTOR.c_str()) != OH_IPC_SUCCESS) {
            OH_IPCParcel_Destroy(data);
            OH_IPCParcel_Destroy(reply);
            return -1;
        }
        OH_IPCParcel_WriteInt32(data, val);
        int ret = OH_IPCRemoteProxy_SendRequest(this->proxy_, NATIVE_TEST_CMD_SEND_ERROR_CODE, data, reply, &option);
        OH_IPCParcel_Destroy(data);
        OH_IPCParcel_Destroy(reply);
        return (ret == expect) ? 0 : -1;
    };

    for (const auto &item : vec) {
        if (func(item.first, item.second) != 0) {
            ZLOGE(LABEL, "SendErrorCode test failed error code:%{public}d, expect error code:%{public}d",
                item.first, item.second);
            return -1;
        }
    }
    return 0;
}

int NativeRemoteProxyTest::AddParallel(bool isSync)
{
    static constexpr int PARALLEL_NUMBER = 1000;
    static constexpr int PARALLEL_ACTION_SLEEP_CNT = 20;
    int parallelNum = PARALLEL_NUMBER;
    while (parallelNum-- > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(PARALLEL_ACTION_SLEEP_CNT));
        int ret = isSync ? SyncAdd() : ASyncAdd();
        if (ret != 0) {
            ZLOGE(LABEL, "Add Parallel Test failed!");
            return ret;
        }
    }
    ZLOGD(LABEL, "Parallel test success!");
    return 0;
}

thread_local const OHIPCParcel *NativeRemoteStubTest::currentData_ = nullptr;
thread_local OHIPCParcel *NativeRemoteStubTest::currentReply_ = nullptr;

std::map<int, std::function<int(NativeRemoteStubTest *stub)>> NativeRemoteStubTest::funcMap_ = {
    { NATIVE_TEST_CMD_SYNC_ADD, [](NativeRemoteStubTest *stub) { return stub->SyncAdd(); }},
    { NATIVE_TEST_CMD_ASYNC_ADD, [](NativeRemoteStubTest *stub) { return stub->ASyncAdd(); }},
    { NATIVE_TEST_CMD_SEND_AND_ECHO_BASE, [](NativeRemoteStubTest *stub) { return stub->SendAndEchoBase(); }},
    { NATIVE_TEST_CMD_SEND_AND_ECHO_SRING, [](NativeRemoteStubTest *stub) { return stub->SendAndEchoString(); }},
    { NATIVE_TEST_CMD_SEND_AND_ECHO_BUFFER, [](NativeRemoteStubTest *stub) { return stub->SendAndEchoBuffer(); }},
    { NATIVE_TEST_CMD_SEND_FILE_DESCRIPTOR, [](NativeRemoteStubTest *stub)
        { return stub->SendAndEchoFileDescriptor(); }},
    { NATIVE_TEST_CMD_SEND_ERROR_CODE, [](NativeRemoteStubTest *stub) { return stub->SendErrorCode(); }},
};

NativeRemoteStubTest::NativeRemoteStubTest(const sptr<ITestService> &testService)
    : NativeRemoteBase(testService)
{
    stub_ = OH_IPCRemoteStub_Create(NATIVEREMOTESTUBTEST_DESCRIPTOR.c_str(),
        &NativeRemoteStubTest::OnRemoteRequest, nullptr, this);
}

NativeRemoteStubTest::~NativeRemoteStubTest()
{
    if (stub_ != nullptr) {
        OH_IPCRemoteStub_Destroy(stub_);
    }
}

int NativeRemoteStubTest::RegisterRemoteStub()
{
    ZLOGD(LABEL, "TestRegisterRemoteStubTest");
    if (testService_ == nullptr) {
        ZLOGE(LABEL, "Member variable testService_ Is a null pointer");
        return OH_IPC_INNER_ERROR;
    }
    int result = testService_->TestRegisterRemoteStub(NATIVEREMOTESTUBTEST_DESCRIPTOR.c_str(), stub_->remote);
    return result;
}

int NativeRemoteStubTest::UnRegisterRemoteStub()
{
    ZLOGD(LABEL, "TestRegisterRemoteStubTest");
    if (testService_ == nullptr) {
        ZLOGE(LABEL, "Member variable testService_ Is a null pointer");
        return OH_IPC_INNER_ERROR;
    }
    int result = testService_->TestUnRegisterRemoteStub(NATIVEREMOTESTUBTEST_DESCRIPTOR.c_str());
    return result;
}

int NativeRemoteStubTest::OnRemoteRequest(uint32_t code, const OHIPCParcel *data, OHIPCParcel *reply, void *userData)
{
    NativeRemoteStubTest *stubTest = reinterpret_cast<NativeRemoteStubTest *>(userData);
    if (stubTest == nullptr) {
        ZLOGE(LABEL, "change user data failed!");
        return OH_IPC_INNER_ERROR;
    }

    int readLen = 0;
    char *token = nullptr;
    if (OH_IPCParcel_ReadInterfaceToken(data, &token, &readLen, LocalMemAllocator) != OH_IPC_SUCCESS
        || NATIVEREMOTESTUBTEST_DESCRIPTOR != token) {
        if (token != nullptr) {
            ZLOGE(LABEL, "ReadInterfaceToken failed");
            free(token);
        }
        return OH_IPC_INNER_ERROR;
    }
    free(token);

    stubTest->currentData_ = data;
    stubTest->currentReply_ = reply;
    auto it = funcMap_.find(static_cast<int>(code));
    if (it != funcMap_.end()) {
        return it->second(stubTest);
    } else {
        ZLOGE(LABEL, "unknown code:%{public}d", code);
        return OH_IPC_INNER_ERROR;
    }
}

int NativeRemoteStubTest::SyncAdd()
{
    int32_t a = 0;
    int32_t b = 0;
    OH_IPCParcel_ReadInt32(this->currentData_, &a);
    OH_IPCParcel_ReadInt32(this->currentData_, &b);

    OH_IPCParcel_WriteInt32(this->currentReply_, a + b);
    return 0;
}

int NativeRemoteStubTest::ASyncAdd()
{
    int32_t a = 0;
    int32_t b = 0;
    OH_IPCParcel_ReadInt32(this->currentData_, &a);
    OH_IPCParcel_ReadInt32(this->currentData_, &b);
    auto proxyCallBack = OH_IPCParcel_ReadRemoteProxy(this->currentData_);
    if (proxyCallBack == nullptr) {
        return OH_IPC_PARCEL_READ_ERROR;
    }
    OHIPCParcel *dataParcel = OH_IPCParcel_Create();
    if (dataParcel == nullptr) {
        OH_IPCRemoteProxy_Destroy(proxyCallBack);
        return OH_IPC_MEM_ALLOCATOR_ERROR;
    }
    OHIPCParcel *replyParcel = OH_IPCParcel_Create();
    if (replyParcel == nullptr) {
        OH_IPCRemoteProxy_Destroy(proxyCallBack);
        OH_IPCParcel_Destroy(dataParcel);
        return OH_IPC_MEM_ALLOCATOR_ERROR;
    }
    ZLOGD(LABEL, "start create sendCallback thread!");
    std::thread th([proxyCallBack, dataParcel, replyParcel, a, b] {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        OH_IPCParcel_WriteInt32(dataParcel, a + b);
        OH_IPC_MessageOption option{ OH_IPC_REQUEST_MODE_ASYNC, 0 };
        ZLOGD(LABEL, "thread start sendCallback!");
        int ret = OH_IPCRemoteProxy_SendRequest(proxyCallBack, NATIVE_TEST_CMD_ASYNC_ADD,
            dataParcel, replyParcel, &option);
        if (ret != OH_IPC_SUCCESS) {
            ZLOGE(LABEL, "ASyncAdd SendRequest failed! ret=%{public}d", ret);
        }
        OH_IPCRemoteProxy_Destroy(proxyCallBack);
        OH_IPCParcel_Destroy(dataParcel);
        OH_IPCParcel_Destroy(replyParcel);
    });
    th.detach();
    return OH_IPC_SUCCESS;
}

template <typename T>
static int ReadAndEchoBaseType(const OHIPCParcel *data, OHIPCParcel *reply,
    int (*readFunc)(const OHIPCParcel *data, T *value), int (*writeFunc)(OHIPCParcel *reply, T value))
{
    T value = 0;
    int ret = readFunc(data, &value);
    if (ret != OH_IPC_SUCCESS) {
        return OH_IPC_PARCEL_READ_ERROR;
    }
    return writeFunc(reply, value);
}

int NativeRemoteStubTest::SendAndEchoBase()
{
    int ret = ReadAndEchoBaseType<int8_t>(this->currentData_, this->currentReply_,
        OH_IPCParcel_ReadInt8, OH_IPCParcel_WriteInt8);
    if (ret != OH_IPC_SUCCESS) {
        ZLOGE(LABEL, "Read or Write Int8 failed! ret:%{public}d", ret);
        return ret;
    }
    ret = ReadAndEchoBaseType<int16_t>(this->currentData_, this->currentReply_,
        OH_IPCParcel_ReadInt16, OH_IPCParcel_WriteInt16);
    if (ret != OH_IPC_SUCCESS) {
        ZLOGE(LABEL, "Read or Write Int16 failed! ret:%{public}d", ret);
        return ret;
    }
    ret = ReadAndEchoBaseType<int32_t>(this->currentData_, this->currentReply_,
        OH_IPCParcel_ReadInt32, OH_IPCParcel_WriteInt32);
    if (ret != OH_IPC_SUCCESS) {
        ZLOGE(LABEL, "Read or Write Int32 failed! ret:%{public}d", ret);
        return ret;
    }
    ret = ReadAndEchoBaseType<int64_t>(this->currentData_, this->currentReply_,
        OH_IPCParcel_ReadInt64, OH_IPCParcel_WriteInt64);
    if (ret != OH_IPC_SUCCESS) {
        ZLOGE(LABEL, "Read or Write Int64 failed! ret:%{public}d", ret);
        return ret;
    }
    ret = ReadAndEchoBaseType<float>(this->currentData_, this->currentReply_,
        OH_IPCParcel_ReadFloat, OH_IPCParcel_WriteFloat);
    if (ret != OH_IPC_SUCCESS) {
        ZLOGE(LABEL, "Read or Write float failed! ret:%{public}d", ret);
        return ret;
    }
    ret = ReadAndEchoBaseType<double>(this->currentData_, this->currentReply_,
        OH_IPCParcel_ReadDouble, OH_IPCParcel_WriteDouble);
    if (ret != OH_IPC_SUCCESS) {
        ZLOGE(LABEL, "Read or Write double failed! ret:%{public}d", ret);
    }
    return ret;
}

int OHOS::NativeRemoteStubTest::SendAndEchoString()
{
    const char *readString = OH_IPCParcel_ReadString(this->currentData_);
    if (readString == nullptr) {
        ZLOGE(LABEL, "OH_IPCParcel_ReadString failed!");
        return OH_IPC_PARCEL_READ_ERROR;
    }

    return OH_IPCParcel_WriteString(this->currentReply_, readString);
}

int OHOS::NativeRemoteStubTest::SendAndEchoBuffer()
{
    int32_t buffLen = 0;
    int ret = OH_IPCParcel_ReadInt32(this->currentData_, &buffLen);
    if (ret != OH_IPC_SUCCESS) {
        ZLOGE(LABEL, "SendAndEchoBuffer read buffer len failed! ret:%{public}d", ret);
        return OH_IPC_PARCEL_READ_ERROR;
    }
    const uint8_t *buffer = OH_IPCParcel_ReadBuffer(this->currentData_, buffLen);
    if (buffer == nullptr) {
        ZLOGE(LABEL, "OH_IPCParcel_ReadBuffer failed!");
        return OH_IPC_PARCEL_READ_ERROR;
    }

    return OH_IPCParcel_WriteBuffer(this->currentReply_, buffer, buffLen);
}

int OHOS::NativeRemoteStubTest::SendAndEchoFileDescriptor()
{
    int32_t fd = INVALID_FD;
    int ret = OH_IPCParcel_ReadFileDescriptor(this->currentData_, &fd);
    if (ret != OH_IPC_SUCCESS || fd == INVALID_FD) {
        ZLOGE(LABEL, "OH_IPCParcel_ReadFileDescriptor failed! ret:%{public}d", ret);
        return OH_IPC_PARCEL_READ_ERROR;
    }
    (void)write(fd, TEST_VAL_STRING.c_str(), TEST_VAL_STRING.length());
    close(fd);
    return OH_IPC_SUCCESS;
}

int NativeRemoteStubTest::SendErrorCode()
{
    int32_t valInt32 = 0;
    int ret = OH_IPCParcel_ReadInt32(this->currentData_, &valInt32);
    return ret == OH_IPC_SUCCESS ? valInt32 : OH_IPC_PARCEL_READ_ERROR;
}
}
