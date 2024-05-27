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

#ifndef OHOS_TEST_CAPI_SKELETON_H
#define OHOS_TEST_CAPI_SKELETON_H

#include "ipc_cremote_object.h"
#include "test_service_skeleton.h"

#include <random>

namespace OHOS {

enum NativeTestCommand : uint32_t {
    NATIVE_TEST_CMD_SYNC_ADD = 1,
    NATIVE_TEST_CMD_ASYNC_ADD = 2,
    NATIVE_TEST_CMD_SYNC_ADD_REPEAT = 3,
    NATIVE_TEST_CMD_ASYNC_ADD_REPEAT = 4,
    NATIVE_TEST_CMD_SEND_AND_ECHO_BASE = 5,
    NATIVE_TEST_CMD_SEND_AND_ECHO_SRING = 6,
    NATIVE_TEST_CMD_SEND_AND_ECHO_BUFFER = 7,
    NATIVE_TEST_CMD_SEND_FILE_DESCRIPTOR = 8,
    NATIVE_TEST_CMD_SEND_ERROR_CODE = 9,
    NATIVE_TEST_CMD_MAX_VALUE,
};

const std::string NATIVEREMOTESTUBTEST_DESCRIPTOR = "native.remote.stub";
const std::string NATIVEREMOTESTUBCALLBACKTEST_DESCRIPTOR = "native.remote.stubCallBack";

class NativeRemoteBase {
public:
    explicit NativeRemoteBase(const sptr<ITestService> &testService);
    virtual ~NativeRemoteBase() = default;

    virtual int SyncAdd() = 0;
    virtual int ASyncAdd() = 0;
    virtual int SendAndEchoBase() = 0;
    virtual int SendAndEchoString() = 0;
    virtual int SendAndEchoBuffer() = 0;
    virtual int SendAndEchoFileDescriptor() = 0;
    virtual int SendErrorCode() = 0;

protected:
    sptr<ITestService> testService_;
};

class NativeRemoteProxyTest : public NativeRemoteBase {
public:
    explicit NativeRemoteProxyTest(const sptr<ITestService> &testService);
    ~NativeRemoteProxyTest() override;

    int SyncAdd() override;
    int ASyncAdd() override;
    int SendAndEchoBase() override;
    int SendAndEchoString() override;
    int SendAndEchoBuffer() override;
    int SendAndEchoFileDescriptor() override;
    int SendErrorCode() override;
    int AddParallel(bool isSync);

private:
    void SendBasicDataType(OHIPCParcel *data);
    int TestBasicDataTypeReply(const OHIPCParcel *reply);
    void SendAsyncReply(int &replyValue);
    int WaitForAsyncReply(int timeout);
    static int OnRemoteRequestStubCallBack(uint32_t code, const OHIPCParcel *data,
        OHIPCParcel *reply, void *userData);

public:
    static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_TEST, "TEST_NATIVE_IPC_SKELETON" };

private:
    int asyncReply_{ 0 };
    std::mutex mutex_;
    std::condition_variable cv_;
    std::random_device randomDevice_;
    std::uniform_int_distribution<> randomDistribution_{ 1, 10000 };

    OHIPCRemoteProxy *proxy_{ nullptr };
    OHIPCRemoteStub *stubCallBack_{ nullptr };
};

class NativeRemoteStubTest : public NativeRemoteBase {
public:
    explicit NativeRemoteStubTest(const sptr<ITestService> &testService);
    ~NativeRemoteStubTest() override;

    int RegisterRemoteStub();
    int UnRegisterRemoteStub();
    static int OnRemoteRequest(uint32_t code, const OHIPCParcel *data, OHIPCParcel *reply, void *userData);

private:
    int SyncAdd() override;
    int ASyncAdd() override;
    int SendAndEchoBase() override;
    int SendAndEchoString() override;
    int SendAndEchoBuffer() override;
    int SendAndEchoFileDescriptor() override;
    int SendErrorCode() override;

private:
    [[maybe_unused]] static thread_local const OHIPCParcel *currentData_;
    [[maybe_unused]] static thread_local OHIPCParcel *currentReply_;
    OHIPCRemoteStub* stub_{ nullptr };
    static std::map<int, std::function<int(NativeRemoteStubTest *stub)>> funcMap_;
    static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_TEST, "TEST_NATIVE_IPC_SKELETON" };
};

} // OHOS

#endif // OHOS_TEST_CAPI_SKELETON_H
