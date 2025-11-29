/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <string>

#include "ipc_cparcel.h"
#include "ipc_cremote_object.h"
#include "ipc_error_code.h"
#include "ipc_inner_object.h"
#include "ipc_remote_object_internal.h"
#include "message_parcel.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
constexpr uint32_t MIN_SEND_REQUEST_CODE = 0x01;
constexpr uint32_t MAX_SEND_REQUEST_CODE = 0x00ffffff;
constexpr uint32_t TEST_CODE = 50;
constexpr uint32_t TEST_TIMEOUT = 60;
constexpr int32_t TEST_LEN = 0;
const char *TEST_DESCRIPTOR = "test_descriptor";
const std::u16string TEST_MOCK_DESCRIPTOR = u"mockProxyService";

class MockDeathRecipient : public IPCDeathRecipient {
public:
    MockDeathRecipient() : IPCDeathRecipient([](void*) {}, [](void*) {}, nullptr){};
    ~MockDeathRecipient() = default;
};

class MockIPCObjectProxy : public IPCObjectProxy {
public:
    MockIPCObjectProxy() : IPCObjectProxy(1, TEST_MOCK_DESCRIPTOR) {};
    ~MockIPCObjectProxy() {};

    MOCK_METHOD0(GetInterfaceDescriptor, std::u16string());
    MOCK_METHOD1(AddDeathRecipient, bool(const sptr<DeathRecipient> &recipient));
    MOCK_METHOD1(RemoveDeathRecipient, bool(const sptr<DeathRecipient> &recipient));
    MOCK_METHOD4(SendRequest, int(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));
    MOCK_CONST_METHOD0(IsObjectDead, bool());
};

class IPCCremoteObjectTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void IPCCremoteObjectTest::SetUpTestCase()
{
}

void IPCCremoteObjectTest::TearDownTestCase()
{
}

void IPCCremoteObjectTest::SetUp()
{
}

void IPCCremoteObjectTest::TearDown()
{
}

/**
 * @tc.name: OH_IPCRemoteStub_CreateTest001
 * @tc.desc: Verify the OH_IPCRemoteStub_Create function when descriptor is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteStub_CreateTest001, TestSize.Level1)
{
    OH_OnRemoteRequestCallback requestCallback = [](
        uint32_t, const OHIPCParcel *, OHIPCParcel *, void *) { return 0; };
    OH_OnRemoteDestroyCallback destroyCallback = [](void*) {};
    void *userData = nullptr;

    OHIPCRemoteStub *result = OH_IPCRemoteStub_Create(nullptr, requestCallback, destroyCallback, userData);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: OH_IPCRemoteStub_CreateTest002
 * @tc.desc: Verify the OH_IPCRemoteStub_Create function when requestCallback is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteStub_CreateTest002, TestSize.Level1)
{
    const char *descriptor = TEST_DESCRIPTOR;
    OH_OnRemoteDestroyCallback destroyCallback = [](void*) {};
    void *userData = nullptr;

    OHIPCRemoteStub *result = OH_IPCRemoteStub_Create(descriptor, nullptr, destroyCallback, userData);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: OH_IPCRemoteStub_CreateTest003
 * @tc.desc: Verify the OH_IPCRemoteStub_Create function when descriptor.length is 0
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteStub_CreateTest003, TestSize.Level1)
{
    const char *descriptor = "";
    OH_OnRemoteRequestCallback requestCallback = [](
        uint32_t, const OHIPCParcel *, OHIPCParcel *, void *) { return 0; };
    OH_OnRemoteDestroyCallback destroyCallback = [](void*) {};
    void *userData = nullptr;

    OHIPCRemoteStub *result = OH_IPCRemoteStub_Create(descriptor, requestCallback, destroyCallback, userData);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: OH_IPCRemoteStub_CreateTest004
 * @tc.desc: Verify the OH_IPCRemoteStub_Create function when descriptor.length is MAX_PARCEL_LEN + 1
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteStub_CreateTest004, TestSize.Level1)
{
    std::string longDescriptor(MAX_PARCEL_LEN + 1, 'a');
    OH_OnRemoteRequestCallback requestCallback = [](
        uint32_t, const OHIPCParcel *, OHIPCParcel *, void *) { return 0; };
    OH_OnRemoteDestroyCallback destroyCallback = [](void*) {};
    void *userData = nullptr;

    OHIPCRemoteStub *result = OH_IPCRemoteStub_Create(
        longDescriptor.c_str(), requestCallback, destroyCallback, userData);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: OH_IPCRemoteStub_CreateTest008
 * @tc.desc: Verify the OH_IPCRemoteStub_Create function when OH_IPCRemoteStub_Create function is normal state
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteStub_CreateTest008, TestSize.Level1)
{
    const char *descriptor = TEST_DESCRIPTOR;
    OH_OnRemoteRequestCallback requestCallback = [](
        uint32_t, const OHIPCParcel *, OHIPCParcel *, void *) { return 0; };
    OH_OnRemoteDestroyCallback destroyCallback = [](void*) {};
    void *userData = nullptr;

    OHIPCRemoteStub *result = OH_IPCRemoteStub_Create(descriptor, requestCallback, destroyCallback, userData);
    EXPECT_NE(result, nullptr);
    delete result;
}

/**
 * @tc.name: OH_IPCRemoteProxy_SendRequestTest001
 * @tc.desc: Verify the OH_IPCRemoteProxy_SendRequest function when proxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_SendRequestTest001, TestSize.Level1)
{
    uint32_t code = TEST_CODE;
    uint32_t timeout = TEST_TIMEOUT;
    OHIPCParcel data = {new MessageParcel()};
    OHIPCParcel reply = {new MessageParcel()};
    OH_IPC_MessageOption option = {OH_IPC_REQUEST_MODE_SYNC, timeout, nullptr};

    int result = OH_IPCRemoteProxy_SendRequest(nullptr, code, &data, &reply, &option);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);

    delete data.msgParcel;
    delete reply.msgParcel;
}

/**
 * @tc.name: OH_IPCRemoteProxy_SendRequestTest002
 * @tc.desc: Verify the OH_IPCRemoteProxy_SendRequest function when data is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_SendRequestTest002, TestSize.Level1)
{
    sptr<MockIPCObjectProxy> mock = sptr<MockIPCObjectProxy>::MakeSptr();
    OHIPCRemoteProxy proxy = {mock};
    uint32_t code = TEST_CODE;
    uint32_t timeout = TEST_TIMEOUT;
    OHIPCParcel *data = nullptr;
    OHIPCParcel reply = {new MessageParcel()};
    OH_IPC_MessageOption option = {OH_IPC_REQUEST_MODE_SYNC, timeout, nullptr};

    int result = OH_IPCRemoteProxy_SendRequest(&proxy, code, data, &reply, &option);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);

    delete reply.msgParcel;
}

/**
 * @tc.name: OH_IPCRemoteProxy_SendRequestTest003
 * @tc.desc: Verify the OH_IPCRemoteProxy_SendRequest function when option is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_SendRequestTest003, TestSize.Level1)
{
    sptr<MockIPCObjectProxy> mock = sptr<MockIPCObjectProxy>::MakeSptr();
    OHIPCRemoteProxy proxy = {mock};
    uint32_t code = TEST_CODE;
    uint32_t timeout = TEST_TIMEOUT;
    OHIPCParcel data = {new MessageParcel()};
    OHIPCParcel reply = {new MessageParcel()};
    OH_IPC_MessageOption option = {OH_IPC_REQUEST_MODE_SYNC, timeout, (void*)1};

    int result = OH_IPCRemoteProxy_SendRequest(&proxy, code, &data, &reply, &option);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);

    delete data.msgParcel;
    delete reply.msgParcel;
}

/**
 * @tc.name: OH_IPCRemoteProxy_SendRequestTest004
 * @tc.desc: Verify the OH_IPCRemoteProxy_SendRequest function when code out of range
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_SendRequestTest004, TestSize.Level1)
{
    sptr<MockIPCObjectProxy> mock = sptr<MockIPCObjectProxy>::MakeSptr();
    OHIPCRemoteProxy proxy = {mock};
    uint32_t code = MAX_SEND_REQUEST_CODE + 1;
    uint32_t timeout = TEST_TIMEOUT;
    OHIPCParcel data = {new MessageParcel()};
    OHIPCParcel reply = {new MessageParcel()};
    OH_IPC_MessageOption option = {OH_IPC_REQUEST_MODE_SYNC, timeout, nullptr};

    int result = OH_IPCRemoteProxy_SendRequest(&proxy, code, &data, &reply, &option);
    EXPECT_EQ(result, OH_IPC_CODE_OUT_OF_RANGE);

    code = MIN_SEND_REQUEST_CODE - 1;
    result = OH_IPCRemoteProxy_SendRequest(&proxy, code, &data, &reply, &option);
    EXPECT_EQ(result, OH_IPC_CODE_OUT_OF_RANGE);

    delete data.msgParcel;
    delete reply.msgParcel;
}

/**
 * @tc.name: OH_IPCRemoteProxy_SendRequestTest005
 * @tc.desc: Verify the OH_IPCRemoteProxy_SendRequest function when reply is valid
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_SendRequestTest005, TestSize.Level1)
{
    sptr<MockIPCObjectProxy> mock = sptr<MockIPCObjectProxy>::MakeSptr();
    OHIPCRemoteProxy proxy = {mock};
    uint32_t code = MIN_SEND_REQUEST_CODE;
    uint32_t timeout = TEST_TIMEOUT;
    OHIPCParcel data = {new MessageParcel()};
    OHIPCParcel reply = {new MessageParcel()};
    OH_IPC_MessageOption option = {OH_IPC_REQUEST_MODE_SYNC, timeout, nullptr};

    EXPECT_CALL(*mock, SendRequest(code, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(OH_IPC_SUCCESS));

    int result = OH_IPCRemoteProxy_SendRequest(&proxy, code, &data, &reply, &option);
    EXPECT_EQ(result, OH_IPC_SUCCESS);

    delete data.msgParcel;
    delete reply.msgParcel;
}

/**
 * @tc.name: OH_IPCRemoteProxy_SendRequestTest006
 * @tc.desc: Verify the OH_IPCRemoteProxy_SendRequest function when reply is invalid sync quest
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_SendRequestTest006, TestSize.Level1)
{
    sptr<MockIPCObjectProxy> mock = sptr<MockIPCObjectProxy>::MakeSptr();
    OHIPCRemoteProxy proxy = {mock};
    uint32_t code = TEST_CODE;
    uint32_t timeout = TEST_TIMEOUT;
    OHIPCParcel data = {new MessageParcel()};
    OHIPCParcel *reply = nullptr;
    OH_IPC_MessageOption option = {OH_IPC_REQUEST_MODE_SYNC, timeout, nullptr};

    int result = OH_IPCRemoteProxy_SendRequest(&proxy, code, &data, reply, &option);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);

    delete data.msgParcel;
}

/**
 * @tc.name: OH_IPCRemoteProxy_SendRequestTest007
 * @tc.desc: Verify the OH_IPCRemoteProxy_SendRequest function when reply is invalid async quest
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_SendRequestTest007, TestSize.Level1)
{
    sptr<MockIPCObjectProxy> mock = sptr<MockIPCObjectProxy>::MakeSptr();
    OHIPCRemoteProxy proxy = {mock};
    uint32_t code = TEST_CODE;
    uint32_t timeout = TEST_TIMEOUT;
    OHIPCParcel data = {new MessageParcel()};
    OHIPCParcel *reply = nullptr;
    OH_IPC_MessageOption option = {OH_IPC_REQUEST_MODE_ASYNC, timeout, nullptr};

    EXPECT_CALL(*mock, SendRequest(code, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(OH_IPC_SUCCESS));

    int result = OH_IPCRemoteProxy_SendRequest(&proxy, code, &data, reply, &option);
    EXPECT_EQ(result, OH_IPC_SUCCESS);

    delete data.msgParcel;
}

/**
 * @tc.name: OH_IPCRemoteProxy_GetInterfaceDescriptorTest001
 * @tc.desc: Verify the OH_IPCRemoteProxy_GetInterfaceDescriptor function when proxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_GetInterfaceDescriptorTest001, TestSize.Level1)
{
    char *descriptor = nullptr;
    int32_t len = TEST_LEN;
    OH_IPC_MemAllocator allocator = [](int32_t len) { return std::malloc(len); };

    int result = OH_IPCRemoteProxy_GetInterfaceDescriptor(nullptr, &descriptor, &len, allocator);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);
}

/**
 * @tc.name: OH_IPCRemoteProxy_GetInterfaceDescriptorTest002
 * @tc.desc: Verify the OH_IPCRemoteProxy_GetInterfaceDescriptor function when descriptor is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_GetInterfaceDescriptorTest002, TestSize.Level1)
{
    sptr<MockIPCObjectProxy> mock = sptr<MockIPCObjectProxy>::MakeSptr();
    OHIPCRemoteProxy proxy = {mock};
    char **descriptor = nullptr;
    int32_t len = TEST_LEN;
    OH_IPC_MemAllocator allocator = [](int32_t len) { return std::malloc(len); };

    int result = OH_IPCRemoteProxy_GetInterfaceDescriptor(&proxy, descriptor, &len, allocator);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);
}

/**
 * @tc.name: OH_IPCRemoteProxy_GetInterfaceDescriptorTest003
 * @tc.desc: Verify the OH_IPCRemoteProxy_GetInterfaceDescriptor function when len is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_GetInterfaceDescriptorTest003, TestSize.Level1)
{
    sptr<MockIPCObjectProxy> mock = sptr<MockIPCObjectProxy>::MakeSptr();
    OHIPCRemoteProxy proxy = {mock};
    char *descriptor = nullptr;
    int32_t *len = nullptr;
    OH_IPC_MemAllocator allocator = [](int32_t len) { return std::malloc(len); };

    int result = OH_IPCRemoteProxy_GetInterfaceDescriptor(&proxy, &descriptor, len, allocator);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);
}

/**
 * @tc.name: OH_IPCRemoteProxy_GetInterfaceDescriptorTest004
 * @tc.desc: Verify the OH_IPCRemoteProxy_GetInterfaceDescriptor function when allocator is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_GetInterfaceDescriptorTest004, TestSize.Level1)
{
    sptr<MockIPCObjectProxy> mock = sptr<MockIPCObjectProxy>::MakeSptr();
    OHIPCRemoteProxy proxy = {mock};
    char *descriptor = nullptr;
    int32_t len = TEST_LEN;
    OH_IPC_MemAllocator allocator = nullptr;

    int result = OH_IPCRemoteProxy_GetInterfaceDescriptor(&proxy, &descriptor, &len, allocator);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);
}

/**
 * @tc.name: OH_IPCRemoteProxy_GetInterfaceDescriptorTest005
 * @tc.desc: Verify the OH_IPCRemoteProxy_GetInterfaceDescriptor function when is normal state
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_GetInterfaceDescriptorTest005, TestSize.Level1)
{
    sptr<MockIPCObjectProxy> mock = sptr<MockIPCObjectProxy>::MakeSptr();
    OHIPCRemoteProxy proxy = {mock};
    std::u16string testDesc = u"test";
    EXPECT_CALL(*mock, GetInterfaceDescriptor()).WillOnce(testing::Return(testDesc));

    char *descriptor = nullptr;
    int32_t len = TEST_LEN;
    OH_IPC_MemAllocator allocator = [](int32_t size) { return std::malloc(size); };

    int result = OH_IPCRemoteProxy_GetInterfaceDescriptor(&proxy, &descriptor, &len, allocator);
    EXPECT_EQ(result, OH_IPC_SUCCESS);

    std::string expected = std::string(testDesc.begin(), testDesc.end());
    EXPECT_EQ(std::string(descriptor), expected);
    EXPECT_EQ(len, static_cast<int>(expected.length()) + 1);

    std::free(descriptor);
}

/**
 * @tc.name: OH_IPCDeathRecipient_CreateTest001
 * @tc.desc: Verify the OH_IPCDeathRecipient_Create function when deathRecipientCallback is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCDeathRecipient_CreateTest001, TestSize.Level1)
{
    OH_OnDeathRecipientDestroyCallback destroyCallback = [](void*) {};
    void *userData = nullptr;

    OHIPCDeathRecipient* result = OH_IPCDeathRecipient_Create(nullptr, destroyCallback, userData);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: OH_IPCDeathRecipient_CreateTest002
 * @tc.desc: Verify the OH_IPCDeathRecipient_Create function when OH_IPCDeathRecipient_Create function is narmal state
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCDeathRecipient_CreateTest002, TestSize.Level1)
{
    OH_OnDeathRecipientCallback deathRecipientCallback = [](void*) {};
    OH_OnDeathRecipientDestroyCallback destroyCallback = [](void*) {};
    void *userData = nullptr;

    OHIPCDeathRecipient* result = OH_IPCDeathRecipient_Create(deathRecipientCallback, destroyCallback, userData);
    EXPECT_NE(result, nullptr);
    EXPECT_NE(result->recipient, nullptr);

    delete result;
}

/**
 * @tc.name: OH_IPCRemoteProxy_AddDeathRecipientTest001
 * @tc.desc: Verify the OH_IPCRemoteProxy_AddDeathRecipient function when proxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_AddDeathRecipientTest001, TestSize.Level1)
{
    OHIPCDeathRecipient recipient;

    int result = OH_IPCRemoteProxy_AddDeathRecipient(nullptr, &recipient);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);
}

/**
 * @tc.name: OH_IPCRemoteProxy_AddDeathRecipientTest002
 * @tc.desc: Verify the OH_IPCRemoteProxy_AddDeathRecipient function when recipient is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_AddDeathRecipientTest002, TestSize.Level1)
{
    sptr<MockIPCObjectProxy> mock = sptr<MockIPCObjectProxy>::MakeSptr();
    OHIPCRemoteProxy proxy = {mock};

    int result = OH_IPCRemoteProxy_AddDeathRecipient(&proxy, nullptr);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);
}

/**
 * @tc.name: OH_IPCRemoteProxy_AddDeathRecipientTest003
 * @tc.desc: Verify the OH_IPCRemoteProxy_AddDeathRecipient function when recipient->recipient is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_AddDeathRecipientTest003, TestSize.Level1)
{
    sptr<MockIPCObjectProxy> mock = sptr<MockIPCObjectProxy>::MakeSptr();
    OHIPCRemoteProxy proxy = {mock};
    OHIPCDeathRecipient recipient;
    recipient.recipient = sptr<MockDeathRecipient>(nullptr);

    int result = OH_IPCRemoteProxy_AddDeathRecipient(&proxy, &recipient);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);
}

/**
 * @tc.name: OH_IPCRemoteProxy_AddDeathRecipientTest004
 * @tc.desc: Verify the OH_IPCRemoteProxy_AddDeathRecipient function when AddDeathRecipient is return true
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_AddDeathRecipientTest004, TestSize.Level1)
{
    sptr<MockIPCObjectProxy> mock = sptr<MockIPCObjectProxy>::MakeSptr();
    OHIPCRemoteProxy proxy = {mock};
    sptr<MockDeathRecipient> mockRecipient = sptr<MockDeathRecipient>::MakeSptr();
    OHIPCDeathRecipient recipient = {mockRecipient};

    EXPECT_CALL(*mock, AddDeathRecipient(testing::_)).WillOnce(testing::Return(true));

    int result = OH_IPCRemoteProxy_AddDeathRecipient(&proxy, &recipient);
    EXPECT_EQ(result, OH_IPC_SUCCESS);
}

/**
 * @tc.name: OH_IPCRemoteProxy_AddDeathRecipientTest005
 * @tc.desc: Verify the OH_IPCRemoteProxy_AddDeathRecipient function when AddDeathRecipient is return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_AddDeathRecipientTest005, TestSize.Level1)
{
    sptr<MockIPCObjectProxy> mock = sptr<MockIPCObjectProxy>::MakeSptr();
    OHIPCRemoteProxy proxy = {mock};
    sptr<MockDeathRecipient> mockRecipient = sptr<MockDeathRecipient>::MakeSptr();
    OHIPCDeathRecipient recipient = {mockRecipient};

    EXPECT_CALL(*mock, AddDeathRecipient(testing::_)).WillOnce(testing::Return(false));

    int result = OH_IPCRemoteProxy_AddDeathRecipient(&proxy, &recipient);
    EXPECT_EQ(result, OH_IPC_INNER_ERROR);
}

/**
 * @tc.name: OH_IPCRemoteProxy_RemoveDeathRecipientTest001
 * @tc.desc: Verify the OH_IPCRemoteProxy_RemoveDeathRecipient function when proxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_RemoveDeathRecipientTest001, TestSize.Level1)
{
    sptr<MockDeathRecipient> mockRecipient = sptr<MockDeathRecipient>::MakeSptr();
    OHIPCDeathRecipient recipient = {mockRecipient};

    int result = OH_IPCRemoteProxy_RemoveDeathRecipient(nullptr, &recipient);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);
}

/**
 * @tc.name: OH_IPCRemoteProxy_RemoveDeathRecipientTest002
 * @tc.desc: Verify the OH_IPCRemoteProxy_RemoveDeathRecipient function when recipient is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_RemoveDeathRecipientTest002, TestSize.Level1)
{
    sptr<MockIPCObjectProxy> mock = sptr<MockIPCObjectProxy>::MakeSptr();
    OHIPCRemoteProxy proxy = {mock};

    int result = OH_IPCRemoteProxy_RemoveDeathRecipient(&proxy, nullptr);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);
}

/**
 * @tc.name: OH_IPCRemoteProxy_RemoveDeathRecipientTest003
 * @tc.desc: Verify the OH_IPCRemoteProxy_RemoveDeathRecipient function when recipient->recipient is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_RemoveDeathRecipientTest003, TestSize.Level1)
{
    sptr<MockIPCObjectProxy> mock = sptr<MockIPCObjectProxy>::MakeSptr();
    OHIPCRemoteProxy proxy = {mock};
    OHIPCDeathRecipient recipient;
    recipient.recipient = sptr<MockDeathRecipient>(nullptr);

    int result = OH_IPCRemoteProxy_RemoveDeathRecipient(&proxy, &recipient);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);
}

/**
 * @tc.name: OH_IPCRemoteProxy_RemoveDeathRecipientTest004
 * @tc.desc: Verify the OH_IPCRemoteProxy_RemoveDeathRecipient function when RemoveDeathRecipient return true
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_RemoveDeathRecipientTest004, TestSize.Level1)
{
    sptr<MockIPCObjectProxy> mock = sptr<MockIPCObjectProxy>::MakeSptr();
    OHIPCRemoteProxy proxy = {mock};
    sptr<MockDeathRecipient> mockRecipient = sptr<MockDeathRecipient>::MakeSptr();
    OHIPCDeathRecipient recipient = {mockRecipient};

    EXPECT_CALL(*mock, RemoveDeathRecipient(testing::_))
        .WillOnce(testing::Return(true));

    int result = OH_IPCRemoteProxy_RemoveDeathRecipient(&proxy, &recipient);
    EXPECT_EQ(result, OH_IPC_SUCCESS);
}

/**
 * @tc.name: OH_IPCRemoteProxy_RemoveDeathRecipientTest005
 * @tc.desc: Verify the OH_IPCRemoteProxy_RemoveDeathRecipient function when RemoveDeathRecipient return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_RemoveDeathRecipientTest005, TestSize.Level1)
{
    sptr<MockIPCObjectProxy> mock = sptr<MockIPCObjectProxy>::MakeSptr();
    OHIPCRemoteProxy proxy = {mock};
    sptr<MockDeathRecipient> mockRecipient = sptr<MockDeathRecipient>::MakeSptr();
    OHIPCDeathRecipient recipient = {mockRecipient};

    EXPECT_CALL(*mock, RemoveDeathRecipient(testing::_)).WillOnce(testing::Return(false));

    int result = OH_IPCRemoteProxy_RemoveDeathRecipient(&proxy, &recipient);
    EXPECT_EQ(result, OH_IPC_INNER_ERROR);
}

/**
 * @tc.name: OH_IPCRemoteProxy_IsRemoteDeadTest001
 * @tc.desc: Verify the OH_IPCRemoteProxy_IsRemoteDead function when proxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_IsRemoteDeadTest001, TestSize.Level1)
{
    const OHIPCRemoteProxy *proxy = nullptr;
    int result = OH_IPCRemoteProxy_IsRemoteDead(proxy);
    EXPECT_EQ(result, 1);
}

/**
 * @tc.name: OH_IPCRemoteProxy_IsRemoteDeadTest002
 * @tc.desc: Verify the OH_IPCRemoteProxy_IsRemoteDead function when proxy.remote is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_IsRemoteDeadTest002, TestSize.Level1)
{
    OHIPCRemoteProxy proxy;
    proxy.remote = nullptr;
    int result = OH_IPCRemoteProxy_IsRemoteDead(&proxy);
    EXPECT_EQ(result, 1);
}

/**
 * @tc.name: OH_IPCRemoteProxy_IsRemoteDeadTest003
 * @tc.desc: Verify the OH_IPCRemoteProxy_IsRemoteDead function when result return 1
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_IsRemoteDeadTest003, TestSize.Level1)
{
    sptr<MockIPCObjectProxy> mock = sptr<MockIPCObjectProxy>::MakeSptr();
    OHIPCRemoteProxy proxy = {mock};

    EXPECT_CALL(*mock, IsObjectDead()).WillOnce(testing::Return(true));

    int result = OH_IPCRemoteProxy_IsRemoteDead(&proxy);
    EXPECT_EQ(result, 1);
}

/**
 * @tc.name: OH_IPCRemoteProxy_IsRemoteDeadTest004
 * @tc.desc: Verify the OH_IPCRemoteProxy_IsRemoteDead function when result return 0
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_IsRemoteDeadTest004, TestSize.Level1)
{
    sptr<MockIPCObjectProxy> mock = sptr<MockIPCObjectProxy>::MakeSptr();
    OHIPCRemoteProxy proxy = {mock};

    EXPECT_CALL(*mock, IsObjectDead()).WillOnce(testing::Return(false));

    int result = OH_IPCRemoteProxy_IsRemoteDead(&proxy);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: OH_IPCRemoteProxy_SendRequestTest008
 * @tc.desc: Verify the OH_IPCRemoteProxy_SendRequest function
 * when SendRequest function return OH_IPC_USER_ERROR_CODE_MIN
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_SendRequestTest008, TestSize.Level1)
{
    sptr<MockIPCObjectProxy> mock = sptr<MockIPCObjectProxy>::MakeSptr();
    OHIPCRemoteProxy proxy = {mock};
    OHIPCParcel data = {new MessageParcel()};
    OHIPCParcel *reply = nullptr;
    OH_IPC_MessageOption option = {OH_IPC_REQUEST_MODE_ASYNC, TEST_TIMEOUT, nullptr};

    EXPECT_CALL(*mock, SendRequest(TEST_CODE, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(OH_IPC_USER_ERROR_CODE_MIN));

    int result = OH_IPCRemoteProxy_SendRequest(&proxy, TEST_CODE, &data, reply, &option);
    EXPECT_EQ(result, OH_IPC_USER_ERROR_CODE_MIN);
    delete data.msgParcel;
}

/**
 * @tc.name: OH_IPCRemoteProxy_SendRequestTest009
 * @tc.desc: Verify the OH_IPCRemoteProxy_SendRequest function
 * when SendRequest function return OH_IPC_USER_ERROR_CODE_MAX
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_SendRequestTest009, TestSize.Level1)
{
    sptr<MockIPCObjectProxy> mock = sptr<MockIPCObjectProxy>::MakeSptr();
    OHIPCRemoteProxy proxy = {mock};
    OHIPCParcel data = {new MessageParcel()};
    OHIPCParcel *reply = nullptr;
    OH_IPC_MessageOption option = {OH_IPC_REQUEST_MODE_ASYNC, TEST_TIMEOUT, nullptr};

    EXPECT_CALL(*mock, SendRequest(TEST_CODE, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(OH_IPC_USER_ERROR_CODE_MAX));

    int result = OH_IPCRemoteProxy_SendRequest(&proxy, TEST_CODE, &data, reply, &option);
    EXPECT_EQ(result, OH_IPC_USER_ERROR_CODE_MAX);
    delete data.msgParcel;
}

/**
 * @tc.name: OH_IPCRemoteProxy_SendRequestTest010
 * @tc.desc: Verify the OH_IPCRemoteProxy_SendRequest function when SendRequest function return OH_IPC_ERROR_CODE_BASE
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_SendRequestTest010, TestSize.Level1)
{
    sptr<MockIPCObjectProxy> mock = sptr<MockIPCObjectProxy>::MakeSptr();
    OHIPCRemoteProxy proxy = {mock};
    OHIPCParcel data = {new MessageParcel()};
    OHIPCParcel *reply = nullptr;
    OH_IPC_MessageOption option = {OH_IPC_REQUEST_MODE_ASYNC, TEST_TIMEOUT, nullptr};

    EXPECT_CALL(*mock, SendRequest(TEST_CODE, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(OH_IPC_ERROR_CODE_BASE));

    int result = OH_IPCRemoteProxy_SendRequest(&proxy, TEST_CODE, &data, reply, &option);
    EXPECT_EQ(result, OH_IPC_ERROR_CODE_BASE);
    delete data.msgParcel;
}

/**
 * @tc.name: OH_IPCRemoteProxy_SendRequestTest011
 * @tc.desc: Verify the OH_IPCRemoteProxy_SendRequest function when SendRequest function return OH_IPC_INNER_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_SendRequestTest011, TestSize.Level1)
{
    sptr<MockIPCObjectProxy> mock = sptr<MockIPCObjectProxy>::MakeSptr();
    OHIPCRemoteProxy proxy = {mock};
    OHIPCParcel data = {new MessageParcel()};
    OHIPCParcel *reply = nullptr;
    OH_IPC_MessageOption option = {OH_IPC_REQUEST_MODE_ASYNC, TEST_TIMEOUT, nullptr};

    EXPECT_CALL(*mock, SendRequest(TEST_CODE, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(OH_IPC_INNER_ERROR));

    int result = OH_IPCRemoteProxy_SendRequest(&proxy, TEST_CODE, &data, reply, &option);
    EXPECT_EQ(result, OH_IPC_INNER_ERROR);
    delete data.msgParcel;
}
/**
 * @tc.name: OH_IPCRemoteProxy_SendRequestTest012
 * @tc.desc: Verify the OH_IPCRemoteProxy_SendRequest function
 * when SendRequest function return OH_IPC_ERROR_CODE_BASE - 1
 * @tc.type: FUNC
 */
HWTEST_F(IPCCremoteObjectTest, OH_IPCRemoteProxy_SendRequestTest012, TestSize.Level1)
{
    sptr<MockIPCObjectProxy> mock = sptr<MockIPCObjectProxy>::MakeSptr();
    OHIPCRemoteProxy proxy = {mock};
    OHIPCParcel data = {new MessageParcel()};
    OHIPCParcel *reply = nullptr;
    OH_IPC_MessageOption option = {OH_IPC_REQUEST_MODE_ASYNC, TEST_TIMEOUT, nullptr};

    EXPECT_CALL(*mock, SendRequest(TEST_CODE, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(OH_IPC_ERROR_CODE_BASE - 1));

    int result = OH_IPCRemoteProxy_SendRequest(&proxy, TEST_CODE, &data, reply, &option);
    EXPECT_EQ(result, OH_IPC_INNER_ERROR);
    delete data.msgParcel;
}
} // namespace OHOS