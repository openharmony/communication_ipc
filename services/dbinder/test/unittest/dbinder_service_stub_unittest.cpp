/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "ipc_types.h"
#include "iremote_object.h"
#include "log_tags.h"
#include "message_parcel.h"
#include "rpc_log.h"
#include "gtest/gtest.h"
#include <iostream>

#define private public
#define protected public
#include "dbinder_service.h"
#include "dbinder_service_stub.h"
#undef protected
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HiviewDFX;

namespace {
    constexpr binder_uintptr_t BINDER_OBJECT = 11;
    constexpr uint32_t PROCESS_PROTO_CODE = 11;
    constexpr uint32_t SESSION_TYPE_UNKNOWN = 99;
    constexpr int32_t UNKNOWN_TRANSACTION_CODE = 999;
}

typedef unsigned long long binder_uintptr_t;
class DBinderServiceStubUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DBinderServiceStubUnitTest::SetUp()
{}

void DBinderServiceStubUnitTest::TearDown()
{}

void DBinderServiceStubUnitTest::SetUpTestCase()
{}

void DBinderServiceStubUnitTest::TearDownTestCase()
{}

/**
 * @tc.name: DBinderServiceStub001
 * @tc.desc: Verify the DBinderServiceStub function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, DBinderServiceStub001, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    int32_t num = dBinderServiceStub.GetObjectRefCount();
    EXPECT_NE(num, 0);
}

/**
 * @tc.name: DBinderServiceStub002
 * @tc.desc: Verify the DBinderServiceStub function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, DBinderServiceStub002, TestSize.Level1)
{
    const std::string service = "";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    int32_t num = dBinderServiceStub.GetObjectRefCount();
    EXPECT_NE(num, 0);
}

/**
 * @tc.name: DBinderServiceStub003
 * @tc.desc: Verify the DBinderServiceStub function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, DBinderServiceStub003, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    int32_t num = dBinderServiceStub.GetObjectRefCount();
    EXPECT_NE(num, 0);
}

/**
 * @tc.name: DBinderServiceStub004
 * @tc.desc: Verify the DBinderServiceStub function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, DBinderServiceStub004, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = UINT_MAX;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    int32_t num = dBinderServiceStub.GetObjectRefCount();
    EXPECT_NE(num, 0);
}


/**
 * @tc.name: GetServiceName001
 * @tc.desc: Verify the GetServiceName function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, GetServiceName001, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    std::string ret = dBinderServiceStub.GetServiceName();
    EXPECT_EQ(ret, "serviceTest");
}

/**
 * @tc.name: GetServiceName002
 * @tc.desc: Verify the GetServiceName function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, GetServiceName002, TestSize.Level1)
{
    const std::string service;
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    std::string ret = dBinderServiceStub.GetServiceName();
    EXPECT_EQ(ret, "");
}

/**
 * @tc.name: GetDeviceID001
 * @tc.desc: Verify the GetDeviceID function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, GetDeviceID001, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    std::string ret = dBinderServiceStub.GetDeviceID();
    EXPECT_EQ(ret, "deviceTest");
}

/**
 * @tc.name: GetDeviceID002
 * @tc.desc: Verify the GetDeviceID function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, GetDeviceID002, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device;
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    std::string ret = dBinderServiceStub.GetDeviceID();
    EXPECT_EQ(ret, "");
}

/**
 * @tc.name: GetBinderObject001
 * @tc.desc: Verify the GetBinderObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, GetBinderObject001, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    binder_uintptr_t ret = dBinderServiceStub.GetBinderObject();
    EXPECT_EQ(ret, BINDER_OBJECT);
}

/**
 * @tc.name: GetBinderObject002
 * @tc.desc: Verify the GetBinderObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, GetBinderObject002, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = UINT_MAX;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    binder_uintptr_t ret = dBinderServiceStub.GetBinderObject();
    EXPECT_EQ(ret, UINT_MAX);
}

/**
 * @tc.name: ProcessProto001
 * @tc.desc: Verify the ProcessProto function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, ProcessProto001, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    uint32_t code = PROCESS_PROTO_CODE;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = dBinderServiceStub.ProcessProto(code, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
}

/**
 * @tc.name: ProcessProto002
 * @tc.desc: Verify the ProcessProto function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, ProcessProto002, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    binder_uintptr_t key = reinterpret_cast<binder_uintptr_t>(&dBinderServiceStub);
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    EXPECT_TRUE(sessionInfo != nullptr);
    dBinderService->sessionObject_[key] = sessionInfo;
    uint32_t code = PROCESS_PROTO_CODE;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = dBinderServiceStub.ProcessProto(code, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
}

/**
 * @tc.name: ProcessProto003
 * @tc.desc: Verify the ProcessProto function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, ProcessProto003, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    uint32_t code = PROCESS_PROTO_CODE;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = dBinderServiceStub.ProcessProto(code, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
}

/**
 * @tc.name: ProcessProto004
 * @tc.desc: Verify the ProcessProto function with unknown session type
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, ProcessProto004, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    uint32_t code = PROCESS_PROTO_CODE;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    binder_uintptr_t key = reinterpret_cast<binder_uintptr_t>(&dBinderServiceStub);
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    EXPECT_TRUE(sessionInfo != nullptr);
    sessionInfo->type = SESSION_TYPE_UNKNOWN;
    dBinderService->sessionObject_[key] = sessionInfo;

    int32_t ret = dBinderServiceStub.ProcessProto(code, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
}

/**
 * @tc.name: ProcessProto005
 * @tc.desc: Verify the ProcessProto function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, ProcessProto005, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    uint32_t code = UINT_MAX;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = dBinderServiceStub.ProcessProto(code, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
}

/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: Verify the OnRemoteRequest function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, OnRemoteRequest001, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    uint32_t code = GET_PROTO_INFO;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = dBinderServiceStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
}

/**
 * @tc.name: OnRemoteRequest002
 * @tc.desc: Verify the OnRemoteRequest function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, OnRemoteRequest002, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    uint32_t code = DBINDER_OBITUARY_TRANSACTION;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = dBinderServiceStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_INVALID_DATA_ERR);
}

/**
 * @tc.name: OnRemoteRequest003
 * @tc.desc: Verify the OnRemoteRequest function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, OnRemoteRequest003, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    uint32_t code = PROCESS_PROTO_CODE;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = dBinderServiceStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: ProcessDeathRecipient001
 * @tc.desc: Verify the ProcessDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, ProcessDeathRecipient001, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    MessageParcel data;
    data.WriteInt32(IRemoteObject::DeathRecipient::ADD_DEATH_RECIPIENT);
    int32_t ret = dBinderServiceStub.ProcessDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_INVALID_DATA_ERR);
}

/**
 * @tc.name: ProcessDeathRecipient002
 * @tc.desc: Verify the ProcessDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, ProcessDeathRecipient002, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    MessageParcel data;
    data.WriteInt32(IRemoteObject::DeathRecipient::REMOVE_DEATH_RECIPIENT);
    int32_t ret = dBinderServiceStub.ProcessDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_REMOVE_DEATH_ERR);
}

/**
 * @tc.name: ProcessDeathRecipient003
 * @tc.desc: Verify the ProcessDeathRecipient function with unknown type
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, ProcessDeathRecipient003, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    MessageParcel data;
    data.WriteInt32(UNKNOWN_TRANSACTION_CODE);

    int32_t ret = dBinderServiceStub.ProcessDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: ProcessDeathRecipient004
 * @tc.desc: Verify the ProcessDeathRecipient function with unknown type
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, ProcessDeathRecipient004, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    MessageParcel data;
    data.WriteString("");

    int32_t ret = dBinderServiceStub.ProcessDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_INVALID_DATA_ERR);
}

/**
 * @tc.name: AddDbinderDeathRecipient001
 * @tc.desc: Verify the AddDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, AddDbinderDeathRecipient001, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    MessageParcel data;
    int32_t ret = dBinderServiceStub.AddDbinderDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_INVALID_DATA_ERR);
}

/**
 * @tc.name: AddDbinderDeathRecipient002
 * @tc.desc: Verify the AddDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, AddDbinderDeathRecipient002, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    sptr<IPCObjectStub> callbackStub = new (std::nothrow) IPCObjectStub(u"testStub");
    EXPECT_TRUE(callbackStub != nullptr);
    MessageParcel data;
    data.WriteRemoteObject(callbackStub);
    data.WriteString("");
    int32_t ret = dBinderServiceStub.AddDbinderDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_ADD_DEATH_ERR);
}

/**
 * @tc.name: AddDbinderDeathRecipient003
 * @tc.desc: Verify the AddDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, AddDbinderDeathRecipient003, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    sptr<IPCObjectStub> callbackStub = new (std::nothrow) IPCObjectStub(u"testStub");
    EXPECT_TRUE(callbackStub != nullptr);
    MessageParcel data;
    data.WriteRemoteObject(callbackStub);
    data.WriteString("test");
    int32_t ret = dBinderServiceStub.AddDbinderDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_ADD_DEATH_ERR);
}

/**
 * @tc.name: AddDbinderDeathRecipient004
 * @tc.desc: Verify the AddDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, AddDbinderDeathRecipient004, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    sptr<IPCObjectProxy> callbackProxy = new (std::nothrow) IPCObjectProxy(0);
    EXPECT_TRUE(callbackProxy != nullptr);
    MessageParcel data;
    data.WriteRemoteObject(callbackProxy);
    data.WriteString("test");
    int32_t ret = dBinderServiceStub.AddDbinderDeathRecipient(data);
    EXPECT_EQ(ret, ERR_NONE);
}

/**
 * @tc.name: AddDbinderDeathRecipient005
 * @tc.desc: Verify the AddDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, AddDbinderDeathRecipient005, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    sptr<IPCObjectProxy> callbackProxy = new (std::nothrow) IPCObjectProxy(0);
    EXPECT_TRUE(callbackProxy != nullptr);
    MessageParcel data;
    data.WriteRemoteObject(callbackProxy);
    data.WriteString("");
    int32_t ret = dBinderServiceStub.AddDbinderDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_ADD_DEATH_ERR);
}

/**
 * @tc.name: RemoveDbinderDeathRecipient001
 * @tc.desc: Verify the RemoveDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, RemoveDbinderDeathRecipient001, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    MessageParcel data;
    int32_t ret = dBinderServiceStub.RemoveDbinderDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_REMOVE_DEATH_ERR);
}

/**
 * @tc.name: RemoveDbinderDeathRecipient002
 * @tc.desc: Verify the RemoveDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, RemoveDbinderDeathRecipient002, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    sptr<IPCObjectProxy> callbackProxy = new (std::nothrow) IPCObjectProxy(0);
    EXPECT_TRUE(callbackProxy != nullptr);
    MessageParcel data;
    data.WriteRemoteObject(callbackProxy);
    data.WriteString("test");
    int32_t ret = dBinderServiceStub.RemoveDbinderDeathRecipient(data);
    EXPECT_EQ(ret, ERR_NONE);
}

/**
 * @tc.name: RemoveDbinderDeathRecipient003
 * @tc.desc: Verify the RemoveDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, RemoveDbinderDeathRecipient003, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    sptr<IPCObjectProxy> callbackProxy = new (std::nothrow) IPCObjectProxy(0);
    EXPECT_TRUE(callbackProxy != nullptr);
    MessageParcel data;
    data.WriteRemoteObject(callbackProxy);
    data.WriteString("");
    int32_t ret = dBinderServiceStub.RemoveDbinderDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_REMOVE_DEATH_ERR);
}

/**
 * @tc.name: RemoveDbinderDeathRecipient004
 * @tc.desc: Verify the RemoveDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, RemoveDbinderDeathRecipient004, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    sptr<IPCObjectStub> callbackStub = new (std::nothrow) IPCObjectStub(u"testStub");
    EXPECT_TRUE(callbackStub != nullptr);
    MessageParcel data;
    data.WriteRemoteObject(callbackStub);
    data.WriteString("test");
    int32_t ret = dBinderServiceStub.RemoveDbinderDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_REMOVE_DEATH_ERR);
}

/**
 * @tc.name: RemoveDbinderDeathRecipient005
 * @tc.desc: Verify the RemoveDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubUnitTest, RemoveDbinderDeathRecipient005, TestSize.Level1)
{
    const std::string service = "serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    sptr<IPCObjectStub> callbackStub = new (std::nothrow) IPCObjectStub(u"testStub");
    EXPECT_TRUE(callbackStub != nullptr);
    MessageParcel data;
    data.WriteRemoteObject(callbackStub);
    data.WriteString("");
    int32_t ret = dBinderServiceStub.RemoveDbinderDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_REMOVE_DEATH_ERR);
}
