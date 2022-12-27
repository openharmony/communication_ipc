/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "c_process.h"
#include "c_remote_object.h"
#include "c_remote_object_internal.h"

using namespace testing::ext;
using namespace OHOS;

static const uint32_t DUMP_CODE = 1598311760;
static const char *SERVICE_NAME = "ohos.ipc.test";

class IpcCRemoteObjectUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void IpcCRemoteObjectUnitTest::SetUpTestCase()
{}

void IpcCRemoteObjectUnitTest::TearDownTestCase()
{}

void IpcCRemoteObjectUnitTest::SetUp()
{}

void IpcCRemoteObjectUnitTest::TearDown()
{}

static int OnRemoteRequest(const CRemoteObject *stub, int code, const CParcel *data, CParcel *reply)
{
    (void)stub;
    (void)code;
    (void)data;
    (void)reply;
    return 0;
}

static void OnRemoteObjectDestroy(const void *userData)
{
    (void)userData;
}

static void OnDeathRecipient(const void *userData)
{
    (void)userData;
}

static void OnDeathRecipientDestroy(const void *userData)
{
    (void)userData;
}

/**
 * @tc.name: CRemoteObjectRefCount
 * @tc.desc: Verify the CRemoteObject reference count functions
 * @tc.type: FUNC
 */
HWTEST_F(IpcCRemoteObjectUnitTest, CRemoteObjectRefCount, TestSize.Level1)
{
    CRemoteObject *remote = CreateRemoteStub(nullptr, OnRemoteRequest, OnRemoteObjectDestroy, nullptr);
    EXPECT_EQ(remote, nullptr);
    remote = CreateRemoteStub(SERVICE_NAME, OnRemoteRequest, OnRemoteObjectDestroy, nullptr);
    EXPECT_NE(remote, nullptr);
    RefBase *ref = static_cast<RefBase *>(remote);
    EXPECT_EQ(ref->GetSptrRefCount(), 1);
    RemoteObjectIncStrongRef(remote);
    EXPECT_EQ(ref->GetSptrRefCount(), 2);
    RemoteObjectDecStrongRef(remote);
    EXPECT_EQ(ref->GetSptrRefCount(), 1);
    RemoteObjectIncStrongRef(nullptr);
    RemoteObjectDecStrongRef(nullptr);
    // destroy the CRemoteObject object
    RemoteObjectDecStrongRef(remote);
}

/**
 * @tc.name: CRemoteObjectUserData
 * @tc.desc: Verify the CRemoteObject user data function
 * @tc.type: FUNC
 */
HWTEST_F(IpcCRemoteObjectUnitTest, CRemoteObjectUserData, TestSize.Level1)
{
    EXPECT_EQ(RemoteObjectGetUserData(nullptr), nullptr);
    int8_t userData;
    CRemoteObject *remote = CreateRemoteStub(SERVICE_NAME, OnRemoteRequest, OnRemoteObjectDestroy, &userData);
    EXPECT_NE(remote, nullptr);
    EXPECT_EQ(RemoteObjectGetUserData(remote), &userData);
    // destroy the CRemoteObject object
    RemoteObjectDecStrongRef(remote);
}

/**
 * @tc.name: CRemoteObjectCompare
 * @tc.desc: Verify the CRemoteObject less than function
 * @tc.type: FUNC
 */
HWTEST_F(IpcCRemoteObjectUnitTest, CRemoteObjectCompare, TestSize.Level1)
{
    int8_t userData;
    CRemoteObject *remote = CreateRemoteStub(SERVICE_NAME, OnRemoteRequest, OnRemoteObjectDestroy, &userData);
    EXPECT_NE(remote, nullptr);
    EXPECT_FALSE(RemoteObjectLessThan(nullptr, remote));
    EXPECT_FALSE(RemoteObjectLessThan(remote, nullptr));
    CRemoteObject *samgr1 = GetContextManager();
    EXPECT_NE(samgr1, nullptr);
    CRemoteObject *samgr2 = GetContextManager();
    EXPECT_NE(samgr2, nullptr);
    EXPECT_FALSE(RemoteObjectLessThan(samgr1, samgr2));
    EXPECT_FALSE(RemoteObjectLessThan(samgr2, samgr1));
    CRemoteObjectHolder *samgr = static_cast<CRemoteObjectHolder *>(samgr1);
    CRemoteObjectHolder *holder = static_cast<CRemoteObjectHolder *>(remote);
    if (samgr->remote_.GetRefPtr() < holder->remote_.GetRefPtr()) {
        EXPECT_TRUE(RemoteObjectLessThan(samgr1, remote));
    } else {
        EXPECT_FALSE(RemoteObjectLessThan(samgr1, remote));
    }
    // destroy the CRemoteObject object
    RemoteObjectDecStrongRef(remote);
    RemoteObjectDecStrongRef(samgr1);
    RemoteObjectDecStrongRef(samgr2);
}

/**
 * @tc.name: CRemoteObjectSendRequest
 * @tc.desc: Verify the CRemoteObject sendRequest function
 * @tc.type: FUNC
 */
HWTEST_F(IpcCRemoteObjectUnitTest, CRemoteObjectSendRequest, TestSize.Level1)
{
    CRemoteObject *samgr = GetContextManager();
    EXPECT_NE(samgr, nullptr);
    CParcel *data = CParcelObtain();
    EXPECT_NE(data, nullptr);
    CParcel *reply = CParcelObtain();
    EXPECT_NE(reply, nullptr);
    EXPECT_NE(RemoteObjectSendRequest(nullptr, DUMP_CODE, data, reply, true), 0);
    EXPECT_NE(RemoteObjectSendRequest(samgr, DUMP_CODE, nullptr, reply, true), 0);
    EXPECT_NE(RemoteObjectSendRequest(samgr, DUMP_CODE, data, nullptr, true), 0);
    EXPECT_EQ(RemoteObjectSendRequest(samgr, DUMP_CODE, data, reply, true), 0);
    // destroy the CRemoteObject and CParcel object
    RemoteObjectDecStrongRef(samgr);
    CParcelDecStrongRef(data);
    CParcelDecStrongRef(reply);
}

/**
 * @tc.name: CDeathRecipientRefCount
 * @tc.desc: Verify the CDeathRecipient reference count function
 * @tc.type: FUNC
 */
HWTEST_F(IpcCRemoteObjectUnitTest, CDeathRecipientRefCount, TestSize.Level1)
{
    int8_t userData;
    CDeathRecipient *recipient = CreateDeathRecipient(nullptr,
        OnDeathRecipientDestroy, &userData);
    EXPECT_EQ(recipient, nullptr);
    recipient = CreateDeathRecipient(OnDeathRecipient, nullptr, &userData);
    EXPECT_EQ(recipient, nullptr);
    recipient = CreateDeathRecipient(OnDeathRecipient, OnDeathRecipientDestroy, nullptr);
    EXPECT_EQ(recipient, nullptr);
    recipient = CreateDeathRecipient(OnDeathRecipient, OnDeathRecipientDestroy, &userData);
    EXPECT_NE(recipient, nullptr);

    RefBase *ref = static_cast<RefBase *>(recipient);
    EXPECT_EQ(ref->GetSptrRefCount(), 1);
    DeathRecipientIncStrongRef(recipient);
    EXPECT_EQ(ref->GetSptrRefCount(), 2);
    DeathRecipientDecStrongRef(recipient);
    EXPECT_EQ(ref->GetSptrRefCount(), 1);
    DeathRecipientIncStrongRef(nullptr);
    DeathRecipientDecStrongRef(nullptr);
    // destroy the CDeathRecipient object
    DeathRecipientDecStrongRef(recipient);
}

/**
 * @tc.name: CDeathRecipientStub
 * @tc.desc: Verify the CDeathRecipient as stub functions
 * @tc.type: FUNC
 */
HWTEST_F(IpcCRemoteObjectUnitTest, CDeathRecipientStub, TestSize.Level1)
{
    int8_t userData;
    CDeathRecipient *recipient = CreateDeathRecipient(OnDeathRecipient, OnDeathRecipientDestroy, &userData);
    EXPECT_NE(recipient, nullptr);
    CRemoteObject *remote = CreateRemoteStub(SERVICE_NAME, OnRemoteRequest, OnRemoteObjectDestroy, &userData);
    EXPECT_NE(remote, nullptr);
    EXPECT_FALSE(AddDeathRecipient(remote, recipient));
    EXPECT_FALSE(RemoveDeathRecipient(remote, recipient));

    // destroy the CDeathRecipient object
    DeathRecipientDecStrongRef(recipient);
    RemoteObjectDecStrongRef(remote);
}

/**
 * @tc.name: CDeathRecipient
 * @tc.desc: Verify the CDeathRecipient functions
 * @tc.type: FUNC
 */
HWTEST_F(IpcCRemoteObjectUnitTest, CDeathRecipient, TestSize.Level1)
{
    int8_t userData;
    CDeathRecipient *recipient = CreateDeathRecipient(OnDeathRecipient, OnDeathRecipientDestroy, &userData);
    EXPECT_NE(recipient, nullptr);
    CRemoteObject *samgr = GetContextManager();
    EXPECT_NE(samgr, nullptr);

    EXPECT_FALSE(AddDeathRecipient(nullptr, recipient));
    EXPECT_FALSE(AddDeathRecipient(samgr, nullptr));
    EXPECT_FALSE(RemoveDeathRecipient(nullptr, recipient));
    EXPECT_FALSE(RemoveDeathRecipient(samgr, nullptr));

    EXPECT_TRUE(AddDeathRecipient(samgr, recipient));
    EXPECT_TRUE(RemoveDeathRecipient(samgr, recipient));
    // destroy the CDeathRecipient object
    DeathRecipientDecStrongRef(recipient);
    RemoteObjectDecStrongRef(samgr);
}