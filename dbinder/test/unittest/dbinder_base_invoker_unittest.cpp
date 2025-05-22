/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#define private public
#include "mock_dbinder_base_invoker.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HiviewDFX;

class DBinderBaseInvokerUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: ProcessTransactionAbnormalBranch001
 * @tc.desc: Mock IRemoteObjectTranslateWhenRcv translate remote object fail
 * @tc.type: FUNC
 */
HWTEST_F(DBinderBaseInvokerUnitTest, ProcessTransactionAbnormalBranch001, TestSize.Level1)
{
    std::shared_ptr<MockDBinderBaseInvoker> invoker = std::make_shared<MockDBinderBaseInvoker>();
    EXPECT_TRUE(invoker != nullptr);
    int32_t listenFd = 0;
    /**                                     |-----tr->buffer_size-----|---tr->offsets_size------|
     * |* sizeof(dbinder_transaction_data) *|* sizeof(binder_size_t) *|* sizeof(binder_size_t) *|
     *                                    tr->buffer       tr->buffer + tr->offsets
     */
    size_t pkgSize = sizeof(dbinder_transaction_data) + sizeof(binder_size_t) + sizeof(binder_size_t);
    std::shared_ptr<dbinder_transaction_data> tr(reinterpret_cast<dbinder_transaction_data *>(
        ::operator new(pkgSize)));
    EXPECT_TRUE(tr != nullptr);
    tr->sizeOfSelf = pkgSize;
    tr->magic = DBINDER_MAGICWORD;
    tr->version = SUPPORT_TOKENID_VERSION_NUM;
    tr->cmd = BC_TRANSACTION;
    tr->code = 0;
    tr->flags = MessageOption::TF_STATUS_CODE;
    tr->seqNumber = 0;
    tr->buffer_size = sizeof(binder_size_t);
    tr->offsets = tr->buffer_size;
    tr->offsets_size = sizeof(binder_size_t);
    binder_size_t *binderObjectOffsets = reinterpret_cast<binder_size_t *>(tr->buffer + tr->offsets);
    binderObjectOffsets[0] = tr->buffer_size;  // To make IsValidRemoteObjectOffset function fail
    bool ret = invoker->CheckTransactionData(tr.get());
    ASSERT_TRUE(ret);
    invoker->ProcessTransaction(tr.get(), listenFd);
    EXPECT_EQ(invoker->result_, RPC_BASE_INVOKER_TRANSLATE_ERR);
}

/**
 * @tc.name: ProcessTransactionAbnormalBranch002
 * @tc.desc: Mock CheckAndSetCallerInfo return err branch
 * @tc.type: FUNC
 */
HWTEST_F(DBinderBaseInvokerUnitTest, ProcessTransactionAbnormalBranch002, TestSize.Level1)
{
    std::shared_ptr<MockDBinderBaseInvoker> invoker = std::make_shared<MockDBinderBaseInvoker>();
    EXPECT_TRUE(invoker != nullptr);
    int32_t listenFd = 0;
    /**                                     |-----tr->buffer_size-----|--tr->offsets_size--|
     * |* sizeof(dbinder_transaction_data) *|* sizeof(binder_size_t) *|*       empty      *|
     *                                    tr->buffer       tr->buffer + tr->offsets
     */
    size_t pkgSize = sizeof(dbinder_transaction_data) + sizeof(binder_size_t);
    std::shared_ptr<dbinder_transaction_data> tr(reinterpret_cast<dbinder_transaction_data *>(
        ::operator new(pkgSize)));
    EXPECT_TRUE(tr != nullptr);
    tr->sizeOfSelf = pkgSize;
    tr->magic = DBINDER_MAGICWORD;
    tr->version = SUPPORT_TOKENID_VERSION_NUM;
    tr->cmd = BC_TRANSACTION;
    tr->code = 0;
    tr->flags = MessageOption::TF_STATUS_CODE;
    tr->seqNumber = 0;
    tr->buffer_size = sizeof(binder_size_t);
    tr->offsets = tr->buffer_size;
    tr->offsets_size = 0;

    bool ret = invoker->CheckTransactionData(tr.get());
    ASSERT_TRUE(ret);

    EXPECT_CALL(*invoker,
        CheckAndSetCallerInfo(testing::_, testing::_)).WillOnce(testing::Return(RPC_DATABUS_INVOKER_INVALID_DATA_ERR));
    invoker->ProcessTransaction(tr.get(), listenFd);
    EXPECT_EQ(invoker->result_, RPC_DATABUS_INVOKER_INVALID_DATA_ERR);
}

/**
 * @tc.name: StartProcessLoopAbnormalBranch001
 * @tc.desc: Mock StartProcessLoop can not get the IPCProcessSkeleton instance
 * @tc.type: FUNC
 */
HWTEST_F(DBinderBaseInvokerUnitTest, StartProcessLoopAbnormalBranch001, TestSize.Level1)
{
    testing::NiceMock<MockDBinderBaseInvoker> mock;
    int32_t socketId = 0;
    std::shared_ptr<dbinder_transaction_data> tr(new dbinder_transaction_data);
    EXPECT_TRUE(tr != nullptr);
    uint32_t size = sizeof(dbinder_transaction_data) + sizeof(binder_size_t);

    tr->magic = DBINDER_MAGICWORD;
    tr->flags = MessageOption::TF_STATUS_CODE;
    tr->offsets = sizeof(binder_size_t);
    tr->buffer_size = sizeof(binder_size_t);
    tr->sizeOfSelf = sizeof(dbinder_transaction_data) + sizeof(binder_size_t);

    IPCProcessSkeleton::exitFlag_ = true;
    IPCProcessSkeleton::instance_ = nullptr;

    mock.StartProcessLoop(socketId, reinterpret_cast<const char*>(tr.get()), size);
    EXPECT_EQ(mock.result_, RPC_BASE_INVOKER_CURRENT_NULL_ERR);

    IPCProcessSkeleton::exitFlag_ = false;
}

/**
 * @tc.name: StartProcessLoopAbnormalBranch002
 * @tc.desc: Mock StartProcessLoop can not get the IPCProcessSkeleton instance
 * @tc.type: FUNC
 */
HWTEST_F(DBinderBaseInvokerUnitTest, StartProcessLoopAbnormalBranch002, TestSize.Level1)
{
    testing::NiceMock<MockDBinderBaseInvoker> mock;
    int32_t socketId = 0;
    std::shared_ptr<dbinder_transaction_data> tr(new dbinder_transaction_data);
    EXPECT_TRUE(tr != nullptr);
    uint32_t size = SOCKET_MAX_BUFF_SIZE + 1;

    tr->magic = DBINDER_MAGICWORD;
    tr->flags = MessageOption::TF_STATUS_CODE;
    tr->offsets = sizeof(binder_size_t);
    tr->buffer_size = sizeof(binder_size_t);
    tr->sizeOfSelf = sizeof(dbinder_transaction_data) + sizeof(binder_size_t);

    mock.StartProcessLoop(socketId, reinterpret_cast<const char*>(tr.get()), size);
    EXPECT_EQ(mock.result_, RPC_BASE_INVOKER_MALLOC_ERR);
}
