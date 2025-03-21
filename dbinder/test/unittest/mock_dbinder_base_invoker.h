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

#ifndef OHOS_MOCK_DBINDER_BASE_INVOKER_H
#define OHOS_MOCK_DBINDER_BASE_INVOKER_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "dbinder_base_invoker.h"

namespace OHOS {
class MockDBinderBaseInvoker : public DBinderBaseInvoker<DBinderSessionObject> {
public:
    MockDBinderBaseInvoker();
    MOCK_METHOD2(CheckAndSetCallerInfo, int(int32_t socketId, uint64_t stubIndex));
    MOCK_METHOD1(AcquireHandle, bool(int32_t handle));
    MOCK_METHOD1(ReleaseHandle, bool(int32_t handle));
    MOCK_METHOD1(JoinThread, void(bool initiative));
    MOCK_METHOD1(JoinProcessThread, void(bool initiative));
    MOCK_METHOD0(StopWorkThread, void());
    MOCK_CONST_METHOD0(GetCallerSid, std::string());
    MOCK_CONST_METHOD0(GetCallerPid, pid_t());
    MOCK_CONST_METHOD0(GetCallerRealPid, pid_t());
    MOCK_CONST_METHOD0(GetCallerUid, uid_t());
    MOCK_CONST_METHOD0(GetCallerTokenID, uint64_t());
    MOCK_CONST_METHOD0(GetFirstCallerTokenID, uint64_t());
    MOCK_CONST_METHOD0(GetSelfTokenID, uint64_t());
    MOCK_CONST_METHOD0(GetSelfFirstCallerTokenID, uint64_t());
    MOCK_METHOD0(IsLocalCalling, bool());
    MOCK_METHOD0(GetLocalDeviceID, std::string());
    MOCK_CONST_METHOD0(GetCallerDeviceID, std::string());
    MOCK_CONST_METHOD2(FlattenObject, bool(Parcel &parcel, const IRemoteObject *object));
    MOCK_METHOD1(UnflattenObject, sptr<IRemoteObject>(Parcel &parcel));
    MOCK_METHOD1(ReadFileDescriptor, int(Parcel &parcel));
    MOCK_METHOD3(WriteFileDescriptor, bool(Parcel &parcel, int fd, bool takeOwnership));
    MOCK_METHOD1(FlushCommands, int(IRemoteObject *object));
    MOCK_METHOD0(ResetCallingIdentity, std::string());
    MOCK_METHOD2(SetCallingIdentity, bool(std::string &identity, bool flag));
    MOCK_METHOD0(TriggerSystemIPCThreadReclaim, bool());
    MOCK_METHOD1(EnableIPCThreadReclaim, bool(bool enable));
    MOCK_METHOD1(QueryServerSessionObject, std::shared_ptr<DBinderSessionObject>(uint32_t handle));
    MOCK_METHOD1(UpdateClientSession, bool(std::shared_ptr<DBinderSessionObject> sessionObject));
    MOCK_METHOD1(QueryHandleBySession, uint32_t(std::shared_ptr<DBinderSessionObject> session));
    MOCK_METHOD1(QueryClientSessionObject, std::shared_ptr<DBinderSessionObject>(uint32_t databusHandle));
    MOCK_METHOD2(NewSessionOfBinderProxy, std::shared_ptr<DBinderSessionObject>(uint32_t handle,
        std::shared_ptr<DBinderSessionObject> session));
    MOCK_METHOD2(QuerySessionOfBinderProxy, std::shared_ptr<DBinderSessionObject>(uint32_t handle,
        std::shared_ptr<DBinderSessionObject> session));
    MOCK_METHOD2(CreateServerSessionObject, std::shared_ptr<DBinderSessionObject>(binder_uintptr_t binder,
        std::shared_ptr<DBinderSessionObject> sessionObject));
    MOCK_METHOD3(FlattenSession, uint32_t(unsigned char *sessionOffset,
        const std::shared_ptr<DBinderSessionObject> connectSession, uint32_t binderVersion));
    MOCK_METHOD2(UnFlattenSession, std::shared_ptr<DBinderSessionObject>(unsigned char *sessionOffset,
        uint32_t binderVersion));
    MOCK_METHOD1(OnSendMessage, int(std::shared_ptr<DBinderSessionObject> sessionOfPeer));
    MOCK_METHOD0(CreateProcessThread, bool());
    MOCK_CONST_METHOD0(GetSeqNum, uint64_t());
    MOCK_CONST_METHOD0(GetClientFd, int32_t());
    MOCK_METHOD1(SetClientFd, void(int32_t fd));
    MOCK_METHOD1(SetCallerPid, void(pid_t pid));
    MOCK_METHOD1(SetCallerUid, void(pid_t uid));
    MOCK_METHOD1(SetCallerDeviceID, void(const std::string &deviceId));
    MOCK_METHOD1(SetCallerTokenID, void(const uint32_t tokerId));
    MOCK_METHOD3(OnSendRawData, int(std::shared_ptr<DBinderSessionObject> session, const void *data, size_t size));

    uint32_t GetStatus() override;
    void GetCallerInfo(DBinderCallerInfo &callerInfo) override;
    void SetStatus(uint32_t status) override;
    void SetCallerInfo(DBinderCallerInfo &callerInfo) override;
    void SetSeqNum(uint64_t seq) override;
    int SendReply(MessageParcel &reply, uint32_t flags, int32_t result) override;

private:
    pid_t callerPid_;
    pid_t callerUid_;
    std::string callerDeviceID_;
    uint64_t callerTokenID_;
    uint64_t firstTokenID_;
    uint64_t seqNumber_ = 0;
    int32_t clientFd_ = 0;
    uint32_t status_;
    int32_t result_ = 0;
};

MockDBinderBaseInvoker::MockDBinderBaseInvoker()
    : callerPid_(getpid()), callerUid_(getuid()), callerDeviceID_(""),
    callerTokenID_(0), firstTokenID_(0), status_(0)
{
}

/* These functions can be overridden if needed by unittest, here just implement them by default */
uint32_t MockDBinderBaseInvoker::GetStatus()
{
    return status_;
}

void MockDBinderBaseInvoker::GetCallerInfo(DBinderCallerInfo &callerInfo)
{
    callerInfo.callerPid = callerPid_;
    callerInfo.callerUid = callerUid_;
    callerInfo.callerDeviceID = callerDeviceID_;
    callerInfo.clientFd = clientFd_;
    callerInfo.callerTokenID = callerTokenID_;
    callerInfo.firstTokenID = firstTokenID_;
}

void MockDBinderBaseInvoker::SetStatus(uint32_t status)
{
    status_ = status;
}

void MockDBinderBaseInvoker::SetCallerInfo(DBinderCallerInfo &callerInfo)
{
    callerPid_ = callerInfo.callerPid;
    callerUid_ = callerInfo.callerUid;
    callerDeviceID_ = callerInfo.callerDeviceID;
    clientFd_ = callerInfo.clientFd;
    callerTokenID_ = callerInfo.callerTokenID;
    firstTokenID_ = callerInfo.firstTokenID;
}

int MockDBinderBaseInvoker::SendReply(MessageParcel &reply, uint32_t flags, int32_t result)
{
    (void)reply;
    (void)flags;
    result_ = result;

    return 0;
}

void MockDBinderBaseInvoker::SetSeqNum(uint64_t seq)
{
    seqNumber_ = seq;
}

} // namespace OHOS
#endif // OHOS_MOCK_DBINDER_BASE_INVOKER_H