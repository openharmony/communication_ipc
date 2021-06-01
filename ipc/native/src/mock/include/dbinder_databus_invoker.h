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

#ifndef OHOS_IPC_DBINDER_DATABUS_INVOKER_H
#define OHOS_IPC_DBINDER_DATABUS_INVOKER_H

#include <unistd.h>
#include <sys/types.h>
#include "hilog/log.h"
#include "dbinder_base_invoker.h"
#include "invoker_factory.h"
#include "dbinder_session_object.h"
#include "sys_binder.h"

#include "Session.h"
#include "ISessionService.h"

using Communication::SoftBus::ISessionService;
using Communication::SoftBus::Session;

namespace OHOS {
class DBinderDatabusInvoker : public DBinderBaseInvoker<DBinderSessionObject> {
public:
    DBinderDatabusInvoker();
    ~DBinderDatabusInvoker();
    bool AcquireHandle(int32_t handle) override;
    bool ReleaseHandle(int32_t handle) override;
    void JoinThread(bool initiative) override;
    void JoinProcessThread(bool initiative) override;
    void StopWorkThread() override;
    bool FlattenObject(Parcel &parcel, const IRemoteObject *object) const override;
    IRemoteObject *UnflattenObject(Parcel &parcel) override;
    int ReadFileDescriptor(Parcel &parcel) override;
    bool WriteFileDescriptor(Parcel &parcel, int fd, bool takeOwnership) override;
    pid_t GetCallerPid() const override;
    uid_t GetCallerUid() const override;
    uint32_t GetStatus() const override;
    bool IsLocalCalling() override;
    std::string GetLocalDeviceID() override;
    std::string GetCallerDeviceID() const override;

    bool UpdateClientSession(uint32_t handle, std::shared_ptr<DBinderSessionObject> sessionObject) override;
    std::shared_ptr<DBinderSessionObject> QueryClientSessionObject(uint32_t databusHandle) override;
    std::shared_ptr<DBinderSessionObject> QueryServerSessionObject(uint32_t handle) override;
    std::shared_ptr<DBinderSessionObject> CreateServerSessionObject(binder_uintptr_t binder, uint64_t &stubIndex,
        std::shared_ptr<DBinderSessionObject> sessionObject) override;
    int FlushCommands(IRemoteObject *object) override;

    bool OnDatabusSessionClosed(std::shared_ptr<Session> session);
    bool OnReceiveNewConnection(std::shared_ptr<Session> session);
    std::string ResetCallingIdentity() override;
    bool SetCallingIdentity(std::string &identity) override;
    int TranslateProxy(uint32_t handle, uint32_t flag) override;
    int TranslateStub(binder_uintptr_t cookie, binder_uintptr_t ptr, uint32_t flag, int cmd) override;
    void OnMessageAvailable(std::shared_ptr<Session> session, const char *data, ssize_t len);

private:
    bool CreateProcessThread() override;
    int OnSendMessage(std::shared_ptr<DBinderSessionObject> sessionOfPeer) override;
    int OnSendRawData(std::shared_ptr<DBinderSessionObject> session, const void *data, size_t size) override;
    std::shared_ptr<DBinderSessionObject> NewSessionOfBinderProxy(uint32_t handle,
        std::shared_ptr<DBinderSessionObject> session) override;
    std::shared_ptr<DBinderSessionObject> QuerySessionOfBinderProxy(uint32_t handle,
        std::shared_ptr<DBinderSessionObject> session) override;
    uint32_t FlattenSession(char *sessionOffset, const std::shared_ptr<DBinderSessionObject> connectSession,
        uint64_t stubIndex) override;
    std::shared_ptr<DBinderSessionObject> UnFlattenSession(char *sessionOffset, uint64_t &stubIndex) override;
    uint32_t QueryHandleBySession(std::shared_ptr<DBinderSessionObject> session, uint64_t stubIndex) override;
    virtual uint64_t GetSeqNum() const override;
    virtual void SetSeqNum(uint64_t seq) override;
    virtual uint32_t GetClientFd() const override;
    virtual void SetClientFd(uint32_t fd) override;
    virtual void SetCallerPid(pid_t pid) override;
    virtual void SetCallerUid(pid_t uid) override;
    virtual void SetStatus(uint32_t status) override;
    virtual void SetCallerDeviceID(const std::string &deviceId) override;
    virtual int CheckAndSetCallerInfo(uint32_t listenFd, uint64_t stubIndex) override;
    uint32_t HasRawDataPackage(const char *data, ssize_t len);
    uint32_t HasCompletePackage(const char *data, uint32_t readCursor, ssize_t len);
    void OnRawDataAvailable(std::shared_ptr<Session> session, const char *data, uint32_t dataSize);
    uint64_t MakeStubIndexByRemoteObject(IRemoteObject *stubObject);
    std::shared_ptr<DBinderSessionObject> MakeDefaultServerSessionObject();
    bool ConnectRemoteObject2Session(IRemoteObject *stubObject, uint64_t stubIndex,
        const std::shared_ptr<DBinderSessionObject> sessionObject);
    bool AuthSession2Proxy(uint32_t handle, const std::shared_ptr<DBinderSessionObject> Session);

private:
    DISALLOW_COPY_AND_MOVE(DBinderDatabusInvoker);
    bool stopWorkThread_;
    pid_t callerPid_;
    pid_t callerUid_;
    std::string callerDeviceID_;
    uint64_t seqNumber_ = 0;
    uint32_t clientFd_ = 0;
    uint32_t status_;
    static inline InvokerDelegator<DBinderDatabusInvoker> DBinderDatabusDelegator_ = { IRemoteObject::IF_PROT_DATABUS };
};
} // namespace OHOS
#endif // OHOS_IPC_DBINDER_DATABUS_INVOKER_H
