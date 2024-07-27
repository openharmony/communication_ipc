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

#ifndef OHOS_MOCK_IPC_IREMOTE_INVOKER_H
#define OHOS_MOCK_IPC_IREMOTE_INVOKER_H

#include <unistd.h>
#include <sys/types.h>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "binder_connector.h"
#include "iremote_invoker.h"
#include "invoker_factory.h"

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
namespace IPC_SINGLE {
#endif

class MockIRemoteInvoker : public IRemoteInvoker {
public:
    MockIRemoteInvoker() = default;

    MOCK_METHOD1(AcquireHandle, bool(int32_t handle));
    MOCK_METHOD1(ReleaseHandle, bool(int32_t handle));
    MOCK_METHOD1(PingService, bool(int32_t handle));
    MOCK_METHOD3(SendReply, int(MessageParcel &reply, uint32_t flags, int32_t result));
    MOCK_METHOD5(SendRequest, int(int handle, uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option));
    MOCK_METHOD2(AddDeathRecipient, bool(int32_t handle, void *cookie));
    MOCK_METHOD2(RemoveDeathRecipient, bool(int32_t handle, void *cookie));
    MOCK_METHOD1(SetMaxWorkThread, bool(int maxThreadNum));
    MOCK_METHOD1(JoinThread, void(bool initiative));
    MOCK_METHOD1(JoinProcessThread, void(bool initiative));
    MOCK_METHOD1(FreeBuffer, void(void *data));
    MOCK_METHOD1(SetRegistryObject, bool(sptr<IRemoteObject> &object));
    MOCK_METHOD0(StopWorkThread, void());
    MOCK_CONST_METHOD0(GetCallerSid, std::string());
    MOCK_CONST_METHOD0(GetCallerPid, pid_t());
    MOCK_CONST_METHOD0(GetCallerRealPid, pid_t());
    MOCK_CONST_METHOD0(GetCallerUid, uid_t());
    MOCK_CONST_METHOD0(GetCallerTokenID, uint64_t());
    MOCK_CONST_METHOD0(GetFirstCallerTokenID, uint64_t());
    MOCK_CONST_METHOD0(GetSelfTokenID, uint64_t());
    MOCK_CONST_METHOD0(GetSelfFirstCallerTokenID, uint64_t());
    MOCK_METHOD0(GetStatus, uint32_t());
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

#ifndef CONFIG_IPC_SINGLE
    MOCK_METHOD0(GetSAMgrObject, sptr<IRemoteObject>());
    MOCK_METHOD2(TranslateIRemoteObject, int(int32_t cmd, const sptr<IRemoteObject> &obj));
#endif
};
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS
#endif // OHOS_MOCK_IPC_IREMOTE_INVOKER_H
