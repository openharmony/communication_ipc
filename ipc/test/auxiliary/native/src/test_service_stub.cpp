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

#include "test_service_stub.h"
#include <cinttypes>
#include <fcntl.h>
#include <iostream>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <thread>
#include "access_token_adapter.h"
#include "ipc_debug.h"
#include "string_ex.h"
#include "iremote_proxy.h"
#include "ipc_skeleton.h"
#include "ipc_file_descriptor.h"
#include "ipc_test_helper.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
using namespace OHOS::HiviewDFX;

constexpr int32_t MAX_RECURSIVE_SENDS = 5;

TestServiceStub::TestServiceStub(bool serialInvokeFlag)
    : IRemoteStub(serialInvokeFlag), serialInvokeFlag_(serialInvokeFlag)
{
    InitMessageProcessMap();
}

void TestServiceStub::InitMessageProcessMap()
{
    funcMap_[static_cast<uint32_t>(TRANS_ID_SYNC_TRANSACTION)] = &TestServiceStub::ServerSyncTransaction;
    funcMap_[static_cast<uint32_t>(TRANS_ID_ASYNC_TRANSACTION)] = &TestServiceStub::ServerAsyncTransaction;
    funcMap_[static_cast<uint32_t>(TRANS_ID_PING_SERVICE)] = &TestServiceStub::ServerPingService;
    funcMap_[static_cast<uint32_t>(TRANS_ID_GET_FOO_SERVICE)] = &TestServiceStub::ServerGetFooService;
    funcMap_[static_cast<uint32_t>(TRANS_ID_TRANSACT_FILE_DESC)] = &TestServiceStub::ServerTransactFileDesc;
    funcMap_[static_cast<uint32_t>(TRANS_ID_STRING_TRANSACTION)] = &TestServiceStub::ServerStringTransaction;
    funcMap_[static_cast<uint32_t>(TRANS_ID_ZTRACE_TRANSACTION)] = &TestServiceStub::ServerZtraceTransaction;
    funcMap_[static_cast<uint32_t>(TRANS_ID_RAWDATA_TRANSACTION)] = &TestServiceStub::TransferRawData;
    funcMap_[static_cast<uint32_t>(TRANS_ID_RAWDATA_REPLY)] = &TestServiceStub::ReplyRawData;
    funcMap_[static_cast<uint32_t>(TRANS_ID_FLUSH_ASYNC_CALLS)] = &TestServiceStub::ServerFlushAsyncCalls;
    funcMap_[static_cast<uint32_t>(TRANS_ID_ASHMEM)] = &TestServiceStub::ReadAshmem;
    funcMap_[static_cast<uint32_t>(TRANS_ID_MULTIPLE_PROCESSES)] = &TestServiceStub::TransferToNextProcess;
    funcMap_[static_cast<uint32_t>(TRANS_ID_CALLING_UID_PID)] = &TestServiceStub::ServerCallingUidAndPid;
    funcMap_[static_cast<uint32_t>(TRANS_ID_NESTING_SEND)] = &TestServiceStub::ServerNestingSend;
    funcMap_[static_cast<uint32_t>(TRANS_ID_ACCESS_TOKENID)] = &TestServiceStub::ServerAccessTokenId;
    funcMap_[static_cast<uint32_t>(TRANS_ID_ACCESS_TOKENID_64)] = &TestServiceStub::ServerAccessTokenId64;
    funcMap_[static_cast<uint32_t>(TRANS_MESSAGE_PARCEL_ADDPED)] = &TestServiceStub::ServerMessageParcelAddped;
    funcMap_[static_cast<uint32_t>(TRANS_MESSAGE_PARCEL_ADDPED_WITH_OBJECT)] =
        &TestServiceStub::ServerMessageParcelAddpedWithObject;
    funcMap_[static_cast<uint32_t>(TRANS_ENABLE_SERIAL_INVOKE_FLAG)] = &TestServiceStub::ServerEnableSerialInvokeFlag;
    funcMap_[static_cast<uint32_t>(TRANS_ID_REGISTER_REMOTE_STUB_OBJECT)] = &TestServiceStub::RegisterRemoteStub;
    funcMap_[static_cast<uint32_t>(TRANS_ID_UNREGISTER_REMOTE_STUB_OBJECT)] = &TestServiceStub::UnRegisterRemoteStub;
    funcMap_[static_cast<uint32_t>(TRANS_ID_QUERY_REMOTE_PROXY_OBJECT)] = &TestServiceStub::QueryRemoteProxy;
}

int32_t TestServiceStub::ServerSyncTransaction(MessageParcel &data, MessageParcel &reply)
{
    int32_t result = 0;
    int32_t reqData = data.ReadInt32();
    int32_t delayTime = data.ReadInt32();
    int32_t ret = TestSyncTransaction(reqData, result, delayTime);
    reply.WriteInt32(result);
    return ret;
}

int32_t TestServiceStub::ServerAsyncTransaction(MessageParcel &data, MessageParcel &reply)
{
    int32_t result = 0;
    int32_t reqData = data.ReadInt32();
    int timeout = data.ReadInt32();
    bool acquireResult = data.ReadBool();
    if (acquireResult) {
        sptr<IFoo> fooProxy = iface_cast<IFoo>(data.ReadRemoteObject());
        if (fooProxy != nullptr) {
            TestAsyncCallbackTrans(reqData, result, timeout);
            fooProxy->SendAsyncReply(result);
        }
    } else {
        (void)TestAsyncTransaction(reqData, timeout);
    }
    return 0;
}

int32_t TestServiceStub::ServerPingService(MessageParcel &data, MessageParcel &reply)
{
    std::u16string serviceName = data.ReadString16();
    int32_t result = TestPingService(serviceName);
    ZLOGI(LABEL, "Result:%{public}d", result);
    reply.WriteInt32(result);
    return 0;
}

int32_t TestServiceStub::ServerGetFooService(MessageParcel &data, MessageParcel &reply)
{
    sptr<IFoo> fooService = TestGetFooService();
    sptr<IRemoteObject> object = fooService->AsObject();
    object->SetBehavior(Parcelable::BehaviorFlag::HOLD_OBJECT);
    reply.WriteRemoteObject(object);
    return 0;
}

int32_t TestServiceStub::ServerTransactFileDesc(MessageParcel &data, MessageParcel &reply)
{
    int desc = TestGetFileDescriptor();
    reply.WriteFileDescriptor(desc);
    close(desc);
    return 0;
}

int32_t TestServiceStub::ServerStringTransaction(MessageParcel &data, MessageParcel &reply)
{
    const std::string testString = data.ReadString();
    int testSize = TestStringTransaction(testString);
    reply.WriteInt32(testSize);
    reply.WriteString(testString);
    return 0;
}

int32_t TestServiceStub::ServerZtraceTransaction(MessageParcel &data, MessageParcel &reply)
{
    int32_t ret = 0;
    int32_t len = data.ReadInt32();
    if (len < 0) {
        ZLOGE(LABEL, "Get len failed, len = %{public}d", len);
        return ret;
    }
    std::string recvString;
    std::string replyString(len, 0);
    recvString = data.ReadString();
    ret = TestZtraceTransaction(recvString, replyString, len);
    if (!ret) {
        reply.WriteString(replyString);
    }
    return ret;
}

int32_t TestServiceStub::ServerCallingUidAndPid(MessageParcel &data, MessageParcel &reply)
{
    reply.WriteInt32(IPCSkeleton::GetCallingUid());
    reply.WriteInt32(IPCSkeleton::GetCallingPid());

    ZLOGI(LABEL, "Calling before reset uid = %{public}d, pid = %{public}d",
        IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingPid());
    std::string token = IPCSkeleton::ResetCallingIdentity();

    ZLOGI(LABEL, "Calling before set uid = %{public}d, pid = %{public}d",
        IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingPid());
    if (!IPCSkeleton::SetCallingIdentity(token)) {
        ZLOGE(LABEL, "Set Calling Identity fail");
        return 0;
    }

    ZLOGI(LABEL, "Calling after set uid = %{public}d, pid = %{public}d",
        IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingPid());
    return 0;
}

int32_t TestServiceStub::ServerNestingSend(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        ZLOGE(LABEL, "object is nullptr");
        return -1;
    }
    sptr<IFoo> foo = iface_cast<IFoo>(object);
    if (foo == nullptr) {
        ZLOGE(LABEL, "foo is nullptr");
        return -1;
    }
    int innerResult = foo->TestNestingSend(data.ReadInt32());
    reply.WriteInt32(innerResult);
    return 0;
}

int32_t TestServiceStub::ServerAccessTokenId(MessageParcel &data, MessageParcel &reply)
{
    int32_t token = static_cast<int32_t>(IPCSkeleton::GetCallingTokenID());
    int32_t ftoken = static_cast<int32_t>(IPCSkeleton::GetFirstTokenID());
    ZLOGI(LABEL, "Server GetCallingTokenID:%{public}d", token);
    ZLOGI(LABEL, "Server GetFirstTokenID:%{public}d", ftoken);
    reply.WriteInt32(token);
    reply.WriteInt32(ftoken);
    return 0;
}

int32_t TestServiceStub::ServerAccessTokenId64(MessageParcel &data, MessageParcel &reply)
{
    uint64_t token = IPCSkeleton::GetCallingFullTokenID();
    uint64_t ftoken = IPCSkeleton::GetFirstFullTokenID();
    ZLOGI(LABEL, "Server GetCallingFullTokenID:%{public}" PRIu64, token);
    ZLOGI(LABEL, "Server GetFirstFullTokenID:%{public}" PRIu64, ftoken);
    reply.WriteUint64(token);
    reply.WriteUint64(ftoken);
    return 0;
}

int32_t TestServiceStub::ServerMessageParcelAddped(MessageParcel &data, MessageParcel &reply)
{
    reply.WriteInt32(data.ReadInt32());
    reply.WriteInt32(data.ReadInt32());
    reply.WriteString(data.ReadString());
    return 0;
}

int32_t TestServiceStub::ServerMessageParcelAddpedWithObject(MessageParcel &data, MessageParcel &reply)
{
    reply.WriteInt32(data.ReadInt32());
    reply.WriteInt32(data.ReadInt32());
    reply.WriteString(data.ReadString());
    reply.WriteRemoteObject(data.ReadRemoteObject());
    reply.WriteFileDescriptor(data.ReadFileDescriptor());
    return 0;
}

int32_t TestServiceStub::ServerEnableSerialInvokeFlag(MessageParcel &data, MessageParcel &reply)
{
    int32_t ret = 0;
    static int sendCount = 0;

    if (sendCount == 0) {
        if (serialInvokeFlag_) {
            ZLOGI(LABEL, "Enable serial invoke flag");
        } else {
            ZLOGI(LABEL, "Not enable serial invoke flag");
        }
    }

    reply.WriteString(data.ReadString());
    sendCount++;

    if (sendCount >= MAX_RECURSIVE_SENDS) {
        return ret;
    }

    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    std::string value = std::to_string(sendCount); // The last time was 4.

    std::thread::id id_1 = std::this_thread::get_id();
    ZLOGI(LABEL, "Current thread ID = %{public}u", *(unsigned int*)&id_1);
    ZLOGI(LABEL, "Send to server data = %{public}s", value.c_str());
    dataParcel.WriteString(value);
    ret = IPCObjectStub::SendRequest(TRANS_ENABLE_SERIAL_INVOKE_FLAG, dataParcel, replyParcel, option);
    std::string result = replyParcel.ReadString();

    std::thread::id id_2 = std::this_thread::get_id();
    ZLOGI(LABEL, "Current thread ID = %{public}u", *(unsigned int*)&id_2);
    ZLOGI(LABEL, "Get result from server data = %{public}s", result.c_str());
    return ret;
}

int32_t TestServiceStub::RegisterRemoteStub(MessageParcel &data, MessageParcel &reply)
{
    std::string descriptor = data.ReadString();
    auto remoteObject = data.ReadRemoteObject();
    return TestRegisterRemoteStub(descriptor.c_str(), remoteObject);
}

int32_t TestServiceStub::UnRegisterRemoteStub(MessageParcel &data, MessageParcel &reply)
{
    std::string descriptor = data.ReadString();
    return TestUnRegisterRemoteStub(descriptor.c_str());
}

int32_t TestServiceStub::QueryRemoteProxy(MessageParcel &data, MessageParcel &reply)
{
    std::string descriptor = data.ReadString();
    sptr<IRemoteObject> remoteObject = TestQueryRemoteProxy(descriptor.c_str());
    return reply.WriteRemoteObject(remoteObject);
}

int TestServiceStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    std::map<uint32_t, OHOS::TestServiceStub::TestServiceStubFunc>::iterator it = funcMap_.find(code);
    if (it != funcMap_.end()) {
        OHOS::TestServiceStub::TestServiceStubFunc itFunc = it->second;
        if (itFunc != nullptr) {
            return (this->*itFunc)(data, reply);
        }
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t TestServiceStub::TransferRawData(MessageParcel &data, MessageParcel &reply)
{
    ZLOGI(LABEL, "Enter transfer raw data");
    int length = data.ReadInt32();
    if (length <= 1) {
        ZLOGE(LABEL, "Length should > 1, length is %{public}d", length);
        if (!reply.WriteInt32(length)) {
            ZLOGE(LABEL, "Fail to write parcel");
        }
        return ERR_INVALID_DATA;
    }

    if (!data.ContainFileDescriptors()) {
        ZLOGE(LABEL, "Sent raw data is less than 32k");
    }

    const char *buffer = nullptr;
    if ((buffer = reinterpret_cast<const char *>(data.ReadRawData((size_t)length))) == nullptr) {
        ZLOGE(LABEL, "Read raw data failed, length = %{public}d", length);
        if (reply.WriteInt32(0)) {
            ZLOGE(LABEL, "Fail to write parcel");
        }
        return ERR_INVALID_DATA;
    }
    if (buffer[0] != 'a' || buffer[length - 1] != 'z') {
        ZLOGE(LABEL, "Buffer error, length = %{public}d", length);
        if (reply.WriteInt32(0)) {
            ZLOGE(LABEL, "Fail to write parcel");
        }
        return ERR_INVALID_DATA;
    }
    if (data.ReadInt32() != length) {
        ZLOGE(LABEL, "Read raw data after failed, length = %{public}d", length);
        if (!reply.WriteInt32(0)) {
            ZLOGE(LABEL, "Fail to write parcel");
        }
        return ERR_INVALID_DATA;
    }
    if (!reply.WriteInt32(length)) {
        ZLOGE(LABEL, "Fail to write parcel");
        return ERR_INVALID_DATA;
    }
    return ERR_NONE;
}

int32_t TestServiceStub::ReplyRawData(MessageParcel &data, MessageParcel &reply)
{
    ZLOGI(LABEL, "Enter reply raw data");
    int length = data.ReadInt32();
    if (length <= 1) {
        ZLOGE(LABEL, "Length should > 1, length is %{public}d", length);
        if (!reply.WriteInt32(length)) {
            ZLOGE(LABEL, "Fail to write parcel");
        }
        return ERR_INVALID_DATA;
    }

    unsigned char *buffer = new (std::nothrow) unsigned char[length];
    if (buffer == nullptr) {
        ZLOGE(LABEL, "New buffer failed of length = %{public}d", length);
        return ERR_INVALID_STATE;
    }
    buffer[0] = 'a';
    buffer[length - 1] = 'z';
    if (!reply.WriteInt32(length) ||
        !reply.WriteRawData(buffer, (size_t)length) ||
        !reply.WriteInt32(length)) {
        ZLOGE(LABEL, "Fail to write parcel");
        delete [] buffer;
        return ERR_INVALID_STATE;
    }

    delete [] buffer;
    return ERR_NONE;
}

int32_t TestServiceStub::TransferToNextProcess(MessageParcel &data, MessageParcel &reply)
{
    int32_t reqData = data.ReadInt32();
    int32_t delayTime = data.ReadInt32();
    int result;
    int ret = TestSyncTransaction(reqData, result, delayTime);
    reply.WriteInt32(result);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        reply.WriteInt32(ERR_TRANSACTION_FAILED);
        return ERR_TRANSACTION_FAILED;
    }

    sptr<IRemoteObject> object = saMgr->GetSystemAbility(IPC_EXTRA_TEST_SERVICE);
    if (object == nullptr) {
        reply.WriteInt32(ERR_TRANSACTION_FAILED);
        return ERR_TRANSACTION_FAILED;
    }

    sptr<ITestService> testService = iface_cast<ITestService>(object);
    if (testService == nullptr) {
        reply.WriteInt32(ERR_TRANSACTION_FAILED);
        return ERR_TRANSACTION_FAILED;
    }

    ret += testService->TestSyncTransaction(reqData, result, delayTime);
    ret += testService->TestAsyncCallbackTrans(reqData, result, delayTime);
    if (ret != 0) {
        reply.WriteInt32(ERR_TRANSACTION_FAILED);
        return ERR_TRANSACTION_FAILED;
    }

    reply.WriteInt32(ERR_NONE);
    return ERR_NONE;
}

int32_t TestServiceStub::ReadAshmem(MessageParcel &data, MessageParcel &reply)
{
    int32_t contentSize = data.ReadInt32();
    if (contentSize < 0) {
        reply.WriteInt32(-1);
        return ERR_TRANSACTION_FAILED;
    }

    sptr<Ashmem> ashmem = data.ReadAshmem();
    if (ashmem == nullptr) {
        reply.WriteInt32(-1);
        return ERR_TRANSACTION_FAILED;
    }

    int32_t ashmemSize = ashmem->GetAshmemSize();
    if (ashmemSize < contentSize || !ashmem->MapReadOnlyAshmem()) {
        reply.WriteInt32(-1);
        return ERR_TRANSACTION_FAILED;
    }

    const void *content = ashmem->ReadFromAshmem(contentSize, 0);
    if (content == nullptr) {
        reply.WriteInt32(-1);
        ashmem->UnmapAshmem();
        ashmem->CloseAshmem();
        return ERR_TRANSACTION_FAILED;
    }

    auto pt = static_cast<const char *>(content);
    std::string str(pt, contentSize);
    ashmem->UnmapAshmem();
    ashmem->CloseAshmem();

    std::string name = "ashmem2";
    sptr<Ashmem> ashmem2 = Ashmem::CreateAshmem(name.c_str(), ashmemSize);
    if (ashmem2 == nullptr || !ashmem2->MapReadAndWriteAshmem() ||
        !ashmem2->WriteToAshmem(str.c_str(), contentSize, 0)) {
        reply.WriteInt32(-1);
        if (ashmem2 != nullptr) {
            ashmem2->UnmapAshmem();
            ashmem2->CloseAshmem();
        }
        return ERR_TRANSACTION_FAILED;
    }

    reply.WriteInt32(contentSize);
    reply.WriteAshmem(ashmem2);

    ashmem2->UnmapAshmem();
    ashmem2->CloseAshmem();
    return ERR_NONE;
}

int32_t TestServiceStub::ServerFlushAsyncCalls(MessageParcel &data, MessageParcel &reply)
{
    (void)data.ReadString16();
    return ERR_NONE;
}

}  // namespace OHOS
