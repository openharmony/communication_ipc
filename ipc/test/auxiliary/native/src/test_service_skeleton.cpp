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

#include "test_service_skeleton.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
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

TestServiceProxy::TestServiceProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ITestService>(impl)
{
}

int TestServiceProxy::TestSyncTransaction(int data, int &reply, int delayTime)
{
    int error;
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    ZLOGI(LABEL, "send to server data = %{public}d", data);
    if (data > 0) {
        dataParcel.WriteInt32(data);
        dataParcel.WriteInt32(delayTime);
    }
    error = Remote()->SendRequest(TRANS_ID_SYNC_TRANSACTION, dataParcel, replyParcel, option);
    reply = replyParcel.ReadInt32();
    ZLOGI(LABEL, "get result from server data = %{public}d", reply);
    return error;
}

int TestServiceProxy::TestAsyncTransaction(int data, int timeout)
{
    MessageOption option = { MessageOption::TF_ASYNC };
    MessageParcel dataParcel, replyParcel;
    ZLOGI(LABEL, "%{public}s:in, data = %{public}d", __func__, data);
    dataParcel.WriteInt32(data);
    dataParcel.WriteInt32(timeout);
    dataParcel.WriteBool(false);
    return Remote()->SendRequest(TRANS_ID_ASYNC_TRANSACTION, dataParcel, replyParcel, option);
}

int TestServiceProxy::TestAsyncCallbackTrans(int data, int &reply, int timeout)
{
    int error;
    MessageOption option = { MessageOption::TF_ASYNC };
    MessageParcel dataParcel, replyParcel;
    ZLOGI(LABEL, "%{public}s:in, data = %{public}d", __func__, data);
    dataParcel.WriteInt32(data);
    dataParcel.WriteInt32(timeout);
    dataParcel.WriteBool(true);
    sptr<FooStub> fooCallback = new FooStub();
    dataParcel.WriteRemoteObject(fooCallback->AsObject());
    error = Remote()->SendRequest(TRANS_ID_ASYNC_TRANSACTION, dataParcel, replyParcel, option);
    reply = fooCallback->WaitForAsyncReply(timeout);

    FooStub::CleanDecTimes();
    fooCallback = nullptr;
    if (FooStub::GetDecTimes() != 1) {
        error = ERR_TRANSACTION_FAILED;
    }
    return error;
}

int TestServiceProxy::TestZtraceTransaction(std::string &send, std::string &reply, int len)
{
    int error;
    MessageParcel dataParcel, replyParcel;
    MessageOption option;

    dataParcel.WriteInt32(len);
    dataParcel.WriteString(send);
    error = Remote()->SendRequest(TRANS_ID_ZTRACE_TRANSACTION, dataParcel, replyParcel, option);
    reply = replyParcel.ReadString();

    return error;
}

int TestServiceProxy::TestPingService(const std::u16string &serviceName)
{
    int error;
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    ZLOGI(LABEL, "PingService");
    dataParcel.WriteString16(serviceName);
    error = Remote()->SendRequest(TRANS_ID_PING_SERVICE, dataParcel, replyParcel, option);
    int result = (error == ERR_NONE) ? replyParcel.ReadInt32() : -1;
    ZLOGI(LABEL, "PingService result = %d", result);
    return result;
}

sptr<IFoo> TestServiceProxy::TestGetFooService()
{
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    Remote()->SendRequest(TRANS_ID_GET_FOO_SERVICE, dataParcel, replyParcel, option);
    auto rep = replyParcel.ReadRemoteObject();
    if (rep == nullptr) {
        ZLOGE(LABEL, "null foo service");
        return nullptr;
    }
    return iface_cast<IFoo>(rep);
}

int TestServiceProxy::TestGetFileDescriptor()
{
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    sptr<IPCFileDescriptor> desc;
    option.SetFlags(MessageOption::TF_ACCEPT_FDS);
    Remote()->SendRequest(TRANS_ID_TRANSACT_FILE_DESC, dataParcel, replyParcel, option);
    int fd = replyParcel.ReadFileDescriptor();
    return fd;
}

int TestServiceProxy::TestStringTransaction(const std::string &data)
{
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    dataParcel.WriteString(data);
    Remote()->SendRequest(TRANS_ID_STRING_TRANSACTION, dataParcel, replyParcel, option);
    int testSize = replyParcel.ReadInt32();
    return testSize;
}

void TestServiceProxy::TestDumpService()
{
    ZLOGI(LABEL, "call StartDumpService");
    int fd = open("/data/test/dump.txt",
        O_RDWR | O_APPEND | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
    if (fd != INVALID_FD) {
        ZLOGI(LABEL, "Start Dump Service");
        std::vector<std::u16string> args;
        args.push_back(u"DumpTest");
        Remote()->Dump(fd, args);
        close(fd);
    }
}

void TestServiceProxy::TestAsyncDumpService()
{
    int fd = open("/data/test/nonblockingDump.txt",
        O_RDWR | O_APPEND | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
    if (fd == INVALID_FD) {
        return;
    }

    ZLOGI(LABEL, "Start Async Dump Service");
    std::vector<std::u16string> args;
    args.push_back(u"NonblockingDumpTest");
    MessageParcel data, reply;
    MessageOption option {MessageOption::TF_ASYNC};
    data.WriteFileDescriptor(fd);
    data.WriteString16Vector(args);
    (void)Remote()->SendRequest(DUMP_TRANSACTION, data, reply, option);
    close(fd);
}

int TestServiceProxy::TestRawDataTransaction(int length, int &reply)
{
    int error;
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    ZLOGE(LABEL, "send to server data length = %{public}d", length);
    if (length <= 1 || static_cast<unsigned>(length) > dataParcel.GetRawDataCapacity()) {
        ZLOGE(LABEL, "length should > 1, length is %{public}d", length);
        return -1;
    }
    unsigned char *buffer = new (std::nothrow) unsigned char[length];
    if (buffer == nullptr) {
        ZLOGE(LABEL, "new buffer failed of length = %{public}d", length);
        return -1;
    }
    buffer[0] = 'a';
    buffer[length - 1] = 'z';

    dataParcel.WriteInt32(length);
    dataParcel.WriteRawData(buffer, length);
    dataParcel.WriteInt32(length);
    error = Remote()->SendRequest(TRANS_ID_RAWDATA_TRANSACTION, dataParcel, replyParcel, option);
    reply = replyParcel.ReadInt32();
    ZLOGE(LABEL, "get result from server data = %{public}d", reply);
    delete [] buffer;
    return error;
}

int TestServiceProxy::TestRawDataReply(int length)
{
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    if (length <= 1 || static_cast<unsigned>(length) > dataParcel.GetRawDataCapacity()) {
        ZLOGE(LABEL, "length should > 1, length is %{public}d", length);
        return ERR_INVALID_STATE;
    }

    if (!dataParcel.WriteInt32(length)) {
        ZLOGE(LABEL, "fail to write parcel");
        return ERR_INVALID_STATE;
    }

    int ret = Remote()->SendRequest(TRANS_ID_RAWDATA_REPLY, dataParcel, replyParcel, option);
    if (ret != ERR_NONE) {
        ZLOGE(LABEL, "ret = %{public}d", ret);
        return ret;
    }

    if (replyParcel.ReadInt32() != length) {
        ZLOGE(LABEL, "reply false data");
        return ERR_INVALID_DATA;
    }

    if (!replyParcel.ContainFileDescriptors()) {
        ZLOGE(LABEL, "replied raw data is less than 32k");
    }

    const char *buffer = nullptr;
    if ((buffer = reinterpret_cast<const char *>(replyParcel.ReadRawData(length))) == nullptr) {
        ZLOGE(LABEL, "read raw data failed, length = %{public}d", length);
        return ERR_INVALID_DATA;
    }
    if (buffer[0] != 'a' || buffer[length - 1] != 'z') {
        ZLOGE(LABEL, "buffer error, length = %{public}d", length);
        return ERR_INVALID_DATA;
    }

    if (replyParcel.ReadInt32() != length) {
        ZLOGE(LABEL, "read raw data after failed, length = %{public}d", length);
        return ERR_INVALID_DATA;
    }

    return ERR_NONE;
}


int TestServiceProxy::TestCallingUidPid()
{
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    int ret = Remote()->SendRequest(TRANS_ID_CALLING_UID_PID, dataParcel, replyParcel, option);
    if (ret != ERR_NONE) {
        ZLOGE(LABEL, "ret = %{public}d", ret);
        return ret;
    }

    int uid  = replyParcel.ReadInt32();
    int pid  = replyParcel.ReadInt32();

    IPCTestHelper helper;
    int actualUid = helper.GetUid();
    int actualPid = helper.GetPid();
    ZLOGI(LABEL, "uid = %{public}d, pid = %{public}d, actualUid = %{public}d, actualPid = %{public}d",
        uid, pid, actualUid, actualPid);

    if (uid == actualUid && pid == actualPid) {
        return 0;
    }
    return -1;
}

int TestServiceProxy::TestFlushAsyncCalls(int count, int length)
{
    int ret;
    MessageOption option = { MessageOption::TF_ASYNC };
    MessageParcel dataParcel, replyParcel;
    std::u16string legalData(length, 'a');
    dataParcel.WriteString16(legalData);
    for (int i = 0; i < count; i++) {
        ret = Remote()->SendRequest(TRANS_ID_FLUSH_ASYNC_CALLS, dataParcel, replyParcel, option);
        if (ret != ERR_NONE) {
            ZLOGE(LABEL, "fail to send request when count = %{public}d, ret = %{public}d", count, ret);
            return ret;
        }
    }

    ret = IPCSkeleton::FlushCommands(this->AsObject());
    return ret;
}

int TestServiceProxy::TestMultipleProcesses(int data, int &rep, int delayTime)
{
    int error;
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    ZLOGI(LABEL, "send to server data = %{public}d", data);
    if (data > 0) {
        dataParcel.WriteInt32(data);
        dataParcel.WriteInt32(delayTime);
    }
    error = Remote()->SendRequest(TRANS_ID_MULTIPLE_PROCESSES, dataParcel, replyParcel, option);
    rep = replyParcel.ReadInt32();
    error += replyParcel.ReadInt32();
    return error;
}

std::u16string TestServiceProxy::TestAshmem(sptr<Ashmem> ashmem, int32_t contentSize)
{
    if (ashmem == nullptr || contentSize <= 0) {
        return u"";
    }

    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    if (!dataParcel.WriteInt32(contentSize) || !dataParcel.WriteAshmem(ashmem)) {
        return u"";
    }

    int error = Remote()->SendRequest(TRANS_ID_ASHMEM, dataParcel, replyParcel, option);
    if (error != ERR_NONE) {
        return u"";
    }

    int32_t readContentSize = replyParcel.ReadInt32();
    if (readContentSize <= 0) {
        return u"";
    }

    sptr<Ashmem> ashmem2 = replyParcel.ReadAshmem();
    if (ashmem2 == nullptr || !ashmem2->MapReadAndWriteAshmem()) {
        return u"";
    }

    const void *content = ashmem2->ReadFromAshmem(readContentSize, 0);
    if (content == nullptr) {
        ashmem2->UnmapAshmem();
        return u"";
    }

    auto readContent = static_cast<const char *>(content);
    std::string str(readContent, readContentSize);

    ashmem2->UnmapAshmem();
    ashmem2->CloseAshmem();
    return Str8ToStr16(str);
}

int TestServiceProxy::TestNestingSend(int sendCode, int &replyCode)
{
    ZLOGW(LABEL, "%{public}s", __func__);
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    sptr<IFoo> foo = new FooStub();
    sptr<IRemoteObject> sendFoo = foo->AsObject();
    sendFoo->SetBehavior(Parcelable::BehaviorFlag::HOLD_OBJECT);
    if (!dataParcel.WriteRemoteObject(sendFoo) || !dataParcel.WriteInt32(sendCode)) {
        ZLOGE(LABEL, "%{public}s: fail to write data", __func__);
        return -1;
    }
    int error = Remote()->SendRequest(TRANS_ID_NESTING_SEND, dataParcel, replyParcel, option);
    replyCode = replyParcel.ReadInt32();
    ZLOGW(LABEL, "%{public}s: outer = %{public}d, inner = %{public}d", __func__, error, replyCode);
    return error;
}

int TestServiceStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int ret = 0;
    int result = 0;
    ZLOGI(LABEL, "OnRemoteRequest, cmd = %{public}d, flags= %{public}d", code, option.GetFlags());
    switch (code) {
        case TRANS_ID_SYNC_TRANSACTION: {
            int32_t reqData = data.ReadInt32();
            int32_t delayTime = data.ReadInt32();
            ret = TestSyncTransaction(reqData, result, delayTime);
            reply.WriteInt32(result);
            break;
        }
        case TRANS_ID_ASYNC_TRANSACTION: {
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
                result = TestAsyncTransaction(reqData, timeout);
            }
            break;
        }
        case TRANS_ID_PING_SERVICE: {
            std::u16string serviceName = data.ReadString16();
            result = TestPingService(serviceName);
            ZLOGI(LABEL, "%s:PingService: result=%d", __func__, result);
            reply.WriteInt32(result);
            break;
        }
        case TRANS_ID_GET_FOO_SERVICE: {
            sptr<IFoo> fooService = TestGetFooService();
            sptr<IRemoteObject> object = fooService->AsObject();
            object->SetBehavior(Parcelable::BehaviorFlag::HOLD_OBJECT);
            reply.WriteRemoteObject(object);
            break;
        }
        case TRANS_ID_TRANSACT_FILE_DESC: {
            int desc = TestGetFileDescriptor();
            reply.WriteFileDescriptor(desc);
            close(desc);
            break;
        }
        case TRANS_ID_STRING_TRANSACTION: {
            const std::string testString = data.ReadString();
            int testSize = TestStringTransaction(testString);
            reply.WriteInt32(testSize);
            reply.WriteString(testString);
            break;
        }
        case TRANS_ID_ZTRACE_TRANSACTION: {
            int32_t len = data.ReadInt32();
            if (len < 0) {
                ZLOGE(LABEL, "%s:get len failed, len = %d", __func__, len);
                break;
            }
            std::string recvString;
            std::string replyString(len, 0);
            recvString = data.ReadString();
            ret = TestZtraceTransaction(recvString, replyString, len);
            if (!ret) {
                reply.WriteString(replyString);
            }
            break;
        }
        case TRANS_ID_RAWDATA_TRANSACTION: {
            ret = TransferRawData(data, reply);
            break;
        }
        case TRANS_ID_RAWDATA_REPLY: {
            ret = ReplyRawData(data, reply);
            break;
        }
        case TRANS_ID_CALLING_UID_PID: {
            reply.WriteInt32(IPCSkeleton::GetCallingUid());
            reply.WriteInt32(IPCSkeleton::GetCallingPid());

            ZLOGE(LABEL, "calling before reset uid = %{public}d, pid = %{public}d",
                IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingPid());
            std::string token = IPCSkeleton::ResetCallingIdentity();

            ZLOGE(LABEL, "calling before set uid = %{public}d, pid = %{public}d",
                IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingPid());
            if (!IPCSkeleton::SetCallingIdentity(token)) {
                ZLOGE(LABEL, "Set Calling Identity fail");
                break;
            }

            ZLOGE(LABEL, "calling after set uid = %{public}d, pid = %{public}d",
                IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingPid());
            break;
        }
        case TRANS_ID_FLUSH_ASYNC_CALLS: {
            (void)data.ReadString16();
            break;
        }
        case TRANS_ID_MULTIPLE_PROCESSES: {
            TransferToNextProcess(data, reply);
            break;
        }
        case TRANS_ID_ASHMEM: {
            ReadAshmem(data, reply);
            break;
        }
        case TRANS_ID_NESTING_SEND: {
            sptr<IRemoteObject> object = data.ReadRemoteObject();
            sptr<IFoo> foo = iface_cast<IFoo>(object);
            int innerResult = foo->TestNestingSend(data.ReadInt32());
            reply.WriteInt32(innerResult);
            break;
        }
        default:
            ret = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
    }

    return ret;
}

int TestServiceStub::TransferRawData(MessageParcel &data, MessageParcel &reply)
{
    ZLOGI(LABEL, "enter transfer raw data");
    int length = data.ReadInt32();
    if (length <= 1) {
        ZLOGE(LABEL, "%{public}s: length should > 1, length is %{public}d", __func__, length);
        if (!reply.WriteInt32(length)) {
            ZLOGE(LABEL, "fail to write parcel");
        }
        return ERR_INVALID_DATA;
    }

    if (!data.ContainFileDescriptors()) {
        ZLOGE(LABEL, "sent raw data is less than 32k");
    }

    const char *buffer = nullptr;
    if ((buffer = reinterpret_cast<const char *>(data.ReadRawData(length))) == nullptr) {
        ZLOGE(LABEL, "%{public}s:read raw data failed, length = %{public}d", __func__, length);
        if (reply.WriteInt32(0)) {
            ZLOGE(LABEL, "fail to write parcel");
        }
        return ERR_INVALID_DATA;
    }
    if (buffer[0] != 'a' || buffer[length - 1] != 'z') {
        ZLOGE(LABEL, "%{public}s:buffer error, length = %{public}d", __func__, length);
        if (reply.WriteInt32(0)) {
            ZLOGE(LABEL, "fail to write parcel");
        }
        return ERR_INVALID_DATA;
    }
    if (data.ReadInt32() != length) {
        ZLOGE(LABEL, "%{public}s:read raw data after failed, length = %{public}d", __func__, length);
        if (!reply.WriteInt32(0)) {
            ZLOGE(LABEL, "fail to write parcel");
        }
        return ERR_INVALID_DATA;
    }
    if (!reply.WriteInt32(length)) {
        ZLOGE(LABEL, "fail to write parcel");
        return ERR_INVALID_DATA;
    }
    return ERR_NONE;
}

int TestServiceStub::ReplyRawData(MessageParcel &data, MessageParcel &reply)
{
    ZLOGI(LABEL, "enter reply raw data");
    int length = data.ReadInt32();
    if (length <= 1) {
        ZLOGE(LABEL, "%{public}s: length should > 1, length is %{public}d", __func__, length);
        if (!reply.WriteInt32(length)) {
            ZLOGE(LABEL, "fail to write parcel");
        }
        return ERR_INVALID_DATA;
    }

    unsigned char *buffer = new (std::nothrow) unsigned char[length];
    if (buffer == nullptr) {
        ZLOGE(LABEL, "new buffer failed of length = %{public}d", length);
        return ERR_INVALID_STATE;
    }
    buffer[0] = 'a';
    buffer[length - 1] = 'z';
    if (!reply.WriteInt32(length) ||
        !reply.WriteRawData(buffer, length) ||
        !reply.WriteInt32(length)) {
        ZLOGE(LABEL, "fail to write parcel");
        delete [] buffer;
        return ERR_INVALID_STATE;
    }

    delete [] buffer;
    return ERR_NONE;
}

void TestServiceStub::TransferToNextProcess(MessageParcel &data, MessageParcel &reply)
{
    int32_t reqData = data.ReadInt32();
    int32_t delayTime = data.ReadInt32();
    int result;
    int ret = TestSyncTransaction(reqData, result, delayTime);
    reply.WriteInt32(result);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        reply.WriteInt32(ERR_TRANSACTION_FAILED);
        return;
    }

    sptr<IRemoteObject> object = saMgr->GetSystemAbility(IPC_EXTRA_TEST_SERVICE);
    if (object == nullptr) {
        reply.WriteInt32(ERR_TRANSACTION_FAILED);
        return;
    }

    sptr<ITestService> testService = iface_cast<ITestService>(object);
    if (testService == nullptr) {
        reply.WriteInt32(ERR_TRANSACTION_FAILED);
        return;
    }

    ret += testService->TestSyncTransaction(reqData, result, delayTime);
    ret += testService->TestAsyncCallbackTrans(reqData, result, delayTime);
    if (ret != 0) {
        reply.WriteInt32(ERR_TRANSACTION_FAILED);
        return;
    }

    reply.WriteInt32(ERR_NONE);
}

void TestServiceStub::ReadAshmem(MessageParcel &data, MessageParcel &reply)
{
    int32_t contentSize = data.ReadInt32();
    if (contentSize < 0) {
        reply.WriteInt32(-1);
        return;
    }

    sptr<Ashmem> ashmem = data.ReadAshmem();
    if (ashmem == nullptr) {
        reply.WriteInt32(-1);
        return;
    }

    int32_t ashmemSize = ashmem->GetAshmemSize();
    if (ashmemSize < contentSize || !ashmem->MapReadOnlyAshmem()) {
        reply.WriteInt32(-1);
        return;
    }

    const void *content = ashmem->ReadFromAshmem(contentSize, 0);
    if (content == nullptr) {
        reply.WriteInt32(-1);
        ashmem->UnmapAshmem();
        ashmem->CloseAshmem();
        return;
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
        return;
    }

    reply.WriteInt32(contentSize);
    reply.WriteAshmem(ashmem2);

    ashmem2->UnmapAshmem();
    ashmem2->CloseAshmem();
}

bool TestDeathRecipient::gotDeathRecipient_ = false;

bool TestDeathRecipient::GotDeathRecipient()
{
    return gotDeathRecipient_;
}

void TestDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    gotDeathRecipient_ = true;
    ZLOGI(LABEL, "recv death notice");
}

TestDeathRecipient::TestDeathRecipient()
{
}

TestDeathRecipient::~TestDeathRecipient()
{
}
}  // namespace OHOS
