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
#include <cinttypes>
#include <fcntl.h>
#include <iostream>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
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
constexpr int32_t SEDNREQUEST_TIMES = 2000;
constexpr int32_t NUMBER_OF_THREADS = 20;

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


TestServiceStub::TestServiceStub(bool serialInvokeFlag)
    : IRemoteStub(serialInvokeFlag), serialInvokeFlag_(serialInvokeFlag)
{
    InitMessageProcessMap();
}

TestServiceProxy::TestServiceProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ITestService>(impl)
{
}

int TestServiceProxy::TestEnableSerialInvokeFlag()
{
    int error;
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    std::string value = "testData";

    ZLOGD(LABEL, "send to server data = %{public}s", value.c_str());
    dataParcel.WriteString(value);
    error = Remote()->SendRequest(TRANS_ENABLE_SERIAL_INVOKE_FLAG, dataParcel, replyParcel, option);
    std::string reply = replyParcel.ReadString();
    ZLOGD(LABEL, "get result from server data = %{public}s", reply.c_str());
    return error;
}

int TestServiceProxy::TestSyncTransaction(int data, int &reply, int delayTime)
{
    int error;
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    ZLOGD(LABEL, "send to server data = %{public}d", data);
    if (data > 0) {
        dataParcel.WriteInt32(data);
        dataParcel.WriteInt32(delayTime);
    }
    error = Remote()->SendRequest(TRANS_ID_SYNC_TRANSACTION, dataParcel, replyParcel, option);
    reply = replyParcel.ReadInt32();
    ZLOGD(LABEL, "get result from server data = %{public}d", reply);
    return error;
}

int TestServiceProxy::TestSendTooManyRequest(int data, int &reply)
{
    int error;
    int delayTime = 0;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel[SEDNREQUEST_TIMES];

    ZLOGD(LABEL, "send to server data = %{public}d", data);
    if (data > 0) {
        dataParcel.WriteInt32(data);
        dataParcel.WriteInt32(delayTime);
    }
    for (int32_t i = 0; i < SEDNREQUEST_TIMES; i++) {
        error = Remote()->SendRequest(TRANS_ID_SYNC_TRANSACTION, dataParcel, replyParcel[i], option);
    }
    reply = replyParcel[0].ReadInt32();
    ZLOGD(LABEL, "get result from server data = %{public}d", reply);
    return error;
}

int TestServiceProxy::TestMultiThreadSendRequest(int data, int &reply)
{
    int error = 0;

    sptr<IRemoteObject> proxyObject = Remote();
    for (int32_t i = 0; i < NUMBER_OF_THREADS; i++) {
        // Different threads correspond to different sets of parcels.
        std::thread t([&proxyObject, &data, &reply] {
            MessageParcel dataParcel;
            MessageParcel replyParcel;
            MessageOption option;
            if (data > 0) {
                dataParcel.WriteInt32(data);
                dataParcel.WriteInt32(0);
            }
            int error = proxyObject->SendRequest(TRANS_ID_SYNC_TRANSACTION, dataParcel, replyParcel, option);
            if (error != 0) {
                ZLOGD(LABEL, "SendRequest is failed: %{public}d", error);
                return;
            }
            reply = replyParcel.ReadInt32();
        });
        t.detach();
        std::cout << "Thead: " << i << std::endl;
    }

    return error;
}

int TestServiceProxy::TestAsyncTransaction(int data, int timeout)
{
    MessageOption option = { MessageOption::TF_ASYNC };
    MessageParcel dataParcel, replyParcel;
    ZLOGD(LABEL, "%{public}s:in, data = %{public}d", __func__, data);
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
    ZLOGD(LABEL, "%{public}s:in, data = %{public}d", __func__, data);
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
    ZLOGD(LABEL, "PingService");
    dataParcel.WriteString16(serviceName);
    error = Remote()->SendRequest(TRANS_ID_PING_SERVICE, dataParcel, replyParcel, option);
    int result = (error == ERR_NONE) ? replyParcel.ReadInt32() : -1;
    ZLOGD(LABEL, "PingService result = %{public}d", result);
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
    ZLOGD(LABEL, "call StartDumpService");
    int fd = open("/data/dump.txt",
        O_RDWR | O_APPEND | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
    if (fd != INVALID_FD) {
        ZLOGD(LABEL, "Start Dump Service");
        std::vector<std::u16string> args;
        args.push_back(u"DumpTest");
        Remote()->Dump(fd, args);
        close(fd);
    }
}

void TestServiceProxy::TestAsyncDumpService()
{
    int fd = open("/data/nonblockingDump.txt",
        O_RDWR | O_APPEND | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
    if (fd == INVALID_FD) {
        return;
    }

    ZLOGD(LABEL, "Start Async Dump Service");
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
    if ((buffer = reinterpret_cast<const char *>(replyParcel.ReadRawData((size_t)length))) == nullptr) {
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
    int actualUid = static_cast<int>(helper.GetUid());
    int actualPid = static_cast<int>(helper.GetPid());
    ZLOGD(LABEL, "uid = %{public}d, pid = %{public}d, actualUid = %{public}d, actualPid = %{public}d",
        uid, pid, actualUid, actualPid);

    if (uid == actualUid && pid == actualPid) {
        return 0;
    }
    return -1;
}

int TestServiceProxy::TestRegisterRemoteStub(const char *descriptor, const sptr<IRemoteObject> object)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    dataParcel.WriteString(descriptor);
    dataParcel.WriteRemoteObject(object);
    int ret = Remote()->SendRequest(TRANS_ID_REGISTER_REMOTE_STUB_OBJECT, dataParcel, replyParcel, option);
    if (ret != ERR_NONE) {
        ZLOGE(LABEL, "ret = %{public}d", ret);
        return ret;
    }
    return 0;
}

int TestServiceProxy::TestUnRegisterRemoteStub(const char *descriptor)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    dataParcel.WriteString(descriptor);
    int ret = Remote()->SendRequest(TRANS_ID_UNREGISTER_REMOTE_STUB_OBJECT, dataParcel, replyParcel, option);
    if (ret != ERR_NONE) {
        ZLOGE(LABEL, "ret = %{public}d", ret);
        return ret;
    }
    return 0;
}

sptr<IRemoteObject> TestServiceProxy::TestQueryRemoteProxy(const char *descriptor)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    dataParcel.WriteString(descriptor);
    int ret = Remote()->SendRequest(TRANS_ID_QUERY_REMOTE_PROXY_OBJECT, dataParcel, replyParcel, option);
    if (ret != ERR_NONE) {
        ZLOGE(LABEL, "ret = %{public}d", ret);
        return nullptr;
    }
    auto readRemoteObject = replyParcel.ReadRemoteObject();
    return readRemoteObject;
}

constexpr char ACCESS_TOKEN_ID_IOCTL_BASE = 'A';

enum {
    GET_TOKEN_ID = 1,
    SET_TOKEN_ID,
    GET_FTOKEN_ID,
    SET_FTOKEN_ID,
    ACCESS_TOKENID_MAX_NR,
};

#define ACCESS_TOKENID_SET_TOKENID \
    _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, SET_TOKEN_ID, unsigned long long)
#define ACCESS_TOKENID_SET_FTOKENID \
    _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, SET_FTOKEN_ID, unsigned long long)

constexpr int ACCESS_TOKEN_OK = 0;
constexpr int ACCESS_TOKEN_ERROR = -1;

constexpr char TOKENID_DEVNODE[] = "/dev/access_token_id";

int RpcSetSelfTokenID(uint64_t tokenID)
{
    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_ERROR;
    }
    int ret = ioctl(fd, ACCESS_TOKENID_SET_TOKENID, &tokenID);
    if (ret) {
        close(fd);
        return ACCESS_TOKEN_ERROR;
    }

    close(fd);
    return ACCESS_TOKEN_OK;
}

int RpcSetFirstCallerTokenID(uint64_t tokenID)
{
    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_ERROR;
    }
    int ret = ioctl(fd, ACCESS_TOKENID_SET_FTOKENID, &tokenID);
    if (ret) {
        close(fd);
        return ACCESS_TOKEN_ERROR;
    }

    close(fd);
    return ACCESS_TOKEN_OK;
}

bool TestServiceProxy::CheckTokenSelf(uint64_t token, uint64_t tokenSelf, uint64_t ftoken, uint64_t ftoken_expected)
{
    if (token != tokenSelf) {
        ZLOGE(LABEL, "token != tokenSelf");
        return false;
    }
    if (ftoken != ftoken_expected) {
        ZLOGE(LABEL, "ftoken != ftoken_expected");
        return false;
    }
    return true;
}

bool TestServiceProxy::CheckSetFirstToken(uint64_t ftoken_expected)
{
    int ret = RpcSetFirstCallerTokenID(ftoken_expected);
    if (ret != 0) {
        ZLOGE(LABEL, "RpcSetFirstCallerTokenID ret = %{public}d", ret);
        return false;
    }
    uint64_t result = RpcGetFirstCallerTokenID();
    if (result != ftoken_expected) {
        ZLOGE(LABEL, "TestServiceProxy get ftoken after set: %{public}" PRIu64, result);
        return false;
    }
    return true;
}

bool TestServiceProxy::CheckSetSelfToken(uint64_t token_expected)
{
    int ret = RpcSetSelfTokenID(token_expected);
    if (ret != 0) {
        ZLOGE(LABEL, "RpcSetSelfTokenID ret = %{public}d", ret);
        return false;
    }
    uint64_t result = RpcGetSelfTokenID();
    if (result != token_expected) {
        ZLOGE(LABEL, "TestServiceProxy get selftoken after set: %{public}" PRIu64, result);
        return false;
    }
    return true;
}

int TestServiceProxy::TestAccessTokenID64(uint64_t token_expected, uint64_t ftoken_expected)
{
    MessageOption option;
    MessageParcel dataParcel, replyParcel1, replyParcel2;
    uint64_t token  = IPCSkeleton::GetCallingFullTokenID();
    uint64_t ftoken  = IPCSkeleton::GetFirstFullTokenID();
    uint64_t tokenSelf = IPCSkeleton::GetSelfTokenID();
    uint64_t oldTokenSelf = tokenSelf;
    int32_t ret = 0;

    if (!CheckTokenSelf(token, tokenSelf, ftoken, 0)) {
        return -1;
    }
    if (!CheckSetFirstToken(ftoken_expected)) {
        ret = -1;
        goto ERR;
    }
    if (!CheckSetSelfToken(token_expected)) {
        ret = -1;
        goto ERR;
    }
    ret = Remote()->SendRequest(TRANS_ID_ACCESS_TOKENID_64, dataParcel, replyParcel1, option);
    if (ret != ERR_NONE) {
        ZLOGE(LABEL, "SendRequest ret = %{public}d", ret);
        ret = -1;
        goto ERR;
    }
    token  = replyParcel1.ReadUint64();
    ftoken  = replyParcel1.ReadUint64();

    if (token != token_expected) {
        ZLOGE(LABEL, "token != token_expected, token:%{public}" PRIu64, token);
        ret = -1;
        goto ERR;
    }
    if (ftoken != ftoken_expected) {
        ZLOGE(LABEL, "ftoken != ftoken_expected, ftoken:%{public}" PRIu64, ftoken);
        ret = -1;
        goto ERR;
    }

ERR:
    RpcSetFirstCallerTokenID(0);
    RpcSetSelfTokenID(oldTokenSelf);
    return ret;
}

int TestServiceProxy::TestAccessTokenID(int32_t ftoken_expected)
{
    MessageOption option;
    MessageParcel dataParcel, replyParcel1, replyParcel2;

    int32_t token  = (int32_t)IPCSkeleton::GetCallingTokenID();
    int32_t ftoken  = (int32_t)IPCSkeleton::GetFirstTokenID();
    int32_t tokenSelf = RpcGetSelfTokenID();
    ZLOGE(LABEL, "TestServiceProxy tokenSelf: %{public}d", tokenSelf);
    ZLOGE(LABEL, "TestServiceProxy ftoken: %{public}d", ftoken);
    ZLOGE(LABEL, "TestServiceProxy ftoken_expected: %{public}d", ftoken_expected);
    if (!CheckTokenSelf(token, tokenSelf, ftoken, 0)) {
        ZLOGE(LABEL, "first");
        return -1;
    }
    if (!CheckSetFirstToken(ftoken_expected)) {
        return -1;
    }
    int ret = Remote()->SendRequest(TRANS_ID_ACCESS_TOKENID, dataParcel, replyParcel1, option);
    if (ret != ERR_NONE) {
        ZLOGE(LABEL, "SendRequest ret = %{public}d", ret);
        return ret;
    }
    token  = replyParcel1.ReadInt32();
    ftoken  = replyParcel1.ReadInt32();
    if (!CheckTokenSelf(token, tokenSelf, ftoken, ftoken_expected)) {
        ZLOGE(LABEL, "second");
        return -1;
    }
    if (!CheckSetSelfToken(666)) { // 666: test data
        return -1;
    }
    ret = Remote()->SendRequest(TRANS_ID_ACCESS_TOKENID, dataParcel, replyParcel2, option);
    if (ret != ERR_NONE) {
        ZLOGE(LABEL, "ret = %{public}d", ret);
        return ret;
    }
    token  = replyParcel2.ReadInt32();
    ftoken  = replyParcel2.ReadInt32();
    if (!CheckTokenSelf(token, tokenSelf, ftoken, ftoken_expected)) {
        ZLOGE(LABEL, "third");
        return -1;
    }
    ret = RpcSetFirstCallerTokenID(0);
    ret = RpcSetSelfTokenID(0);
    if (ret != ERR_NONE) {
        return -1;
    }
    return 0;
}

int TestServiceProxy::TestMessageParcelAppend(MessageParcel &dst, MessageParcel &src)
{
    bool res = dst.Append(src);
    if (!res) {
        ZLOGE(LABEL, "message parcel append without ipc failed");
        return -1;
    }
    return 0;
}

int TestServiceProxy::TestMessageParcelAppendWithIpc(MessageParcel &dst, MessageParcel &src,
    MessageParcel &reply, bool withObject)
{
    bool res = dst.Append(src);
    if (!res) {
        ZLOGE(LABEL, "message parcel append with ipc failed");
        return -1;
    }
    MessageOption option;
    uint32_t code = TRANS_MESSAGE_PARCEL_ADDPED;
    if (withObject) {
        code = TRANS_MESSAGE_PARCEL_ADDPED_WITH_OBJECT;
    }
    int ret = Remote()->SendRequest(code, dst, reply, option);
    ZLOGE(LABEL, "TestMessageParcelAppend with ipc sendrequest ret = %{public}d", ret);
    return ret;
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
    ZLOGD(LABEL, "send to server data = %{public}d", data);
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
    ZLOGD(LABEL, "%{public}s:PingService: result=%{public}d", __func__, result);
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
        ZLOGE(LABEL, "%{public}s:get len failed, len = %{public}d", __func__, len);
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

    ZLOGE(LABEL, "calling before reset uid = %{public}d, pid = %{public}d",
        IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingPid());
    std::string token = IPCSkeleton::ResetCallingIdentity();

    ZLOGE(LABEL, "calling before set uid = %{public}d, pid = %{public}d",
        IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingPid());
    if (!IPCSkeleton::SetCallingIdentity(token)) {
        ZLOGE(LABEL, "Set Calling Identity fail");
        return 0;
    }

    ZLOGE(LABEL, "calling after set uid = %{public}d, pid = %{public}d",
        IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingPid());
    return 0;
}

int32_t TestServiceStub::ServerNestingSend(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    sptr<IFoo> foo = iface_cast<IFoo>(object);
    int innerResult = foo->TestNestingSend(data.ReadInt32());
    reply.WriteInt32(innerResult);
    return 0;
}

int32_t TestServiceStub::ServerAccessTokenId(MessageParcel &data, MessageParcel &reply)
{
    int32_t token = static_cast<int32_t>(IPCSkeleton::GetCallingTokenID());
    int32_t ftoken = static_cast<int32_t>(IPCSkeleton::GetFirstTokenID());
    ZLOGE(LABEL, "server GetCallingTokenID:%{public}d", token);
    ZLOGE(LABEL, "server GetFirstTokenID:%{public}d", ftoken);
    reply.WriteInt32(token);
    reply.WriteInt32(ftoken);
    return 0;
}

int32_t TestServiceStub::ServerAccessTokenId64(MessageParcel &data, MessageParcel &reply)
{
    uint64_t token = IPCSkeleton::GetCallingFullTokenID();
    uint64_t ftoken = IPCSkeleton::GetFirstFullTokenID();
    ZLOGE(LABEL, "server GetCallingFullTokenID:%{public}" PRIu64, token);
    ZLOGE(LABEL, "server GetFirstFullTokenID:%{public}" PRIu64, ftoken);
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
            std::cout<< "Enable serial invoke flag" << std::endl;
        } else {
            std::cout<< "Not enable serial invoke flag" << std::endl;
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

    std::cout << "Current thread ID = " << std::this_thread::get_id();
    std::cout << " Send to server data = " << value << std::endl;
    dataParcel.WriteString(value);
    ret = IPCObjectStub::SendRequest(TRANS_ENABLE_SERIAL_INVOKE_FLAG, dataParcel, replyParcel, option);
    std::string result = replyParcel.ReadString();

    std::cout << "Current thread ID = " << std::this_thread::get_id();
    std::cout << " Get result from server data = " << result << std::endl;
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
    ZLOGD(LABEL, "enter transfer raw data");
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
    if ((buffer = reinterpret_cast<const char *>(data.ReadRawData((size_t)length))) == nullptr) {
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

int32_t TestServiceStub::ReplyRawData(MessageParcel &data, MessageParcel &reply)
{
    ZLOGD(LABEL, "enter reply raw data");
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
        !reply.WriteRawData(buffer, (size_t)length) ||
        !reply.WriteInt32(length)) {
        ZLOGE(LABEL, "fail to write parcel");
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

bool TestDeathRecipient::gotDeathRecipient_ = false;

bool TestDeathRecipient::GotDeathRecipient()
{
    return gotDeathRecipient_;
}

void TestDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    gotDeathRecipient_ = true;
    ZLOGD(LABEL, "recv death notice");
}

TestDeathRecipient::TestDeathRecipient()
{
}

TestDeathRecipient::~TestDeathRecipient()
{
}
}  // namespace OHOS
