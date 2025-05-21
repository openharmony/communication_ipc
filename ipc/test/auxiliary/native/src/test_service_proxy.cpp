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

#include "test_service_proxy.h"
#include <cinttypes>
#include <fcntl.h>
#include <iostream>
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
#include "fd_san.h"

namespace OHOS {
using namespace OHOS::HiviewDFX;

constexpr int32_t SEDNREQUEST_TIMES = 2000;
constexpr int32_t NUMBER_OF_THREADS = 20;

TestServiceProxy::TestServiceProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ITestService>(impl)
{
}

int TestServiceProxy::TestEnableSerialInvokeFlag()
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    std::string value = "testData";

    ZLOGI(LABEL, "Send to server data = %{public}s", value.c_str());
    dataParcel.WriteString(value);
    auto remote = Remote();
    if (remote == nullptr) {
        ZLOGI(LABEL, "The obtained proxy is a null pointer");
        return -1;
    }

    int ret = remote->SendRequest(TRANS_ENABLE_SERIAL_INVOKE_FLAG, dataParcel, replyParcel, option);
    std::string reply = replyParcel.ReadString();
    ZLOGI(LABEL, "Get result from server data = %{public}s", reply.c_str());
    return ret;
}

int TestServiceProxy::TestSyncTransaction(int value, int &reply, int delayTime)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    int ret = -1;

    ZLOGI(LABEL, "Send to server data = %{public}d", value);
    if (value > 0) {
        dataParcel.WriteInt32(value);
        dataParcel.WriteInt32(delayTime);
    }
    auto remote = Remote();
    if (remote == nullptr) {
        ZLOGI(LABEL, "The obtained proxy is a null pointer");
        return ret;
    }

    ret = remote->SendRequest(TRANS_ID_SYNC_TRANSACTION, dataParcel, replyParcel, option);
    if (ret != 0) {
        return ret;
    }

    reply = replyParcel.ReadInt32();
    ZLOGI(LABEL, "Get result from server data = %{public}d", reply);
    return ret;
}

int TestServiceProxy::TestSendTooManyRequest(int data, int &reply)
{
    int ret = 0;
    int delayTime = 0;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel[SEDNREQUEST_TIMES];

    ZLOGI(LABEL, "Send to server data = %{public}d", data);
    if (data > 0) {
        dataParcel.WriteInt32(data);
        dataParcel.WriteInt32(delayTime);
    }
    for (int32_t i = 0; i < SEDNREQUEST_TIMES; i++) {
        ret = Remote()->SendRequest(TRANS_ID_SYNC_TRANSACTION, dataParcel, replyParcel[i], option);
    }
    reply = replyParcel[0].ReadInt32();
    ZLOGI(LABEL, "Get result from server data = %{public}d", reply);
    return ret;
}

int TestServiceProxy::TestMultiThreadSendRequest(int data, int &reply)
{
    int ret = 0;

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
            int ret = proxyObject->SendRequest(TRANS_ID_SYNC_TRANSACTION, dataParcel, replyParcel, option);
            if (ret != 0) {
                ZLOGI(LABEL, "SendRequest is failed: %{public}d", ret);
                return;
            }
            reply = replyParcel.ReadInt32();
        });
        t.detach();
    }
    sleep(1); // Waiting for the thread to finish executing

    return ret;
}

int TestServiceProxy::TestAsyncTransaction(int data, int timeout)
{
    MessageOption option = { MessageOption::TF_ASYNC };
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    ZLOGI(LABEL, "TestAsyncTransaction is called, data = %{public}d", data);
    dataParcel.WriteInt32(data);
    dataParcel.WriteInt32(timeout);
    dataParcel.WriteBool(false);
    auto remote = Remote();
    if (remote == nullptr) {
        ZLOGE(LABEL, "remote is nullptr");
        return -1;
    }
    return remote->SendRequest(TRANS_ID_ASYNC_TRANSACTION, dataParcel, replyParcel, option);
}

int TestServiceProxy::TestAsyncCallbackTrans(int data, int &reply, int timeout)
{
    int ret;
    MessageOption option = { MessageOption::TF_ASYNC };
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    ZLOGI(LABEL, "TestAsyncCallbackTrans is called, data = %{public}d", data);
    dataParcel.WriteInt32(data);
    dataParcel.WriteInt32(timeout);
    dataParcel.WriteBool(true);
    sptr<FooStub> fooCallback = new FooStub();
    dataParcel.WriteRemoteObject(fooCallback->AsObject());
    ret = Remote()->SendRequest(TRANS_ID_ASYNC_TRANSACTION, dataParcel, replyParcel, option);
    reply = fooCallback->WaitForAsyncReply(timeout);

    FooStub::CleanDecTimes();
    fooCallback = nullptr;
    if (FooStub::GetDecTimes() != 1) {
        ret = ERR_TRANSACTION_FAILED;
    }
    return ret;
}

int TestServiceProxy::TestZtraceTransaction(std::string &send, std::string &reply, int len)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;

    dataParcel.WriteInt32(len);
    dataParcel.WriteString(send);
    int ret = Remote()->SendRequest(TRANS_ID_ZTRACE_TRANSACTION, dataParcel, replyParcel, option);
    if (ret != 0) {
        return ret;
    }

    if (!replyParcel.ReadString(reply)) {
        return -1;
    }

    return ret;
}

int TestServiceProxy::TestPingService(const std::u16string &serviceName)
{
    int ret;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    ZLOGI(LABEL, "PingService");
    dataParcel.WriteString16(serviceName);
    ret = Remote()->SendRequest(TRANS_ID_PING_SERVICE, dataParcel, replyParcel, option);
    int result = (ret == ERR_NONE) ? replyParcel.ReadInt32() : -1;
    ZLOGI(LABEL, "PingService result = %{public}d", result);
    return result;
}

sptr<IFoo> TestServiceProxy::TestGetFooService()
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
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
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    sptr<IPCFileDescriptor> desc;
    option.SetFlags(MessageOption::TF_ACCEPT_FDS);
    Remote()->SendRequest(TRANS_ID_TRANSACT_FILE_DESC, dataParcel, replyParcel, option);
    int fd = replyParcel.ReadFileDescriptor();
    return fd;
}

int TestServiceProxy::TestStringTransaction(const std::string &data)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    dataParcel.WriteString(data);
    Remote()->SendRequest(TRANS_ID_STRING_TRANSACTION, dataParcel, replyParcel, option);
    int testSize = replyParcel.ReadInt32();
    return testSize;
}

int TestServiceProxy::TestDumpService()
{
    ZLOGI(LABEL, "call StartDumpService");
    int fd = open("/data/dump.txt", O_RDWR | O_APPEND | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
    if (fd == INVALID_FD) {
        ZLOGE(LABEL, "Call to open system function failed.");
        return -1;
    }
    fdsan_exchange_owner_tag(fd, 0, IPC_FD_TAG);
    ZLOGI(LABEL, "Start Dump Service");
    std::vector<std::u16string> args;
    args.push_back(u"DumpTest");
    int ret = Remote()->Dump(fd, args);
    if (ret != 0) {
        return -1;
    }
    fdsan_close_with_tag(fd, IPC_FD_TAG);
    return ret;
}

int TestServiceProxy::TestRawDataTransaction(int length, int &reply)
{
    int ret;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    ZLOGE(LABEL, "Send to server data length = %{public}d", length);
    if (length <= 1 || static_cast<unsigned>(length) > dataParcel.GetRawDataCapacity()) {
        ZLOGE(LABEL, "length should > 1, length is %{public}d", length);
        return -1;
    }
    unsigned char *buffer = new (std::nothrow) unsigned char[length];
    if (buffer == nullptr) {
        ZLOGE(LABEL, "New buffer failed of length = %{public}d", length);
        return -1;
    }
    buffer[0] = 'a';
    buffer[length - 1] = 'z';

    dataParcel.WriteInt32(length);
    dataParcel.WriteRawData(buffer, length);
    dataParcel.WriteInt32(length);
    ret = Remote()->SendRequest(TRANS_ID_RAWDATA_TRANSACTION, dataParcel, replyParcel, option);
    reply = replyParcel.ReadInt32();
    ZLOGE(LABEL, "Get result from server data = %{public}d", reply);
    delete [] buffer;
    return ret;
}

int TestServiceProxy::TestRawDataReply(int length)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (length <= 1 || static_cast<unsigned>(length) > dataParcel.GetRawDataCapacity()) {
        ZLOGE(LABEL, "Length should > 1, length is %{public}d", length);
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
        ZLOGE(LABEL, "Buffer error, length = %{public}d", length);
        return ERR_INVALID_DATA;
    }

    if (replyParcel.ReadInt32() != length) {
        ZLOGE(LABEL, "Read raw data after failed, length = %{public}d", length);
        return ERR_INVALID_DATA;
    }

    return ERR_NONE;
}

int TestServiceProxy::TestCallingUidPid()
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
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
    ZLOGI(LABEL, "uid = %{public}d, pid = %{public}d, actualUid = %{public}d, actualPid = %{public}d",
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
        ZLOGE(LABEL, "SendRequest failed ret = %{public}d", ret);
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
    FILE *fp = fopen(TOKENID_DEVNODE, "r+");
    if (fp == nullptr) {
        return ACCESS_TOKEN_ERROR;
    }
    int fd = fileno(fp);
    if (fd < 0) {
        (void)fclose(fp);
        return ACCESS_TOKEN_ERROR;
    }
    int ret = ioctl(fd, ACCESS_TOKENID_SET_TOKENID, &tokenID);
    if (ret != 0) {
        (void)fclose(fp);
        return ACCESS_TOKEN_ERROR;
    }
    (void)fclose(fp);
    return ACCESS_TOKEN_OK;
}

int RpcSetFirstCallerTokenID(uint64_t tokenID)
{
    FILE *fp = fopen(TOKENID_DEVNODE, "r+");
    if (fp == nullptr) {
        return ACCESS_TOKEN_ERROR;
    }
    int fd = fileno(fp);
    if (fd < 0) {
        (void)fclose(fp);
        return ACCESS_TOKEN_ERROR;
    }
    int ret = ioctl(fd, ACCESS_TOKENID_SET_FTOKENID, &tokenID);
    if (ret != 0) {
        (void)fclose(fp);
        return ACCESS_TOKEN_ERROR;
    }
    (void)fclose(fp);
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
    MessageParcel dataParcel;
    MessageParcel replyParcel1;
    MessageParcel replyParcel2;
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
    token = replyParcel1.ReadUint64();
    ftoken = replyParcel1.ReadUint64();

    if (token != token_expected) {
        ZLOGE(LABEL, "token != token_expected, token = %{public}" PRIu64, token);
        ret = -1;
        goto ERR;
    }
    if (ftoken != ftoken_expected) {
        ZLOGE(LABEL, "ftoken != ftoken_expected, ftoken = %{public}" PRIu64, ftoken);
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
    MessageParcel dataParcel;
    MessageParcel replyParcel1;
    MessageParcel replyParcel2;

    int32_t token  = (int32_t)IPCSkeleton::GetCallingTokenID();
    int32_t ftoken  = (int32_t)IPCSkeleton::GetFirstTokenID();
    int32_t tokenSelf = RpcGetSelfTokenID();
    ZLOGI(LABEL, "TestServiceProxy tokenSelf: %{public}d", tokenSelf);
    ZLOGI(LABEL, "TestServiceProxy ftoken: %{public}d", ftoken);
    ZLOGI(LABEL, "TestServiceProxy ftoken_expected: %{public}d", ftoken_expected);
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
        ZLOGE(LABEL, "Message parcel append without ipc failed");
        return -1;
    }
    return 0;
}

int TestServiceProxy::TestMessageParcelAppendWithIpc(MessageParcel &dst, MessageParcel &src,
    MessageParcel &reply, bool withObject)
{
    bool res = dst.Append(src);
    if (!res) {
        ZLOGE(LABEL, "Message parcel append with ipc failed");
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
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    std::u16string legalData(length, 'a');
    dataParcel.WriteString16(legalData);
    for (int i = 0; i < count; i++) {
        ret = Remote()->SendRequest(TRANS_ID_FLUSH_ASYNC_CALLS, dataParcel, replyParcel, option);
        if (ret != ERR_NONE) {
            ZLOGE(LABEL, "Fail to send request when count = %{public}d, ret = %{public}d", count, ret);
            return ret;
        }
    }

    ret = IPCSkeleton::FlushCommands(this->AsObject());
    return ret;
}

int TestServiceProxy::TestMultipleProcesses(int data, int &rep, int delayTime)
{
    int ret;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    ZLOGI(LABEL, "Send to server data = %{public}d", data);
    if (data > 0) {
        dataParcel.WriteInt32(data);
        dataParcel.WriteInt32(delayTime);
    }
    ret = Remote()->SendRequest(TRANS_ID_MULTIPLE_PROCESSES, dataParcel, replyParcel, option);
    rep = replyParcel.ReadInt32();
    ret += replyParcel.ReadInt32();
    return ret;
}

std::u16string TestServiceProxy::TestAshmem(sptr<Ashmem> ashmem, int32_t contentSize)
{
    if (ashmem == nullptr || contentSize <= 0) {
        return u"";
    }

    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInt32(contentSize) || !dataParcel.WriteAshmem(ashmem)) {
        return u"";
    }

    int ret = Remote()->SendRequest(TRANS_ID_ASHMEM, dataParcel, replyParcel, option);
    if (ret != ERR_NONE) {
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
    ZLOGW(LABEL, "Start");
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    sptr<IFoo> foo = new FooStub();
    sptr<IRemoteObject> sendFoo = foo->AsObject();
    sendFoo->SetBehavior(Parcelable::BehaviorFlag::HOLD_OBJECT);
    if (!dataParcel.WriteRemoteObject(sendFoo) || !dataParcel.WriteInt32(sendCode)) {
        ZLOGE(LABEL, "Fail to write data.");
        return -1;
    }
    int ret = Remote()->SendRequest(TRANS_ID_NESTING_SEND, dataParcel, replyParcel, option);
    replyCode = replyParcel.ReadInt32();
    ZLOGW(LABEL, "Outer = %{public}d, inner = %{public}d", ret, replyCode);
    return ret;
}

int TestServiceProxy::TestQueryThreadInvocationState()
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;

    auto remote = Remote();
    if (remote == nullptr) {
        ZLOGI(LABEL, "The obtained proxy is a null pointer");
        return -1;
    }

    int ret = remote->SendRequest(TRANS_ID_QUERY_THREAD_INVOCATION_STATE, dataParcel, replyParcel, option);
    int reply = replyParcel.ReadInt32();
    ZLOGI(LABEL, "Get result from server data = %{public}d %{public}d", reply, ret);
    if (reply != STATUS_NOT_FIRST_INVOKE) {
        ret = ERR_TRANSACTION_FAILED;
    }
    return ret;
}
}  // namespace OHOS
