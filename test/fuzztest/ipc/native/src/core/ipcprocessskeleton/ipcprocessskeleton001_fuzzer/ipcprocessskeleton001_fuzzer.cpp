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

#include "ipcprocessskeleton_fuzzer.h"
#include "ipc_process_skeleton.h"
#include "fuzz_data_generator.h"
#include "message_parcel.h"
#include "string_ex.h"

namespace OHOS {
bool AttachToDetachAppInfoToStubIndexTest001()
{
    uint32_t pid;
    uint32_t uid;
    uint32_t tokenId;
    uint64_t stubIndex;
    int32_t listenFd;
    std::string deviceId;
    if (!GenerateUint32(pid) || !GenerateUint32(uid) || !GenerateUint32(tokenId) || !GenerateInt32(listenFd) ||
        !GenerateUint64(stubIndex) || !GenerateStringByLength(deviceId)) {
        return false;
    }
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->AttachAppInfoToStubIndex(pid, uid, tokenId, deviceId, stubIndex, listenFd);
    current->QueryAppInfoToStubIndex(pid, uid, tokenId, deviceId, stubIndex, listenFd);
    current->DetachAppInfoToStubIndex(stubIndex);
    current->AttachAppInfoToStubIndex(pid, uid, tokenId, deviceId, stubIndex, listenFd);
    current->DetachAppInfoToStubIndex(pid, uid, tokenId, deviceId, stubIndex, listenFd);
    return true;
}

bool AttachToDetachAppInfoToStubIndexTest002()
{
    uint32_t pid;
    uint32_t uid;
    uint32_t tokenId;
    int32_t listenFd;
    std::string deviceId;
    if (!GenerateUint32(pid) || !GenerateUint32(uid) || !GenerateUint32(tokenId) || !GenerateInt32(listenFd) ||
        !GenerateStringByLength(deviceId)) {
        return false;
    }
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->AttachAppInfoToStubIndex(pid, uid, tokenId, deviceId, listenFd);
    current->DetachAppInfoToStubIndex(listenFd);
    current->AttachAppInfoToStubIndex(pid, uid, tokenId, deviceId, listenFd);
    current->DetachAppInfoToStubIndex(pid, uid, tokenId, deviceId, listenFd);
    return true;
}

bool SetIPCProxyLimitTest()
{
    std::function<void(uint64_t num)> callback;
    uint64_t num;
    if (!GenerateUint64(num)) {
        return false;
    }
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->SetIPCProxyLimit(num, callback);
    return true;
}

bool SetMaxWorkThreadTest()
{
    int maxThreadNum = 16;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->SetMaxWorkThread(maxThreadNum);
    return true;
}

bool QueryProxyBySocketIdTest001()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    uint32_t handle;
    std::string serviceName;
    uint64_t stubIndex;
    uint32_t tokenId;
    std::string serverDeviceId;
    if (!GenerateUint32(handle) || !GenerateUint64(stubIndex) || !GenerateUint32(tokenId) ||
        !GenerateString(serviceName) || !GenerateString(serverDeviceId)) {
        return false;
    }
    sptr<IPCObjectProxy> remoteObj = new IPCObjectProxy(0, u"proxyTest", 0);
    IPCObjectProxy* proxy = remoteObj.GetRefPtr();
    
    std::shared_ptr<DBinderSessionObject> object = std::make_shared<DBinderSessionObject>(
        serviceName, serverDeviceId, stubIndex, proxy, tokenId);
    current->ProxyAttachDBinderSession(handle, object);
    std::vector<uint32_t> proxyHandle;
    current->QueryProxyBySocketId(handle, proxyHandle);
    current->ProxyDetachDBinderSession(handle, object->GetProxy());
    return true;
}

bool QueryProxyBySocketIdTest002()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    int32_t socketId;
    if (!GenerateInt32(socketId)) {
        return false;
    }
    std::vector<uint32_t> proxyHandle;
    current->QueryProxyBySocketId(socketId, proxyHandle);
    return true;
}

bool QuerySessionByInfoTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    std::string name;
    std::string deviceId;
    if (!GenerateString(name) || !GenerateString(deviceId)) {
        return false;
    }
    current->QuerySessionByInfo(name, deviceId);
    return true;
}

bool AttachThreadLockInfoTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    std::shared_ptr<SocketThreadLockInfo> object = std::make_shared<SocketThreadLockInfo>();
    std::thread::id threadId = std::this_thread::get_id();
    current->AttachThreadLockInfo(object, threadId);
    current->QueryThreadLockInfo(threadId);
    current->DetachThreadLockInfo(threadId);
    return true;
}

bool EraseThreadBySeqNumberTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    uint64_t seqNumber;
    if (!GenerateUint64(seqNumber)) {
        return false;
    }
    std::shared_ptr<ThreadMessageInfo> messageInfo = std::make_shared<ThreadMessageInfo>();
    current->AddThreadBySeqNumber(seqNumber, messageInfo);
    current->QueryThreadBySeqNumber(seqNumber);
    current->EraseThreadBySeqNumber(seqNumber);
    return true;
}

bool QueryThreadBySeqNumberTest001()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    uint64_t seqNumber;
    if (!GenerateUint64(seqNumber)) {
        return false;
    }
    current->QueryThreadBySeqNumber(seqNumber);
    return true;
}

bool AddSendThreadInWaitTest001()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    uint64_t seqNumber;
    if (!GenerateUint64(seqNumber)) {
        return false;
    }
    std::shared_ptr<ThreadMessageInfo> messageInfo = std::make_shared<ThreadMessageInfo>();
    current->AddSendThreadInWait(seqNumber, messageInfo, 1);
    return true;
}

bool AddSendThreadInWaitTest002()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    std::shared_ptr<ThreadMessageInfo> messageInfo = std::make_shared<ThreadMessageInfo>();
    if (messageInfo == nullptr) {
        return false;
    }
    uint64_t seqNumber;
    int handle;
    if (!GenerateUint64(seqNumber) || !GenerateBool(messageInfo->ready) || !GenerateInt32(handle)) {
        return false;
    }
    messageInfo->socketId = handle;
    current->AddSendThreadInWait(seqNumber, messageInfo, 1);
    current->WakeUpThreadBySeqNumber(seqNumber, handle);
    current->EraseThreadBySeqNumber(seqNumber);
    return true;
}

bool GetSocketIdleThreadNumTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->GetSocketIdleThreadNum();
    return true;
}

bool GetSocketTotalThreadNumTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->GetSocketTotalThreadNum();
    return true;
}

bool WakeUpThreadBySeqNumberTest002()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    uint64_t seqNumber;
    uint32_t handle;
    if (!GenerateUint64(seqNumber) || !GenerateUint32(handle)) {
        return false;
    }
    current->WakeUpThreadBySeqNumber(seqNumber, handle);
    return true;
}

bool WakeUpThreadBySeqNumberTest003()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    uint64_t seqNumber;
    uint32_t handle;
    if (!GenerateUint64(seqNumber) || !GenerateUint32(handle)) {
        return false;
    }
    std::shared_ptr<ThreadMessageInfo> messageInfo = std::make_shared<ThreadMessageInfo>();
    messageInfo->socketId = handle;
    current->AddThreadBySeqNumber(seqNumber, messageInfo);
    current->WakeUpThreadBySeqNumber(seqNumber, handle);
    current->EraseThreadBySeqNumber(seqNumber);
    return true;
}

bool AddStubByIndexTest001()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    uint32_t handle;
    if (!GenerateUint32(handle)) {
        return false;
    }
    IRemoteObject *stubObject = reinterpret_cast<IPCObjectStub *>(handle);

    current->AddStubByIndex(stubObject);
    current->EraseStubIndex(stubObject);
    return true;
}

bool QueryStubByIndexTest001()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    uint64_t stubIndex;
    uint32_t handle;
    if (!GenerateUint64(stubIndex) || !GenerateUint32(handle)) {
        return false;
    }
    IRemoteObject *stubObject = reinterpret_cast<IPCObjectStub *>(handle);
    current->AddStubByIndex(stubObject);
    current->QueryStubByIndex(1);
    current->EraseStubIndex(stubObject);
    return true;
}

bool QueryStubByIndexTest002()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->QueryStubByIndex(0);
    return true;
}

bool QueryStubIndexTest001()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    uint32_t handle;
    if (!GenerateUint32(handle)) {
        return false;
    }
    IRemoteObject *stubObject = reinterpret_cast<IPCObjectStub *>(handle);
    current->QueryStubIndex(stubObject);
    return true;
}

bool QueryStubIndexTest002()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    uint32_t handle;
    if (!GenerateUint32(handle)) {
        return false;
    }
    IRemoteObject *stubObject = reinterpret_cast<IPCObjectStub *>(handle);
    
    current->AddStubByIndex(stubObject);
    current->QueryStubIndex(stubObject);
    current->EraseStubIndex(stubObject);
    return true;
}

bool EraseStubIndexTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    uint32_t handle;
    if (!GenerateUint32(handle)) {
        return false;
    }
    IRemoteObject *stubObject = reinterpret_cast<IPCObjectStub *>(handle);
    current->EraseStubIndex(stubObject);
    return true;
}

bool GetSeqNumberTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->GetSeqNumber();
    return true;
}

bool GetLocalDeviceIDTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->GetLocalDeviceID();
    return true;
}

bool AttachToDetachCallbackStubTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    sptr<IPCObjectStub> callbackStub = new IPCObjectStub(u"stubTest");
    sptr<IPCObjectProxy> remoteObj = new IPCObjectProxy(0, u"proxyTest", 0);
    IPCObjectProxy* ipcProxy = remoteObj.GetRefPtr();
    current->AttachCallbackStub(ipcProxy, callbackStub);
    current->QueryCallbackStub(ipcProxy);
    current->QueryCallbackProxy(callbackStub);
    current->DetachCallbackStub(ipcProxy);
    return true;
}

bool QueryHandleByDatabusSessionTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    uint32_t handle;
    std::string serviceName;
    uint64_t stubIndex;
    uint32_t tokenId;
    std::string serverDeviceId;

    if (!GenerateUint32(handle) || !GenerateUint64(stubIndex) || !GenerateUint32(tokenId) ||
        !GenerateString(serviceName) || !GenerateString(serverDeviceId)) {
        return false;
    }
    sptr<IPCObjectProxy> remoteObj = new IPCObjectProxy(0, u"proxyTest", 0);
    IPCObjectProxy* proxy = remoteObj.GetRefPtr();
    std::shared_ptr<DBinderSessionObject> object = std::make_shared<DBinderSessionObject>(
        serviceName, serverDeviceId, stubIndex, proxy, tokenId);
    current->ProxyAttachDBinderSession(handle, object);
    current->QueryHandleByDatabusSession(serviceName, serverDeviceId, stubIndex);
    current->ProxyDetachDBinderSession(handle, object->GetProxy());
    return true;
}

bool StubAttachToDetachDBinderSessionTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    uint32_t handle;
    std::string serviceName;
    uint64_t stubIndex;
    uint32_t tokenId;
    std::string serverDeviceId;

    if (!GenerateUint32(handle) || !GenerateUint64(stubIndex) || !GenerateUint32(tokenId) ||
        !GenerateString(serviceName) || !GenerateString(serverDeviceId)) {
        return false;
    }
    sptr<IPCObjectProxy> remoteObj = new IPCObjectProxy(0, u"proxyTest", 0);
    IPCObjectProxy* proxy = remoteObj.GetRefPtr();
    std::shared_ptr<DBinderSessionObject> object = std::make_shared<DBinderSessionObject>(
        serviceName, serverDeviceId, stubIndex, proxy, tokenId);
    current->StubAttachDBinderSession(handle, object);
    current->StubQueryDBinderSession(handle);
    current->StubDetachDBinderSession(handle, tokenId);
    return true;
}

bool GetDatabusNameTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->GetDatabusName();
    return true;
}

bool CreateSoftbusServerTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    std::string serverName;
    if (!GenerateString(serverName)) {
        return false;
    }
    current->CreateSoftbusServer(serverName);
    return true;
}

bool DetachCommAuthInfoBySocketIdTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    int pid;
    int uid;
    uint32_t tokenId;
    std::string deviceId;
    int32_t socketId;
    sptr<IRemoteObject> remoteObj = new IPCObjectProxy(0, u"proxyTest", 0);
    IRemoteObject *stub = remoteObj.GetRefPtr();
    if (!GenerateInt32(pid) || !GenerateInt32(uid) || !GenerateUint32(tokenId) ||
        !GenerateInt32(socketId) || !GenerateStringByLength(deviceId)) {
        return false;
    }
    current->QueryCommAuthInfo(pid, uid, tokenId, deviceId);
    current->AttachCommAuthInfo(stub, pid, uid, tokenId, deviceId);
    current->QueryCommAuthInfo(pid, uid, tokenId, deviceId);
    current->UpdateCommAuthSocketInfo(pid, uid, tokenId, deviceId, socketId);
    current->DetachCommAuthInfoBySocketId(socketId);
    return true;
}

bool DetachCommAuthInfoByStubTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    int pid;
    int uid;
    uint32_t tokenId;
    std::string deviceId;
    int32_t socketId;
    sptr<IRemoteObject> remoteObj = new IPCObjectProxy(0, u"proxyTest", 0);
    IRemoteObject *stub = remoteObj.GetRefPtr();
    if (!GenerateInt32(pid) || !GenerateInt32(uid) || !GenerateUint32(tokenId) ||
        !GenerateInt32(socketId) || !GenerateStringByLength(deviceId)) {
        return false;
    }
    current->AttachCommAuthInfo(stub, pid, uid, tokenId, deviceId);
    current->DetachCommAuthInfoByStub(stub);
    return true;
}

bool DetachCommAuthInfoTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    int pid;
    int uid;
    uint32_t tokenId;
    std::string deviceId;
    int32_t socketId;
    sptr<IRemoteObject> remoteObj = new IPCObjectProxy(0, u"proxyTest", 0);
    IRemoteObject *stub = remoteObj.GetRefPtr();
    if (!GenerateInt32(pid) || !GenerateInt32(uid) || !GenerateUint32(tokenId) ||
        !GenerateInt32(socketId) || !GenerateStringByLength(deviceId)) {
        return false;
    }
    current->AttachCommAuthInfo(stub, pid, uid, tokenId, deviceId);
    current->DetachCommAuthInfo(stub, pid, uid, tokenId, deviceId);
    return true;
}

bool AddToDeleteDataThreadToIdleTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    std::thread::id threadId = std::this_thread::get_id();
    current->GetIdleDataThread();
    current->DeleteDataThreadFromIdle(threadId);
    current->AddDataThreadToIdle(threadId);
    current->GetIdleDataThread();
    current->DeleteDataThreadFromIdle(threadId);
    return true;
}

bool AddToPopDataInfoToThreadTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    std::thread::id threadId = std::this_thread::get_id();
    std::shared_ptr<ThreadProcessInfo> processInfo = std::make_shared<ThreadProcessInfo>();
    current->PopDataInfoFromThread(threadId);
    current->AddDataInfoToThread(threadId, processInfo);
    current->PopDataInfoFromThread(threadId);
    return true;
}

bool AttachToDetachDBinderCallbackStubTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    std::string service;
    std::string device;
    std::string localDevice;
    uint64_t stubIndex;
    uint32_t handle;
    uint32_t tokenId;
    if (!GenerateString(service) || !GenerateString(device) || !GenerateString(localDevice) ||
        !GenerateUint64(stubIndex) || !GenerateUint32(handle) || !GenerateUint32(tokenId)) {
        return false;
    }
    sptr<IRemoteObject> proxy = new IPCObjectProxy(handle, u"proxyTest", tokenId);
    sptr<DBinderCallbackStub> stub = new DBinderCallbackStub(service, device, localDevice, stubIndex,
        handle, tokenId);
    current->AttachDBinderCallbackStub(proxy, stub);
    current->QueryDBinderCallbackStub(proxy);
    current->QueryDBinderCallbackProxy(stub);
    current->DetachDBinderCallbackStubByProxy(proxy);
    current->AttachDBinderCallbackStub(proxy, stub);
    current->DetachDBinderCallbackStub(stub);
    return true;
}

bool GetDBinderIdleHandleTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    std::shared_ptr<DBinderSessionObject> session = nullptr;
    current->GetDBinderIdleHandle(session);
    return true;
}

void FuzzerTestInner1(const uint8_t* data, size_t size)
{
    DataGenerator::Write(data, size);
    AttachToDetachAppInfoToStubIndexTest001();
    AttachToDetachAppInfoToStubIndexTest002();
    SetIPCProxyLimitTest();
    SetMaxWorkThreadTest();
    DataGenerator::Clear();
}

void FuzzerTestInner2(const uint8_t* data, size_t size)
{
    DataGenerator::Write(data, size);
    QueryProxyBySocketIdTest001();
    QueryProxyBySocketIdTest002();
    QuerySessionByInfoTest();
    AttachThreadLockInfoTest();
    EraseThreadBySeqNumberTest();
    QueryThreadBySeqNumberTest001();
    AddSendThreadInWaitTest001();
    AddSendThreadInWaitTest002();
    GetSocketIdleThreadNumTest();
    GetSocketTotalThreadNumTest();
    WakeUpThreadBySeqNumberTest002();
    WakeUpThreadBySeqNumberTest003();
    DataGenerator::Clear();
}

void FuzzerTestInner3(const uint8_t* data, size_t size)
{
    DataGenerator::Write(data, size);
    QueryStubByIndexTest001();
    QueryStubByIndexTest002();
    QueryStubIndexTest001();
    QueryStubIndexTest002();
    AddStubByIndexTest001();
    EraseStubIndexTest();
    GetSeqNumberTest();
    GetDBinderIdleHandleTest();
    GetLocalDeviceIDTest();
    AttachToDetachCallbackStubTest();
    QueryHandleByDatabusSessionTest();
    StubAttachToDetachDBinderSessionTest();
    GetDatabusNameTest();
    CreateSoftbusServerTest();
    DetachCommAuthInfoBySocketIdTest();
    DetachCommAuthInfoByStubTest();
    DetachCommAuthInfoTest();
    AddToDeleteDataThreadToIdleTest();
    AddToPopDataInfoToThreadTest();
    AttachToDetachDBinderCallbackStubTest();
    DataGenerator::Clear();
}

void ConvertToSecureStringFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    size_t length = parcel.GetReadableBytes();
    if (length == 0) {
        return;
    }
    const char *bufData = reinterpret_cast<const char *>(parcel.ReadBuffer(length));
    if (bufData == nullptr) {
        return;
    }
    std::string secureString(bufData, length);
    IPCProcessSkeleton::ConvertToSecureString(secureString);
}

void ConvertChannelID2IntFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int64_t databusChannelId = parcel.ReadInt64();
    IPCProcessSkeleton::ConvertChannelID2Int(databusChannelId);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzerTestInner1(data, size);
    OHOS::FuzzerTestInner2(data, size);
    OHOS::FuzzerTestInner3(data, size);
    OHOS::ConvertToSecureStringFuzzTest(data, size);
    OHOS::ConvertChannelID2IntFuzzTest(data, size);
    return 0;
}
