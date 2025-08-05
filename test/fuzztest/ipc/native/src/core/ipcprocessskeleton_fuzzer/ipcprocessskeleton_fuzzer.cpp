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
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "ipc_process_skeleton.h"
#undef private
#include "fuzz_data_generator.h"
#include "message_parcel.h"

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

bool MakeHandleDescriptorTest()
{
    int handle;
    if (!GenerateInt32(handle)) {
        return false;
    }
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->MakeHandleDescriptor(handle);
    return true;
}

bool OnThreadTerminatedTest()
{
    std::string threadName;
    if (!GenerateString(threadName)) {
        return false;
    }
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->OnThreadTerminated(threadName);
    return true;
}

bool SpawnThreadTest()
{
    int32_t policy;
    int32_t proto;
    if (!GenerateInt32(policy) || !GenerateInt32(proto)) {
        return false;
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->SpawnThread(policy, proto);
    return true;
}

bool FindOrNewObjectTest()
{
    int handle;
    if (!GenerateInt32(handle)) {
        return false;
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->FindOrNewObject(handle);
    return true;
}

bool IsContainsObjectTest001()
{
    sptr<IRemoteObject> object = new IPCObjectProxy(0, u"proxyTest", 0);

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->IsContainsObject(object);
    return true;
}

bool IsContainsObjectTest002()
{
    sptr<IRemoteObject> object = nullptr;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->IsContainsObject(object);
    return true;
}

bool AttachObjectTest001()
{
    sptr<IRemoteObject> object = nullptr;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->AttachObject(object);
    return true;
}

bool AttachObjectTest002()
{
    sptr<IRemoteObject> object = new IPCObjectProxy(0, u"proxyTest", 0);
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->AttachObject(object);
    current->DetachObject(object);
    return true;
}

bool QueryObjectTest001()
{
    int handle;
    if (!GenerateInt32(handle)) {
        return false;
    }
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    std::u16string descriptor = current->MakeHandleDescriptor(handle);
    current->QueryObject(descriptor);
    return true;
}

bool QueryObjectTest002()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->QueryObject(u"");
    return true;
}
bool DetachObjectTest001()
{
    sptr<IRemoteObject> object = nullptr;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->DetachObject(object);
    return true;
}

bool DetachObjectTest002()
{
    sptr<IRemoteObject> object = new IPCObjectProxy(0, u"proxyTest", 0);
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->DetachObject(object);
    return true;
}

bool GetProxyObjectTest()
{
    int handle;
    bool newFlag;
    if (!GenerateInt32(handle) || !GenerateBool(newFlag)) {
        return false;
    }
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = current->GetProxyObject(handle, newFlag);
    current->DetachObject(object);
    return true;
}

bool SetRegistryObjectTest001()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    sptr<IRemoteObject> object = nullptr;
    current->SetRegistryObject(object);
    return true;
}

bool SetRegistryObjectTest002()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    sptr<IRemoteObject> proxy = new IPCObjectProxy(0, u"", 0);
    current->SetRegistryObject(proxy);
    return true;
}

bool GetRegistryObjectTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->GetRegistryObject();
    return true;
}

bool BlockUntilThreadAvailableTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->BlockUntilThreadAvailable();
    return true;
}

bool LockForNumExecutingTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->LockForNumExecuting();
    return true;
}

bool UnlockForNumExecutingTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->UnlockForNumExecuting();
    return true;
}

bool AttachToDetachRawDataTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    int32_t socketId;
    uint32_t rawDataSize;
    uint64_t seqNumber;
    if (!GenerateUint32(rawDataSize) || !GenerateInt32(socketId) || !GenerateUint64(seqNumber)) {
        return false;
    }
    std::shared_ptr<InvokerRawData> rawData = std::make_shared<InvokerRawData>(rawDataSize);
    current->AttachRawData(socketId, seqNumber, rawData);
    current->QueryRawData(socketId, seqNumber);
    current->DetachRawData(socketId, seqNumber);
    return true;
}

bool GetSAMgrObjectTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    current->GetSAMgrObject();
    return true;
}

bool ProxyAttachToDetachDBinderSessionTest()
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
    std::shared_ptr<DBinderSessionObject> object = std::make_shared<DBinderSessionObject>(
        serviceName, serverDeviceId, stubIndex, nullptr, tokenId);
    current->ProxyAttachDBinderSession(handle, object);
    current->ProxyQueryDBinderSession(handle);
    current->ProxyDetachDBinderSession(handle, object->GetProxy());
    return true;
}

bool ProxyQueryDBinderSessionTest()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return false;
    }
    uint32_t handle;
    if (!GenerateUint32(handle)) {
        return false;
    }
    current->ProxyQueryDBinderSession(handle);
    return true;
}

bool ProxyMoveDBinderSessionTest()
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
    current->ProxyMoveDBinderSession(handle, proxy);
    current->ProxyDetachDBinderSession(handle, object->GetProxy());
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
    MakeHandleDescriptorTest();
    OnThreadTerminatedTest();
    SpawnThreadTest();
    FindOrNewObjectTest();
    IsContainsObjectTest001();
    IsContainsObjectTest002();
    QueryObjectTest001();
    QueryObjectTest002();
    AttachObjectTest001();
    AttachObjectTest002();
    DetachObjectTest001();
    DetachObjectTest002();
    GetProxyObjectTest();
    GetRegistryObjectTest();
    SetRegistryObjectTest001();
    SetRegistryObjectTest002();
    DataGenerator::Clear();
}

void FuzzerTestInner2(const uint8_t* data, size_t size)
{
    DataGenerator::Write(data, size);
    BlockUntilThreadAvailableTest();
    LockForNumExecutingTest();
    UnlockForNumExecutingTest();
    AttachToDetachRawDataTest();
    GetSAMgrObjectTest();
    ProxyAttachToDetachDBinderSessionTest();
    ProxyQueryDBinderSessionTest();
    ProxyMoveDBinderSessionTest();
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

void IsHandleMadeByUserFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    uint32_t handle = parcel.ReadUint32();
    IPCProcessSkeleton::IsHandleMadeByUser(handle);
}

void SetIPCProxyLimitFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int ipcProxyLimitNum = parcel.ReadInt32();
    std::function<void(uint64_t num)> callback;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    current->SetIPCProxyLimit(ipcProxyLimitNum, callback);
}

void SetMaxWorkThreadFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int maxThreadNum = parcel.ReadInt32();
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->SetMaxWorkThread(maxThreadNum);
}

void MakeHandleDescriptorFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int handle = parcel.ReadInt32();
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->MakeHandleDescriptor(handle);
}

void OnThreadTerminatedFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    std::string threadName(reinterpret_cast<const char *>(data), size);
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->OnThreadTerminated(threadName);
}

void SpawnThreadFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int policy = parcel.ReadInt32();
    int proto = parcel.ReadInt32();
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(ipcSktPtr->threadPool_->mutex_);
        if (ipcSktPtr->threadPool_->threads_.size() >= IPCProcessSkeleton::DEFAULT_WORK_THREAD_NUM) {
            return;
        }
    }
    (void)ipcSktPtr->SpawnThread(policy, proto);
}

void FindOrNewObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int handle = parcel.ReadInt32();
    const dbinder_negotiation_data *dbinderData = nullptr;
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->FindOrNewObject(handle, dbinderData);
}

void IsContainsObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    sptr<IRemoteObject> object = parcel.ReadRemoteObject();
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->IsContainsObject(object);
}

void QueryObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    bool lockFlag = parcel.ReadBool();
    const char16_t *charData = reinterpret_cast<const char16_t *>(data);
    size_t charCount = size / sizeof(char16_t);
    std::u16string descriptor(charData, charCount);
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->QueryObject(descriptor, lockFlag);
}

void AttachObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    bool lockFlag = parcel.ReadBool();
    sptr<IRemoteObject> object = parcel.ReadRemoteObject();
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->AttachObject(object, lockFlag);
}

void DetachObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    sptr<IRemoteObject> object = parcel.ReadRemoteObject();
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->DetachObject(object);
}

void GetProxyObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int handle = parcel.ReadInt32();
    bool newFlag = parcel.ReadBool();
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    (void)ipcSktPtr->GetProxyObject(handle, newFlag);
}

void SetRegistryObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    sptr<IRemoteObject> object = parcel.ReadRemoteObject();
    OHOS::IPCProcessSkeleton *ipcSktPtr = IPCProcessSkeleton::GetCurrent();
    if (ipcSktPtr == nullptr) {
        return;
    }
    ipcSktPtr->SetRegistryObject(object);
}

void WakeUpDataThreadFuzzTest(FuzzedDataProvider &provider)
{
    std::thread::id threadId = std::this_thread::get_id();
    std::thread([threadId]() {
        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return;
        }
        current->AttachThreadLockInfo(std::make_shared<SocketThreadLockInfo>(), threadId);
        current->WakeUpDataThread(threadId);
    }).detach();
}

void UIntToStringFuzzTest(FuzzedDataProvider &provider)
{
    OHOS::IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    uint32_t value = provider.ConsumeIntegral<uint32_t>();
    current->UIntToString(value);
}

void AttachOrUpdateAppAuthInfoFuzzTest(FuzzedDataProvider &provider)
{
    OHOS::IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    AppAuthInfo appAuthInfo;
    appAuthInfo.stubIndex = provider.ConsumeIntegral<uint64_t>();
    appAuthInfo.socketId = provider.ConsumeIntegral<int32_t>();
    appAuthInfo.pid = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.uid = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.tokenId = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.deviceId = provider.ConsumeRandomLengthString();
    appAuthInfo.stub = nullptr;
    current->AttachOrUpdateAppAuthInfo(appAuthInfo);
    sptr<IPCObjectStub> stubObject = sptr<IPCObjectStub>::MakeSptr();
    if (stubObject == nullptr) {
        return;
    }
    appAuthInfo.stub = stubObject.GetRefPtr();
    current->AttachOrUpdateAppAuthInfo(appAuthInfo);
}

void DetachAppAuthInfoFuzzTest(FuzzedDataProvider &provider)
{
    OHOS::IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    AppAuthInfo appAuthInfo;
    appAuthInfo.stubIndex = provider.ConsumeIntegral<uint64_t>();
    appAuthInfo.socketId = provider.ConsumeIntegral<int32_t>();
    appAuthInfo.pid = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.uid = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.tokenId = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.deviceId = provider.ConsumeRandomLengthString();
    sptr<IPCObjectStub> stubObject = sptr<IPCObjectStub>::MakeSptr();
    if (stubObject == nullptr) {
        return;
    }
    appAuthInfo.stub = stubObject.GetRefPtr();
    current->DetachAppAuthInfo(appAuthInfo);
    current->AttachOrUpdateAppAuthInfo(appAuthInfo);
    current->DetachAppAuthInfo(appAuthInfo);
}

void DetachAppAuthInfoBySocketIdFuzzTest(FuzzedDataProvider &provider)
{
    OHOS::IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    AppAuthInfo appAuthInfo;
    appAuthInfo.stubIndex = provider.ConsumeIntegral<uint64_t>();
    appAuthInfo.socketId = provider.ConsumeIntegral<int32_t>();
    appAuthInfo.pid = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.uid = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.tokenId = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.deviceId = provider.ConsumeRandomLengthString();
    sptr<IPCObjectStub> stubObject = sptr<IPCObjectStub>::MakeSptr();
    if (stubObject == nullptr) {
        return;
    }
    appAuthInfo.stub = stubObject.GetRefPtr();
    current->AttachOrUpdateAppAuthInfo(appAuthInfo);
    current->DetachAppAuthInfoBySocketId(appAuthInfo.socketId);
}

void DetachAppAuthInfoByStubFuzzTest(FuzzedDataProvider &provider)
{
    OHOS::IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    AppAuthInfo appAuthInfo;
    appAuthInfo.stubIndex = provider.ConsumeIntegral<uint64_t>();
    appAuthInfo.socketId = provider.ConsumeIntegral<int32_t>();
    appAuthInfo.pid = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.uid = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.tokenId = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.deviceId = provider.ConsumeRandomLengthString();
    sptr<IPCObjectStub> stubObject = sptr<IPCObjectStub>::MakeSptr();
    if (stubObject == nullptr) {
        return;
    }
    appAuthInfo.stub = stubObject.GetRefPtr();
    current->AttachOrUpdateAppAuthInfo(appAuthInfo);
    current->DetachAppAuthInfoByStub(stubObject.GetRefPtr(), appAuthInfo.stubIndex);
}

void QueryCommAuthInfoFuzzTest(FuzzedDataProvider &provider)
{
    OHOS::IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    AppAuthInfo appAuthInfo;
    appAuthInfo.stubIndex = provider.ConsumeIntegral<uint64_t>();
    appAuthInfo.socketId = provider.ConsumeIntegral<int32_t>();
    appAuthInfo.pid = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.uid = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.tokenId = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.deviceId = provider.ConsumeRandomLengthString();
    sptr<IPCObjectStub> stubObject = sptr<IPCObjectStub>::MakeSptr();
    if (stubObject == nullptr) {
        return;
    }
    appAuthInfo.stub = stubObject.GetRefPtr();
    current->AttachCommAuthInfo(appAuthInfo.stub, appAuthInfo.pid, appAuthInfo.uid, appAuthInfo.tokenId,
        appAuthInfo.deviceId);
    current->QueryCommAuthInfo(appAuthInfo);
}

void QueryAppInfoToStubIndexFuzzTest(FuzzedDataProvider &provider)
{
    OHOS::IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    AppAuthInfo appAuthInfo;
    appAuthInfo.stubIndex = provider.ConsumeIntegral<uint64_t>();
    appAuthInfo.socketId = provider.ConsumeIntegral<int32_t>();
    appAuthInfo.pid = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.uid = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.tokenId = provider.ConsumeIntegral<uint32_t>();
    appAuthInfo.deviceId = provider.ConsumeRandomLengthString();
    current->QueryAppInfoToStubIndex(appAuthInfo);
    current->AttachAppInfoToStubIndex(appAuthInfo.pid, appAuthInfo.uid, appAuthInfo.tokenId, appAuthInfo.deviceId,
        appAuthInfo.stubIndex, appAuthInfo.socketId);
    current->QueryAppInfoToStubIndex(appAuthInfo);
}

void DetachCommAuthInfoByStubFuzzTest(FuzzedDataProvider &provider)
{
    OHOS::IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    int pid = provider.ConsumeIntegral<int>();
    int uid = provider.ConsumeIntegral<int>();
    uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
    std::string deviceId = provider.ConsumeRandomLengthString();
    sptr<IPCObjectStub> stubObject = sptr<IPCObjectStub>::MakeSptr();
    if (stubObject == nullptr) {
        return;
    }
    current->AttachCommAuthInfo(stubObject.GetRefPtr(), pid, uid, tokenId, deviceId);
    current->DetachCommAuthInfoByStub(stubObject.GetRefPtr());
}

void AttachDBinderCallbackStubFuzzTest(FuzzedDataProvider &provider)
{
    OHOS::IPCProcessSkeleton *current = OHOS::IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    int handle = provider.ConsumeIntegral<int>();
    std::string serviceName = provider.ConsumeRandomLengthString();
    std::string peerDeviceID = provider.ConsumeRandomLengthString();
    std::string localDeviceID = provider.ConsumeRandomLengthString();
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
    sptr<IPCObjectProxy> proxy = sptr<IPCObjectProxy>::MakeSptr(handle);
    sptr<DBinderCallbackStub> stub =
        sptr<DBinderCallbackStub>::MakeSptr(serviceName, peerDeviceID, localDeviceID, stubIndex, handle, tokenId);
    if (proxy == nullptr || stub == nullptr) {
        return;
    }
    current->AttachDBinderCallbackStub(proxy, stub);
}

void DetachDBinderCallbackStubByProxyFuzzTest(FuzzedDataProvider &provider)
{
    OHOS::IPCProcessSkeleton *current = OHOS::IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    int handle = provider.ConsumeIntegral<int>();
    sptr<IPCObjectProxy> proxy = sptr<IPCObjectProxy>::MakeSptr(handle);
    if (proxy == nullptr) {
        return;
    }
    current->DetachDBinderCallbackStubByProxy(proxy.GetRefPtr());
}

void DetachDBinderCallbackStubFuzzTest(FuzzedDataProvider &provider)
{
    OHOS::IPCProcessSkeleton *current = OHOS::IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    int handle = provider.ConsumeIntegral<int>();
    std::string descriptor = provider.ConsumeRandomLengthString();
    std::u16string descriptor16(descriptor.begin(), descriptor.end());
    std::string service = provider.ConsumeRandomLengthString();
    std::string device = provider.ConsumeRandomLengthString();
    std::string localDevice = provider.ConsumeRandomLengthString();
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
    int proto = provider.ConsumeIntegral<int>();
    sptr<IPCObjectProxy> proxy = sptr<IPCObjectProxy>::MakeSptr(handle, descriptor16, proto);
    sptr<DBinderCallbackStub> stub =
        sptr<DBinderCallbackStub>::MakeSptr(service, device, localDevice, stubIndex, handle, tokenId);
    if (proxy == nullptr || stub == nullptr) {
        return;
    }
    current->AttachDBinderCallbackStub(proxy, stub);
    current->DetachDBinderCallbackStub(stub.GetRefPtr());
}

void QueryDBinderCallbackStubFuzzTest(FuzzedDataProvider &provider)
{
    OHOS::IPCProcessSkeleton *current = OHOS::IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    int handle = provider.ConsumeIntegral<int>();
    std::string descriptor = provider.ConsumeRandomLengthString();
    std::u16string descriptor16(descriptor.begin(), descriptor.end());
    uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
    std::string service = provider.ConsumeRandomLengthString();
    std::string device = provider.ConsumeRandomLengthString();
    std::string localDevice = provider.ConsumeRandomLengthString();
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    int proto = provider.ConsumeIntegral<int>();
    sptr<IPCObjectProxy> proxy = sptr<IPCObjectProxy>::MakeSptr(handle, descriptor16, proto);
    sptr<DBinderCallbackStub> stub =
        sptr<DBinderCallbackStub>::MakeSptr(service, device, localDevice, stubIndex, handle, tokenId);
    if (proxy == nullptr || stub == nullptr) {
        return;
    }
    current->QueryDBinderCallbackStub(proxy);
    current->AttachDBinderCallbackStub(proxy, stub);
    current->QueryDBinderCallbackStub(proxy);
}

void QueryDBinderCallbackProxyFuzzTest(FuzzedDataProvider &provider)
{
    OHOS::IPCProcessSkeleton *current = OHOS::IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    int handle = provider.ConsumeIntegral<int>();
    std::string descriptor = provider.ConsumeRandomLengthString();
    std::u16string descriptor16(descriptor.begin(), descriptor.end());
    uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
    std::string service = provider.ConsumeRandomLengthString();
    std::string device = provider.ConsumeRandomLengthString();
    std::string localDevice = provider.ConsumeRandomLengthString();
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    int proto = provider.ConsumeIntegral<int>();
    sptr<IPCObjectProxy> proxy = sptr<IPCObjectProxy>::MakeSptr(handle, descriptor16, proto);
    sptr<DBinderCallbackStub> stub =
        sptr<DBinderCallbackStub>::MakeSptr(service, device, localDevice, stubIndex, handle, tokenId);
    if (proxy == nullptr || stub == nullptr) {
        return;
    }
    current->QueryDBinderCallbackProxy(stub);
    current->AttachDBinderCallbackStub(proxy, stub);
    current->QueryDBinderCallbackProxy(stub);
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
    OHOS::IsHandleMadeByUserFuzzTest(data, size);
    OHOS::SetIPCProxyLimitFuzzTest(data, size);
    OHOS::SetMaxWorkThreadFuzzTest(data, size);
    OHOS::MakeHandleDescriptorFuzzTest(data, size);
    OHOS::OnThreadTerminatedFuzzTest(data, size);
    OHOS::SpawnThreadFuzzTest(data, size);
    OHOS::FindOrNewObjectFuzzTest(data, size);
    OHOS::IsContainsObjectFuzzTest(data, size);
    OHOS::QueryObjectFuzzTest(data, size);
    OHOS::AttachObjectFuzzTest(data, size);
    OHOS::DetachObjectFuzzTest(data, size);
    OHOS::GetProxyObjectFuzzTest(data, size);
    OHOS::SetRegistryObjectFuzzTest(data, size);

    FuzzedDataProvider provider(data, size);
    OHOS::WakeUpDataThreadFuzzTest(provider);
    OHOS::UIntToStringFuzzTest(provider);
    OHOS::AttachOrUpdateAppAuthInfoFuzzTest(provider);
    OHOS::DetachAppAuthInfoFuzzTest(provider);
    OHOS::DetachAppAuthInfoByStubFuzzTest(provider);
    OHOS::DetachAppAuthInfoBySocketIdFuzzTest(provider);
    OHOS::QueryCommAuthInfoFuzzTest(provider);
    OHOS::QueryAppInfoToStubIndexFuzzTest(provider);
    OHOS::DetachCommAuthInfoByStubFuzzTest(provider);
    OHOS::AttachDBinderCallbackStubFuzzTest(provider);
    OHOS::DetachDBinderCallbackStubByProxyFuzzTest(provider);
    OHOS::DetachDBinderCallbackStubFuzzTest(provider);
    OHOS::QueryDBinderCallbackStubFuzzTest(provider);
    OHOS::QueryDBinderCallbackProxyFuzzTest(provider);
    return 0;
}
