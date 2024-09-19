/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <securec.h>
#include "fuzz_data_generator.h"
#include "iremote_object.h"
#include "ipc_process_skeleton.h"

namespace OHOS {
    bool AttachAppInfoToStubIndexTest001()
    {
        uint32_t pid;
        uint32_t uid;
        uint32_t tokenId;
        uint64_t stubIndex;
        uint32_t listenFd;
        std::string deviceId;
        if (!GenerateUint32(pid) || !GenerateUint32(uid) || !GenerateUint32(tokenId) || !GenerateUint32(listenFd) ||
            !GenerateUint64(stubIndex) || !GenerateString(deviceId)) {
            return false;
        }
        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        current->AttachAppInfoToStubIndex(pid, uid, tokenId, deviceId, stubIndex, listenFd);
        return true;
    }

    bool AttachAppInfoToStubIndexTest002()
    {
        uint32_t pid;
        uint32_t uid;
        uint32_t tokenId;
        uint32_t listenFd;
        std::string deviceId;
        if (!GenerateUint32(pid) || !GenerateUint32(uid) || !GenerateUint32(tokenId) || !GenerateUint32(listenFd) ||
            !GenerateString(deviceId)) {
            return false;
        }
        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        current->AttachAppInfoToStubIndex(pid, uid, tokenId, deviceId, listenFd);
        return true;
    }

    bool AttachCommAuthInfoTest()
    {
        sptr<IRemoteObject> remoteObj;
        IRemoteObject *stub = remoteObj.GetRefPtr();

        int pid;
        int uid;
        uint32_t tokenId;
        std::string deviceId;
        if (!GenerateInt32(pid) || !GenerateInt32(uid) || !GenerateUint32(tokenId) || !GenerateString(deviceId)) {
            return false;
        }
        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        current->AttachCommAuthInfo(stub, pid, uid, tokenId, deviceId);
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
        sptr<IRemoteObject> object;

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
        const std::u16string &descriptor = current->MakeHandleDescriptor(handle);
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
        sptr<IRemoteObject> object;
        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        current->AttachObject(object);
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
        sptr<IRemoteObject> object;
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

    bool GetRegistryObjectTest()
    {
        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        current->GetRegistryObject();
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
        sptr<IRemoteObject> object;
        current->SetRegistryObject(object);
        
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
        if (!GenerateUint32(rawDataSize) || !GenerateInt32(socketId)) {
            return false;
        }
        std::shared_ptr<InvokerRawData> rawData = std::make_shared<InvokerRawData>(rawDataSize);
        current->AttachRawData(socketId, rawData);
        current->QueryRawData(socketId);
        current->DetachRawData(socketId);
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

    bool ProxyDetachDBinderSessionTest001()
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

    bool ProxyAttachDBinderSessionTest()
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
        if (!GenerateUint32(handle) || !GenerateString(serviceName) || !GenerateUint32(tokenId) ||
            !GenerateUint64(stubIndex) || !GenerateString(serverDeviceId)) {
            return false;
        }
        sptr<IPCObjectProxy> remoteObj;
        IPCObjectProxy* proxy = remoteObj.GetRefPtr();
        std::shared_ptr<DBinderSessionObject> object = std::make_shared<DBinderSessionObject>(
            serviceName, serverDeviceId, stubIndex, proxy, tokenId);
        current->ProxyAttachDBinderSession(handle, object);
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
        sptr<IPCObjectProxy> remoteObj;
        IPCObjectProxy* proxy = remoteObj.GetRefPtr();
        std::shared_ptr<DBinderSessionObject> object = std::make_shared<DBinderSessionObject>(
            serviceName, serverDeviceId, stubIndex, proxy, tokenId);
        current->ProxyAttachDBinderSession(handle, object);
        current->ProxyMoveDBinderSession(handle, proxy);
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
        sptr<IPCObjectProxy> remoteObj;
        IPCObjectProxy* proxy = remoteObj.GetRefPtr();
        
        std::shared_ptr<DBinderSessionObject> object = std::make_shared<DBinderSessionObject>(
            serviceName, serverDeviceId, stubIndex, proxy, tokenId);
        current->ProxyAttachDBinderSession(handle, object);
        std::vector<uint32_t> proxyHandle;
        current->QueryProxyBySocketId(handle, proxyHandle);
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

    bool DetachThreadLockInfoTest()
    {
        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        std::thread::id threadId = std::this_thread::get_id();
        current->DetachThreadLockInfo(threadId);
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
        return true;
    }

    bool QueryThreadLockInfoTest()
    {
        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        std::shared_ptr<SocketThreadLockInfo> object = std::make_shared<SocketThreadLockInfo>();
        std::thread::id threadId = std::this_thread::get_id();
        current->AttachThreadLockInfo(object, threadId);
        current->QueryThreadLockInfo(threadId);
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
        current->EraseThreadBySeqNumber(seqNumber);
        return true;
    }

    bool AddThreadBySeqNumberTest()
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
        std::shared_ptr<ThreadMessageInfo> messageInfo = std::make_shared<ThreadMessageInfo>();
        current->AddThreadBySeqNumber(seqNumber, messageInfo);
        current->QueryThreadBySeqNumber(seqNumber);
        return true;
    }

    bool QueryThreadBySeqNumberTest002()
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
        current->AddSendThreadInWait(seqNumber, messageInfo, 0);
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
        if (!GenerateUint64(seqNumber) || !GenerateBool(messageInfo->ready)) {
            return false;
        }
        current->AddSendThreadInWait(seqNumber, messageInfo, 0);
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

    bool WakeUpThreadBySeqNumberTest001()
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
        if (messageInfo == nullptr) {
            return false;
        }
        current->AddThreadBySeqNumber(seqNumber, messageInfo);
        current->WakeUpThreadBySeqNumber(seqNumber, handle);
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
        return true;
    }

    bool AddStubByIndexTest002()
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
        current->AddStubByIndex(stubObject);
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
        sptr<IPCObjectStub> callbackStub;
        sptr<IPCObjectProxy> remoteObj;
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
        sptr<IPCObjectProxy> remoteObj;
        IPCObjectProxy* proxy = remoteObj.GetRefPtr();
        std::shared_ptr<DBinderSessionObject> object = std::make_shared<DBinderSessionObject>(
            serviceName, serverDeviceId, stubIndex, proxy, tokenId);
        current->ProxyAttachDBinderSession(handle, object);
        current->QueryHandleByDatabusSession(serviceName, serverDeviceId, stubIndex);
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
        sptr<IPCObjectProxy> remoteObj;
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
        sptr<IRemoteObject> remoteObj;
        IRemoteObject *stub = remoteObj.GetRefPtr();
        if (!GenerateInt32(pid) || !GenerateInt32(uid) || !GenerateUint32(tokenId) ||
            !GenerateString(deviceId) || !GenerateInt32(socketId)) {
            return false;
        }
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
        sptr<IRemoteObject> remoteObj;
        IRemoteObject *stub = remoteObj.GetRefPtr();
        if (!GenerateInt32(pid) || !GenerateInt32(uid) || !GenerateUint32(tokenId) ||
            !GenerateString(deviceId) || !GenerateInt32(socketId)) {
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
        sptr<IRemoteObject> remoteObj;
        IRemoteObject *stub = remoteObj.GetRefPtr();
        if (!GenerateInt32(pid) || !GenerateInt32(uid) || !GenerateUint32(tokenId) ||
            !GenerateString(deviceId) || !GenerateInt32(socketId)) {
            return false;
        }
        current->AttachCommAuthInfo(stub, pid, uid, tokenId, deviceId);
        current->DetachCommAuthInfo(stub, pid, uid, tokenId, deviceId);
        return true;
    }

    void FuzzerTestInner1()
    {
        AttachAppInfoToStubIndexTest001();
        AttachAppInfoToStubIndexTest002();
        AttachCommAuthInfoTest();
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
        BlockUntilThreadAvailableTest();
        LockForNumExecutingTest();
        UnlockForNumExecutingTest();
        AttachToDetachRawDataTest();
        GetSAMgrObjectTest();
        ProxyDetachDBinderSessionTest001();
        ProxyAttachDBinderSessionTest();
        ProxyQueryDBinderSessionTest();
        ProxyMoveDBinderSessionTest();
        QueryProxyBySocketIdTest001();
        QueryProxyBySocketIdTest002();
        QuerySessionByInfoTest();
        DetachThreadLockInfoTest();
        AttachThreadLockInfoTest();
        QueryThreadLockInfoTest();
        EraseThreadBySeqNumberTest();
        AddThreadBySeqNumberTest();
        QueryThreadBySeqNumberTest001();
        QueryThreadBySeqNumberTest002();
        AddSendThreadInWaitTest001();
        AddSendThreadInWaitTest002();
        GetSocketIdleThreadNumTest();
        GetSocketTotalThreadNumTest();
        WakeUpThreadBySeqNumberTest001();
        WakeUpThreadBySeqNumberTest002();
        WakeUpThreadBySeqNumberTest003();
    }

    void FuzzerTestInner2()
    {
        QueryStubByIndexTest001();
        QueryStubByIndexTest002();
        QueryStubIndexTest001();
        QueryStubIndexTest002();
        AddStubByIndexTest001();
        AddStubByIndexTest002();
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
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    DataGenerator::Write(data, size);
    OHOS::FuzzerTestInner1();
    OHOS::FuzzerTestInner2();
    DataGenerator::Clear();
    return 0;
}
