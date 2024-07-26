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
    static constexpr int32_t THREAD_NAME_LEN = 10;
    bool AttachAppInfoToStubIndexTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint64_t)) {
            return false;
        }

        char tmp[DEVICE_ID_SIZE_MAX] = {0};
        if (memcpy_s(tmp, sizeof(tmp) - 1, data, size) != EOK) {
            return false;
        }
        DataGenerator::Write(data, size);
        uint32_t pid;
        uint32_t uid;
        uint32_t tokenId;
        uint64_t stubIndex;
        uint32_t listenFd;
        if (!GenerateUint32(pid) || !GenerateUint32(uid) || !GenerateUint32(tokenId) || !GenerateUint32(listenFd)) {
            DataGenerator::Clear();
            return false;
        }
        if (!GenerateUint64(stubIndex)) {
            DataGenerator::Clear();
            return false;
        }
        std::string deviceId = tmp;
        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            DataGenerator::Clear();
            return false;
        }

        bool ret = current->AttachAppInfoToStubIndex(pid, uid, tokenId, deviceId, stubIndex, listenFd);
        DataGenerator::Clear();
        return ret;
    }

    bool AttachCommAuthInfoTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        char tmp[DEVICE_ID_SIZE_MAX] = {0};
        if (memcpy_s(tmp, sizeof(tmp) - 1, data, size) != EOK) {
            return false;
        }

        sptr<IRemoteObject> remoteObj;
        IRemoteObject *stub = remoteObj.GetRefPtr();
        int pid = *(reinterpret_cast<const uint32_t*>(data));
        int uid = *(reinterpret_cast<const uint32_t*>(data));
        uint32_t tokenId = *(reinterpret_cast<const uint32_t*>(data));
        std::string deviceId = tmp;
        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }

        bool ret = current->AttachCommAuthInfo(stub, pid, uid, tokenId, deviceId);

        return ret;
    }

    bool SetIPCProxyLimitTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        std::function<void (uint64_t num)> callback;
        uint64_t num = *(reinterpret_cast<const uint64_t*>(data));

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        bool ret = current->SetIPCProxyLimit(num, callback);
        return ret;
    }

    bool SetMaxWorkThreadTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        int maxThreadNum = *(reinterpret_cast<const int32_t*>(data));

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        bool ret = current->SetMaxWorkThread(maxThreadNum);
        return ret;
    }

    bool MakeHandleDescriptorTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        int handle = *(reinterpret_cast<const int32_t*>(data));

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        std::u16string ret = current->MakeHandleDescriptor(handle);
        return true;
    }

    bool OnThreadTerminatedTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        char tmp[THREAD_NAME_LEN] = { 0 };
        if (memcpy_s(tmp, sizeof(tmp) - 1, data, size) != EOK) {
            return false;
        }
        std::string threadName = tmp;

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        bool ret = current->OnThreadTerminated(threadName);
        return ret;
    }

    bool SpawnThreadTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        int32_t policy = *(reinterpret_cast<const int32_t*>(data));
        int32_t proto = *(reinterpret_cast<const int32_t*>(data));

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        bool ret = current->SpawnThread(policy, proto);
        return ret;
    }

    bool FindOrNewObjectTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        int handle = *(reinterpret_cast<const int32_t*>(data));

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        bool ret = current->FindOrNewObject(handle);
        return ret;
    }

    bool IsContainsObjectTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        sptr<IRemoteObject> object = new IPCObjectStub(u"testStub");
        if (object == nullptr) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        bool ret = current->IsContainsObject(object);
        return ret;
    }

    bool QueryObjectTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        DataGenerator::Write(data, size);
        
        int handle;
        if (!GenerateInt32(handle)) {
            DataGenerator::Clear();
            return false;
        }
        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            DataGenerator::Clear();
            return false;
        }
        const std::u16string &descriptor = current->MakeHandleDescriptor(handle);
        
        bool ret = current->QueryObject(descriptor);
        DataGenerator::Clear();
        return ret;
    }

    bool AttachObjectTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        sptr<IRemoteObject> object = new IPCObjectStub(u"testStub");
        if (object == nullptr) {
            return false;
        }
        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        bool ret = current->AttachObject(object);
        return ret;
    }

    bool DetachObjectTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        sptr<IRemoteObject> object = new IPCObjectStub(u"testStub");
        if (object == nullptr) {
            return false;
        }
        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        bool ret = current->DetachObject(object);
        return ret;
    }

    bool GetProxyObjectTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }
        DataGenerator::Write(data, size);
        
        int handle;
        bool newFlag;
        if (!GenerateInt32(handle) || !GenerateBool(newFlag)) {
            DataGenerator::Clear();
            return false;
        }
        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            DataGenerator::Clear();
            return false;
        }
        bool ret = current->GetProxyObject(handle, newFlag);
        DataGenerator::Clear();
        return ret;
    }

    bool GetRegistryObjectTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        bool ret = current->GetRegistryObject();
        return ret;
    }

    bool SetRegistryObjectTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        sptr<IRemoteObject> object = new IPCObjectStub(u"testStub");
        if (object == nullptr) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        bool ret = current->SetRegistryObject(object);
        return ret;
    }

    bool BlockUntilThreadAvailableTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        current->BlockUntilThreadAvailable();
        return true;
    }

    bool LockForNumExecutingTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        current->LockForNumExecuting();
        return true;
    }

    bool UnlockForNumExecutingTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        current->UnlockForNumExecuting();
        return true;
    }

    bool AttachRawDataTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        DataGenerator::Write(data, size);
        int32_t socketId;
        uint32_t rawDataSize;
        if (!GenerateUint32(rawDataSize) || !GenerateInt32(socketId)) {
            DataGenerator::Clear();
            return false;
        }
        std::shared_ptr<InvokerRawData> rawData = std::make_shared<InvokerRawData>(rawDataSize);
        if (rawData == nullptr) {
            DataGenerator::Clear();
            return false;
        }
        bool ret = current->AttachRawData(socketId, rawData);
        DataGenerator::Clear();
        return ret;
    }

    bool DetachRawDataTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        DataGenerator::Write(data, size);
        int32_t socketId;
        if (!GenerateInt32(socketId)) {
            DataGenerator::Clear();
            return false;
        }
        bool ret = current->DetachRawData(socketId);
        DataGenerator::Clear();
        return ret;
    }

    bool QueryRawDataTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        DataGenerator::Write(data, size);
        int32_t socketId;
        if (!GenerateInt32(socketId)) {
            DataGenerator::Clear();
            return false;
        }
        std::shared_ptr<InvokerRawData> ret = current->QueryRawData(socketId);
        DataGenerator::Clear();
        return true;
    }

    bool GetSAMgrObjectTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }

        sptr<IRemoteObject> ret = current->GetSAMgrObject();
        return true;
    }

    bool ProxyDetachDBinderSessionTest001(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        DataGenerator::Write(data, size);
        uint32_t handle;
        std::string serviceName;
        uint64_t stubIndex;
        uint32_t tokenId;
        std::string serverDeviceId;
        
        if (!GenerateUint32(handle) || !GenerateUint64(stubIndex) || !GenerateUint32(tokenId) ||
            !GenerateString(serviceName) || !GenerateString(serverDeviceId)) {
            DataGenerator::Clear();
            return false;
        }
        
        std::shared_ptr<DBinderSessionObject> object = std::make_shared<DBinderSessionObject>(
            serviceName, serverDeviceId, stubIndex, nullptr, tokenId);
            
        if (object == nullptr) {
            DataGenerator::Clear();
            return false;
        }
        
        std::shared_ptr<DBinderSessionObject> object1 = current->ProxyDetachDBinderSession(handle, object->GetProxy());
        DataGenerator::Clear();
        return true;
    }
    bool ProxyDetachDBinderSessionTest002(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        DataGenerator::Write(data, size);
        uint32_t handle;
        std::string serviceName;
        uint64_t stubIndex;
        uint32_t tokenId;
        std::string serverDeviceId;
        
        if (!GenerateUint32(handle) || !GenerateUint64(stubIndex) || !GenerateUint32(tokenId) ||
            !GenerateString(serviceName) || !GenerateString(serverDeviceId)) {
            DataGenerator::Clear();
            return false;
        }
        IPCObjectProxy *proxy = new IPCObjectProxy(handle, u"proxyTest", handle);
        if (proxy == nullptr) {
            DataGenerator::Clear();
            return false;
        }
        std::shared_ptr<DBinderSessionObject> object = std::make_shared<DBinderSessionObject>(
            serviceName, serverDeviceId, stubIndex, proxy, tokenId);
            
        if (object == nullptr) {
            DataGenerator::Clear();
            delete(proxy);
            return false;
        }
        bool ret = current->ProxyAttachDBinderSession(handle, object);
        if (!ret) {
            DataGenerator::Clear();
            delete(proxy);
            return false;
        }
        
        std::shared_ptr<DBinderSessionObject> object1 = current->ProxyDetachDBinderSession(handle, object->GetProxy());
        DataGenerator::Clear();
        delete(proxy);
        return true;
    }

    bool ProxyAttachDBinderSessionTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        DataGenerator::Write(data, size);
        uint32_t handle;
        std::string serviceName;
        uint64_t stubIndex;
        uint32_t tokenId;
        std::string serverDeviceId;
        
        if (!GenerateUint32(handle) || !GenerateString(serviceName) || !GenerateUint32(tokenId) ||
            !GenerateUint64(stubIndex) || !GenerateString(serverDeviceId)) {
            DataGenerator::Clear();
            return false;
        }
        IPCObjectProxy *proxy = new IPCObjectProxy(handle, u"proxyTest", handle);
        if (proxy == nullptr) {
            DataGenerator::Clear();
            return false;
        }
        std::shared_ptr<DBinderSessionObject> object = std::make_shared<DBinderSessionObject>(
            serviceName, serverDeviceId, stubIndex, proxy, tokenId);
            
        if (object == nullptr) {
            DataGenerator::Clear();
            delete(proxy);
            return false;
        }
        bool ret = current->ProxyAttachDBinderSession(handle, object);
        DataGenerator::Clear();
        delete(proxy);
        return ret;
    }

    bool ProxyQueryDBinderSessionTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        DataGenerator::Write(data, size);
        uint32_t handle;
        
        if (!GenerateUint32(handle)) {
            DataGenerator::Clear();
            return false;
        }
        std::shared_ptr<DBinderSessionObject> ret = current->ProxyQueryDBinderSession(handle);
        DataGenerator::Clear();
        return true;
    }

    bool ProxyMoveDBinderSessionTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        DataGenerator::Write(data, size);
        uint32_t handle;
        std::string serviceName;
        uint64_t stubIndex;
        uint32_t tokenId;
        std::string serverDeviceId;
        
        if (!GenerateUint32(handle) || !GenerateUint64(stubIndex) || !GenerateUint32(tokenId) ||
            !GenerateString(serviceName) || !GenerateString(serverDeviceId)) {
            DataGenerator::Clear();
            return false;
        }
        IPCObjectProxy *proxy = new IPCObjectProxy(handle, u"proxyTest", handle);
        if (proxy == nullptr) {
            DataGenerator::Clear();
            return false;
        }
        std::shared_ptr<DBinderSessionObject> object = std::make_shared<DBinderSessionObject>(
            serviceName, serverDeviceId, stubIndex, proxy, tokenId);
            
        if (object == nullptr) {
            DataGenerator::Clear();
            delete(proxy);
            return false;
        }
        bool ret = current->ProxyAttachDBinderSession(handle, object);
        if (!ret) {
            DataGenerator::Clear();
            delete(proxy);
            return false;
        }
        ret = current->ProxyMoveDBinderSession(handle, proxy);
        DataGenerator::Clear();
        return ret;
    }

    bool QueryProxyBySocketIdTest001(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        DataGenerator::Write(data, size);
        uint32_t handle;
        std::string serviceName;
        uint64_t stubIndex;
        uint32_t tokenId;
        std::string serverDeviceId;
        
        if (!GenerateUint32(handle) || !GenerateUint64(stubIndex) || !GenerateUint32(tokenId) ||
            !GenerateString(serviceName) || !GenerateString(serverDeviceId)) {
            DataGenerator::Clear();
            return false;
        }
        IPCObjectProxy *proxy = new IPCObjectProxy(handle, u"proxyTest", handle);
        if (proxy == nullptr) {
            DataGenerator::Clear();
            return false;
        }
        std::shared_ptr<DBinderSessionObject> object = std::make_shared<DBinderSessionObject>(
            serviceName, serverDeviceId, stubIndex, proxy, tokenId);
            
        if (object == nullptr) {
            DataGenerator::Clear();
            delete(proxy);
            return false;
        }
        bool ret = current->ProxyAttachDBinderSession(handle, object);
        if (!ret) {
            DataGenerator::Clear();
            delete(proxy);
            return false;
        }
        std::vector<uint32_t> proxyHandle;
        ret = current->QueryProxyBySocketId(handle, proxyHandle);
        DataGenerator::Clear();
        return ret;
    }

    bool QueryProxyBySocketIdTest002(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        uint32_t handle;
        DataGenerator::Write(data, size);
        if (!GenerateUint32(handle)) {
            DataGenerator::Clear();
            return false;
        }
        std::vector<uint32_t> proxyHandle;
        bool ret = current->QueryProxyBySocketId(handle, proxyHandle);
        DataGenerator::Clear();
        return ret;
    }

    bool QuerySessionByInfoTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        std::string name;
        std::string deviceId;
        DataGenerator::Write(data, size);
        if (!GenerateString(name) || !GenerateString(deviceId)) {
            DataGenerator::Clear();
            return false;
        }
        
        std::shared_ptr<DBinderSessionObject> ret = current->QuerySessionByInfo(name, deviceId);
        DataGenerator::Clear();
        return true;
    }

    bool DetachThreadLockInfoTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        
        std::thread::id threadId = std::this_thread::get_id();
        bool ret = current->DetachThreadLockInfo(threadId);
        return ret;
    }

    bool AttachThreadLockInfoTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        std::shared_ptr<SocketThreadLockInfo> object = std::make_shared<SocketThreadLockInfo>();
        if (object == nullptr) {
            return false;
        }
        std::thread::id threadId = std::this_thread::get_id();
        
        bool ret = current->AttachThreadLockInfo(object, threadId);
        return ret;
    }

    bool QueryThreadLockInfoTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        std::shared_ptr<SocketThreadLockInfo> object = std::make_shared<SocketThreadLockInfo>();
        if (object == nullptr) {
            return false;
        }
        std::thread::id threadId = std::this_thread::get_id();
        
        bool ret = current->AttachThreadLockInfo(object, threadId);
        if (!ret) {
            return false;
        }
        std::shared_ptr<SocketThreadLockInfo> ret2 = current->QueryThreadLockInfo(threadId);
        if (ret2 != object) {
            return false;
        }
        return ret;
    }

    bool EraseThreadBySeqNumberTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        uint64_t seqNumber;
        DataGenerator::Write(data, size);
        if (!GenerateUint64(seqNumber)) {
            DataGenerator::Clear();
            return false;
        }
        std::shared_ptr<ThreadMessageInfo> messageInfo = std::make_shared<ThreadMessageInfo>();
        if (messageInfo == nullptr) {
            DataGenerator::Clear();
            return false;
        }
        bool ret = current->AddThreadBySeqNumber(seqNumber, messageInfo);
        if (!ret) {
            DataGenerator::Clear();
            return false;
        }
        current->EraseThreadBySeqNumber(seqNumber);
        DataGenerator::Clear();
        return true;
    }

    bool AddThreadBySeqNumberTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        uint64_t seqNumber;
        DataGenerator::Write(data, size);
        if (!GenerateUint64(seqNumber)) {
            DataGenerator::Clear();
            return false;
        }
        std::shared_ptr<ThreadMessageInfo> messageInfo = std::make_shared<ThreadMessageInfo>();
        if (messageInfo == nullptr) {
            DataGenerator::Clear();
            return false;
        }
        bool ret = current->AddThreadBySeqNumber(seqNumber, messageInfo);
        DataGenerator::Clear();
        return ret;
    }

    bool QueryThreadBySeqNumberTest001(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        uint64_t seqNumber;
        DataGenerator::Write(data, size);
        if (!GenerateUint64(seqNumber)) {
            DataGenerator::Clear();
            return false;
        }
        std::shared_ptr<ThreadMessageInfo> messageInfo = std::make_shared<ThreadMessageInfo>();
        if (messageInfo == nullptr) {
            DataGenerator::Clear();
            return false;
        }
        bool ret = current->AddThreadBySeqNumber(seqNumber, messageInfo);
        if (!ret) {
            DataGenerator::Clear();
            return false;
        }
        std::shared_ptr<ThreadMessageInfo> ret2 = current->QueryThreadBySeqNumber(seqNumber);
        if (ret2 != messageInfo) {
            DataGenerator::Clear();
            return false;
        }
        DataGenerator::Clear();
        return true;
    }

    bool QueryThreadBySeqNumberTest002(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        uint64_t seqNumber;
        DataGenerator::Write(data, size);
        if (!GenerateUint64(seqNumber)) {
            DataGenerator::Clear();
            return false;
        }
        std::shared_ptr<ThreadMessageInfo> ret2 = current->QueryThreadBySeqNumber(seqNumber);
        if (ret2 != nullptr) {
            DataGenerator::Clear();
            return false;
        }
        DataGenerator::Clear();
        return true;
    }

    bool AddSendThreadInWaitTest001(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        uint64_t seqNumber;
        int userWaitTime;
        DataGenerator::Write(data, size);
        if (!GenerateUint64(seqNumber) || !GenerateInt32(userWaitTime)) {
            DataGenerator::Clear();
            return false;
        }
        std::shared_ptr<ThreadMessageInfo> messageInfo = std::make_shared<ThreadMessageInfo>();
        if (messageInfo == nullptr) {
            DataGenerator::Clear();
            return false;
        }
        bool ret = current->AddSendThreadInWait(seqNumber, messageInfo, userWaitTime);
        
        DataGenerator::Clear();
        return ret;
    }

    bool AddSendThreadInWaitTest002(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        std::shared_ptr<ThreadMessageInfo> messageInfo = std::make_shared<ThreadMessageInfo>();
        if (messageInfo == nullptr) {
            DataGenerator::Clear();
            return false;
        }
        uint64_t seqNumber;
        int userWaitTime;
        DataGenerator::Write(data, size);
        if (!GenerateUint64(seqNumber) || !GenerateInt32(userWaitTime) || !!GenerateBool(messageInfo->ready)) {
            DataGenerator::Clear();
            return false;
        }
        
        bool ret = current->AddSendThreadInWait(seqNumber, messageInfo, userWaitTime);
        
        DataGenerator::Clear();
        return ret;
    }

    bool GetSocketIdleThreadNumTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current == nullptr) {
            return false;
        }
        int maxThreadNum;
        DataGenerator::Write(data, size);
        if (!GenerateInt32(maxThreadNum)) {
            DataGenerator::Clear();
            return false;
        }
        bool ret = current->SetMaxWorkThread(maxThreadNum);
        if (!ret) {
            DataGenerator::Clear();
            return false;
        }
        int ret2 = current->GetSocketIdleThreadNum();
        if (ret2 > maxThreadNum) {
            DataGenerator::Clear();
            return false;
        }
        
        DataGenerator::Clear();
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AttachAppInfoToStubIndexTest(data, size);
    OHOS::AttachCommAuthInfoTest(data, size);
    OHOS::SetIPCProxyLimitTest(data, size);
    OHOS::SetMaxWorkThreadTest(data, size);
    OHOS::MakeHandleDescriptorTest(data, size);
    OHOS::OnThreadTerminatedTest(data, size);
    OHOS::SpawnThreadTest(data, size);
    OHOS::FindOrNewObjectTest(data, size);
    OHOS::IsContainsObjectTest(data, size);
    OHOS::QueryObjectTest(data, size);
    OHOS::AttachObjectTest(data, size);
    OHOS::DetachObjectTest(data, size);
    OHOS::GetProxyObjectTest(data, size);
    OHOS::GetRegistryObjectTest(data, size);
    OHOS::SetRegistryObjectTest(data, size);
    OHOS::BlockUntilThreadAvailableTest(data, size);
    OHOS::LockForNumExecutingTest(data, size);
    OHOS::UnlockForNumExecutingTest(data, size);
    OHOS::AttachRawDataTest(data, size);
    OHOS::DetachRawDataTest(data, size);
    OHOS::QueryRawDataTest(data, size);
    OHOS::GetSAMgrObjectTest(data, size);
    OHOS::ProxyDetachDBinderSessionTest001(data, size);
    OHOS::ProxyDetachDBinderSessionTest002(data, size);
    OHOS::ProxyAttachDBinderSessionTest(data, size);
    OHOS::ProxyQueryDBinderSessionTest(data, size);
    OHOS::ProxyMoveDBinderSessionTest(data, size);
    OHOS::QueryProxyBySocketIdTest001(data, size);
    OHOS::QueryProxyBySocketIdTest002(data, size);
    OHOS::QuerySessionByInfoTest(data, size);
    OHOS::DetachThreadLockInfoTest(data, size);
    OHOS::AttachThreadLockInfoTest(data, size);
    OHOS::QueryThreadLockInfoTest(data, size);
    OHOS::EraseThreadBySeqNumberTest(data, size);
    OHOS::AddThreadBySeqNumberTest(data, size);
    OHOS::QueryThreadBySeqNumberTest001(data, size);
    OHOS::QueryThreadBySeqNumberTest002(data, size);
    OHOS::AddSendThreadInWaitTest001(data, size);
    OHOS::AddSendThreadInWaitTest002(data, size);
    OHOS::GetSocketIdleThreadNumTest(data, size);

    return 0;
}
