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

#include "dbinderservicenew_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include "dbinder_service.h"
#include "dbinder_service_stub.h"
#include "string_ex.h"

namespace OHOS {
    const static size_t MAX_STRING_PARAM_LEN = 100;
    class TestRpcSystemAbilityCallback : public RpcSystemAbilityCallback {
    public:
        sptr<IRemoteObject> GetSystemAbilityFromRemote(int32_t systemAbilityId) override
        {
            return nullptr;
        }

        bool LoadSystemAbilityFromRemote(const std::string& srcNetworkId, int32_t systemAbilityId) override
        {
            return isLoad_;
        }
        bool IsDistributedSystemAbility(int32_t systemAbilityId) override
        {
            return isSystemAbility_;
        }
        bool isSystemAbility_ = true;
        bool isLoad_ = true;
    };

    class TestDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        TestDeathRecipient() {}
        virtual ~TestDeathRecipient() {}
        void OnRemoteDied(const wptr<IRemoteObject>& object) override {}
    };

    void OnRemoteMessageTaskTest(FuzzedDataProvider &provider)
    {
        std::shared_ptr<struct DHandleEntryTxRx> handleEntry = std::make_shared<struct DHandleEntryTxRx>();
        if (handleEntry == nullptr) {
            return;
        }
        handleEntry->head.len = sizeof(DHandleEntryTxRx);
        handleEntry->head.version = provider.ConsumeIntegral<uint32_t>();
        handleEntry->dBinderCode = provider.ConsumeIntegral<uint32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.OnRemoteMessageTask(handleEntry);
        handleEntry->dBinderCode = DBinderCode::MESSAGE_AS_INVOKER;
        dBinderService.OnRemoteMessageTask(handleEntry);
        handleEntry->dBinderCode = DBinderCode::MESSAGE_AS_OBITUARY;
        dBinderService.OnRemoteMessageTask(handleEntry);
    }

    void StartDBinderServiceTest(FuzzedDataProvider &provider)
    {
        OHOS::DBinderService dBinderService;
        std::shared_ptr<RpcSystemAbilityCallback> callbackImpl = nullptr;
        dBinderService.StartDBinderService(callbackImpl);
        callbackImpl = std::make_shared<TestRpcSystemAbilityCallback>();
        if (callbackImpl == nullptr) {
            return;
        }
        int32_t systemAbilityId = provider.ConsumeIntegral<int32_t>();
        callbackImpl->IsDistributedSystemAbility(systemAbilityId);

        dBinderService.StartDBinderService(callbackImpl);
    }

    void AddStubByTagTest(FuzzedDataProvider &provider)
    {
        const std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        const std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
        if (stub == nullptr) {
            return;
        }
        binder_uintptr_t binderObjectPtr = reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr());
        OHOS::DBinderService dBinderService;
        dBinderService.AddStubByTag(binderObjectPtr);
    }

    void CheckBinderObject1Test(FuzzedDataProvider &provider)
    {
        const std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        const std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
        if (stub == nullptr) {
            return;
        }
        binder_uintptr_t binderObjectPtr = reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr());
        OHOS::DBinderService dBinderService;
        dBinderService.CheckBinderObject(stub, binderObjectPtr);
    }

    void CheckBinderObject2Test(FuzzedDataProvider &provider)
    {
        const std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        const std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
        if (stub == nullptr) {
            return;
        }
        OHOS::DBinderService dBinderService;
        dBinderService.CheckBinderObject(stub, binderObject);
    }

    void HasDBinderStubTest(FuzzedDataProvider &provider)
    {
        const std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        const std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
        if (stub == nullptr) {
            return;
        }
        binder_uintptr_t binderObjectPtr = reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr());
        OHOS::DBinderService dBinderService;
        dBinderService.HasDBinderStub(binderObjectPtr);
    }

    void IsSameStubObject1Test(FuzzedDataProvider &provider)
    {
        const std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        const std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
        if (stub == nullptr) {
            return;
        }
        OHOS::DBinderService dBinderService;
        dBinderService.IsSameStubObject(stub, serviceName, deviceID);
    }

    void IsSameStubObject2Test(FuzzedDataProvider &provider)
    {
        std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        sptr<DBinderServiceStub> stub = nullptr;
        OHOS::DBinderService dBinderService;
        dBinderService.IsSameStubObject(stub, serviceName, deviceID);
    }

    void FindDBinderStubTest(FuzzedDataProvider &provider)
    {
        std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        std::string device = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        OHOS::DBinderService dBinderService;
        dBinderService.FindDBinderStub(serviceName, device);
    }

    void DeleteDBinderStubTest(FuzzedDataProvider &provider)
    {
        std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        std::string device = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        OHOS::DBinderService dBinderService;
        dBinderService.DeleteDBinderStub(serviceName, device);
    }

    void FindOrNewDBinderStubTest(FuzzedDataProvider &provider)
    {
        std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        std::string device = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        uint32_t pid = provider.ConsumeIntegral<uint32_t>();
        uint32_t uid = provider.ConsumeIntegral<uint32_t>();
        bool isNew = false;
        OHOS::DBinderService dBinderService;
        dBinderService.FindOrNewDBinderStub(serviceName, device, binderObject, pid, uid, isNew);
    }

    void MakeRemoteBinderTest(FuzzedDataProvider &provider)
    {
        std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        uint32_t pid = provider.ConsumeIntegral<uint32_t>();
        uint32_t uid = provider.ConsumeIntegral<uint32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.MakeRemoteBinder(serviceName, deviceID, binderObject, pid, uid);
    }

    void CheckDeviceIDsInvalidTest(FuzzedDataProvider &provider)
    {
        std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        std::string localDevID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        OHOS::DBinderService dBinderService;
        dBinderService.CheckDeviceIDsInvalid(deviceID, localDevID);
    }

    void CopyDeviceIDsToMessageTest(FuzzedDataProvider &provider)
    {
        std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        std::string localDevID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        auto message = std::make_shared<struct DHandleEntryTxRx>();
        if (message == nullptr) {
            return;
        }
        OHOS::DBinderService dBinderService;
        dBinderService.CopyDeviceIDsToMessage(message, localDevID, deviceID);
    }

    void CreateMessageTest(FuzzedDataProvider &provider)
    {
        const std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        const std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
        if (stub == nullptr) {
            return;
        }
        uint32_t seqNumber = provider.ConsumeIntegral<uint32_t>();
        uint32_t pid = provider.ConsumeIntegral<uint32_t>();
        uint32_t uid = provider.ConsumeIntegral<uint32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.CreateMessage(stub, seqNumber, pid, uid);
    }

    void SendEntryToRemoteTest(FuzzedDataProvider &provider)
    {
        OHOS::DBinderService dBinderService;
        const std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        const std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
        if (stub == nullptr) {
            return;
        }
        uint32_t seqNumber = provider.ConsumeIntegral<uint32_t>();
        uint32_t pid = provider.ConsumeIntegral<uint32_t>();
        uint32_t uid = provider.ConsumeIntegral<uint32_t>();
        dBinderService.SendEntryToRemote(stub, seqNumber, pid, uid);
    }

    void InvokerRemoteDBinderTest(FuzzedDataProvider &provider)
    {
        const std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        const std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
        if (stub == nullptr) {
            return;
        }
        uint32_t seqNumber = provider.ConsumeIntegral<uint32_t>();
        uint32_t pid = provider.ConsumeIntegral<uint32_t>();
        uint32_t uid = provider.ConsumeIntegral<uint32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.InvokerRemoteDBinder(stub, seqNumber, pid, uid);
    }

    void CheckSystemAbilityIdTest(FuzzedDataProvider &provider)
    {
        int32_t systemAbilityId = provider.ConsumeIntegral<int32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.CheckSystemAbilityId(systemAbilityId);
    }

    void IsSameLoadSaItemTest(FuzzedDataProvider &provider)
    {
        std::string srcNetworkId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        int32_t systemAbilityId = provider.ConsumeIntegral<int32_t>();
        std::shared_ptr<DHandleEntryTxRx> loadSaItem = std::make_shared<DHandleEntryTxRx>();
        if (loadSaItem == nullptr) {
            return;
        }
        OHOS::DBinderService dBinderService;
        dBinderService.IsSameLoadSaItem(srcNetworkId, systemAbilityId, loadSaItem);
    }

    void PopLoadSaItemTest(FuzzedDataProvider &provider)
    {
        std::string srcNetworkId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        int32_t systemAbilityId = provider.ConsumeIntegral<int32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.PopLoadSaItem(srcNetworkId, systemAbilityId);
    }

    void LoadSystemAbilityComplete1Test(FuzzedDataProvider &provider)
    {
        std::string srcNetworkId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        int handle = provider.ConsumeIntegral<int>();
        sptr<IRemoteObject> remoteObject = new (std::nothrow) IPCObjectProxy(handle);
        if (remoteObject == nullptr) {
            return;
        }
        int32_t systemAbilityId = provider.ConsumeIntegral<int32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.LoadSystemAbilityComplete(srcNetworkId, systemAbilityId, remoteObject);
    }

    void LoadSystemAbilityComplete2Test(FuzzedDataProvider &provider)
    {
        std::string srcNetworkId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        sptr<IRemoteObject> remoteObject = nullptr;
        int32_t systemAbilityId = provider.ConsumeIntegral<int32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.LoadSystemAbilityComplete(srcNetworkId, systemAbilityId, remoteObject);
    }

    void CheckAndAmendSaIdTest(FuzzedDataProvider &provider)
    {
        auto message = std::make_shared<DHandleEntryTxRx>();
        if (message == nullptr) {
            return;
        }
        message->transType = provider.ConsumeIntegral<int32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.CheckAndAmendSaId(message);
    }

    void OnRemoteInvokerMessageTest(FuzzedDataProvider &provider)
    {
        auto message = std::make_shared<DHandleEntryTxRx>();
        if (message == nullptr) {
            return;
        }
        message->transType = provider.ConsumeIntegral<int32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.OnRemoteInvokerMessage(message);
    }

    void CreateDatabusNameTest(FuzzedDataProvider &provider)
    {
        int uid = provider.ConsumeIntegral<int>();
        int pid = provider.ConsumeIntegral<int>();
        OHOS::DBinderService dBinderService;
        dBinderService.CreateDatabusName(uid, pid);
    }

    void CheckDeviceIdIllegalTest(FuzzedDataProvider &provider)
    {
        std::string remoteDeviceId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        OHOS::DBinderService dBinderService;
        dBinderService.CheckDeviceIdIllegal(remoteDeviceId);
    }

    void CheckSessionNameIsEmptyTest(FuzzedDataProvider &provider)
    {
        std::string sessionName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        OHOS::DBinderService dBinderService;
        dBinderService.CheckSessionNameIsEmpty(sessionName);
    }

    void CheckInvokeListenThreadIllegalTest(FuzzedDataProvider &provider)
    {
        std::string sessionName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        int handle = provider.ConsumeIntegral<int>();
        sptr<IPCObjectProxy> proxy = new (std::nothrow) IPCObjectProxy(handle);
        if (proxy == nullptr) {
            return;
        }
        MessageParcel parcel;
        MessageParcel reply;
        OHOS::DBinderService dBinderService;
        dBinderService.CheckInvokeListenThreadIllegal(proxy, parcel, reply);
    }

    void CheckStubIndexAndSessionNameIllegalTest(FuzzedDataProvider &provider)
    {
        uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
        std::string serverSessionName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        std::string deviceId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        int handle = provider.ConsumeIntegral<int>();
        sptr<IPCObjectProxy> proxy = new (std::nothrow) IPCObjectProxy(handle);
        if (proxy == nullptr) {
            return;
        }
        OHOS::DBinderService dBinderService;
        dBinderService.CheckStubIndexAndSessionNameIllegal(stubIndex, serverSessionName, deviceId, proxy);
    }

    void SetReplyMessageTest(FuzzedDataProvider &provider)
    {
        std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<struct DHandleEntryTxRx>();
        if (replyMessage == nullptr) {
            return;
        }
        replyMessage->transType = provider.ConsumeIntegral<uint32_t>();
        uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
        std::string serverSessionName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        uint32_t selfTokenId = provider.ConsumeIntegral<uint32_t>();
        int handle = provider.ConsumeIntegral<int>();
        sptr<IPCObjectProxy> proxy = new (std::nothrow) IPCObjectProxy(handle);
        if (proxy == nullptr) {
            return;
        }
        OHOS::DBinderService dBinderService;
        dBinderService.SetReplyMessage(replyMessage, stubIndex, serverSessionName, selfTokenId, proxy);
    }

    void OnRemoteInvokerDataBusMessageTest(FuzzedDataProvider &provider)
    {
        int handle = provider.ConsumeIntegral<int>();
        sptr<IPCObjectProxy> proxy = new (std::nothrow) IPCObjectProxy(handle);
        if (proxy == nullptr) {
            return;
        }
        std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<struct DHandleEntryTxRx>();
        if (replyMessage == nullptr) {
            return;
        }
        replyMessage->transType = provider.ConsumeIntegral<uint32_t>();
        std::string remoteDeviceId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        int pid = provider.ConsumeIntegral<int>();
        int uid = provider.ConsumeIntegral<int>();
        uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();

        OHOS::DBinderService dBinderService;
        dBinderService.OnRemoteInvokerDataBusMessage(proxy, replyMessage, remoteDeviceId, pid, uid, tokenId);
    }

    void GetRegisterServiceTest(FuzzedDataProvider &provider)
    {
        binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        OHOS::DBinderService dBinderService;
        dBinderService.GetRegisterService(binderObject);
    }

    void RegisterRemoteProxyTest(FuzzedDataProvider &provider)
    {
        std::string service = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        std::u16string serviceName = Str8ToStr16(service);
        int handle = provider.ConsumeIntegral<int>();
        sptr<IRemoteObject> binderObject = new (std::nothrow) IPCObjectProxy(handle);
        if (binderObject == nullptr) {
            return;
        }
        OHOS::DBinderService dBinderService;
        dBinderService.RegisterRemoteProxy(serviceName, binderObject);
    }

    void ProcessOnSessionClosedTest(FuzzedDataProvider &provider)
    {
        std::string networkId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        OHOS::DBinderService dBinderService;
        dBinderService.ProcessOnSessionClosed(networkId);
    }

    void OnRemoteErrorMessageTest(FuzzedDataProvider &provider)
    {
        std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<struct DHandleEntryTxRx>();
        if (replyMessage == nullptr) {
            return;
        }
        replyMessage->transType = provider.ConsumeIntegral<uint32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.OnRemoteErrorMessage(replyMessage);
    }

    void OnRemoteReplyMessageTest(FuzzedDataProvider &provider)
    {
        std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<struct DHandleEntryTxRx>();
        if (replyMessage == nullptr) {
            return;
        }
        replyMessage->transType = provider.ConsumeIntegral<uint32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.OnRemoteReplyMessage(replyMessage);
    }

    void IsSameSessionTest(FuzzedDataProvider &provider)
    {
        std::shared_ptr<struct SessionInfo> oldSession = std::make_shared<struct SessionInfo>();
        std::shared_ptr<struct SessionInfo> newSession = std::make_shared<struct SessionInfo>();
        if (oldSession == nullptr && newSession == nullptr) {
            return;
        }
        oldSession->type = provider.ConsumeIntegral<uint32_t>();
        newSession->type = provider.ConsumeIntegral<uint32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.IsSameSession(oldSession, newSession);
    }

    void IsInvalidStubTest(FuzzedDataProvider &provider)
    {
        std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<struct DHandleEntryTxRx>();
        if (replyMessage == nullptr) {
            return;
        }
        replyMessage->transType = provider.ConsumeIntegral<uint32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.IsInvalidStub(replyMessage);
    }

    void IsValidSessionNameTest(FuzzedDataProvider &provider)
    {
        std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<struct DHandleEntryTxRx>();
        if (replyMessage == nullptr) {
            return;
        }
        replyMessage->transType = provider.ConsumeIntegral<uint32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.IsValidSessionName(replyMessage);
    }

    void CopyDeviceIdInfoTest(FuzzedDataProvider &provider)
    {
        std::shared_ptr<struct SessionInfo> session = std::make_shared<struct SessionInfo>();
        std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<struct DHandleEntryTxRx>();
        if (session == nullptr && replyMessage == nullptr) {
            return;
        }
        session->type = provider.ConsumeIntegral<uint32_t>();
        replyMessage->transType = provider.ConsumeIntegral<uint32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.CopyDeviceIdInfo(session, replyMessage);
    }

    void InitializeSessionTest(FuzzedDataProvider &provider)
    {
        std::shared_ptr<struct SessionInfo> session = std::make_shared<struct SessionInfo>();
        std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<struct DHandleEntryTxRx>();
        if (session == nullptr && replyMessage == nullptr) {
            return;
        }
        session->type = provider.ConsumeIntegral<uint32_t>();
        replyMessage->transType = provider.ConsumeIntegral<uint32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.InitializeSession(session, replyMessage);
    }

    void MakeSessionByReplyMessageTest(FuzzedDataProvider &provider)
    {
        std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<struct DHandleEntryTxRx>();
        if (replyMessage == nullptr) {
            return;
        }
        replyMessage->transType = provider.ConsumeIntegral<uint32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.MakeSessionByReplyMessage(replyMessage);
    }

    void WakeupThreadByStubTest(FuzzedDataProvider &provider)
    {
        uint32_t seqNumber = provider.ConsumeIntegral<uint32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.WakeupThreadByStub(seqNumber);
    }

    void DetachThreadLockInfoTest(FuzzedDataProvider &provider)
    {
        uint32_t seqNumber = provider.ConsumeIntegral<uint32_t>();
        OHOS::DBinderService dBinderService;
        dBinderService.DetachThreadLockInfo(seqNumber);
    }

    void DetachProxyObjectTest(FuzzedDataProvider &provider)
    {
        binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        OHOS::DBinderService dBinderService;
        dBinderService.DetachProxyObject(binderObject);
    }

    void AttachThreadLockInfoTest(FuzzedDataProvider &provider)
    {
        uint32_t seqNumber = provider.ConsumeIntegral<uint32_t>();
        std::string networkId = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        OHOS::DBinderService dBinderService;
        auto threadLockInfo = std::make_shared<struct ThreadLockInfo>();
        dBinderService.AttachThreadLockInfo(seqNumber, networkId, threadLockInfo);
    }

    void AttachProxyObjectTest(FuzzedDataProvider &provider)
    {
        int handle = provider.ConsumeIntegral<int>();
        sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(handle);
        if (object == nullptr) {
            return;
        }
        binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        OHOS::DBinderService dBinderService;
        dBinderService.AttachProxyObject(object, binderObject);
    }

    void QueryProxyObjectTest(FuzzedDataProvider &provider)
    {
        binder_uintptr_t binderObject = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        OHOS::DBinderService dBinderService;
        dBinderService.QueryProxyObject(binderObject);
    }

    void DetachSessionObjectTest(FuzzedDataProvider &provider)
    {
        binder_uintptr_t stub = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        OHOS::DBinderService dBinderService;
        dBinderService.DetachSessionObject(stub);
    }

    void QuerySessionObjectTest(FuzzedDataProvider &provider)
    {
        binder_uintptr_t stub = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        OHOS::DBinderService dBinderService;
        dBinderService.QuerySessionObject(stub);
    }

    void DetachDeathRecipientTest(FuzzedDataProvider &provider)
    {
        int handle = provider.ConsumeIntegral<int>();
        sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(handle);
        if (object == nullptr) {
            return;
        }
        OHOS::DBinderService dBinderService;
        dBinderService.DetachDeathRecipient(object);
    }

    void AttachDeathRecipientTest(FuzzedDataProvider &provider)
    {
        int handle = provider.ConsumeIntegral<int>();
        sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(handle);
        if (object == nullptr) {
            return;
        }
        sptr<IRemoteObject::DeathRecipient> deathRecipient = new (std::nothrow) TestDeathRecipient();
        if (deathRecipient == nullptr) {
            return;
        }
        OHOS::DBinderService dBinderService;
        dBinderService.AttachDeathRecipient(object, deathRecipient);
    }

    void QueryDeathRecipientTest(FuzzedDataProvider &provider)
    {
        int handle = provider.ConsumeIntegral<int>();
        sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(handle);
        if (object == nullptr) {
            return;
        }
        OHOS::DBinderService dBinderService;
        dBinderService.QueryDeathRecipient(object);
    }

    void DetachCallbackProxyTest(FuzzedDataProvider &provider)
    {
        int handle = provider.ConsumeIntegral<int>();
        sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(handle);
        if (object == nullptr) {
            return;
        }
        OHOS::DBinderService dBinderService;
        dBinderService.DetachCallbackProxy(object);
    }

    void AttachCallbackProxyTest(FuzzedDataProvider &provider)
    {
        int handle = provider.ConsumeIntegral<int>();
        sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(handle);
        if (object == nullptr) {
            return;
        }
        std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        binder_uintptr_t stub = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        sptr<DBinderServiceStub> dBinderServiceStub
            = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, stub);
        if (dBinderServiceStub == nullptr) {
            return;
        }
        OHOS::DBinderService dBinderService;
        dBinderService.AttachCallbackProxy(object, dBinderServiceStub.GetRefPtr());
    }

    void NoticeCallbackProxyTest(FuzzedDataProvider &provider)
    {
        std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        OHOS::DBinderService dBinderService;
        dBinderService.NoticeCallbackProxy(serviceName, deviceID);
    }

    void ProcessCallbackProxyTest(FuzzedDataProvider &provider)
    {
        std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        binder_uintptr_t stub = static_cast<binder_uintptr_t>(provider.ConsumeIntegral<uint64_t>());
        sptr<DBinderServiceStub> dbStub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, stub);
        if (dbStub == nullptr) {
            return;
        }
        std::vector<sptr<DBinderServiceStub>> dbStubs;
        dbStubs.emplace_back(dbStub);
        OHOS::DBinderService dBinderService;
        dBinderService.ProcessCallbackProxy(dbStubs);
    }

    void NoticeServiceDieInnerTest(FuzzedDataProvider &provider)
    {
        std::u16string serviceName = Str8ToStr16(provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN));
        std::string deviceID = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
        OHOS::DBinderService dBinderService;
        dBinderService.NoticeServiceDieInner(serviceName, deviceID);
    }

    void FuzzTest(FuzzedDataProvider &provider)
    {
        OHOS::DetachThreadLockInfoTest(provider);
        OHOS::DetachProxyObjectTest(provider);
        OHOS::AttachProxyObjectTest(provider);
        OHOS::QueryProxyObjectTest(provider);
        OHOS::DetachSessionObjectTest(provider);
        OHOS::QuerySessionObjectTest(provider);
        OHOS::DetachDeathRecipientTest(provider);
        OHOS::AttachDeathRecipientTest(provider);
        OHOS::QueryDeathRecipientTest(provider);
        OHOS::DetachCallbackProxyTest(provider);
        OHOS::AttachCallbackProxyTest(provider);
        OHOS::NoticeCallbackProxyTest(provider);
        OHOS::ProcessCallbackProxyTest(provider);
        OHOS::NoticeServiceDieInnerTest(provider);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::OnRemoteMessageTaskTest(provider);
    OHOS::StartDBinderServiceTest(provider);
    OHOS::AddStubByTagTest(provider);
    OHOS::CheckBinderObject1Test(provider);
    OHOS::CheckBinderObject2Test(provider);
    OHOS::HasDBinderStubTest(provider);
    OHOS::IsSameStubObject1Test(provider);
    OHOS::IsSameStubObject2Test(provider);
    OHOS::FindDBinderStubTest(provider);
    OHOS::DeleteDBinderStubTest(provider);
    OHOS::FindOrNewDBinderStubTest(provider);
    OHOS::MakeRemoteBinderTest(provider);
    OHOS::CheckDeviceIDsInvalidTest(provider);
    OHOS::CopyDeviceIDsToMessageTest(provider);
    OHOS::CreateMessageTest(provider);
    OHOS::SendEntryToRemoteTest(provider);
    OHOS::InvokerRemoteDBinderTest(provider);
    OHOS::CheckSystemAbilityIdTest(provider);
    OHOS::IsSameLoadSaItemTest(provider);
    OHOS::PopLoadSaItemTest(provider);
    OHOS::LoadSystemAbilityComplete1Test(provider);
    OHOS::LoadSystemAbilityComplete2Test(provider);
    OHOS::CheckAndAmendSaIdTest(provider);
    OHOS::OnRemoteInvokerMessageTest(provider);
    OHOS::CreateDatabusNameTest(provider);
    OHOS::CheckDeviceIdIllegalTest(provider);
    OHOS::CheckSessionNameIsEmptyTest(provider);
    OHOS::CheckInvokeListenThreadIllegalTest(provider);
    OHOS::CheckStubIndexAndSessionNameIllegalTest(provider);
    OHOS::SetReplyMessageTest(provider);
    OHOS::OnRemoteInvokerDataBusMessageTest(provider);
    OHOS::GetRegisterServiceTest(provider);
    OHOS::RegisterRemoteProxyTest(provider);
    OHOS::ProcessOnSessionClosedTest(provider);
    OHOS::OnRemoteErrorMessageTest(provider);
    OHOS::OnRemoteReplyMessageTest(provider);
    OHOS::IsSameSessionTest(provider);
    OHOS::IsInvalidStubTest(provider);
    OHOS::IsValidSessionNameTest(provider);
    OHOS::CopyDeviceIdInfoTest(provider);
    OHOS::InitializeSessionTest(provider);
    OHOS::MakeSessionByReplyMessageTest(provider);
    OHOS::WakeupThreadByStubTest(provider);
    OHOS::FuzzTest(provider);
    return 0;
}
