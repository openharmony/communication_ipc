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

#include "dbinder_service.h"
#include "securec.h"
#include "string_ex.h"
#include "ipc_skeleton.h"
#include "ipc_thread_skeleton.h"

#include "dbinder_log.h"
#include "dbinder_service_stub.h"
#include "dbinder_remote_listener.h"
#include "dbinder_error_code.h"
#include "dbinder_sa_death_recipient.h"
#include "rpc_feature_set.h"
#include "softbus_bus_center.h"

namespace OHOS {
using namespace Communication;

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_RPC, "DbinderService" };

sptr<DBinderService> DBinderService::instance_ = nullptr;
bool DBinderService::mainThreadCreated_ = false;
std::mutex DBinderService::instanceMutex_;
std::shared_ptr<DBinderRemoteListener> DBinderService::remoteListener_ = nullptr;
constexpr int32_t DBINDER_UID_START_INDEX = 7;

DBinderService::DBinderService()
{
    DBINDER_LOGI(LOG_LABEL, "create dbinder service");
}

DBinderService::~DBinderService()
{
    StopRemoteListener();

    DBinderStubRegisted_.clear();
    mapRemoteBinderObjects_.clear();
    threadLockInfo_.clear();
    proxyObject_.clear();
    sessionObject_.clear();
    noticeProxy_.clear();
    deathRecipients_.clear();
    busNameObject_.clear();
    loadSaReply_.clear();
    dbinderCallback_ = nullptr;

    DBINDER_LOGI(LOG_LABEL, "dbinder service died");
}

std::string DBinderService::GetLocalDeviceID()
{
    std::string pkgName = "DBinderService";
    NodeBasicInfo nodeBasicInfo;
    if (GetLocalNodeDeviceInfo(pkgName.c_str(), &nodeBasicInfo) != 0) {
        DBINDER_LOGE(LOG_LABEL, "Get local node device info failed");
        return "";
    }
    std::string networkId(nodeBasicInfo.networkId);
    return networkId;
}

bool DBinderService::StartDBinderService(std::shared_ptr<RpcSystemAbilityCallback> &callbackImpl)
{
    if (mainThreadCreated_) {
        return ReStartRemoteListener();
    }

    bool result = StartRemoteListener();
    if (!result) {
        return false;
    }
    mainThreadCreated_ = true;
    dbinderCallback_ = callbackImpl;

    return true;
}

bool DBinderService::StartRemoteListener()
{
    if (remoteListener_ != nullptr) {
        DBINDER_LOGI(LOG_LABEL, "remote listener started");
        return true;
    }

    remoteListener_ = std::make_shared<DBinderRemoteListener>(GetInstance());
    if (remoteListener_ == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "failed to create remote listener");
        return false;
    }

    if (remoteListener_->StartListener(remoteListener_) != true) {
        StopRemoteListener();
        return false;
    }

    DBINDER_LOGI(LOG_LABEL, "start remote listener ok");
    return true;
}

bool DBinderService::ReStartRemoteListener()
{
    if (remoteListener_ == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "restart remote listener got null");
        return false;
    }
    if (remoteListener_->StartListener(remoteListener_) != true) {
        DBINDER_LOGE(LOG_LABEL, "restart dbinder server failed");
        StopRemoteListener();
        return false;
    }

    auto it = busNameObject_.begin();
    while (it != busNameObject_.end()) {
        std::string sessionName = it->second;
        if (ReGrantPermission(sessionName) != true) {
            DBINDER_LOGE(LOG_LABEL, "%s grant permission failed", sessionName.c_str());
        }
        ++it;
    }
    return true;
}

void DBinderService::StopRemoteListener()
{
    if (remoteListener_ != nullptr) {
        remoteListener_->StopListener();
        remoteListener_ = nullptr;
    }
}

std::shared_ptr<DBinderRemoteListener> DBinderService::GetRemoteListener()
{
    if (remoteListener_ == nullptr && !StartRemoteListener()) {
        return nullptr;
    }
    return remoteListener_;
}

sptr<DBinderService> DBinderService::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lockGuard(instanceMutex_);
        if (instance_ == nullptr) {
            sptr<DBinderService> temp = new DBinderService();
            instance_ = temp;
        }
    }
    return instance_;
}

uint32_t DBinderService::GetSeqNumber()
{
    std::lock_guard<std::mutex> lockGuard(instanceMutex_);
    seqNumber_++; // can be overflow
    return seqNumber_;
}

bool DBinderService::IsDeviceIdIllegal(const std::string &deviceID)
{
    if (deviceID.empty() || deviceID.length() > DEVICEID_LENGTH) {
        return true;
    }
    return false;
}

bool DBinderService::CheckBinderObject(const sptr<DBinderServiceStub> &stub, binder_uintptr_t binderObject)
{
    if (stub == nullptr) {
        return false;
    }

    if (stub->GetBinderObject() == binderObject) {
        DBINDER_LOGI(LOG_LABEL, "found registered stub");
        return true;
    }
    return false;
}

bool DBinderService::HasDBinderStub(binder_uintptr_t binderObject)
{
    auto checkStub = [&binderObject, this](const sptr<DBinderServiceStub> &stub) {
        return CheckBinderObject(stub, binderObject);
    };

    std::lock_guard<std::mutex> lockGuard(handleEntryMutex_);
    auto it = std::find_if(DBinderStubRegisted_.begin(), DBinderStubRegisted_.end(), checkStub);
    if (it != DBinderStubRegisted_.end()) {
        return true;
    }
    return false;
}

bool DBinderService::IsSameStubObject(const sptr<DBinderServiceStub> &stub, const std::u16string &service,
    const std::string &device)
{
    if (stub == nullptr) {
        return false;
    }
    if (IsSameTextStr(stub->GetServiceName(), Str16ToStr8(service)) && IsSameTextStr(stub->GetDeviceID(), device)) {
        DBINDER_LOGI(LOG_LABEL, "found registered service with name = %{public}s", Str16ToStr8(service).c_str());
        return true;
    }
    return false;
}
sptr<DBinderServiceStub> DBinderService::FindDBinderStub(const std::u16string &service, const std::string &device)
{
    auto checkStub = [&service, &device, this](const sptr<DBinderServiceStub> &stub) {
        return IsSameStubObject(stub, service, device);
    };

    std::lock_guard<std::mutex> lockGuard(handleEntryMutex_);
    auto it = std::find_if(DBinderStubRegisted_.begin(), DBinderStubRegisted_.end(), checkStub);
    if (it == DBinderStubRegisted_.end()) {
        return nullptr;
    }
    return (*it);
}

bool DBinderService::DeleteDBinderStub(const std::u16string &service, const std::string &device)
{
    auto checkStub = [&service, &device, this](const sptr<DBinderServiceStub> &stub) {
        return IsSameStubObject(stub, service, device);
    };

    std::lock_guard<std::mutex> lockGuard(handleEntryMutex_);
    auto it = std::find_if(DBinderStubRegisted_.begin(), DBinderStubRegisted_.end(), checkStub);
    if (it == DBinderStubRegisted_.end()) {
        return false;
    }
    DBinderStubRegisted_.erase(it);
    return true;
}

sptr<DBinderServiceStub> DBinderService::FindOrNewDBinderStub(const std::u16string &service, const std::string &device,
    binder_uintptr_t binderObject)
{
    auto checkStub = [&service, &device, this](const sptr<DBinderServiceStub> &stub) {
        return IsSameStubObject(stub, service, device);
    };

    std::lock_guard<std::mutex> lockGuard(handleEntryMutex_);
    auto it = std::find_if(DBinderStubRegisted_.begin(), DBinderStubRegisted_.end(), checkStub);
    if (it != DBinderStubRegisted_.end()) {
        return (*it);
    }

    sptr<DBinderServiceStub> dBinderServiceStub = new DBinderServiceStub(Str16ToStr8(service), device, binderObject);
    DBinderStubRegisted_.push_back(dBinderServiceStub);
    return dBinderServiceStub;
}

sptr<DBinderServiceStub> DBinderService::MakeRemoteBinder(const std::u16string &serviceName,
    const std::string &deviceID, binder_uintptr_t binderObject, uint32_t pid, uint32_t uid)
{
    if (IsDeviceIdIllegal(deviceID) || serviceName.length() == 0) {
        DBINDER_LOGE(LOG_LABEL, "para is wrong device id length = %zu, service name length = %zu", deviceID.length(),
            serviceName.length());
        return nullptr;
    }
    DBINDER_LOGI(LOG_LABEL, "name = %{public}s, deviceID = %{public}s", Str16ToStr8(serviceName).c_str(),
        DBinderService::ConvertToSecureDeviceID(deviceID).c_str());

    sptr<DBinderServiceStub> dBinderServiceStub = FindOrNewDBinderStub(serviceName, deviceID, binderObject);
    if (dBinderServiceStub == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "fail to find or new service, service name = %{public}s",
            Str16ToStr8(serviceName).c_str());
        return nullptr;
    }

    /* if not found dBinderServiceStub, should send msg to toDeviceID
     * to invoker socket thread and add authentication info for create softbus session
     */
    int retryTimes = 0;
    bool ret = false;
    do {
        ret = InvokerRemoteDBinder(dBinderServiceStub, GetSeqNumber(), pid, uid);
        retryTimes++;
    } while (!ret && (retryTimes < RETRY_TIMES));
    if (!ret) {
        DBINDER_LOGE(LOG_LABEL, "fail to invoke service, service name = %{public}s, device = %{public}s "
            "DBinderServiceStub refcount = %{public}d",
            Str16ToStr8(serviceName).c_str(), DBinderService::ConvertToSecureDeviceID(deviceID).c_str(),
            dBinderServiceStub->GetSptrRefCount());
        /* invoke fail, delete dbinder stub info */
        (void)DeleteDBinderStub(serviceName, deviceID);
        (void)DetachSessionObject(reinterpret_cast<binder_uintptr_t>(dBinderServiceStub.GetRefPtr()));
        return nullptr;
    }
    return dBinderServiceStub;
}

bool DBinderService::SendEntryToRemote(const sptr<DBinderServiceStub> stub, uint32_t seqNumber, uint32_t pid,
    uint32_t uid)
{
    const std::string deviceID = stub->GetDeviceID();
    const std::string localDevID = GetLocalDeviceID();
    if (IsDeviceIdIllegal(deviceID) || IsDeviceIdIllegal(localDevID)) {
        DBINDER_LOGE(LOG_LABEL, "wrong device ID");
        return false;
    }

    std::shared_ptr<struct DHandleEntryTxRx> message = std::make_shared<struct DHandleEntryTxRx>();
    message->head.len            = sizeof(DHandleEntryTxRx);
    message->head.version        = VERSION_NUM;
    message->dBinderCode         = MESSAGE_AS_INVOKER;
    message->transType           = GetRemoteTransType();
    message->rpcFeatureSet       = GetLocalRpcFeature();
    message->stubIndex           = static_cast<uint64_t>(std::atoi(stub->GetServiceName().c_str()));
    message->seqNumber           = seqNumber;
    message->binderObject        = stub->GetBinderObject();
    message->stub                = reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr());
    message->deviceIdInfo.afType = DATABBUS_TYPE;
    message->pid                 = pid;
    message->uid                 = uid;
    if (memcpy_s(message->deviceIdInfo.fromDeviceId, DEVICEID_LENGTH, localDevID.data(), localDevID.length()) != 0 ||
        memcpy_s(message->deviceIdInfo.toDeviceId, DEVICEID_LENGTH, deviceID.data(), deviceID.length()) != 0) {
        DBINDER_LOGE(LOG_LABEL, "fail to copy memory");
        return false;
    }
    message->deviceIdInfo.fromDeviceId[localDevID.length()] = '\0';
    message->deviceIdInfo.toDeviceId[deviceID.length()] = '\0';

    std::shared_ptr<DBinderRemoteListener> remoteListener = GetRemoteListener();
    if (remoteListener == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "remoteListener is null");
        return false;
    }
    bool result = remoteListener->SendDataToRemote(deviceID, message.get());
    if (result != true) {
        DBINDER_LOGE(LOG_LABEL, "send to remote dbinderService failed");
        return false;
    }
    return true;
}

bool DBinderService::InvokerRemoteDBinder(const sptr<DBinderServiceStub> stub, uint32_t seqNumber,
    uint32_t pid, uint32_t uid)
{
    if (stub == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "stub is nullptr");
        return false;
    }
    bool result = SendEntryToRemote(stub, seqNumber, pid, uid);
    if (!result) {
        DBINDER_LOGE(LOG_LABEL, "send entry to remote dbinderService fail");
        return false;
    }

    /* pend to wait reply */
    std::shared_ptr<struct ThreadLockInfo> threadLockInfo = std::make_shared<struct ThreadLockInfo>();
    result = AttachThreadLockInfo(seqNumber, stub->GetDeviceID(), threadLockInfo);
    if (result != true) {
        DBINDER_LOGE(LOG_LABEL, "attach lock info fail");
        return false;
    }

    std::unique_lock<std::mutex> lock(threadLockInfo->mutex);
    if (threadLockInfo->condition.wait_for(lock, std::chrono::seconds(WAIT_FOR_REPLY_MAX_SEC),
        [&threadLockInfo] { return threadLockInfo->ready; }) == false) {
        DBINDER_LOGE(LOG_LABEL, "get remote data failed");
        DetachThreadLockInfo(seqNumber);
        threadLockInfo->ready = false;
        return false;
    }
    /* if can not find session, means invoke failed or nothing in OnRemoteReplyMessage() */
    auto session = QuerySessionObject(reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr()));
    if (session == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "client find session is null");
        return false;
    }
    return true;
}

bool DBinderService::CheckSystemAbilityId(int32_t systemAbilityId)
{
    return systemAbilityId >= FIRST_SYS_ABILITY_ID && systemAbilityId <= LAST_SYS_ABILITY_ID;
}

uint16_t DBinderService::AllocFreeSocketPort()
{
    /* alloc port by system */
    return 0;
}

bool DBinderService::IsSameLoadSaItem(const std::string& srcNetworkId, int32_t systemAbilityId,
    std::shared_ptr<DHandleEntryTxRx> loadSaItem)
{
    if (static_cast<int32_t>(loadSaItem->stubIndex) == systemAbilityId &&
        loadSaItem->deviceIdInfo.fromDeviceId == srcNetworkId) {
        DBINDER_LOGI(LOG_LABEL, "match succeed");
        return true;
    }
    return false;
}

std::shared_ptr<DHandleEntryTxRx> DBinderService::PopLoadSaItem(const std::string& srcNetworkId,
    int32_t systemAbilityId)
{
    auto checkSaItem = [srcNetworkId, systemAbilityId, this](std::shared_ptr<DHandleEntryTxRx> loadSaItem) {
        return IsSameLoadSaItem(srcNetworkId, systemAbilityId, loadSaItem);
    };

    auto it = std::find_if(loadSaReply_.begin(), loadSaReply_.end(), checkSaItem);
    if (it == loadSaReply_.end()) {
        DBINDER_LOGE(LOG_LABEL, "findSaItem failed");
        return nullptr;
    }
    std::shared_ptr<DHandleEntryTxRx> replymsg = (*it);
    it = loadSaReply_.erase(it);
    return replymsg;
}

void DBinderService::LoadSystemAbilityComplete(const std::string& srcNetworkId, int32_t systemAbilityId,
    const sptr<IRemoteObject>& remoteObject)
{
    std::lock_guard<std::shared_mutex> lockGuard(loadSaMutex_);
    while (true) {
        std::shared_ptr<struct DHandleEntryTxRx> replyMessage = PopLoadSaItem(srcNetworkId, systemAbilityId);
        if (replyMessage == nullptr) {
            break;
        }
        if (remoteObject == nullptr) {
            SendMessageToRemote(MESSAGE_AS_REMOTE_ERROR, replyMessage);
            DBINDER_LOGE(LOG_LABEL, "GetSystemAbility from samgr error, saId:%{public}d", systemAbilityId);
            continue;
        }
        binder_uintptr_t binderObject = replyMessage->binderObject;
        IPCObjectProxy *saProxy = reinterpret_cast<IPCObjectProxy *>(remoteObject.GetRefPtr());
        if (QueryProxyObject(binderObject) == nullptr) {
            /* When the stub object dies, you need to delete the corresponding busName information */
            sptr<IRemoteObject::DeathRecipient> death(new DbinderSaDeathRecipient(binderObject));
            if (!saProxy->AddDeathRecipient(death)) {
                SendMessageToRemote(MESSAGE_AS_REMOTE_ERROR, replyMessage);
                DBINDER_LOGE(LOG_LABEL, "fail to add death recipient");
                continue;
            }
            if (!AttachProxyObject(remoteObject, binderObject)) {
                SendMessageToRemote(MESSAGE_AS_REMOTE_ERROR, replyMessage);
                DBINDER_LOGE(LOG_LABEL, "attach proxy object fail");
                continue;
            }
        }
        std::string deviceId = replyMessage->deviceIdInfo.fromDeviceId;
        if (replyMessage->transType != IRemoteObject::DATABUS_TYPE) {
            SendMessageToRemote(MESSAGE_AS_REMOTE_ERROR, replyMessage);
            DBINDER_LOGE(LOG_LABEL, "Invalid Message Type");
        } else {
            if (!OnRemoteInvokerDataBusMessage(saProxy, replyMessage.get(), deviceId,
                replyMessage->pid, replyMessage->uid)) {
                SendMessageToRemote(MESSAGE_AS_REMOTE_ERROR, replyMessage);
                continue;
            }
            SendMessageToRemote(MESSAGE_AS_REPLY, replyMessage);
        }
    }
    DBINDER_LOGI(LOG_LABEL, "LoadSystemAbility complete");
}

void DBinderService::SendMessageToRemote(uint32_t binderCode, std::shared_ptr<struct DHandleEntryTxRx> replyMessage)
{
    std::shared_ptr<DBinderRemoteListener> remoteListener = GetRemoteListener();
    if (remoteListener == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "remoteListener is null");
        return;
    }
    replyMessage->dBinderCode = binderCode;
    if (!remoteListener->SendDataToRemote(replyMessage->deviceIdInfo.fromDeviceId, replyMessage.get())) {
        DBINDER_LOGE(LOG_LABEL, "fail to send data from server DBS to client DBS");
    }
}

bool DBinderService::OnRemoteInvokerMessage(const struct DHandleEntryTxRx *message)
{
    std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<struct DHandleEntryTxRx>();
    if (memcpy_s(replyMessage.get(), sizeof(DHandleEntryTxRx), message, sizeof(DHandleEntryTxRx)) != 0) {
        DBINDER_LOGE(LOG_LABEL, "fail to copy memory");
        return false;
    }

    std::lock_guard<std::shared_mutex> lockGuard(loadSaMutex_);
    bool isSaAvailable = dbinderCallback_->LoadSystemAbilityFromRemote(replyMessage->deviceIdInfo.fromDeviceId,
        static_cast<int32_t>(replyMessage->stubIndex));
    if (!isSaAvailable) {
        DBINDER_LOGE(LOG_LABEL, "fail to call the system ability");
        return false;
    }
    loadSaReply_.push_back(replyMessage);
    return true;
}

std::string DBinderService::GetDatabusNameByProxy(IPCObjectProxy *proxy, int32_t systemAbilityId)
{
    if (proxy == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "proxy can not be null");
        return "";
    }
    std::string sessionName = QueryBusNameObject(proxy);
    if (!sessionName.empty()) {
        DBINDER_LOGI(LOG_LABEL, "sessionName has been granded");
        return sessionName;
    }
    sessionName = proxy->GetPidAndUidInfo(systemAbilityId);
    if (sessionName.empty()) {
        DBINDER_LOGE(LOG_LABEL, "grand session name failed");
        return "";
    }
    return sessionName;
}

std::string DBinderService::CreateDatabusName(int uid, int pid)
{
    std::shared_ptr<ISessionService> softbusManager = ISessionService::GetInstance();
    if (softbusManager == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "fail to get softbus service");
        return "";
    }

    std::string sessionName = "DBinder" + std::to_string(uid) + std::string("_") + std::to_string(pid);
    if (softbusManager->GrantPermission(uid, pid, sessionName) != ERR_NONE) {
        DBINDER_LOGE(LOG_LABEL, "fail to Grant Permission softbus name");
        return "";
    }

    return sessionName;
}

bool DBinderService::HandleInvokeListenThread(IPCObjectProxy *proxy, uint64_t stubIndex,
    std::string serverSessionName, struct DHandleEntryTxRx *replyMessage)
{
    if (stubIndex == 0 || serverSessionName.empty() || serverSessionName.length() > SERVICENAME_LENGTH) {
        DBINDER_LOGE(LOG_LABEL, "stubindex or session name invalid");
        return false;
    }

    replyMessage->dBinderCode = MESSAGE_AS_REPLY;
    replyMessage->stubIndex = stubIndex;
    replyMessage->serviceNameLength = serverSessionName.length();
    if (memcpy_s(replyMessage->serviceName, SERVICENAME_LENGTH, serverSessionName.data(),
        replyMessage->serviceNameLength) != 0) {
        DBINDER_LOGE(LOG_LABEL, "fail to copy memory");
        return false;
    }
    replyMessage->serviceName[replyMessage->serviceNameLength] = '\0';
    replyMessage->rpcFeatureSet = GetLocalRpcFeature() | GetRpcFeatureAck();

    (void)AttachBusNameObject(proxy, serverSessionName);
    return true;
}

bool DBinderService::OnRemoteInvokerDataBusMessage(IPCObjectProxy *proxy, struct DHandleEntryTxRx *replyMessage,
    std::string &remoteDeviceId, int pid, int uid)
{
    if (IsDeviceIdIllegal(remoteDeviceId)) {
        DBINDER_LOGE(LOG_LABEL, "remote device id is error");
        return false;
    }
    std::string sessionName = GetDatabusNameByProxy(proxy, replyMessage->stubIndex);
    if (sessionName.empty()) {
        DBINDER_LOGE(LOG_LABEL, "get bus name fail");
        return false;
    }

    uint32_t featureSet = replyMessage->rpcFeatureSet & GetLocalRpcFeature();
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteUint16(IRemoteObject::DATABUS_TYPE) || !data.WriteString(GetLocalDeviceID()) ||
        !data.WriteUint32(pid) || !data.WriteUint32(uid) || !data.WriteString(remoteDeviceId) ||
        !data.WriteString(sessionName) || !data.WriteUint32(featureSet)) {
        DBINDER_LOGE(LOG_LABEL, "write to parcel fail");
        return false;
    }
    int err = proxy->InvokeListenThread(data, reply);
    if (err != ERR_NONE) {
        DBINDER_LOGE(LOG_LABEL, "start service listen error = %d", err);
        return false;
    }
    uint64_t stubIndex = reply.ReadUint64();
    std::string serverSessionName = reply.ReadString();
    return HandleInvokeListenThread(proxy, stubIndex, serverSessionName, replyMessage);
}

std::u16string DBinderService::GetRegisterService(binder_uintptr_t binderObject)
{
    DBINDER_LOGI(LOG_LABEL, "get service binderObject");
    std::shared_lock<std::shared_mutex> lockGuard(remoteBinderMutex_);
    for (auto it = mapRemoteBinderObjects_.begin(); it != mapRemoteBinderObjects_.end(); it++) {
        if (it->second == binderObject) {
            return it->first;
        }
    }
    return std::u16string();
}

bool DBinderService::RegisterRemoteProxy(std::u16string serviceName, sptr<IRemoteObject> binderObject)
{
    DBINDER_LOGI(LOG_LABEL, "register remote proxy, service name = %{public}s", Str16ToStr8(serviceName).c_str());

    if (serviceName.length() == 0 || binderObject == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "serviceName.length() = %zu", serviceName.length());
        return false;
    }

    binder_uintptr_t binder = (binder_uintptr_t)binderObject.GetRefPtr();
    DBINDER_LOGI(LOG_LABEL, "register remote proxy");
    return RegisterRemoteProxyInner(serviceName, binder);
}

bool DBinderService::RegisterRemoteProxy(std::u16string serviceName, int32_t systemAbilityId)
{
    DBINDER_LOGI(LOG_LABEL, "register remote proxy, service name = %{public}s", Str16ToStr8(serviceName).c_str());

    if (serviceName.length() == 0 || systemAbilityId <= 0) {
        DBINDER_LOGE(LOG_LABEL, "serviceName.length() = %zu", serviceName.length());
        return false;
    }

    binder_uintptr_t binder = (binder_uintptr_t)systemAbilityId;
    return RegisterRemoteProxyInner(serviceName, binder);
}

bool DBinderService::RegisterRemoteProxyInner(std::u16string serviceName, binder_uintptr_t binder)
{
    std::unique_lock<std::shared_mutex> lockGuard(remoteBinderMutex_);
    // clear historical remnants, Don't care if it succeeds
    (void)mapRemoteBinderObjects_.erase(serviceName);
    auto result = mapRemoteBinderObjects_.insert(std::pair<std::u16string, binder_uintptr_t>(serviceName, binder));
    return result.second;
}

bool DBinderService::OnRemoteMessageTask(const struct DHandleEntryTxRx *message)
{
    if (message == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "message is null");
        return false;
    }

    bool result = true;
    switch (message->dBinderCode) {
        case MESSAGE_AS_INVOKER: {
            result = OnRemoteInvokerMessage(message);
            break;
        }
        case MESSAGE_AS_REPLY: {
            OnRemoteReplyMessage(message);
            break;
        }
        case MESSAGE_AS_REMOTE_ERROR: {
            OnRemoteErrorMessage(message);
            break;
        }
        default: {
            DBINDER_LOGE(LOG_LABEL, "ERROR! DbinderCode is wrong value, code =%u", message->dBinderCode);
            result = false;
            break;
        }
    }
    return result;
}

bool DBinderService::ProcessOnSessionClosed(std::shared_ptr<Session> session)
{
    if (session == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "ERROR!Session is nullptr!");
        return false;
    }
    std::lock_guard<std::mutex> lock(threadLockMutex_);
    for (auto it = threadLockInfo_.begin(); it != threadLockInfo_.end();) {
        if (it->second->networkId != session->GetPeerDeviceId()) {
            continue;
        }
        std::unique_lock<std::mutex> lock(it->second->mutex);
        it->second->ready = true;
        it->second->condition.notify_all();
        it = threadLockInfo_.erase(it);
    }
    return true;
}

void DBinderService::OnRemoteErrorMessage(const struct DHandleEntryTxRx *replyMessage)
{
    DBINDER_LOGI(LOG_LABEL, "invoke remote stub = %{public}d error, seq = %{public}u",
        static_cast<int32_t>(replyMessage->stubIndex), replyMessage->seqNumber);
    WakeupThreadByStub(replyMessage->seqNumber);
    DetachThreadLockInfo(replyMessage->seqNumber);
}

void DBinderService::OnRemoteReplyMessage(const struct DHandleEntryTxRx *replyMessage)
{
    MakeSessionByReplyMessage(replyMessage);
    WakeupThreadByStub(replyMessage->seqNumber);
    DetachThreadLockInfo(replyMessage->seqNumber);
}

bool DBinderService::IsSameSession(std::shared_ptr<struct SessionInfo> oldSession,
    std::shared_ptr<struct SessionInfo> nowSession)
{
    if ((oldSession->stubIndex != nowSession->stubIndex) || (oldSession->type != nowSession->type)
        ||(oldSession->serviceName != nowSession->serviceName)) {
        return false;
    }
    if (strncmp(oldSession->deviceIdInfo.fromDeviceId, nowSession->deviceIdInfo.fromDeviceId, DEVICEID_LENGTH) != 0
        || strncmp(oldSession->deviceIdInfo.toDeviceId, nowSession->deviceIdInfo.toDeviceId, DEVICEID_LENGTH) != 0) {
        return false;
    }

    return true;
}

void DBinderService::MakeSessionByReplyMessage(const struct DHandleEntryTxRx *replyMessage)
{
    if (HasDBinderStub(replyMessage->binderObject) == false) {
        DBINDER_LOGE(LOG_LABEL, "invalid stub object");
        return;
    }

    std::shared_ptr<struct SessionInfo> session = std::make_shared<struct SessionInfo>();
    if (session == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "new SessionInfo fail");
        return;
    }

    if (memcpy_s(&session->deviceIdInfo, sizeof(struct DeviceIdInfo), &replyMessage->deviceIdInfo,
        sizeof(struct DeviceIdInfo)) != 0) {
        DBINDER_LOGE(LOG_LABEL, "fail to copy memory");
        return;
    }
    session->seqNumber = replyMessage->seqNumber;
    session->socketFd    = 0;
    session->stubIndex   = replyMessage->stubIndex;
    session->rpcFeatureSet = 0;
    if (IsFeatureAck(replyMessage->rpcFeatureSet) == true) {
        session->rpcFeatureSet = replyMessage->rpcFeatureSet & GetLocalRpcFeature();
    }
    session->type        = replyMessage->transType;
    session->serviceName = replyMessage->serviceName;

    if (session->stubIndex == 0) {
        DBINDER_LOGE(LOG_LABEL, "get stub index == 0, it is invalid");
        return;
    }

    std::shared_ptr<struct SessionInfo> oldSession = QuerySessionObject(replyMessage->stub);
    if (oldSession != nullptr) {
        if (IsSameSession(oldSession, session)) {
            DBINDER_LOGI(LOG_LABEL, "invoker remote session already, do nothing");
            return;
        }
        if (oldSession->seqNumber < session->seqNumber) {
            DBINDER_LOGI(LOG_LABEL, "replace oldsession %{public}s with newsession %{public}s",
                oldSession->serviceName.c_str(), session->serviceName.c_str());
            if (!DetachSessionObject(replyMessage->stub)) {
                DBINDER_LOGE(LOG_LABEL, "failed to detach session object");
            }
        }
    }

    if (!AttachSessionObject(session, replyMessage->stub)) {
        DBINDER_LOGE(LOG_LABEL, "attach SessionInfo fail");
        return;
    }
}

void DBinderService::WakeupThreadByStub(uint32_t seqNumber)
{
    std::shared_ptr<struct ThreadLockInfo> threadLockInfo = QueryThreadLockInfo(seqNumber);
    if (threadLockInfo == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "threadLockInfo is not exist");
        return;
    }
    /* Wake up the client processing thread */
    std::unique_lock<std::mutex> lock(threadLockInfo->mutex);
    threadLockInfo->ready = true;
    threadLockInfo->condition.notify_all();
}

void DBinderService::DetachThreadLockInfo(uint32_t seqNumber)
{
    std::lock_guard<std::mutex> lock(threadLockMutex_);
    threadLockInfo_.erase(seqNumber);
}

bool DBinderService::AttachThreadLockInfo(uint32_t seqNumber, const std::string &networkId,
    std::shared_ptr<struct ThreadLockInfo> object)
{
    std::lock_guard<std::mutex> lock(threadLockMutex_);
    object->networkId = networkId;
    auto result =
        threadLockInfo_.insert(std::pair<uint32_t, std::shared_ptr<struct ThreadLockInfo>>(seqNumber, object));

    return result.second;
}

std::shared_ptr<struct ThreadLockInfo> DBinderService::QueryThreadLockInfo(uint32_t seqNumber)
{
    std::lock_guard<std::mutex> lock(threadLockMutex_);

    auto it = threadLockInfo_.find(seqNumber);
    if (it != threadLockInfo_.end()) {
        return it->second;
    }
    return nullptr;
}

bool DBinderService::DetachProxyObject(binder_uintptr_t binderObject)
{
    std::unique_lock<std::shared_mutex> lock(proxyMutex_);

    return (proxyObject_.erase(binderObject) > 0);
}

bool DBinderService::AttachProxyObject(sptr<IRemoteObject> object, binder_uintptr_t binderObject)
{
    std::unique_lock<std::shared_mutex> lock(proxyMutex_);

    auto result = proxyObject_.insert(std::pair<int, sptr<IRemoteObject>>(binderObject, object));
    return result.second;
}

sptr<IRemoteObject> DBinderService::QueryProxyObject(binder_uintptr_t binderObject)
{
    std::shared_lock<std::shared_mutex> lock(proxyMutex_);

    auto it = proxyObject_.find(binderObject);
    if (it != proxyObject_.end()) {
        return it->second;
    }
    return nullptr;
}

bool DBinderService::DetachSessionObject(binder_uintptr_t stub)
{
    std::unique_lock<std::shared_mutex> lock(sessionMutex_);

    return (sessionObject_.erase(stub) > 0);
}

bool DBinderService::AttachSessionObject(std::shared_ptr<struct SessionInfo> object, binder_uintptr_t stub)
{
    std::unique_lock<std::shared_mutex> lock(sessionMutex_);

    auto ret = sessionObject_.insert(std::pair<binder_uintptr_t, std::shared_ptr<struct SessionInfo>>(stub, object));

    return ret.second;
}

std::shared_ptr<struct SessionInfo> DBinderService::QuerySessionObject(binder_uintptr_t stub)
{
    std::shared_lock<std::shared_mutex> lock(sessionMutex_);

    auto it = sessionObject_.find(stub);
    if (it != sessionObject_.end()) {
        return it->second;
    }
    return nullptr;
}

bool DBinderService::DetachBusNameObject(IPCObjectProxy *proxy)
{
    std::unique_lock<std::shared_mutex> lock(busNameMutex_);

    return (busNameObject_.erase(proxy) > 0);
}

bool DBinderService::AttachBusNameObject(IPCObjectProxy *proxy, const std::string &name)
{
    std::unique_lock<std::shared_mutex> lock(busNameMutex_);

    auto ret = busNameObject_.insert(std::pair<IPCObjectProxy *, std::string>(proxy, name));

    return ret.second;
}

std::string DBinderService::QueryBusNameObject(IPCObjectProxy *proxy)
{
    std::shared_lock<std::shared_mutex> lock(busNameMutex_);

    auto it = busNameObject_.find(proxy);
    if (it != busNameObject_.end()) {
        return it->second;
    }
    return "";
}

bool DBinderService::DetachDeathRecipient(sptr<IRemoteObject> object)
{
    std::unique_lock<std::shared_mutex> lockGuard(deathRecipientMutex_);

    return (deathRecipients_.erase(object) > 0);
}

bool DBinderService::AttachDeathRecipient(sptr<IRemoteObject> object,
    sptr<IRemoteObject::DeathRecipient> deathRecipient)
{
    std::unique_lock<std::shared_mutex> lockGuard(deathRecipientMutex_);

    auto ret = deathRecipients_.insert(
        std::pair<sptr<IRemoteObject>, sptr<IRemoteObject::DeathRecipient>>(object, deathRecipient));

    return ret.second;
}

sptr<IRemoteObject::DeathRecipient> DBinderService::QueryDeathRecipient(sptr<IRemoteObject> object)
{
    std::shared_lock<std::shared_mutex> lockGuard(deathRecipientMutex_);

    auto it = deathRecipients_.find(object);
    if (it != deathRecipients_.end()) {
        return it->second;
    }

    return nullptr;
}


bool DBinderService::DetachCallbackProxy(sptr<IRemoteObject> object)
{
    std::lock_guard<std::mutex> lockGuard(callbackProxyMutex_);

    return (noticeProxy_.erase(object) > 0);
}

bool DBinderService::AttachCallbackProxy(sptr<IRemoteObject> object, DBinderServiceStub *dbStub)
{
    std::lock_guard<std::mutex> lockGuard(callbackProxyMutex_);

    auto result = noticeProxy_.insert(std::pair<sptr<IRemoteObject>, DBinderServiceStub *>(object, dbStub));

    return result.second;
}

bool DBinderService::NoticeCallbackProxy(sptr<DBinderServiceStub> dbStub)
{
    DBINDER_LOGI(LOG_LABEL, "%{public}s: enter, service:%{public}s devicId:%{public}s",
        __func__, dbStub->GetServiceName().c_str(),
        DBinderService::ConvertToSecureDeviceID(dbStub->GetDeviceID()).c_str());
    bool status = true;
    const binder_uintptr_t binderObject = reinterpret_cast<binder_uintptr_t>(dbStub.GetRefPtr());
    if (!DetachSessionObject(binderObject)) {
        DBINDER_LOGE(LOG_LABEL, "fail to detach session object");
        status = false;
    }

    if (!DeleteDBinderStub(Str8ToStr16(dbStub->GetServiceName()), dbStub->GetDeviceID())) {
        DBINDER_LOGE(LOG_LABEL, "fail to delete DBinder stub");
        status = false;
    }

    ProcessCallbackProxy(dbStub);

    return status;
}

void DBinderService::ProcessCallbackProxy(sptr<DBinderServiceStub> dbStub)
{
    std::lock_guard<std::mutex> lockGuard(callbackProxyMutex_);

    for (auto it = noticeProxy_.begin(); it != noticeProxy_.end();) {
        if (it->second == dbStub.GetRefPtr()) {
            IPCObjectProxy *callbackProxy = reinterpret_cast<IPCObjectProxy *>((it->first).GetRefPtr());
            int status = callbackProxy->NoticeServiceDie();
            if (status != ERR_NONE) {
                DBINDER_LOGE(LOG_LABEL, "fail to notice service");
                // do nothing, Continue to clear subsequent data
            }

            sptr<IRemoteObject::DeathRecipient> death = QueryDeathRecipient((it->first));
            if (death != nullptr) {
                // Continue to clear subsequent data
                callbackProxy->RemoveDeathRecipient(death);
            }

            if (!DetachDeathRecipient((it->first))) {
                DBINDER_LOGE(LOG_LABEL, "detaching death recipient is failed");
            }

            it = noticeProxy_.erase(it);
        } else {
            it++;
        }
    }
}

int32_t DBinderService::NoticeServiceDieInner(const std::u16string &serviceName, const std::string &deviceID)
{
    if (serviceName.empty() || IsDeviceIdIllegal(deviceID)) {
        DBINDER_LOGE(LOG_LABEL, "service name length = %zu, deviceID length = %zu",
            serviceName.length(), deviceID.length());
        return DBINDER_SERVICE_INVALID_DATA_ERR;
    }

    DBINDER_LOGI(LOG_LABEL, "%{public}s: service:%{public}s devicId:%{public}s",
        __func__, Str16ToStr8(serviceName).c_str(),
        DBinderService::ConvertToSecureDeviceID(deviceID).c_str());

    sptr<DBinderServiceStub> dbStub = FindDBinderStub(serviceName, deviceID);
    if (dbStub == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "find null stub, do not need notice death");
        return ERR_NONE;
    }

    if (!NoticeCallbackProxy(dbStub)) {
        DBINDER_LOGE(LOG_LABEL, "find null proxy");
        return DBINDER_SERVICE_NOTICE_DIE_ERR;
    }
    return ERR_NONE;
}

int32_t DBinderService::NoticeServiceDie(const std::u16string &serviceName, const std::string &deviceID)
{
    std::lock_guard<std::mutex> lockGuard(deathNotificationMutex_);
    return NoticeServiceDieInner(serviceName, deviceID);
}

int32_t DBinderService::NoticeDeviceDie(const std::string &deviceID)
{
    if (IsDeviceIdIllegal(deviceID)) {
        DBINDER_LOGE(LOG_LABEL, "deviceID length = %zu", deviceID.length());
        return DBINDER_SERVICE_INVALID_DATA_ERR;
    }
    DBINDER_LOGI(LOG_LABEL, "remote device is dead, device = %s",
        DBinderService::ConvertToSecureDeviceID(deviceID).c_str());
    if (remoteListener_ == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "remote listener is null");
        return DBINDER_SERVICE_NOTICE_DIE_ERR;
    }

    if (!remoteListener_->CloseDatabusSession(deviceID)) {
        DBINDER_LOGE(LOG_LABEL, "close databus session fail");
        // do nothing
    }

    std::list<std::u16string> serviceNames = FindServicesByDeviceID(deviceID);
    if (serviceNames.empty()) {
        DBINDER_LOGE(LOG_LABEL, "the device does not have any registered service");
        return ERR_NONE;
    }

    int status = ERR_NONE;
    std::lock_guard<std::mutex> lockGuard(deathNotificationMutex_);

    for (auto it = serviceNames.begin(); it != serviceNames.end(); it++) {
        status += NoticeServiceDieInner((*it), deviceID);
    }

    return status;
}

std::list<std::u16string> DBinderService::FindServicesByDeviceID(const std::string &deviceID)
{
    std::lock_guard<std::mutex> lockGuard(handleEntryMutex_);
    std::list<std::u16string> serviceNames;
    for (auto it = DBinderStubRegisted_.begin(); it != DBinderStubRegisted_.end(); it++) {
        if ((*it)->GetDeviceID() == deviceID) {
            serviceNames.push_back(Str8ToStr16((*it)->GetServiceName()));
        }
    }

    return serviceNames;
}

uint32_t DBinderService::GetRemoteTransType()
{
    return IRemoteObject::DATABUS_TYPE;
}

std::string DBinderService::ConvertToSecureDeviceID(const std::string &deviceID)
{
    if (strlen(deviceID.c_str()) <= ENCRYPT_LENGTH) {
        return "****";
    }
    return deviceID.substr(0, ENCRYPT_LENGTH) + "****" + deviceID.substr(strlen(deviceID.c_str()) - ENCRYPT_LENGTH);
}

bool DBinderService::ReGrantPermission(const std::string &sessionName)
{
    if (sessionName.empty()) {
        return false;
    }
    std::string::size_type splitIndex = sessionName.find('_');
    if (splitIndex == std::string::npos) {
        DBINDER_LOGE(LOG_LABEL, "grant permission not found _");
        return false;
    }
    int32_t uidLength = static_cast<int32_t>(splitIndex) - DBINDER_UID_START_INDEX;
    std::string uidString = sessionName.substr(DBINDER_UID_START_INDEX, uidLength);
    std::string pidString = sessionName.substr(splitIndex + 1);
    std::shared_ptr<ISessionService> softbusManager = ISessionService::GetInstance();
    if (softbusManager == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "fail to get softbus service");
        return false;
    }

    if (softbusManager->GrantPermission(std::stoi(uidString), std::stoi(pidString), sessionName) != ERR_NONE) {
        DBINDER_LOGE(LOG_LABEL, "fail to Grant Permission softbus name");
        return false;
    }
    return true;
}
} // namespace OHOS
