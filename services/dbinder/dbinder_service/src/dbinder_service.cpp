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

#include <cinttypes>
#include "securec.h"
#include "string_ex.h"
#include "ipc_skeleton.h"
#include "ipc_thread_skeleton.h"

#include "dbinder_error_code.h"
#include "dbinder_log.h"
#include "dbinder_remote_listener.h"
#include "dbinder_sa_death_recipient.h"
#include "dbinder_service_stub.h"
#include "ffrt.h"
#include "softbus_bus_center.h"

namespace OHOS {

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_RPC_DBINDER_SER, "DbinderService" };

sptr<DBinderService> DBinderService::instance_ = nullptr;
bool DBinderService::mainThreadCreated_ = false;
std::mutex DBinderService::instanceMutex_;
std::shared_ptr<DBinderRemoteListener> DBinderService::remoteListener_ = nullptr;
constexpr unsigned int BINDER_MASK = 0xffff;
// DBinderServiceStub's reference count in a MakeRemoteBinder call.
constexpr int DBINDER_STUB_REF_COUNT = 2;

DBinderService::DBinderService()
{
    DBINDER_LOGI(LOG_LABEL, "create dbinder service");
}

DBinderService::~DBinderService()
{
    StopRemoteListener();

    DBinderStubRegisted_.clear();
    mapDBinderStubRegisters_.clear();
    mapRemoteBinderObjects_.clear();
    threadLockInfo_.clear();
    proxyObject_.clear();
    sessionObject_.clear();
    noticeProxy_.clear();
    deathRecipients_.clear();
    loadSaReply_.clear();
    dbinderCallback_ = nullptr;
    DBINDER_LOGI(LOG_LABEL, "dbinder service died");
}

std::string DBinderService::GetLocalDeviceID()
{
    std::string pkgName = "DBinderService";
    std::string networkId;

    if (DBinderSoftbusClient::GetInstance().GetLocalNodeDeviceId(
        pkgName.c_str(), networkId) != SOFTBUS_CLIENT_SUCCESS) {
        DBINDER_LOGE(LOG_LABEL, "Get local node device id failed");
    }

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

    remoteListener_ = std::make_shared<DBinderRemoteListener>();
    if (remoteListener_ == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "failed to create remote listener");
        return false;
    }

    if (remoteListener_->StartListener() != true) {
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
    if (remoteListener_->StartListener() != true) {
        DBINDER_LOGE(LOG_LABEL, "restart dbinder server failed");
        StopRemoteListener();
        return false;
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
    if (seqNumber_ == std::numeric_limits<uint32_t>::max()) {
        seqNumber_ = 0;
    }
    seqNumber_++;
    return seqNumber_;
}

bool DBinderService::IsDeviceIdIllegal(const std::string &deviceID)
{
    if (deviceID.empty() || deviceID.length() > DEVICEID_LENGTH) {
        return true;
    }
    return false;
}

binder_uintptr_t DBinderService::AddStubByTag(binder_uintptr_t stub)
{
    std::lock_guard<std::mutex> lockGuard(handleEntryMutex_);

    // the same stub needs add stubNum to mapDBinderStubRegisters_, the previous corresponding stubNum will be returned.
    for (auto iter = mapDBinderStubRegisters_.begin(); iter != mapDBinderStubRegisters_.end(); iter++) {
        if (iter->second == stub) {
            return iter->first;
        }
    }
    binder_uintptr_t stubTag = stubTagNum_++;
    auto result = mapDBinderStubRegisters_.insert(
        std::pair<binder_uintptr_t, binder_uintptr_t>(stubTag, stub));
    if (result.second) {
        return stubTag;
    } else {
        return 0;
    }
}

binder_uintptr_t DBinderService::QueryStubPtr(binder_uintptr_t stubTag)
{
    std::lock_guard<std::mutex> lockGuard(handleEntryMutex_);

    auto iter = mapDBinderStubRegisters_.find(stubTag);
    if (iter != mapDBinderStubRegisters_.end()) {
        return iter->second;
    }

    return 0;
}

bool DBinderService::CheckBinderObject(const sptr<DBinderServiceStub> &stub, binder_uintptr_t stubPtr)
{
    if (stub == nullptr) {
        return false;
    }

    if (reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr()) == stubPtr) {
        DBINDER_LOGI(LOG_LABEL, "found registered stub");
        return true;
    }
    return false;
}

bool DBinderService::HasDBinderStub(binder_uintptr_t stubPtr)
{
    auto checkStub = [&stubPtr, this](const sptr<DBinderServiceStub> &stub) {
        return CheckBinderObject(stub, stubPtr);
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
    const std::string serviceStr8 = Str16ToStr8(service);
    if (IsSameTextStr(stub->GetServiceName(), serviceStr8) && IsSameTextStr(stub->GetDeviceID(), device)) {
        DBINDER_LOGI(LOG_LABEL, "found registered service, name:%{public}s device:%{public}s",
            serviceStr8.c_str(), DBinderService::ConvertToSecureDeviceID(device).c_str());
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
        DBINDER_LOGW(LOG_LABEL, "not found, service:%{public}s device:%{public}s", Str16ToStr8(service).c_str(),
            DBinderService::ConvertToSecureDeviceID(device).c_str());
        return nullptr;
    }
    DBINDER_LOGD(LOG_LABEL, "found, service:%{public}s device:%{public}s", Str16ToStr8(service).c_str(),
        DBinderService::ConvertToSecureDeviceID(device).c_str());
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
        DBINDER_LOGW(LOG_LABEL, "not found, service:%{public}s device:%{public}s", Str16ToStr8(service).c_str(),
            DBinderService::ConvertToSecureDeviceID(device).c_str());
        return false;
    }

    for (auto mapIt = mapDBinderStubRegisters_.begin(); mapIt != mapDBinderStubRegisters_.end();) {
        if (mapIt->second == reinterpret_cast<binder_uintptr_t>((*it).GetRefPtr())) {
            mapIt = mapDBinderStubRegisters_.erase(mapIt);
        } else {
            ++mapIt;
        }
    }
    DBinderStubRegisted_.erase(it);
    DBINDER_LOGI(LOG_LABEL, "succ, service:%{public}s device:%{public}s", Str16ToStr8(service).c_str(),
        DBinderService::ConvertToSecureDeviceID(device).c_str());
    return true;
}

sptr<DBinderServiceStub> DBinderService::FindOrNewDBinderStub(const std::u16string &service, const std::string &device,
    binder_uintptr_t binderObject)
{
    auto checkStub = [&service, &device, this](const sptr<DBinderServiceStub> &stub) {
        return IsSameStubObject(stub, service, device);
    };

    std::lock_guard<std::mutex> lockGuard(handleEntryMutex_);
    const std::string serviceStr8 = Str16ToStr8(service);
    auto it = std::find_if(DBinderStubRegisted_.begin(), DBinderStubRegisted_.end(), checkStub);
    if (it != DBinderStubRegisted_.end()) {
        DBINDER_LOGD(LOG_LABEL, "found, service:%{public}s device:%{public}s", serviceStr8.c_str(),
            DBinderService::ConvertToSecureDeviceID(device).c_str());
        return (*it);
    }

    sptr<DBinderServiceStub> dBinderServiceStub = new DBinderServiceStub(serviceStr8, device, binderObject);
    DBinderStubRegisted_.push_back(dBinderServiceStub);
    DBINDER_LOGD(LOG_LABEL, "create, service:%{public}s device:%{public}s", serviceStr8.c_str(),
        DBinderService::ConvertToSecureDeviceID(device).c_str());
    return dBinderServiceStub;
}

sptr<DBinderServiceStub> DBinderService::MakeRemoteBinder(const std::u16string &serviceName,
    const std::string &deviceID, int32_t binderObject, uint32_t pid, uint32_t uid)
{
    if (IsDeviceIdIllegal(deviceID) || serviceName.length() == 0) {
        DBINDER_LOGE(LOG_LABEL, "para is wrong, device length:%{public}zu, service length:%{public}zu",
            deviceID.length(), serviceName.length());
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ERR_INVALID_DATA, __FUNCTION__);
        return nullptr;
    }
    const std::string serviceNameStr8 = Str16ToStr8(serviceName);
    DBINDER_LOGI(LOG_LABEL, "service:%{public}s device:%{public}s", serviceNameStr8.c_str(),
        DBinderService::ConvertToSecureDeviceID(deviceID).c_str());
    DfxReportDeviceEvent(DbinderErrorCode::RPC_DRIVER, DbinderErrorCode::IPC_RESULT_IDLE,
        DBinderService::ConvertToSecureDeviceID(deviceID).c_str(), __FUNCTION__);

    sptr<DBinderServiceStub> dBinderServiceStub = FindOrNewDBinderStub(serviceName, deviceID,
        static_cast<binder_uintptr_t>(binderObject));
    if (dBinderServiceStub == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "FindOrNewDBinderStub fail, service:%{public}s", serviceNameStr8.c_str());
        return nullptr;
    }

    /* if not found dBinderServiceStub, should send msg to toDeviceID
     * to invoker socket thread and add authentication info for create softbus session
     */
    int retryTimes = 0;
    int32_t ret = -1;
    do {
        ret = InvokerRemoteDBinder(dBinderServiceStub, GetSeqNumber(), pid, uid);
        retryTimes++;
    } while (ret == WAIT_REPLY_TIMEOUT && (retryTimes < RETRY_TIMES));

    if (ret != DBINDER_OK) {
        DBINDER_LOGE(LOG_LABEL, "fail to invoke service, service:%{public}s device:%{public}s "
            "DBinderServiceStub refcount:%{public}d",
            serviceNameStr8.c_str(), DBinderService::ConvertToSecureDeviceID(deviceID).c_str(),
            dBinderServiceStub->GetSptrRefCount());
        if (dBinderServiceStub->GetSptrRefCount() <= DBINDER_STUB_REF_COUNT) {
            /* invoke fail, delete dbinder stub info */
            (void)DeleteDBinderStub(serviceName, deviceID);
            (void)DetachSessionObject(reinterpret_cast<binder_uintptr_t>(dBinderServiceStub.GetRefPtr()));
        }
        return nullptr;
    }

    return dBinderServiceStub;
}

bool DBinderService::CheckDeviceIDsInvalid(const std::string &deviceID, const std::string &localDevID)
{
    if (IsDeviceIdIllegal(deviceID) || IsDeviceIdIllegal(localDevID)) {
        DBINDER_LOGE(LOG_LABEL, "wrong device id length, remote:%{public}zu local:%{public}zu",
            deviceID.length(), localDevID.length());
        return true;
    }
    return false;
}

bool DBinderService::CopyDeviceIDsToMessage(std::shared_ptr<struct DHandleEntryTxRx> message,
    const std::string &localDevID, const std::string &deviceID)
{
    if (memcpy_s(message->deviceIdInfo.fromDeviceId, DEVICEID_LENGTH, localDevID.data(), localDevID.length()) != 0 ||
        memcpy_s(message->deviceIdInfo.toDeviceId, DEVICEID_LENGTH, deviceID.data(), deviceID.length()) != 0) {
        DBINDER_LOGE(LOG_LABEL, "fail to copy memory, service:%{public}" PRIu64" seq:%{public}u",
            message->stubIndex, message->seqNumber);
        return false;
    }
    message->deviceIdInfo.fromDeviceId[localDevID.length()] = '\0';
    message->deviceIdInfo.toDeviceId[deviceID.length()] = '\0';
    return true;
}

std::shared_ptr<struct DHandleEntryTxRx> DBinderService::CreateMessage(const sptr<DBinderServiceStub> &stub,
    uint32_t seqNumber, uint32_t pid, uint32_t uid)
{
    auto message = std::make_shared<struct DHandleEntryTxRx>();
    if (message == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "new DHandleEntryTxRx fail");
        return nullptr;
    }

    message->head.len = sizeof(DHandleEntryTxRx);
    message->head.version = RPC_TOKENID_SUPPORT_VERSION;
    message->dBinderCode = MESSAGE_AS_INVOKER;
    message->transType = GetRemoteTransType();
    message->fromPort = 0;
    message->toPort = 0;
    message->stubIndex = static_cast<uint64_t>(std::atoi(stub->GetServiceName().c_str()));
    message->seqNumber = seqNumber;
    message->binderObject = stub->GetBinderObject();
    message->stub = AddStubByTag(reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr()));
    message->deviceIdInfo.tokenId = IPCSkeleton::GetCallingTokenID();
    message->pid = pid;
    message->uid = uid;

    return message;
}

bool DBinderService::SendEntryToRemote(const sptr<DBinderServiceStub> stub, uint32_t seqNumber, uint32_t pid,
    uint32_t uid)
{
    const std::string deviceID = stub->GetDeviceID();
    const std::string localDevID = GetLocalDeviceID();
    if (CheckDeviceIDsInvalid(deviceID, localDevID)) {
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ERR_INVALID_DATA, __FUNCTION__);
        return false;
    }

    auto message = CreateMessage(stub, seqNumber, pid, uid);
    if (message == nullptr) {
        return false;
    }

    if (!CopyDeviceIDsToMessage(message, localDevID, deviceID)) {
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ERR_MEMCPY_DATA, __FUNCTION__);
        return false;
    }

    DBINDER_LOGI(LOG_LABEL, "pid:%{public}u uid:%{public}u seq:%{public}u stub:%{public}llu"
        " tokenId:%{public}u", message->pid, message->uid, message->seqNumber,
        (message->stub & BINDER_MASK), message->deviceIdInfo.tokenId);
    std::shared_ptr<DBinderRemoteListener> remoteListener = GetRemoteListener();
    if (remoteListener == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "remoteListener is null, service:%{public}" PRIu64 " seq:%{public}u",
            message->stubIndex, message->seqNumber);
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_GET_REMOTE_LISTENER_FAIL, __FUNCTION__);
        return false;
    }
    bool result = remoteListener->SendDataToRemote(deviceID, message.get());
    if (result != true) {
        DBINDER_LOGE(LOG_LABEL, "SendDataToRemote failed, service:%{public}" PRIu64" seq:%{public}u",
            message->stubIndex, message->seqNumber);
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_SEND_DATA_TO_REMOTE_FAIL, __FUNCTION__);
        return false;
    }
    return true;
}

int32_t DBinderService::InvokerRemoteDBinder(const sptr<DBinderServiceStub> stub, uint32_t seqNumber,
    uint32_t pid, uint32_t uid)
{
    if (stub == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "stub is nullptr");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ERR_INVALID_DATA, __FUNCTION__);
        return STUB_INVALID;
    }

    bool result = SendEntryToRemote(stub, seqNumber, pid, uid);
    if (!result) {
        DBINDER_LOGE(LOG_LABEL, "SendEntryToRemote fail, seq:%{public}u", seqNumber);
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_SEND_ENTRY_TO_REMOTE_FAIL, __FUNCTION__);
        return SEND_MESSAGE_FAILED;
    }

    /* pend to wait reply */
    std::shared_ptr<struct ThreadLockInfo> threadLockInfo = std::make_shared<struct ThreadLockInfo>();
    result = AttachThreadLockInfo(seqNumber, stub->GetDeviceID(), threadLockInfo);
    if (result != true) {
        DBINDER_LOGE(LOG_LABEL, "AttachThreadLockInfo fail, seq:%{public}u", seqNumber);
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ATTACH_THREADLOCK_FAIL, __FUNCTION__);
        return MAKE_THREADLOCK_FAILED;
    }

    std::unique_lock<std::mutex> lock(threadLockInfo->mutex);
    if (threadLockInfo->condition.wait_for(lock, std::chrono::seconds(WAIT_FOR_REPLY_MAX_SEC),
        [&threadLockInfo] { return threadLockInfo->ready; }) == false) {
        DBINDER_LOGE(LOG_LABEL, "get remote data timeout or ssession is  closed, seq:%{public}u", seqNumber);
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_WAIT_REPLY_TIMEOUT, __FUNCTION__);
        DetachThreadLockInfo(seqNumber);
        threadLockInfo->ready = false;
        return WAIT_REPLY_TIMEOUT;
    }
    /* if can not find session, means invoke failed or nothing in OnRemoteReplyMessage() */
    auto session = QuerySessionObject(reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr()));
    if (session == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "client find session is null, seq:%{public}u", seqNumber);
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_QUERY_REPLY_SESSION_FAIL, __FUNCTION__);
        return QUERY_REPLY_SESSION_FAILED;
    }
    return DBINDER_OK;
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

    std::lock_guard<std::shared_mutex> lockGuard(loadSaMutex_);
    auto it = std::find_if(loadSaReply_.begin(), loadSaReply_.end(), checkSaItem);
    if (it == loadSaReply_.end()) {
        DBINDER_LOGI(LOG_LABEL, "no msg for saId:%{public}d, deviceId:%{public}s",
            systemAbilityId, DBinderService::ConvertToSecureDeviceID(srcNetworkId).c_str());
        return nullptr;
    }
    std::shared_ptr<DHandleEntryTxRx> replymsg = (*it);
    it = loadSaReply_.erase(it);
    return replymsg;
}

void DBinderService::LoadSystemAbilityComplete(const std::string& srcNetworkId, int32_t systemAbilityId,
    const sptr<IRemoteObject>& remoteObject)
{
    while (true) {
        std::shared_ptr<struct DHandleEntryTxRx> replyMessage = PopLoadSaItem(srcNetworkId, systemAbilityId);
        if (replyMessage == nullptr) {
            break;
        }
        if (remoteObject == nullptr) {
            SendReplyMessageToRemote(MESSAGE_AS_REMOTE_ERROR, SA_NOT_FOUND, replyMessage);
            DBINDER_LOGE(LOG_LABEL, "GetSystemAbility from samgr error, saId:%{public}d", systemAbilityId);
            continue;
        }
        binder_uintptr_t binderObject = replyMessage->binderObject;
        IPCObjectProxy *saProxy = reinterpret_cast<IPCObjectProxy *>(remoteObject.GetRefPtr());
        if (QueryProxyObject(binderObject) == nullptr) {
            /* When the stub object dies, you need to delete the corresponding busName information */
            sptr<IRemoteObject::DeathRecipient> death(new DbinderSaDeathRecipient(binderObject));
            if (!saProxy->AddDeathRecipient(death)) {
                SendReplyMessageToRemote(MESSAGE_AS_REMOTE_ERROR, SA_NOT_FOUND, replyMessage);
                DBINDER_LOGE(LOG_LABEL, "fail to add death recipient");
                DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ADD_DEATH_RECIPIENT_FAIL, __FUNCTION__);
                continue;
            }
            if (!AttachProxyObject(remoteObject, binderObject)) {
                DBINDER_LOGW(LOG_LABEL, "attach proxy object is already existed");
            }
        }
        std::string deviceId = replyMessage->deviceIdInfo.fromDeviceId;
        if (replyMessage->transType != IRemoteObject::DATABUS_TYPE) {
            SendReplyMessageToRemote(MESSAGE_AS_REMOTE_ERROR, SA_INVOKE_FAILED, replyMessage);
            DBINDER_LOGE(LOG_LABEL, "Invalid Message Type");
            DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ERR_INVALID_DATA, __FUNCTION__);
        } else {
            // peer device rpc version == 1, not support thokenId and message->deviceIdInfo.tokenId is random value
            uint32_t tokenId = (replyMessage->head.version < RPC_TOKENID_SUPPORT_VERSION) ?
                0 : replyMessage->deviceIdInfo.tokenId;
            uint32_t result = OnRemoteInvokerDataBusMessage(saProxy, replyMessage, deviceId,
                replyMessage->pid, replyMessage->uid, tokenId);
            if (result != 0) {
                SendReplyMessageToRemote(MESSAGE_AS_REMOTE_ERROR, result, replyMessage);
                continue;
            }
            SendReplyMessageToRemote(MESSAGE_AS_REPLY, 0, replyMessage);
        }
    }
    DBINDER_LOGI(LOG_LABEL, "LoadSystemAbility complete");
}

void DBinderService::SendReplyMessageToRemote(uint32_t dBinderCode, uint32_t reason,
    std::shared_ptr<struct DHandleEntryTxRx> replyMessage)
{
    std::shared_ptr<DBinderRemoteListener> remoteListener = GetRemoteListener();
    if (remoteListener == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "remoteListener is null");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_GET_REMOTE_LISTENER_FAIL, __FUNCTION__);
        return;
    }
    replyMessage->dBinderCode = dBinderCode;
    if (dBinderCode == MESSAGE_AS_REMOTE_ERROR) {
        replyMessage->transType = reason; // reuse transType send back error code
    }
    if (!remoteListener->SendDataReply(replyMessage->deviceIdInfo.fromDeviceId, replyMessage.get())) {
        DBINDER_LOGE(LOG_LABEL, "fail to send data from server DBS to client DBS");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_SEND_DATA_REPLAY_FAIL, __FUNCTION__);
    }
}

bool DBinderService::CheckAndAmendSaId(std::shared_ptr<struct DHandleEntryTxRx> message)
{
    bool ret = true;
    int32_t stubIndex = static_cast<int32_t>(message->stubIndex);
    int32_t binderObject = static_cast<int32_t>(message->binderObject);
    bool stubIndexVaild = CheckSystemAbilityId(stubIndex);
    bool binderObjectVaild = CheckSystemAbilityId(binderObject);
    if (stubIndexVaild && binderObjectVaild) {
        if (stubIndex != binderObject) {
            DBINDER_LOGW(LOG_LABEL, "stubIndex(%{public}d) != binderObject(%{public}d), update said:%{public}d",
                stubIndex, binderObject, stubIndex);
            message->binderObject = message->stubIndex;
        }
    } else if (stubIndexVaild && !binderObjectVaild) {
        DBINDER_LOGI(LOG_LABEL, "update said, replace binderObject:%{public}d with stubIndex:%{public}d",
            binderObject, stubIndex);
        message->binderObject = message->stubIndex;
    } else if (!stubIndexVaild && binderObjectVaild) {
        DBINDER_LOGI(LOG_LABEL, "update said, replace stubIndex:%{public}d with binderObject:%{public}d",
            stubIndex, binderObject);
        message->stubIndex = message->binderObject;
    } else {
        DBINDER_LOGE(LOG_LABEL, "invalid said, stubIndex:%{public}d binderObject:%{public}d",
            stubIndex, binderObject);
        ret = false;
    }
    return ret;
}

bool DBinderService::OnRemoteInvokerMessage(std::shared_ptr<struct DHandleEntryTxRx> message)
{
    if (!CheckAndAmendSaId(message)) {
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_INVALID_SAID, __FUNCTION__);
        SendReplyMessageToRemote(MESSAGE_AS_REMOTE_ERROR, SAID_INVALID_ERR, message);
        return false;
    }

    DBINDER_LOGI(LOG_LABEL,
        "invoke business service:%{public}d seq:%{public}u stub:%{public}llu tokenId:%{public}u",
        static_cast<int32_t>(message->stubIndex), message->seqNumber,
        (message->stub & BINDER_MASK), message->deviceIdInfo.tokenId);
    if (!dbinderCallback_->IsDistributedSystemAbility(message->binderObject)) {
        DBINDER_LOGE(LOG_LABEL, "SA:%{public}llu not have distributed capability.", message->binderObject);
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_NOT_DISTEIBUTED_SA, __FUNCTION__);
        SendReplyMessageToRemote(MESSAGE_AS_REMOTE_ERROR, SA_NOT_DISTRUBUTED_ERR, message);
        return false;
    }

    std::shared_ptr<DHandleEntryTxRx> replyMessage = message;
    {
        std::lock_guard<std::shared_mutex> lockGuard(loadSaMutex_);
        loadSaReply_.push_back(replyMessage);
    }
    bool isSaAvailable = dbinderCallback_->LoadSystemAbilityFromRemote(replyMessage->deviceIdInfo.fromDeviceId,
        static_cast<int32_t>(replyMessage->stubIndex));
    if (!isSaAvailable) {
        DBINDER_LOGE(LOG_LABEL, "fail to call the system ability:%{public}d",
            static_cast<int32_t>(replyMessage->stubIndex));
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_CALL_SYSTEM_ABILITY_FAIL, __FUNCTION__);
        PopLoadSaItem(replyMessage->deviceIdInfo.fromDeviceId, static_cast<int32_t>(replyMessage->stubIndex));
        SendReplyMessageToRemote(MESSAGE_AS_REMOTE_ERROR, SA_NOT_AVAILABLE, replyMessage);
        return false;
    }

    return true;
}

std::string DBinderService::GetDatabusNameByProxy(IPCObjectProxy *proxy)
{
    if (proxy == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "proxy can not be null");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ERR_INVALID_DATA, __FUNCTION__);
        return "";
    }
    std::string sessionName = proxy->GetSessionName();
    if (sessionName.empty()) {
        DBINDER_LOGE(LOG_LABEL, "grand session name failed");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_GRT_SESSION_NAME_FAIL, __FUNCTION__);
        return "";
    }
    DBINDER_LOGD(LOG_LABEL, "succ, handle:%{public}d sessionName:%{public}s",
        proxy->GetHandle(), sessionName.c_str());
    return sessionName;
}

std::string DBinderService::CreateDatabusName(int uid, int pid)
{
    std::string sessionName = "DBinder" + std::to_string(uid) + std::string("_") + std::to_string(pid);
    if (DBinderSoftbusClient::GetInstance().DBinderGrantPermission(uid, pid, sessionName) != ERR_NONE) {
        DBINDER_LOGE(LOG_LABEL, "fail to Grant Permission softbus name");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_GRANT_PERMISSION_FAIL, __FUNCTION__);
        return "";
    }

    return sessionName;
}

bool DBinderService::CheckDeviceIdIllegal(const std::string &remoteDeviceId)
{
    if (IsDeviceIdIllegal(remoteDeviceId)) {
        DBINDER_LOGE(LOG_LABEL, "remote device id is error");
        return true;
    }
    return false;
}

bool DBinderService::CheckSessionNameIsEmpty(const std::string &sessionName)
{
    if (sessionName.empty()) {
        DBINDER_LOGE(LOG_LABEL, "get bus name fail");
        return true;
    }
    return false;
}

bool DBinderService::CheckInvokeListenThreadIllegal(IPCObjectProxy *proxy, MessageParcel &data, MessageParcel &reply)
{
    int err = proxy->InvokeListenThread(data, reply);
    if (err != ERR_NONE) {
        DBINDER_LOGE(LOG_LABEL, "start service listen error:%{public}d handle:%{public}d", err, proxy->GetHandle());
        return true;
    }
    return false;
}

bool DBinderService::CheckStubIndexAndSessionNameIllegal(uint64_t stubIndex, const std::string &serverSessionName,
    const std::string &deviceId, IPCObjectProxy *proxy)
{
    if (stubIndex == 0 || serverSessionName.empty() || serverSessionName.length() > SERVICENAME_LENGTH) {
        DBINDER_LOGE(LOG_LABEL, "stubindex:%{public}" PRIu64 " or sessionName:%{public}s is invalid"
            " handle:%{public}d deviceId:%{public}s", stubIndex, serverSessionName.c_str(), proxy->GetHandle(),
            DBinderService::ConvertToSecureDeviceID(deviceId).c_str());
        return true;
    }
    return false;
}

bool DBinderService::SetReplyMessage(std::shared_ptr<struct DHandleEntryTxRx> replyMessage, uint64_t stubIndex,
    const std::string &serverSessionName, uint32_t selfTokenId, IPCObjectProxy *proxy)
{
    replyMessage->dBinderCode = MESSAGE_AS_REPLY;
    if (replyMessage->head.version >= RPC_TOKENID_SUPPORT_VERSION) {
        replyMessage->dBinderCode = MESSAGE_AS_REPLY_TOKENID;
    }
    replyMessage->head.version = RPC_TOKENID_SUPPORT_VERSION;
    replyMessage->stubIndex = stubIndex;
    replyMessage->serviceNameLength = serverSessionName.length();
    replyMessage->deviceIdInfo.tokenId = selfTokenId;
    if (memcpy_s(replyMessage->serviceName, SERVICENAME_LENGTH, serverSessionName.data(),
        replyMessage->serviceNameLength) != 0) {
        DBINDER_LOGE(LOG_LABEL, "memcpy serviceName fail, handle:%{public}d", proxy->GetHandle());
        return false;
    }
    replyMessage->serviceName[replyMessage->serviceNameLength] = '\0';
    return true;
}

uint32_t DBinderService::OnRemoteInvokerDataBusMessage(IPCObjectProxy *proxy,
    std::shared_ptr<struct DHandleEntryTxRx> replyMessage,
    std::string &remoteDeviceId, int pid, int uid, uint32_t tokenId)
{
    if (CheckDeviceIdIllegal(remoteDeviceId)) {
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ERR_INVALID_DATA, __FUNCTION__);
        return DEVICEID_INVALID;
    }
    std::string sessionName = GetDatabusNameByProxy(proxy);
    if (CheckSessionNameIsEmpty(sessionName)) {
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_GET_BUS_NAME_FAIL, __FUNCTION__);
        return SESSION_NAME_NOT_FOUND;
    }

    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteUint16(IRemoteObject::DATABUS_TYPE) || !data.WriteString(GetLocalDeviceID()) ||
        !data.WriteUint32(pid) || !data.WriteUint32(uid) || !data.WriteString(remoteDeviceId) ||
        !data.WriteString(sessionName) || !data.WriteUint32(tokenId)) {
        DBINDER_LOGE(LOG_LABEL, "write to parcel fail, handle:%{public}d", proxy->GetHandle());
        DfxReportFailHandleEvent(DbinderErrorCode::RPC_DRIVER, proxy->GetHandle(),
            RADAR_WRITE_PARCEL_FAIL, __FUNCTION__);
        return WRITE_PARCEL_FAILED;
    }
    if (CheckInvokeListenThreadIllegal(proxy, data, reply)) {
        DfxReportFailHandleEvent(DbinderErrorCode::RPC_DRIVER, proxy->GetHandle(),
            RADAR_INVOKE_STUB_THREAD_FAIL, __FUNCTION__);
        return INVOKE_STUB_THREAD_FAILED;
    }

    uint64_t stubIndex = reply.ReadUint64();
    std::string serverSessionName = reply.ReadString();
    std::string deviceId = reply.ReadString();
    uint32_t selfTokenId = reply.ReadUint32();
    if (CheckStubIndexAndSessionNameIllegal(stubIndex, serverSessionName, deviceId, proxy)) {
        DfxReportFailHandleEvent(DbinderErrorCode::RPC_DRIVER, proxy->GetHandle(),
            RADAR_SESSION_NAME_INVALID, __FUNCTION__);
        return SESSION_NAME_INVALID;
    }
    if (!SetReplyMessage(replyMessage, stubIndex, serverSessionName, selfTokenId, proxy)) {
        DfxReportFailHandleEvent(DbinderErrorCode::RPC_DRIVER, proxy->GetHandle(), RADAR_ERR_MEMCPY_DATA, __FUNCTION__);
        return SESSION_NAME_INVALID;
    }
    return 0;
}

std::u16string DBinderService::GetRegisterService(binder_uintptr_t binderObject)
{
    std::shared_lock<std::shared_mutex> lockGuard(remoteBinderMutex_);
    for (auto it = mapRemoteBinderObjects_.begin(); it != mapRemoteBinderObjects_.end(); it++) {
        if (it->second == binderObject) {
            DBINDER_LOGI(LOG_LABEL, "get service:%{public}s", Str16ToStr8(it->first).c_str());
            return it->first;
        }
    }
    return std::u16string();
}

bool DBinderService::RegisterRemoteProxy(std::u16string serviceName, sptr<IRemoteObject> binderObject)
{
    if (serviceName.length() == 0 || binderObject == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "serviceName length:%{public}zu", serviceName.length());
        return false;
    }

    DBINDER_LOGI(LOG_LABEL, "service name:%{public}s", Str16ToStr8(serviceName).c_str());
    binder_uintptr_t binder = (binder_uintptr_t)binderObject.GetRefPtr();
    return RegisterRemoteProxyInner(serviceName, binder);
}

bool DBinderService::RegisterRemoteProxy(std::u16string serviceName, int32_t systemAbilityId)
{
    if (serviceName.length() == 0 || systemAbilityId <= 0) {
        DBINDER_LOGE(LOG_LABEL, "serviceName length:%{public}zu", serviceName.length());
        return false;
    }
    DBINDER_LOGI(LOG_LABEL, "service name:%{public}s saId:%{public}d",
        Str16ToStr8(serviceName).c_str(), systemAbilityId);
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

void DBinderService::AddAsynMessageTask(std::shared_ptr<struct DHandleEntryTxRx> message)
{
    auto task = [this, message] { this->OnRemoteMessageTask(message); };
    ffrt::submit(task);
}

bool DBinderService::OnRemoteMessageTask(std::shared_ptr<struct DHandleEntryTxRx> message)
{
    if (message == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "message is null");
        return false;
    }

    bool result = false;
    switch (message->dBinderCode) {
        case MESSAGE_AS_INVOKER: {
            result = OnRemoteInvokerMessage(message);
            break;
        }
        case MESSAGE_AS_REPLY:
        case MESSAGE_AS_REPLY_TOKENID: {
            result = OnRemoteReplyMessage(message);
            break;
        }
        case MESSAGE_AS_REMOTE_ERROR: {
            result = OnRemoteErrorMessage(message);
            break;
        }
        default: {
            DBINDER_LOGE(LOG_LABEL, "DbinderCode:%{public}u is not support", message->dBinderCode);
            result = false;
            break;
        }
    }
    return result;
}

bool DBinderService::ProcessOnSessionClosed(const std::string &networkId)
{
    std::lock_guard<std::mutex> lock(threadLockMutex_);
    for (auto it = threadLockInfo_.begin(); it != threadLockInfo_.end();) {
        if (it->second->networkId != networkId) {
            it++;
            continue;
        }
        std::unique_lock<std::mutex> lock(it->second->mutex);
        it->second->ready = false;
        it->second->condition.notify_all();
        it = threadLockInfo_.erase(it);
    }
    return true;
}

bool DBinderService::OnRemoteErrorMessage(std::shared_ptr<struct DHandleEntryTxRx> replyMessage)
{
    DfxReportEvent(DbinderErrorCode::RPC_DRIVER, DbinderErrorCode::IPC_RESULT_IDLE, __FUNCTION__);
    DBINDER_LOGI(LOG_LABEL, "invoke remote stubIndex:%{public}d fail, error:%{public}u seq:%{public}u",
        static_cast<int32_t>(replyMessage->stubIndex), replyMessage->transType, replyMessage->seqNumber);
    WakeupThreadByStub(replyMessage->seqNumber);
    DetachThreadLockInfo(replyMessage->seqNumber);
    return true;
}

bool DBinderService::OnRemoteReplyMessage(std::shared_ptr<struct DHandleEntryTxRx> replyMessage)
{
    DBINDER_LOGI(LOG_LABEL, "invoker remote stubIndex:%{public}d succ, seq:%{public}u stub:%{public}llu "
        "tokenId:%{public}u dBinderCode:%{public}u", static_cast<int32_t>(replyMessage->stubIndex),
        replyMessage->seqNumber, (replyMessage->stub & BINDER_MASK), replyMessage->deviceIdInfo.tokenId,
        replyMessage->dBinderCode);
    MakeSessionByReplyMessage(replyMessage);
    WakeupThreadByStub(replyMessage->seqNumber);
    DetachThreadLockInfo(replyMessage->seqNumber);
    return true;
}

bool DBinderService::IsSameSession(std::shared_ptr<struct SessionInfo> oldSession,
    std::shared_ptr<struct SessionInfo> newSession)
{
    if ((oldSession->stubIndex != newSession->stubIndex) || (oldSession->toPort != newSession->toPort)
        || (oldSession->fromPort != newSession->fromPort) || (oldSession->type != newSession->type)
        || (oldSession->serviceName != newSession->serviceName)) {
        return false;
    }
    if (strncmp(oldSession->deviceIdInfo.fromDeviceId, newSession->deviceIdInfo.fromDeviceId, DEVICEID_LENGTH) != 0
        || strncmp(oldSession->deviceIdInfo.toDeviceId, newSession->deviceIdInfo.toDeviceId, DEVICEID_LENGTH) != 0) {
        return false;
    }

    return true;
}

bool DBinderService::IsInvalidStub(std::shared_ptr<struct DHandleEntryTxRx> replyMessage)
{
    if (HasDBinderStub(QueryStubPtr(replyMessage->stub)) == false) {
        DBINDER_LOGE(LOG_LABEL, "invalid stub object");
        return true;
    }
    return false;
}

bool DBinderService::CopyDeviceIdInfo(std::shared_ptr<struct SessionInfo> &session,
    std::shared_ptr<struct DHandleEntryTxRx> replyMessage)
{
    if (memcpy_s(&session->deviceIdInfo, sizeof(struct DeviceIdInfo), &replyMessage->deviceIdInfo,
        sizeof(struct DeviceIdInfo)) != 0) {
        DBINDER_LOGE(LOG_LABEL, "fail to copy memory");
        return false;
    }
    return true;
}

void DBinderService::InitializeSession(std::shared_ptr<struct SessionInfo> &session,
    std::shared_ptr<struct DHandleEntryTxRx> replyMessage)
{
    session->seqNumber   = replyMessage->seqNumber;
    session->socketFd    = 0;
    session->stubIndex   = replyMessage->stubIndex;
    session->toPort      = replyMessage->toPort;
    session->fromPort    = replyMessage->fromPort;
    session->type        = replyMessage->transType;
    session->serviceName = replyMessage->serviceName;
}

void DBinderService::MakeSessionByReplyMessage(std::shared_ptr<struct DHandleEntryTxRx> replyMessage)
{
    if (IsInvalidStub(replyMessage)) {
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_STUB_INVALID, __FUNCTION__);
        return;
    }

    std::shared_ptr<struct SessionInfo> session = std::make_shared<struct SessionInfo>();
    if (session == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "new SessionInfo fail");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_IPC_NEW_SESSION_FAIL, __FUNCTION__);
        return;
    }

    if (!CopyDeviceIdInfo(session, replyMessage)) {
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ERR_MEMCPY_DATA, __FUNCTION__);
        return;
    }
    // remote device NOT support tokenId, clear random value
    if (replyMessage->dBinderCode == MESSAGE_AS_REPLY) {
        session->deviceIdInfo.tokenId = 0;
    }
    DBINDER_LOGI(LOG_LABEL, "stubIndex:%{public}d tokenId:%{public}u",
        static_cast<int32_t>(replyMessage->stubIndex), session->deviceIdInfo.tokenId);
    InitializeSession(session, replyMessage);

    if (session->stubIndex == 0) {
        DBINDER_LOGE(LOG_LABEL, "get stubIndex == 0, it is invalid");
        return;
    }
    // check whether need to update session
    std::shared_ptr<struct SessionInfo> oldSession = QuerySessionObject(QueryStubPtr(replyMessage->stub));
    if (oldSession != nullptr) {
        if (IsSameSession(oldSession, session) == true) {
            DBINDER_LOGI(LOG_LABEL, "invoker remote session already, do nothing");
            return;
        }
        // ignore seqNumber overflow here, greater seqNumber means later request
        if (oldSession->seqNumber < session->seqNumber) {
            // remote old session
            if (!DetachSessionObject(QueryStubPtr(replyMessage->stub))) {
                DBINDER_LOGE(LOG_LABEL, "failed to detach session object");
                DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_DETACH_SESSION_FAIL, __FUNCTION__);
            }
        } else {
            // do nothing, use old session, discard session got this time
            // in this case, old session is requested later, but it comes back earlier
        }
    }

    if (!AttachSessionObject(session, QueryStubPtr(replyMessage->stub))) {
        DBINDER_LOGE(LOG_LABEL, "attach SessionInfo fail");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ATTACH_SESSION_FAIL, __FUNCTION__);
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
    DBINDER_LOGI(LOG_LABEL, "service:%{public}s devicId:%{public}s",
        dbStub->GetServiceName().c_str(), DBinderService::ConvertToSecureDeviceID(dbStub->GetDeviceID()).c_str());
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
                DBINDER_LOGE(LOG_LABEL, "fail to notice service:%{public}s die, handle:%{public}d",
                    dbStub->GetServiceName().c_str(), callbackProxy->GetHandle());
                // do nothing, Continue to clear subsequent data
            }

            sptr<IRemoteObject::DeathRecipient> death = QueryDeathRecipient((it->first));
            if (death != nullptr) {
                // Continue to clear subsequent data
                callbackProxy->RemoveDeathRecipient(death);
            }

            if (!DetachDeathRecipient((it->first))) {
                DBINDER_LOGE(LOG_LABEL, "detaching death recipient is failed, service:%{public}s handle:%{public}d",
                    dbStub->GetServiceName().c_str(), callbackProxy->GetHandle());
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
        DBINDER_LOGE(LOG_LABEL, "service name length:%{public}zu, deviceID length:%{public}zu",
            serviceName.length(), deviceID.length());
        return DBINDER_SERVICE_INVALID_DATA_ERR;
    }

    DBINDER_LOGI(LOG_LABEL, "service:%{public}s deviceId:%{public}s",
        Str16ToStr8(serviceName).c_str(), DBinderService::ConvertToSecureDeviceID(deviceID).c_str());
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
    if (IsDeviceIdIllegal(deviceID)) {
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ERR_INVALID_DATA, __FUNCTION__);
    } else {
        DfxReportDeviceEvent(DbinderErrorCode::RPC_DRIVER, DbinderErrorCode::IPC_RESULT_IDLE,
            DBinderService::ConvertToSecureDeviceID(deviceID).c_str(), __FUNCTION__);
    }
    std::lock_guard<std::mutex> lockGuard(deathNotificationMutex_);
    return NoticeServiceDieInner(serviceName, deviceID);
}

int32_t DBinderService::NoticeDeviceDie(const std::string &deviceID)
{
    if (IsDeviceIdIllegal(deviceID)) {
        DBINDER_LOGE(LOG_LABEL, "deviceID length:%{public}zu", deviceID.length());
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ERR_INVALID_DATA, __FUNCTION__);
        return DBINDER_SERVICE_INVALID_DATA_ERR;
    }
    DBINDER_LOGI(LOG_LABEL, "remote device:%{public}s is dead",
        DBinderService::ConvertToSecureDeviceID(deviceID).c_str());
    DfxReportDeviceEvent(DbinderErrorCode::RPC_DRIVER, DbinderErrorCode::IPC_RESULT_IDLE,
        DBinderService::ConvertToSecureDeviceID(deviceID).c_str(), __FUNCTION__);

    if (remoteListener_ == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "remote listener is null");
        return DBINDER_SERVICE_NOTICE_DIE_ERR;
    }

    if (!remoteListener_->ShutdownSocket(deviceID)) {
        DBINDER_LOGE(LOG_LABEL, "Shutdown fail");
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

    DBINDER_LOGI(LOG_LABEL, "deviceId:%{public}s, service size:%{public}zu",
        DBinderService::ConvertToSecureDeviceID(deviceID).c_str(), serviceNames.size());
    return serviceNames;
}

uint32_t DBinderService::GetRemoteTransType()
{
    return IRemoteObject::DATABUS_TYPE;
}

std::string DBinderService::ConvertToSecureDeviceID(const std::string &str)
{
    size_t len = str.size();
    if (len <= ENCRYPT_LENGTH) {
        return "****";
    }
    return str.substr(0, ENCRYPT_LENGTH) + "****" + str.substr(len - ENCRYPT_LENGTH);
}
} // namespace OHOS
