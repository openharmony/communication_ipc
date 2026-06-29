/*
 * Copyright (C) 2021-2025 Huawei Device Co., Ltd.
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
#include <charconv>
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
#include "dsoftbus_interface.h"

namespace OHOS {

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_RPC_DBINDER_SER, "DBinderService" };

sptr<DBinderService> DBinderService::instance_ = nullptr;
bool DBinderService::mainThreadCreated_ = false;
std::mutex DBinderService::instanceMutex_;
std::shared_ptr<DBinderRemoteListener> DBinderService::remoteListener_ = nullptr;
constexpr unsigned int BINDER_MASK = 0xffff;
// DBinderServiceStub's reference count in a MakeRemoteBinder call.
constexpr int32_t DBINDER_STUB_REF_COUNT = 2;
constexpr int32_t DBINDER_WAIT_SLEEP_TIME = 1000;
constexpr int32_t THREAD_LOCK_RETRY_TIMES = 10;

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

// LCOV_EXCL_START
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
// LCOV_EXCL_STOP

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

// LCOV_EXCL_START
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
// LCOV_EXCL_STOP

// LCOV_EXCL_START
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
// LCOV_EXCL_STOP

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

// LCOV_EXCL_START
uint32_t DBinderService::GetSeqNumber()
{
    std::lock_guard<std::mutex> lockGuard(instanceMutex_);
    if (seqNumber_ == std::numeric_limits<uint32_t>::max()) {
        seqNumber_ = 0;
    }
    seqNumber_++;
    return seqNumber_;
}
// LCOV_EXCL_STOP

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
    const std::string &device, uint32_t pid, uint32_t uid)
{
    if (stub == nullptr) {
        return false;
    }
    if ((stub->GetServiceName() == service) && (stub->GetDeviceID() == device) &&
        (stub->GetPeerPid() == pid) && (stub->GetPeerUid() == uid)) {
        DBINDER_LOGD(LOG_LABEL, "found registered service, name:%{public}s device:%{public}s pid:%{public}u",
            Str16ToStr8(service).c_str(), DBinderService::ConvertToSecureDeviceID(device).c_str(), stub->GetPeerPid());
        return true;
    }
    return false;
}

std::vector<sptr<DBinderServiceStub>> DBinderService::FindDBinderStub(const std::u16string &service,
    const std::string &device)
{
    std::vector<sptr<DBinderServiceStub>> result;
    std::lock_guard<std::mutex> lockGuard(handleEntryMutex_);
    for (auto it = DBinderStubRegisted_.begin(); it != DBinderStubRegisted_.end(); ++it) {
        if (((*it)->GetServiceName() == service) && ((*it)->GetDeviceID() == device)) {
            result.emplace_back(*it);
        }
    }
    if (result.size() == 0) {
        DBINDER_LOGW(LOG_LABEL, "not found, service:%{public}s device:%{public}s",
            Str16ToStr8(service).c_str(), DBinderService::ConvertToSecureDeviceID(device).c_str());
        return result;
    }
    DBINDER_LOGD(LOG_LABEL, "found, service:%{public}s device:%{public}s count:%{public}zu",
        Str16ToStr8(service).c_str(), DBinderService::ConvertToSecureDeviceID(device).c_str(), result.size());
    return result;
}

bool DBinderService::DeleteDBinderStub(const std::u16string &service, const std::string &device, uint32_t pid,
    uint32_t uid)
{
    auto checkStub = [&service, &device, pid, uid, this](const sptr<DBinderServiceStub> &stub) {
        return IsSameStubObject(stub, service, device, pid, uid);
    };

    std::lock_guard<std::mutex> lockGuard(handleEntryMutex_);
    auto it = std::find_if(DBinderStubRegisted_.begin(), DBinderStubRegisted_.end(), checkStub);
    if (it == DBinderStubRegisted_.end()) {
        DBINDER_LOGW(LOG_LABEL, "not found, service:%{public}s device:%{public}s pid:%{public}u",
            Str16ToStr8(service).c_str(), DBinderService::ConvertToSecureDeviceID(device).c_str(), pid);
        return false;
    }
    auto dbStub = *it;
    DBinderStubRegisted_.erase(it);

    for (auto mapIt = mapDBinderStubRegisters_.begin(); mapIt != mapDBinderStubRegisters_.end();) {
        if (mapIt->second == reinterpret_cast<binder_uintptr_t>(dbStub.GetRefPtr())) {
            mapIt = mapDBinderStubRegisters_.erase(mapIt);
            break;
        } else {
            ++mapIt;
        }
    }
    DBINDER_LOGI(LOG_LABEL, "succ, service:%{public}s device:%{public}s pid:%{public}u",
        Str16ToStr8(service).c_str(), DBinderService::ConvertToSecureDeviceID(device).c_str(), pid);
    return true;
}

bool DBinderService::DeleteDBinderStub(const std::u16string &service, const std::string &device)
{
    uint32_t count = 0;
    std::lock_guard<std::mutex> lockGuard(handleEntryMutex_);
    for (auto it = DBinderStubRegisted_.begin(); it != DBinderStubRegisted_.end();) {
        auto dbStub = (*it);
        if ((dbStub->GetServiceName() == service) && (dbStub->GetDeviceID() == device)) {
            for (auto mapIt = mapDBinderStubRegisters_.begin(); mapIt != mapDBinderStubRegisters_.end(); ++mapIt) {
                if (mapIt->second == reinterpret_cast<binder_uintptr_t>(dbStub.GetRefPtr())) {
                    mapDBinderStubRegisters_.erase(mapIt);
                    break;
                }
            }
            ++count;
            it = DBinderStubRegisted_.erase(it);
        } else {
            ++it;
        }
    }

    if (count == 0) {
        DBINDER_LOGW(LOG_LABEL, "not found, service:%{public}s device:%{public}s",
            Str16ToStr8(service).c_str(), DBinderService::ConvertToSecureDeviceID(device).c_str());
        return false;
    }
    DBINDER_LOGI(LOG_LABEL, "succ, service:%{public}s device:%{public}s count:%{public}u",
        Str16ToStr8(service).c_str(), DBinderService::ConvertToSecureDeviceID(device).c_str(), count);
    return true;
}

sptr<DBinderServiceStub> DBinderService::FindOrNewDBinderStub(const std::u16string &service, const std::string &device,
    binder_uintptr_t binderObject, uint32_t pid, uint32_t uid, bool &isNew)
{
    auto checkStub = [&service, &device, pid, uid, this](const sptr<DBinderServiceStub> &stub) {
        return IsSameStubObject(stub, service, device, pid, uid);
    };

    std::lock_guard<std::mutex> lockGuard(handleEntryMutex_);
    const std::string serviceStr8 = Str16ToStr8(service);
    auto it = std::find_if(DBinderStubRegisted_.begin(), DBinderStubRegisted_.end(), checkStub);
    if (it != DBinderStubRegisted_.end()) {
        DBINDER_LOGD(LOG_LABEL, "found, service:%{public}s device:%{public}s pid:%{public}u", serviceStr8.c_str(),
            DBinderService::ConvertToSecureDeviceID(device).c_str(), pid);
        return (*it);
    }

    sptr<DBinderServiceStub> dBinderServiceStub = new DBinderServiceStub(service, device, binderObject, pid, uid);
    DBinderStubRegisted_.push_back(dBinderServiceStub);
    isNew = true;
    DBINDER_LOGD(LOG_LABEL, "create, service:%{public}s device:%{public}s pid:%{public}u", serviceStr8.c_str(),
        DBinderService::ConvertToSecureDeviceID(device).c_str(), pid);
    return dBinderServiceStub;
}

sptr<DBinderServiceStub> DBinderService::MakeRemoteBinder(const std::u16string &serviceName,
    const std::string &deviceID, int32_t binderObject, uint32_t pid, uint32_t uid)
{
    auto start = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
    if (IsDeviceIdIllegal(deviceID) || serviceName.length() == 0) {
        DBINDER_LOGE(LOG_LABEL, "para is wrong, device length:%{public}zu, service length:%{public}zu",
            deviceID.length(), serviceName.length());
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ERR_INVALID_DATA, __FUNCTION__);
        auto errCode = (serviceName.length() == 0) ? DBINDER_SAID_INVALID : DBINDER_DEVICEID_INVALID;
        DfxReportNegotiationEvent(binderObject, errCode, start, deviceID);
        return nullptr;
    }

    auto serviceNameStr8 = Str16ToStr8(serviceName);
    auto secureDeviceId = DBinderService::ConvertToSecureDeviceID(deviceID);
    DBINDER_LOGI(LOG_LABEL, "service:%{public}s device:%{public}s pid:%{public}u", serviceNameStr8.c_str(),
        secureDeviceId.c_str(), pid);

    bool isNew = false;
    sptr<DBinderServiceStub> dBinderServiceStub = FindOrNewDBinderStub(serviceName, deviceID,
        static_cast<binder_uintptr_t>(binderObject), pid, uid, isNew);
    if (dBinderServiceStub == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "FindOrNewDBinderStub fail, service:%{public}s device:%{public}s pid:%{public}u",
            serviceNameStr8.c_str(), secureDeviceId.c_str(), pid);
        DfxReportNegotiationEvent(binderObject, DBINDER_ALLOC_OBJECT_FAILED, start, deviceID);
        return nullptr;
    }
    uint32_t seqNum = isNew ? GetSeqNumber() : dBinderServiceStub->GetSeqNumber();
    if (isNew) {
        dBinderServiceStub->SetSeqNumber(seqNum);
    }

    int32_t retryTimes = 0;
    int32_t ret = -1;
    do {
        ret = InvokerRemoteDBinder(dBinderServiceStub, seqNum, pid, uid, isNew);
        retryTimes++;
    } while ((ret == DBINDER_WAIT_REPLY_TIMEOUT) && (retryTimes < RETRY_TIMES));

    if (ret != DBINDER_OK) {
        DBINDER_LOGE(LOG_LABEL, "failed to invoke service, service:%{public}s device:%{public}s pid:%{public}u "
            "refcount:%{public}d", serviceNameStr8.c_str(), secureDeviceId.c_str(), pid,
            dBinderServiceStub->GetSptrRefCount());
        if (dBinderServiceStub->GetSptrRefCount() <= DBINDER_STUB_REF_COUNT) {
            /* invoke fail, delete dbinder stub info */
            (void)DeleteDBinderStub(serviceName, deviceID, pid, uid);
            (void)DetachSessionObject(reinterpret_cast<binder_uintptr_t>(dBinderServiceStub.GetRefPtr()));
        }
        DfxReportNegotiationEvent(binderObject, ret, start, deviceID);
        return nullptr;
    }
    DfxReportNegotiationEvent(binderObject, DBINDER_OK, start, deviceID);
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
        DBINDER_LOGE(LOG_LABEL, "fail to copy memory, service:%{public}llu seq:%{public}u",
            message->binderObject, message->seqNumber);
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

    std::string serviceName = Str16ToStr8(stub->GetServiceName());
    uint64_t subIndex = 0;
    auto result = std::from_chars(serviceName.c_str(), serviceName.c_str() + serviceName.size(), subIndex);
    if (result.ec != std::errc()) {
        DBINDER_LOGE(LOG_LABEL, "invalid serviceName:%{public}s", serviceName.c_str());
        return nullptr;
    }

    message->head.len = sizeof(DHandleEntryTxRx);
    message->head.version = RPC_TOKENID_SUPPORT_VERSION;
    message->dBinderCode = MESSAGE_AS_INVOKER;
    message->transType = GetRemoteTransType();
    message->fromPort = 0;
    message->toPort = 0;
    message->stubIndex = subIndex;
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
        DBINDER_LOGE(LOG_LABEL, "remoteListener is null, service:%{public}llu seq:%{public}u",
            message->binderObject, message->seqNumber);
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_GET_REMOTE_LISTENER_FAIL, __FUNCTION__);
        return false;
    }
    bool result = remoteListener->SendDataToRemote(deviceID, message.get());
    if (result != true) {
        DBINDER_LOGE(LOG_LABEL, "SendDataToRemote failed, service:%{public}llu seq:%{public}u",
            message->binderObject, message->seqNumber);
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_SEND_DATA_TO_REMOTE_FAIL, __FUNCTION__);
        return false;
    }
    return true;
}

int32_t DBinderService::InvokerRemoteDBinderWhenRequest(const sptr<DBinderServiceStub> stub, uint32_t seqNumber,
    uint32_t pid, uint32_t uid, std::shared_ptr<struct ThreadLockInfo> &threadLockInfo)
{
    auto time = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
    stub->SetNegoStatusAndTime(NegotiationStatus::NEGO_DOING, time);
    threadLockInfo = std::make_shared<struct ThreadLockInfo>();
    if (!AttachThreadLockInfo(seqNumber, stub->GetDeviceID(), threadLockInfo)) {
        DBINDER_LOGE(LOG_LABEL, "AttachThreadLockInfo fail, seq:%{public}u pid:%{public}u", seqNumber, pid);
        stub->SetNegoStatusAndTime(NegotiationStatus::NEGO_INIT, 0);
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ATTACH_THREADLOCK_FAIL, __FUNCTION__);
        return DBINDER_MAKE_THREADLOCK_FAILED;
    }
    if (!SendEntryToRemote(stub, seqNumber, pid, uid)) {
        DBINDER_LOGE(LOG_LABEL, "SendEntryToRemote fail, seq:%{public}u pid:%{public}u", seqNumber, pid);
        stub->SetNegoStatusAndTime(NegotiationStatus::NEGO_INIT, 0);
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_SEND_ENTRY_TO_REMOTE_FAIL, __FUNCTION__);
        DetachThreadLockInfo(seqNumber);
        return DBINDER_SEND_MESSAGE_FAILED;
    }

    return DBINDER_OK;
}

int32_t DBinderService::InvokerRemoteDBinderWhenWaitRsp(const sptr<DBinderServiceStub> stub, uint32_t seqNumber,
    uint32_t pid, uint32_t uid, std::shared_ptr<struct ThreadLockInfo> &threadLockInfo)
{
    NegotiationStatus negoStatus;
    uint64_t negoTime;
    int32_t count = 0;
    do {
        stub->GetNegoStatusAndTime(negoStatus, negoTime);
        if (negoStatus == NegotiationStatus::NEGO_FINISHED) {
            DBINDER_LOGI(LOG_LABEL, "Negotiation has been finished, seq:%{public}u pid:%{public}u", seqNumber, pid);
            return DBINDER_OK;
        }

        threadLockInfo = QueryThreadLockInfo(seqNumber);
        if (threadLockInfo == nullptr) {
            usleep(DBINDER_WAIT_SLEEP_TIME);
        }
        ++count;
    } while ((threadLockInfo == nullptr) && (count < THREAD_LOCK_RETRY_TIMES));

    if (threadLockInfo == nullptr) {
        DBINDER_LOGW(LOG_LABEL, "QueryThreadLockInfo fail, seq:%{public}u pid:%{public}u", seqNumber, pid);
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_QUERY_THREADLOCK_FAIL, __FUNCTION__);
        return DBINDER_MAKE_THREADLOCK_FAILED;
    }
    return DBINDER_OK;
}

int32_t DBinderService::InvokerRemoteDBinder(const sptr<DBinderServiceStub> stub, uint32_t seqNumber,
    uint32_t pid, uint32_t uid, bool isNew)
{
    if (stub == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "stub is nullptr");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ERR_INVALID_DATA, __FUNCTION__);
        return DBINDER_STUB_INVALID;
    }

    int32_t result = DBINDER_OK;
    std::shared_ptr<struct ThreadLockInfo> threadLockInfo = nullptr;
    NegotiationStatus negoStatus;
    uint64_t negoTime;
    stub->GetNegoStatusAndTime(negoStatus, negoTime);
    if (isNew || negoStatus == NegotiationStatus::NEGO_INIT) {
        result = InvokerRemoteDBinderWhenRequest(stub, seqNumber, pid, uid, threadLockInfo);
        if (result != DBINDER_OK) {
            return result;
        }
    } else {
        result = InvokerRemoteDBinderWhenWaitRsp(stub, seqNumber, pid, uid, threadLockInfo);
        // When NEGO_FINISHED, threadLockInfo has been removed.
        if ((result != DBINDER_OK) || threadLockInfo == nullptr) {
            return result;
        }
    }

    /* pend to wait reply */
    std::unique_lock<std::mutex> lock(threadLockInfo->mutex);
    if (threadLockInfo->condition.wait_for(lock, std::chrono::seconds(WAIT_FOR_REPLY_MAX_SEC),
        [&threadLockInfo] { return threadLockInfo->ready; }) == false) {
        DBINDER_LOGE(LOG_LABEL, "get remote data timeout or session is closed, seq:%{public}u pid:%{public}u",
            seqNumber, pid);
        stub->SetNegoStatusAndTime(NegotiationStatus::NEGO_INIT, 0);
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_WAIT_REPLY_TIMEOUT, __FUNCTION__);
        DetachThreadLockInfo(seqNumber);
        threadLockInfo->ready = false;
        return DBINDER_WAIT_REPLY_TIMEOUT;
    }
    /* if can not find session, means invoke failed or nothing in OnRemoteReplyMessage() */
    auto session = QuerySessionObject(reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr()));
    if (session == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "client find session is null, seq:%{public}u pid:%{public}u", seqNumber, pid);
        stub->SetNegoStatusAndTime(NegotiationStatus::NEGO_INIT, 0);
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_QUERY_REPLY_SESSION_FAIL, __FUNCTION__);
        return DBINDER_QUERY_REPLY_SESSION_FAILED;
    }
    auto time = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
    stub->SetNegoStatusAndTime(NegotiationStatus::NEGO_FINISHED, time);
    return DBINDER_OK;
}

bool DBinderService::CheckSystemAbilityId(int32_t systemAbilityId)
{
    return systemAbilityId >= FIRST_SYS_ABILITY_ID && systemAbilityId <= LAST_SYS_ABILITY_ID;
}

// LCOV_EXCL_START
uint16_t DBinderService::AllocFreeSocketPort()
{
    /* alloc port by system */
    return 0;
}
// LCOV_EXCL_STOP

bool DBinderService::IsSameLoadSaItem(const std::string& srcNetworkId, int32_t systemAbilityId,
    std::shared_ptr<DHandleEntryTxRx> loadSaItem)
{
    if (static_cast<int32_t>(loadSaItem->binderObject) == systemAbilityId &&
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
            SendReplyMessageToRemote(MESSAGE_AS_REMOTE_ERROR, DBINDER_SA_NOT_FOUND, replyMessage);
            DBINDER_LOGE(LOG_LABEL, "GetSystemAbility from samgr error, saId:%{public}d", systemAbilityId);
            continue;
        }
        binder_uintptr_t binderObject = replyMessage->binderObject;
        IPCObjectProxy *saProxy = reinterpret_cast<IPCObjectProxy *>(remoteObject.GetRefPtr());
        if (QueryProxyObject(binderObject) == nullptr) {
            /* When the stub object dies, you need to delete the corresponding busName information */
            sptr<IRemoteObject::DeathRecipient> death(new DbinderSaDeathRecipient(binderObject));
            if (!saProxy->AddDeathRecipient(death)) {
                SendReplyMessageToRemote(MESSAGE_AS_REMOTE_ERROR, DBINDER_SA_NOT_FOUND, replyMessage);
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
            SendReplyMessageToRemote(MESSAGE_AS_REMOTE_ERROR, DBINDER_SA_INVOKE_FAILED, replyMessage);
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
        DBINDER_LOGE(LOG_LABEL, "fail to send data to client");
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
        SendReplyMessageToRemote(MESSAGE_AS_REMOTE_ERROR, DBINDER_SAID_INVALID, message);
        return false;
    }

    DBINDER_LOGI(LOG_LABEL,
        "invoke business service:%{public}llu seq:%{public}u pid:%{public}u stub:%{public}llu tokenId:%{public}u",
        message->binderObject, message->seqNumber, message->pid, (message->stub & BINDER_MASK),
        message->deviceIdInfo.tokenId);
    if (!dbinderCallback_->IsDistributedSystemAbility(message->binderObject)) {
        DBINDER_LOGE(LOG_LABEL, "SA:%{public}llu not have distributed capability.", message->binderObject);
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_NOT_DISTEIBUTED_SA, __FUNCTION__);
        SendReplyMessageToRemote(MESSAGE_AS_REMOTE_ERROR, DBINDER_SA_NOT_DISTRUBUTED, message);
        return false;
    }

    std::shared_ptr<DHandleEntryTxRx> replyMessage = message;
    {
        std::lock_guard<std::shared_mutex> lockGuard(loadSaMutex_);
        loadSaReply_.push_back(replyMessage);
    }
    bool isSaAvailable = dbinderCallback_->LoadSystemAbilityFromRemote(replyMessage->deviceIdInfo.fromDeviceId,
        static_cast<int32_t>(replyMessage->binderObject));
    if (!isSaAvailable) {
        DBINDER_LOGE(LOG_LABEL, "fail to call the system ability:%{public}d",
            static_cast<int32_t>(replyMessage->binderObject));
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_CALL_SYSTEM_ABILITY_FAIL, __FUNCTION__);
        PopLoadSaItem(replyMessage->deviceIdInfo.fromDeviceId, static_cast<int32_t>(replyMessage->binderObject));
        SendReplyMessageToRemote(MESSAGE_AS_REMOTE_ERROR, DBINDER_SA_NOT_AVAILABLE, replyMessage);
        return false;
    }

    return true;
}
} // namespace OHOS
