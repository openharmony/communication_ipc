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
#include <condition_variable>
#include <sys/types.h>
#include <arpa/inet.h>
#include "securec.h"
#include "string_ex.h"
#include "iservice_registry.h"
#include "ipc_skeleton.h"
#include "ipc_thread_skeleton.h"

#include "dbinder_log.h"
#include "dbinder_service_stub.h"
#include "dbinder_remote_listener.h"
#include "if_system_ability_manager.h"
#include "dbinder_error_code.h"
#include "softbus_bus_center.h"
#include "dbinder_sa_death_recipient.h"

namespace OHOS {
using namespace Communication;

sptr<DBinderService> DBinderService::instance_ = nullptr;
bool DBinderService::mainThreadCreated_ = false;
std::mutex DBinderService::instanceMutex_;
std::shared_ptr<DBinderRemoteListener> DBinderService::remoteListener_ = nullptr;

DBinderService::DBinderService()
{
    DBINDER_LOGI("create dbinder service");
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

    DBINDER_LOGI("dbinder service died");
}

std::string DBinderService::GetLocalDeviceID()
{
    std::string pkgName = "dbinderService";
    NodeBasicInfo nodeBasicInfo;
    if (GetLocalNodeDeviceInfo(pkgName.c_str(), &nodeBasicInfo) != 0) {
        DBINDER_LOGE("Get local node device info failed");
        return "";
    }
    std::string networkId(nodeBasicInfo.networkId);
    return networkId;
}

bool DBinderService::StartDBinderService()
{
    if (mainThreadCreated_) {
        return true;
    }

    bool result = StartRemoteListener();
    if (!result) {
        return false;
    }
    mainThreadCreated_ = true;

    return true;
}

bool DBinderService::StartRemoteListener()
{
    if (remoteListener_ != nullptr) {
        DBINDER_LOGI("remote listener started");
        return true;
    }

    remoteListener_ = std::make_shared<DBinderRemoteListener>(GetInstance());
    if (remoteListener_ == nullptr) {
        DBINDER_LOGE("failed to create remote listener");
        return false;
    }

    if (remoteListener_->StartListener() != true) {
        StopRemoteListener();
        return false;
    }

    DBINDER_LOGI("start remote listener ok");
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
        DBINDER_LOGI("found registered stub");
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
        DBINDER_LOGI("found registered service with name = %s", Str16ToStr8(service).c_str());
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
    const std::string &deviceID, binder_uintptr_t binderObject, uint64_t pid)
{
    if (IsDeviceIdIllegal(deviceID) || serviceName.length() == 0 || binderObject == 0) {
        DBINDER_LOGE("para is wrong device id length = %zu, service name length = %zu", deviceID.length(),
            serviceName.length());
        return nullptr;
    }
    DBINDER_LOGI("name = %{public}s, deviceID = %{public}s", Str16ToStr8(serviceName).c_str(),
        DBinderService::ConvertToSecureDeviceID(deviceID).c_str());

    sptr<DBinderServiceStub> dBinderServiceStub = FindOrNewDBinderStub(serviceName, deviceID, binderObject);
    if (dBinderServiceStub == nullptr) {
        DBINDER_LOGE("fail to find or new service, service name = %{public}s", Str16ToStr8(serviceName).c_str());
        return nullptr;
    }

    /* if not found dBinderServiceStub, should send msg to toDeviceID
     * to invoker socket thread and add authentication info for create softbus session
     */
    int retryTimes = 0;
    bool ret = false;
    do {
        ret = InvokerRemoteDBinder(dBinderServiceStub, GetSeqNumber());
        retryTimes++;
    } while (!ret && (retryTimes < RETRY_TIMES));

    if (!ret) {
        DBINDER_LOGE("fail to invoke service, service name = %{public}s", Str16ToStr8(serviceName).c_str());
        /* invoke fail, delete dbinder stub info */
        (void)DeleteDBinderStub(serviceName, deviceID);
        (void)DetachSessionObject(reinterpret_cast<binder_uintptr_t>(dBinderServiceStub.GetRefPtr()));
        return nullptr;
    }

    return dBinderServiceStub;
}

bool DBinderService::SendEntryToRemote(const sptr<DBinderServiceStub> stub, uint32_t seqNumber)
{
    const std::string deviceID = stub->GetDeviceID();
    const std::string localDevID = GetLocalDeviceID();
    if (IsDeviceIdIllegal(deviceID) || IsDeviceIdIllegal(localDevID)) {
        DBINDER_LOGE("wrong device ID");
        return false;
    }

    std::shared_ptr<struct DHandleEntryTxRx> message = std::make_shared<struct DHandleEntryTxRx>();
    message->head.len            = sizeof(DHandleEntryTxRx);
    message->head.version        = VERSION_NUM;
    message->dBinderCode         = MESSAGE_AS_INVOKER;
    message->transType           = GetRemoteTransType();
    message->fromPort            = 0;
    message->toPort              = 0;
    message->stubIndex           = 0;
    message->seqNumber           = seqNumber;
    message->binderObject        = stub->GetBinderObject();
    message->stub                = reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr());
    message->deviceIdInfo.afType = DATABBUS_TYPE;
    message->pid                 = IPCSkeleton::GetCallingPid();
    message->uid                 = IPCSkeleton::GetCallingUid();
    if (memcpy_s(message->deviceIdInfo.fromDeviceId, DEVICEID_LENGTH, localDevID.data(), localDevID.length()) != 0 ||
        memcpy_s(message->deviceIdInfo.toDeviceId, DEVICEID_LENGTH, deviceID.data(), deviceID.length()) != 0) {
        DBINDER_LOGE("fail to copy memory");
        return false;
    }
    message->deviceIdInfo.fromDeviceId[localDevID.length()] = '\0';
    message->deviceIdInfo.toDeviceId[deviceID.length()] = '\0';

    std::shared_ptr<DBinderRemoteListener> remoteListener = GetRemoteListener();
    if (remoteListener == nullptr) {
        DBINDER_LOGE("remoteListener is null");
        return false;
    }
    bool result = remoteListener->SendDataToRemote(deviceID, message.get());
    if (result != true) {
        DBINDER_LOGE("send to remote dbinderService failed");
        return false;
    }
    return true;
}

bool DBinderService::InvokerRemoteDBinder(const sptr<DBinderServiceStub> stub, uint32_t seqNumber)
{
    if (stub == nullptr) {
        DBINDER_LOGE("stub is nullptr");
        return false;
    }
    bool result = SendEntryToRemote(stub, seqNumber);
    if (!result) {
        DBINDER_LOGE("send entry to remote dbinderService fail");
        return false;
    }

    /* pend to wait reply */
    std::shared_ptr<struct ThreadLockInfo> threadLockInfo = std::make_shared<struct ThreadLockInfo>();
    result = AttachThreadLockInfo(seqNumber, threadLockInfo);
    if (result != true) {
        DBINDER_LOGE("attach lock info fail");
        return false;
    }

    std::unique_lock<std::mutex> lock(threadLockInfo->mutex);
    if (threadLockInfo->condition.wait_for(lock, std::chrono::seconds(WAIT_FOR_REPLY_MAX_SEC),
        [&threadLockInfo] { return threadLockInfo->ready; }) == false) {
        DBINDER_LOGE("get remote data failed");
        DetachThreadLockInfo(seqNumber);
        threadLockInfo->ready = false;
        return false;
    }
    /* if can not find session, means invoke failed or nothing in OnRemoteReplyMessage() */
    auto session = QuerySessionObject(reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr()));
    if (session == nullptr) {
        DBINDER_LOGE("client find session is null");
        return false;
    }
    return true;
}

sptr<IRemoteObject> DBinderService::FindOrNewProxy(binder_uintptr_t binderObject)
{
    sptr<IRemoteObject> proxy = QueryProxyObject(binderObject);
    if (proxy != nullptr) {
        DBINDER_LOGI("already have proxy");
        return proxy;
    }
    /* proxy is null, attempt to get a new proxy */
    std::u16string serviceName = GetRegisterService(binderObject);
    if (serviceName.empty()) {
        DBINDER_LOGE("service is not registered in this device");
        return nullptr;
    }

    DBINDER_LOGI("new proxy serviceName = %s", Str16ToStr8(serviceName).c_str());

    auto manager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (manager == nullptr) {
        DBINDER_LOGE("when new proxy, find samgr fail!");
        return nullptr;
    }

    int digitalName = std::atoi(Str16ToStr8(serviceName).c_str());
    proxy = manager->GetSystemAbility(digitalName);
    if (proxy != nullptr) {
        /* When the stub object dies, you need to delete the corresponding busName information */
        IPCObjectProxy *saProxy = reinterpret_cast<IPCObjectProxy *>(proxy.GetRefPtr());
        sptr<IRemoteObject::DeathRecipient> death(new DbinderSaDeathRecipient(binderObject));
        if (!saProxy->AddDeathRecipient(death)) {
            DBINDER_LOGE("fail to add death recipient");
            return nullptr;
        }
        bool ret = AttachProxyObject(proxy, binderObject);
        if (!ret) {
            DBINDER_LOGE("attach proxy object fail");
            return nullptr;
        }
    }
    return proxy;
}
uint16_t DBinderService::AllocFreeSocketPort()
{
    /* alloc port by system */
    return 0;
}

bool DBinderService::OnRemoteInvokerMessage(const struct DHandleEntryTxRx *message)
{
    sptr<IRemoteObject> proxy = FindOrNewProxy(message->binderObject);
    if (proxy == nullptr) {
        DBINDER_LOGE("find and new proxy fail");
        return false;
    }
    IPCObjectProxy *ipcProxy = reinterpret_cast<IPCObjectProxy *>(proxy.GetRefPtr());
    std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<struct DHandleEntryTxRx>();
    if (memcpy_s(replyMessage.get(), sizeof(DHandleEntryTxRx), message, sizeof(DHandleEntryTxRx)) != 0) {
        DBINDER_LOGE("fail to copy memory");
        return false;
    }
    std::string deviceId = replyMessage->deviceIdInfo.fromDeviceId;

    switch (replyMessage->transType) {
        case IRemoteObject::DATABUS_TYPE: {
            if (!OnRemoteInvokerDataBusMessage(ipcProxy, replyMessage.get(), deviceId, message->pid, message->uid)) {
                DBINDER_LOGE("Invoker Databus Message fail");
                return false;
            }
            break;
        }
        default: {
            DBINDER_LOGE("Invalid Message Type");
            return false;
        }
    }
    std::shared_ptr<DBinderRemoteListener> remoteListener = GetRemoteListener();
    if (remoteListener == nullptr) {
        DBINDER_LOGE("remoteListener is null");
        return false;
    }
    bool ret = remoteListener->SendDataToRemote(deviceId, replyMessage.get());
    if (ret != true) {
        DBINDER_LOGE("fail to send data from server DBS to client DBS");
        return false;
    }

    return true;
}

std::string DBinderService::GetDatabusNameByProxy(IPCObjectProxy *proxy)
{
    if (proxy == nullptr) {
        DBINDER_LOGE("proxy can not be null");
        return "";
    }
    std::string sessionName = QueryBusNameObject(proxy);
    if (!sessionName.empty()) {
        DBINDER_LOGI("sessionName has been granded");
        return sessionName;
    }
    sessionName = proxy->GetPidAndUidInfo();
    if (sessionName.empty()) {
        DBINDER_LOGE("grand session name failed");
        return "";
    }
    return sessionName;
}

std::string DBinderService::CreateDatabusName(int uid, int pid)
{
    std::shared_ptr<ISessionService> softbusManager = ISessionService::GetInstance();
    if (softbusManager == nullptr) {
        DBINDER_LOGE("fail to get softbus service");
        return "";
    }

    std::string sessionName = "DBinder" + std::to_string(uid) + std::string("_") + std::to_string(pid);
    if (softbusManager->GrantPermission(uid, pid, sessionName) != ERR_NONE) {
        DBINDER_LOGE("fail to Grant Permission softbus name");
        return "";
    }

    return sessionName;
}

bool DBinderService::OnRemoteInvokerDataBusMessage(IPCObjectProxy *proxy, struct DHandleEntryTxRx *replyMessage,
    std::string &remoteDeviceId, int pid, int uid)
{
    if (IsDeviceIdIllegal(remoteDeviceId)) {
        DBINDER_LOGE("remote device id is error");
        return false;
    }
    std::string sessionName = GetDatabusNameByProxy(proxy);
    if (sessionName.empty()) {
        DBINDER_LOGE("get bus name fail");
        return false;
    }

    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteUint16(IRemoteObject::DATABUS_TYPE) || !data.WriteString(GetLocalDeviceID()) ||
        !data.WriteUint32(pid) || !data.WriteUint32(uid) || !data.WriteString(remoteDeviceId) ||
        !data.WriteString(sessionName)) {
        DBINDER_LOGE("write to parcel fail");
        return false;
    }
    int err = proxy->InvokeListenThread(data, reply);
    if (err != ERR_NONE) {
        DBINDER_LOGE("start service listen error = %d", err);
        return false;
    }
    uint64_t stubIndex = reply.ReadUint64();
    std::string serverSessionName = reply.ReadString();
    if (stubIndex == 0 || serverSessionName.empty() || serverSessionName.length() > SERVICENAME_LENGTH) {
        DBINDER_LOGE("stubindex or session name invalid");
        return false;
    }

    replyMessage->dBinderCode = MESSAGE_AS_REPLY;
    replyMessage->stubIndex = stubIndex;
    replyMessage->serviceNameLength = serverSessionName.length();
    if (memcpy_s(replyMessage->serviceName, SERVICENAME_LENGTH, serverSessionName.data(),
        replyMessage->serviceNameLength) != 0) {
        DBINDER_LOGE("fail to copy memory");
        return false;
    }
    replyMessage->serviceName[replyMessage->serviceNameLength] = '\0';

    (void)AttachBusNameObject(proxy, serverSessionName);
    return true;
}

std::u16string DBinderService::GetRegisterService(binder_uintptr_t binderObject)
{
    DBINDER_LOGI("get service binderObject");
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
    DBINDER_LOGI("register remote proxy, service name = %{public}s", Str16ToStr8(serviceName).c_str());

    if (serviceName.length() == 0 || binderObject == nullptr) {
        DBINDER_LOGE("serviceName.length() = %zu", serviceName.length());
        return false;
    }

    binder_uintptr_t binder = (binder_uintptr_t)binderObject.GetRefPtr();
    DBINDER_LOGI("register remote proxy");

    std::unique_lock<std::shared_mutex> lockGuard(remoteBinderMutex_);

    // clear historical remnants, Don't care if it succeeds
    (void)mapRemoteBinderObjects_.erase(serviceName);
    auto result = mapRemoteBinderObjects_.insert(std::pair<std::u16string, binder_uintptr_t>(serviceName, binder));
    return result.second;
}

bool DBinderService::OnRemoteMessageTask(const struct DHandleEntryTxRx *message)
{
    if (message == nullptr) {
        DBINDER_LOGE("message is null ");
        return false;
    }

    bool result = false;
    switch (message->dBinderCode) {
        case MESSAGE_AS_INVOKER: {
            result = OnRemoteInvokerMessage(message);
            break;
        }
        case MESSAGE_AS_REPLY: {
            result = OnRemoteReplyMessage(message);
            break;
        }
        default: {
            DBINDER_LOGE("ERROR! DbinderCode is wrong value, code =%u", message->dBinderCode);
            result = false;
            break;
        }
    }
    return result;
}

bool DBinderService::OnRemoteReplyMessage(const struct DHandleEntryTxRx *replyMessage)
{
    MakeSessionByReplyMessage(replyMessage);
    WakeupThreadByStub(replyMessage->seqNumber);
    DetachThreadLockInfo(replyMessage->seqNumber);
    return true;
}

void DBinderService::MakeSessionByReplyMessage(const struct DHandleEntryTxRx *replyMessage)
{
    if (HasDBinderStub(replyMessage->binderObject) == false) {
        DBINDER_LOGE("invalid stub object");
        return;
    }
    if (QuerySessionObject(replyMessage->stub) != nullptr) {
        DBINDER_LOGI("invoker remote session already, do nothing");
        return;
    }
    std::shared_ptr<struct SessionInfo> session = std::make_shared<struct SessionInfo>();
    if (session == nullptr) {
        DBINDER_LOGE("new SessionInfo fail");
        return;
    }

    if (memcpy_s(&session->deviceIdInfo, sizeof(struct DeviceIdInfo), &replyMessage->deviceIdInfo,
        sizeof(struct DeviceIdInfo)) != 0) {
        DBINDER_LOGE("fail to copy memory");
        return;
    }
    session->socketFd    = 0;
    session->stubIndex   = replyMessage->stubIndex;
    session->toPort      = replyMessage->toPort;
    session->fromPort    = replyMessage->fromPort;
    session->type        = replyMessage->transType;
    session->serviceName = replyMessage->serviceName;

    if (session->stubIndex == 0) {
        DBINDER_LOGE("get stub index == 0, it is invalid");
        return;
    }

    if (!AttachSessionObject(session, replyMessage->stub)) {
        DBINDER_LOGE("attach SessionInfo fail");
        return;
    }
}

void DBinderService::WakeupThreadByStub(uint32_t seqNumber)
{
    std::shared_ptr<struct ThreadLockInfo> threadLockInfo = QueryThreadLockInfo(seqNumber);
    if (threadLockInfo == nullptr) {
        DBINDER_LOGE("threadLockInfo is not exist");
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

bool DBinderService::AttachThreadLockInfo(uint32_t seqNumber, std::shared_ptr<struct ThreadLockInfo> object)
{
    std::lock_guard<std::mutex> lock(threadLockMutex_);
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
    bool status = true;
    const binder_uintptr_t binderObject = reinterpret_cast<binder_uintptr_t>(dbStub.GetRefPtr());
    if (!DetachSessionObject(binderObject)) {
        DBINDER_LOGE("fail to detach session object");
        status = false;
    }

    if (!DeleteDBinderStub(Str8ToStr16(dbStub->GetServiceName()), dbStub->GetDeviceID())) {
        DBINDER_LOGE("fail to delete DBinder stub");
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
                DBINDER_LOGE("fail to notice service");
                // do nothing, Continue to clear subsequent data
            }

            sptr<IRemoteObject::DeathRecipient> death = QueryDeathRecipient((it->first));
            if (death != nullptr) {
                // Continue to clear subsequent data
                callbackProxy->RemoveDeathRecipient(death);
            }

            if (!DetachDeathRecipient((it->first))) {
                DBINDER_LOGE("detaching death recipient is failed");
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
        DBINDER_LOGE("service name length = %zu, deviceID length = %zu", serviceName.length(), deviceID.length());
        return DBINDER_SERVICE_INVALID_DATA_ERR;
    }

    sptr<DBinderServiceStub> dbStub = FindDBinderStub(serviceName, deviceID);
    if (dbStub == nullptr) {
        DBINDER_LOGE("find null stub, do not need notice death");
        return ERR_NONE;
    }

    if (!NoticeCallbackProxy(dbStub)) {
        DBINDER_LOGE("find null proxy");
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
        DBINDER_LOGE("deviceID length = %zu", deviceID.length());
        return DBINDER_SERVICE_INVALID_DATA_ERR;
    }
    DBINDER_LOGI("remote device is dead, device = %s", DBinderService::ConvertToSecureDeviceID(deviceID).c_str());

    if (remoteListener_ == nullptr) {
        DBINDER_LOGE("remote listener is null");
        return DBINDER_SERVICE_NOTICE_DIE_ERR;
    }

    if (!remoteListener_->CloseDatabusSession(deviceID)) {
        DBINDER_LOGE("close databus session fail");
        // do nothing
    }

    std::list<std::u16string> serviceNames = FindServicesByDeviceID(deviceID);
    if (serviceNames.empty()) {
        DBINDER_LOGE("the device does not have any registered service");
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
} // namespace OHOS
