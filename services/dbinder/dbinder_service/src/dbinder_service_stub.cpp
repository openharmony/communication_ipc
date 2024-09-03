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

#include "dbinder_service_stub.h"

#include <cinttypes>
#include "securec.h"
#include "sys_binder.h"
#include "string_ex.h"

#include "dbinder_death_recipient.h"
#include "dbinder_error_code.h"
#include "dbinder_log.h"
#include "dbinder_service.h"
#include "ipc_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "process_skeleton.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_RPC_DBINDER_SER_STUB,
    "DbinderServiceStub" };

DBinderServiceStub::DBinderServiceStub(const std::string &service, const std::string &device, binder_uintptr_t object)
    : IPCObjectStub(Str8ToStr16(DBinderService::ConvertToSecureDeviceID(device) + service)),
    serviceName_(service), deviceID_(device), binderObject_(object)
{
    DBINDER_LOGD(LOG_LABEL, "created, service:%{public}s device:%{public}s",
        serviceName_.c_str(), DBinderService::ConvertToSecureDeviceID(deviceID_).c_str());
    dbinderData_ = std::make_unique<uint8_t[]>(sizeof(dbinder_negotiation_data));
    if (dbinderData_ == nullptr) {
        DBINDER_LOGW(LOG_LABEL, "malloc dbinderData_ fail");
        return;
    }
    memset_s(dbinderData_.get(), sizeof(dbinder_negotiation_data), 0, sizeof(dbinder_negotiation_data));
}

DBinderServiceStub::~DBinderServiceStub()
{
    DBINDER_LOGD(LOG_LABEL, "destroyed, service:%{public}s device:%{public}s",
        serviceName_.c_str(), DBinderService::ConvertToSecureDeviceID(deviceID_).c_str());
    dbinderData_ = nullptr;
}

const std::string &DBinderServiceStub::GetServiceName()
{
    return serviceName_;
}

const std::string &DBinderServiceStub::GetDeviceID()
{
    return deviceID_;
}

binder_uintptr_t DBinderServiceStub::GetBinderObject() const
{
    return binderObject_;
}

int32_t DBinderServiceStub::ProcessProto(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "DBinderService is nullptr");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_GET_SERVICE_NULL, __FUNCTION__);
        return DBINDER_SERVICE_PROCESS_PROTO_ERR;
    }
    auto session = dBinderService->QuerySessionObject(reinterpret_cast<binder_uintptr_t>(this));
    if (session == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "client find session is null");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_QUERY_SESSION_FAIL, __FUNCTION__);
        return DBINDER_SERVICE_PROCESS_PROTO_ERR;
    }

    DBINDER_LOGI(LOG_LABEL, "serviceName:%{public}s stubIndex:%{public}" PRIu64 " tokenId:%{public}u",
        session->serviceName.c_str(), session->stubIndex, session->deviceIdInfo.tokenId);

    int uid = IPCSkeleton::GetCallingUid();
    int pid = IPCSkeleton::GetCallingPid();
    if (uid < 0 || pid < 0) {
        DBINDER_LOGE(LOG_LABEL, "uid or pid err");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_GET_UID_OR_PID_FAIL, __FUNCTION__);
        return DBINDER_SERVICE_PROCESS_PROTO_ERR;
    }

    std::string localBusName = dBinderService->CreateDatabusName(uid, pid);
    if (localBusName.empty()) {
        DBINDER_LOGE(LOG_LABEL, "local busname nil");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_CREATE_BUS_NAME_FAIL, __FUNCTION__);
        return DBINDER_SERVICE_PROCESS_PROTO_ERR;
    }

    switch (session->type) {
        case IRemoteObject::DATABUS_TYPE: {
            if (!reply.WriteUint32(IRemoteObject::IF_PROT_DATABUS) || !reply.WriteUint64(session->stubIndex) ||
                !reply.WriteString(session->serviceName) || !reply.WriteString(session->deviceIdInfo.toDeviceId) ||
                !reply.WriteString(session->deviceIdInfo.fromDeviceId) || !reply.WriteString(localBusName) ||
                !reply.WriteUint32(session->deviceIdInfo.tokenId) || !reply.WriteString16(descriptor_)) {
                DBINDER_LOGE(LOG_LABEL, "write to parcel fail");
                DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_WRITE_TO_PARCEL_FAIL, __FUNCTION__);
                return DBINDER_SERVICE_PROCESS_PROTO_ERR;
            }
            break;
        }
        default: {
            DBINDER_LOGE(LOG_LABEL, "Invalid Type");
            DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_TYPE_INVALID, __FUNCTION__);
            return DBINDER_SERVICE_PROCESS_PROTO_ERR;
        }
    }
    return ERR_NONE;
}

int32_t DBinderServiceStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    int32_t result = ERR_NONE;
    switch (code) {
        case GET_PROTO_INFO: {
            result = ProcessProto(code, data, reply, option);
            break;
        }
        case DBINDER_OBITUARY_TRANSACTION: {
            result = ProcessDeathRecipient(data);
            break;
        }
        default: {
            DBINDER_LOGI(LOG_LABEL, "unknown code:%{public}u", code);
            result = DBINDER_SERVICE_UNKNOW_TRANS_ERR;
            break;
        }
    }

    return result;
}

int32_t DBinderServiceStub::ProcessDeathRecipient(MessageParcel &data)
{
    int32_t processType = data.ReadInt32();
    DBINDER_LOGD(LOG_LABEL, "recv, DBINDER_OBITUARY_TRANSACTION type:%{public}d", processType);
    if (processType == IRemoteObject::DeathRecipient::ADD_DEATH_RECIPIENT) {
        return AddDbinderDeathRecipient(data);
    }

    if (processType == IRemoteObject::DeathRecipient::REMOVE_DEATH_RECIPIENT) {
        return RemoveDbinderDeathRecipient(data);
    }

    return DBINDER_SERVICE_UNKNOW_TRANS_ERR;
}

int32_t DBinderServiceStub::AddDbinderDeathRecipient(MessageParcel &data)
{
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "received proxy is null");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_RECEIVED_PROXY_NULL, __FUNCTION__);
        return DBINDER_SERVICE_INVALID_DATA_ERR;
    }

    IPCObjectProxy *callbackProxy = reinterpret_cast<IPCObjectProxy *>(object.GetRefPtr());
    sptr<IRemoteObject::DeathRecipient> death(new DbinderDeathRecipient());
    DBINDER_LOGI(LOG_LABEL, "stub desc:%{public}s",
        DBinderService::ConvertToSecureDeviceID(Str16ToStr8(descriptor_)).c_str());

    // If the client dies, notify DBS to delete information of callbackProxy
    if (!callbackProxy->AddDeathRecipient(death)) {
        DBINDER_LOGE(LOG_LABEL, "fail to add death recipient");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ADD_DEATH_RECIPIENT_FAIL, __FUNCTION__);
        return DBINDER_SERVICE_ADD_DEATH_ERR;
    }

    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "dBinder service is null");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_GET_SERVICE_NULL, __FUNCTION__);
        return DBINDER_SERVICE_ADD_DEATH_ERR;
    }

    if (!dBinderService->AttachDeathRecipient(object, death)) {
        DBINDER_LOGE(LOG_LABEL, "fail to attach death recipient");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ATTACH_DEATH_RECIPIENT_FAIL, __FUNCTION__);
        return DBINDER_SERVICE_ADD_DEATH_ERR;
    }

    if (!dBinderService->AttachCallbackProxy(object, this)) {
        DBINDER_LOGE(LOG_LABEL, "fail to attach callback proxy");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ATTACH_CALLBACK_PROXY_FAIL, __FUNCTION__);
        return DBINDER_SERVICE_ADD_DEATH_ERR;
    }
    return ERR_NONE;
}

int32_t DBinderServiceStub::RemoveDbinderDeathRecipient(MessageParcel &data)
{
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "received proxy is null");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_RECEIVED_PROXY_NULL, __FUNCTION__);
        return DBINDER_SERVICE_REMOVE_DEATH_ERR;
    }

    IPCObjectProxy *callbackProxy = reinterpret_cast<IPCObjectProxy *>(object.GetRefPtr());
    DBINDER_LOGI(LOG_LABEL, "stub desc:%{public}s",
        DBinderService::ConvertToSecureDeviceID(Str16ToStr8(descriptor_)).c_str());
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "dBinder service is null");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_GET_SERVICE_NULL, __FUNCTION__);
        return DBINDER_SERVICE_REMOVE_DEATH_ERR;
    }

    sptr<IRemoteObject::DeathRecipient> death = dBinderService->QueryDeathRecipient(object);
    if (death != nullptr) {
        // Continue to clear subsequent data
        callbackProxy->RemoveDeathRecipient(death);
    }

    if (!dBinderService->DetachDeathRecipient(object)) {
        DBINDER_LOGE(LOG_LABEL, "fail to detach death recipient");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_DETACH_DEATH_RECIPIENT_FAIL, __FUNCTION__);
        return DBINDER_SERVICE_REMOVE_DEATH_ERR;
    }

    if (!dBinderService->DetachCallbackProxy(object)) {
        DBINDER_LOGE(LOG_LABEL, "fail to detach callback proxy");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_DETACH_CALLBACK_PROXY_FAIL, __FUNCTION__);
        return DBINDER_SERVICE_REMOVE_DEATH_ERR;
    }
    return ERR_NONE;
}

bool DBinderServiceStub::Marshalling(Parcel &parcel) const
{
    DBINDER_LOGD(LOG_LABEL, "enter");
    if (dbinderData_ == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "dbinderData_ is nullptr");
        return false;
    }
    auto *invoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DEFAULT);
    if (invoker == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "GetRemoteInvoker fail");
        return false;
    }

    size_t offset = parcel.GetWritePosition();
    auto dbinderData = reinterpret_cast<const dbinder_negotiation_data *>(dbinderData_.get());
    if (!ProcessSkeleton::FlattenDBinderData(parcel, dbinderData)) {
        return false;
    }

    if (!invoker->FlattenObject(parcel, this)) {
        DBINDER_LOGE(LOG_LABEL, "FlattenObject fail");
        parcel.RewindWrite(offset);
        return false;
    }
    return true;
}

bool DBinderServiceStub::Marshalling(Parcel &parcel, const sptr<IRemoteObject> &object)
{
    DBINDER_LOGD(LOG_LABEL, "enter");
    auto serviceStub = reinterpret_cast<DBinderServiceStub *>(object.GetRefPtr());
    if (serviceStub == nullptr) {
        return false;
    }
    return serviceStub->Marshalling(parcel);
}

int DBinderServiceStub::SaveDBinderData(const std::string &localBusName)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "DBinderService is nullptr");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_GET_SERVICE_NULL, __FUNCTION__);
        return DBINDER_SERVICE_FILL_DATA_ERR;
    }

    auto session = dBinderService->QuerySessionObject(reinterpret_cast<binder_uintptr_t>(this));
    if (session == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "client find session is null");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_QUERY_SESSION_FAIL, __FUNCTION__);
        return DBINDER_SERVICE_FILL_DATA_ERR;
    }

    if (dbinderData_ == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "dbinderData_ is nullptr");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ERR_MEMCPY_DATA, __FUNCTION__);
        return DBINDER_SERVICE_MALLOC_ERR;
    }

    dbinder_negotiation_data *dbinderData = reinterpret_cast<dbinder_negotiation_data *>(dbinderData_.get());
    (void)memset_s(dbinderData, sizeof(dbinder_negotiation_data), 0, sizeof(dbinder_negotiation_data));
    dbinderData->proto = IRemoteObject::IF_PROT_DATABUS;
    dbinderData->stub_index = session->stubIndex;
    dbinderData->tokenid = session->deviceIdInfo.tokenId;
    auto ret = memcpy_s(dbinderData->target_name, SESSION_NAME_LENGTH, session->serviceName.c_str(),
        session->serviceName.length());
    ret += memcpy_s(dbinderData->target_device, DEVICEID_LENGTH, session->deviceIdInfo.toDeviceId,
        DEVICEID_LENGTH);
    ret += memcpy_s(dbinderData->local_device, DEVICEID_LENGTH, session->deviceIdInfo.fromDeviceId,
        DEVICEID_LENGTH);
    ret += memcpy_s(dbinderData->local_name, SESSION_NAME_LENGTH, localBusName.c_str(), localBusName.length());
    ret += memcpy_s(dbinderData->desc, DBINDER_DESC_LENGTH, descriptor_.c_str(), descriptor_.length());
    if (ret != EOK) {
        DBINDER_LOGE(LOG_LABEL, "memcpy_s fail, ret:%{public}d", ret);
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ERR_MEMCPY_DATA, __FUNCTION__);
        return DBINDER_SERVICE_FILL_DATA_ERR;
    }
    DBINDER_LOGI(LOG_LABEL, "proto:%{public}d stubIndex:%{public}llu tokenid:%{public}u "
        "targetName:%{public}s localName:%{public}s",
        dbinderData->proto, dbinderData->stub_index, dbinderData->tokenid, dbinderData->target_name,
        dbinderData->local_name);
    return ERR_NONE;
}

bool DBinderServiceStub::CheckSessionObjectValidity()
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "DBinderService is nullptr");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_GET_SERVICE_NULL, __FUNCTION__);
        return false;
    }

    auto session = dBinderService->QuerySessionObject(reinterpret_cast<binder_uintptr_t>(this));
    if (session == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "client find session is null");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_QUERY_SESSION_FAIL, __FUNCTION__);
        return false;
    }
    if (session->type != IRemoteObject::DATABUS_TYPE) {
        DBINDER_LOGE(LOG_LABEL, "Invalid Type:%{public}d", session->type);
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_TYPE_INVALID, __FUNCTION__);
        return false;
    }
    return true;
}

int DBinderServiceStub::GetAndSaveDBinderData(pid_t pid, uid_t uid)
{
    if (uid < 0 || pid < 0) {
        DBINDER_LOGE(LOG_LABEL, "uid(%{public}d) or pid(%{public}d) is invalid", uid, pid);
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_GET_UID_OR_PID_FAIL, __FUNCTION__);
        return DBINDER_SERVICE_FILL_DATA_ERR;
    }
    if (!CheckSessionObjectValidity()) {
        return DBINDER_SERVICE_FILL_DATA_ERR;
    }

    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "DBinderService is nullptr");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_GET_SERVICE_NULL, __FUNCTION__);
        return DBINDER_SERVICE_FILL_DATA_ERR;
    }
    std::string localBusName = dBinderService->CreateDatabusName(uid, pid);
    if (localBusName.empty()) {
        DBINDER_LOGE(LOG_LABEL, "local busname nil");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_CREATE_BUS_NAME_FAIL, __FUNCTION__);
        return DBINDER_SERVICE_FILL_DATA_ERR;
    }
    return SaveDBinderData(localBusName);
}
} // namespace OHOS
