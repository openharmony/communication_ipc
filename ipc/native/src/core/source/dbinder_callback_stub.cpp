/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dbinder_callback_stub.h"

#include <cinttypes>

#include "dbinder_error_code.h"
#include "log_tags.h"
#include "ipc_debug.h"
#include "ipc_process_skeleton.h"
#include "ipc_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "ipc_types.h"
#include "securec.h"
#include "string_ex.h"
#include "sys_binder.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_RPC_DBINDER_CB_STUB,
    "DBinderCallbackStub" };

DBinderCallbackStub::DBinderCallbackStub(const std::string &service, const std::string &device,
    const std::string &localDevice, uint64_t stubIndex, uint32_t handle, uint32_t tokenId)
    : IPCObjectStub(Str8ToStr16("DBinderCallback" + IPCProcessSkeleton::ConvertToSecureString(device) + service)),
      serviceName_(service),
      deviceID_(device),
      localDeviceID_(localDevice),
      stubIndex_(stubIndex),
      handle_(handle),
      tokenId_(tokenId)
{
    ZLOGD(LOG_LABEL, "created, service:%{public}s deviceId:%{public}s handle:%{public}u stubIndex:%{public}" PRIu64,
        serviceName_.c_str(), IPCProcessSkeleton::ConvertToSecureString(deviceID_).c_str(), handle_, stubIndex_);
    dbinderData_ = std::make_unique<uint8_t[]>(sizeof(dbinder_negotiation_data));
    if (dbinderData_ == nullptr) {
        ZLOGE(LOG_LABEL, "malloc dbinderData_ fail");
        return;
    }
    memset_s(dbinderData_.get(), sizeof(dbinder_negotiation_data), 0, sizeof(dbinder_negotiation_data));
}

DBinderCallbackStub::~DBinderCallbackStub()
{
    ZLOGD(LOG_LABEL, "destroyed, service:%{public}s deviceId:%{public}s handle:%{public}u stubIndex:%{public}" PRIu64,
        serviceName_.c_str(), IPCProcessSkeleton::ConvertToSecureString(deviceID_).c_str(), handle_, stubIndex_);
    IPCProcessSkeleton::GetCurrent()->DetachDBinderCallbackStub(this);
    dbinderData_ = nullptr;
}

const std::string &DBinderCallbackStub::GetServiceName()
{
    return serviceName_;
}

const std::string &DBinderCallbackStub::GetDeviceID()
{
    return deviceID_;
}

uint64_t DBinderCallbackStub::GetStubIndex() const
{
    return stubIndex_;
}

uint32_t DBinderCallbackStub::GetTokenId() const
{
    return tokenId_;
}

int32_t DBinderCallbackStub::ProcessProto(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    int uid = IPCSkeleton::GetCallingUid();
    int pid = IPCSkeleton::GetCallingPid();
    if (uid < 0 || pid < 0) {
        ZLOGE(LOG_LABEL, "uid or pid err");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_GET_UID_OR_PID_FAIL, __FUNCTION__);
        return DBINDER_SERVICE_PROCESS_PROTO_ERR;
    }
    sptr<IRemoteObject> object = IPCProcessSkeleton::GetCurrent()->GetSAMgrObject();
    if (object == nullptr) {
        ZLOGE(LOG_LABEL, "get sa object is null");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_GET_SA_OBJECT_NULL, __FUNCTION__);
        return DBINDER_CALLBACK_READ_OBJECT_ERR;
    }
    IPCObjectProxy *samgr = reinterpret_cast<IPCObjectProxy *>(object.GetRefPtr());
    std::string sessionName = samgr->GetSessionNameForPidUid(uid, pid);
    if (sessionName.empty()) {
        ZLOGE(LOG_LABEL, "grans session name failed");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_GET_SESSION_NAME_FAIL, __FUNCTION__);
        return DBINDER_SERVICE_WRONG_SESSION;
    }
    return ProcessData(uid, pid, sessionName, data, reply);
}

int32_t DBinderCallbackStub::ProcessData(int uid, int pid, const std::string &sessionName, MessageParcel &data,
    MessageParcel &reply)
{
    MessageParcel authData;
    MessageParcel authReply;
    MessageOption authOption;
    if (!authData.WriteUint32(pid) || !authData.WriteUint32(uid) || !authData.WriteString(localDeviceID_) ||
        !authData.WriteUint64(stubIndex_) || !authData.WriteUint32(tokenId_)) {
        ZLOGE(LOG_LABEL, "write to MessageParcel fail");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ERR_INVALID_DATA, __FUNCTION__);
        return ERR_INVALID_DATA;
    }
    IRemoteInvoker *dbinderInvoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS);
    if (dbinderInvoker == nullptr) {
        ZLOGE(LOG_LABEL, "no databus thread and invoker");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_RPC_DATABUS_INVOKER_ERR, __FUNCTION__);
        return RPC_DATABUS_INVOKER_ERR;
    }
    int err = dbinderInvoker->SendRequest(handle_, DBINDER_ADD_COMMAUTH, authData, authReply, authOption);
    if (err != ERR_NONE) {
        ZLOGE(LOG_LABEL, "send auth info to remote fail");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_BINDER_CALLBACK_AUTHCOMM_ERR, __FUNCTION__);
        return BINDER_CALLBACK_AUTHCOMM_ERR;
    }
    ZLOGI(LOG_LABEL, "send to stub ok! stubIndex:%{public}" PRIu64 " peerDevice:%{public}s "
         "localDeviceID:%{public}s serviceName:%{public}s uid:%{public}d pid:%{public}d "
         "tokenId:%{public}u sessionName:%{public}s",
        stubIndex_, IPCProcessSkeleton::ConvertToSecureString(deviceID_).c_str(),
        IPCProcessSkeleton::ConvertToSecureString(localDeviceID_).c_str(), serviceName_.c_str(), uid, pid, tokenId_,
        sessionName.c_str());
    if (!reply.WriteUint32(IRemoteObject::IF_PROT_DATABUS) || !reply.WriteUint64(stubIndex_) ||
        !reply.WriteString(serviceName_) || !reply.WriteString(deviceID_) || !reply.WriteString(localDeviceID_) ||
        !reply.WriteString(sessionName) || !reply.WriteUint32(tokenId_)) {
        ZLOGE(LOG_LABEL, "write to parcel fail");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ERR_INVALID_DATA, __FUNCTION__);
        return ERR_INVALID_DATA;
    }
    return 0;
}

int32_t DBinderCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    int32_t result = ERR_NONE;
    ZLOGI(LOG_LABEL, "code:%{public}u", code);
    switch (code) {
        case GET_PROTO_INFO: {
            result = ProcessProto(code, data, reply, option);
            break;
        }
        default: {
            ZLOGI(LOG_LABEL, "unknown code:%{public}u", code);
            result = DBINDER_CALLBACK_ERR;
            break;
        }
    }

    return result;
}

bool DBinderCallbackStub::Marshalling(Parcel &parcel) const
{
    ZLOGD(LOG_LABEL, "enter");
    if (dbinderData_ == nullptr) {
        ZLOGE(LOG_LABEL, "dbinderData_ is nullptr");
        return false;
    }

    auto *invoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DEFAULT);
    if (invoker == nullptr) {
        ZLOGE(LOG_LABEL, "GetRemoteInvoker fail");
        return false;
    }

    size_t offset = parcel.GetWritePosition();
    auto dbinderData = reinterpret_cast<const dbinder_negotiation_data *>(dbinderData_.get());
    if (!ProcessSkeleton::FlattenDBinderData(parcel, dbinderData)) {
        return false;
    }

    if (!invoker->FlattenObject(parcel, this)) {
        ZLOGE(LOG_LABEL, "FlattenObject fail");
        parcel.RewindWrite(offset);
        return false;
    }
    return true;
}

bool DBinderCallbackStub::Marshalling(Parcel &parcel, const sptr<IRemoteObject> &object)
{
    ZLOGD(LOG_LABEL, "enter");
    auto callback = reinterpret_cast<DBinderCallbackStub *>(object.GetRefPtr());
    if (callback == nullptr) {
        return false;
    }
    return callback->Marshalling(parcel);
}

int DBinderCallbackStub::AddDBinderCommAuth(pid_t pid, uid_t uid, const std::string &sessionName)
{
    MessageParcel authData, authReply;
    MessageOption authOption;
    if (!authData.WriteUint32(pid) || !authData.WriteUint32(uid) || !authData.WriteString(localDeviceID_) ||
        !authData.WriteUint64(stubIndex_) || !authData.WriteUint32(tokenId_)) {
        ZLOGE(LOG_LABEL, "write to MessageParcel fail");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_WRITE_TO_PARCEL_FAIL, __FUNCTION__);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    IRemoteInvoker *dbinderInvoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS);
    if (dbinderInvoker == nullptr) {
        ZLOGE(LOG_LABEL, "no databus thread and invoker");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_RPC_DATABUS_INVOKER_ERR, __FUNCTION__);
        return RPC_DATABUS_INVOKER_ERR;
    }
    int err = dbinderInvoker->SendRequest(handle_, DBINDER_ADD_COMMAUTH, authData, authReply, authOption);
    if (err != ERR_NONE) {
        ZLOGE(LOG_LABEL, "send auth info to remote fail");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_BINDER_CALLBACK_AUTHCOMM_ERR, __FUNCTION__);
        return BINDER_CALLBACK_AUTHCOMM_ERR;
    }

    ZLOGI(LOG_LABEL, "send to stub ok! stubIndex:%{public}" PRIu64 " peerDevice:%{public}s "
         "localDeviceID:%{public}s serviceName:%{public}s uid:%{public}d pid:%{public}d "
         "tokenId:%{public}u sessionName:%{public}s",
        stubIndex_, IPCProcessSkeleton::ConvertToSecureString(deviceID_).c_str(),
        IPCProcessSkeleton::ConvertToSecureString(localDeviceID_).c_str(), serviceName_.c_str(), uid, pid, tokenId_,
        sessionName.c_str());
    return ERR_NONE;
}

int DBinderCallbackStub::SaveDBinderData(const std::string &sessionName)
{
    if (dbinderData_ == nullptr) {
        ZLOGE(LOG_LABEL, "dbinderData_ is nullptr");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ERR_MEMCPY_DATA, __FUNCTION__);
        return DBINDER_CALLBACK_MALLOC_ERR;
    }

    dbinder_negotiation_data *dbinderData = reinterpret_cast<dbinder_negotiation_data *>(dbinderData_.get());
    (void)memset_s(dbinderData, sizeof(dbinder_negotiation_data), 0, sizeof(dbinder_negotiation_data));
    dbinderData->proto = IRemoteObject::IF_PROT_DATABUS;
    dbinderData->stub_index = stubIndex_;
    dbinderData->tokenid = tokenId_;
    auto ret = memcpy_s(dbinderData->target_name, SESSION_NAME_LENGTH, serviceName_.c_str(),
        serviceName_.length());
    ret += memcpy_s(dbinderData->target_device, DEVICEID_LENGTH, deviceID_.c_str(),
        deviceID_.length());
    ret += memcpy_s(dbinderData->local_device, DEVICEID_LENGTH, localDeviceID_.c_str(),
        localDeviceID_.length());
    ret += memcpy_s(dbinderData->local_name, SESSION_NAME_LENGTH, sessionName.c_str(), sessionName.length());
    ret += memcpy_s(dbinderData->desc, DBINDER_DESC_LENGTH, descriptor_.c_str(), descriptor_.length());
    if (ret != EOK) {
        ZLOGE(LOG_LABEL, "memcpy_s fail, ret:%{public}d", ret);
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ERR_MEMCPY_DATA, __FUNCTION__);
        return DBINDER_CALLBACK_MEMCPY_ERR;
    }
    ZLOGI(LOG_LABEL, "proto:%{public}u stubIndex:%{public}llu tokenId:%{public}u "
        "targetName:%{public}s localName:%{public}s",
        dbinderData->proto, dbinderData->stub_index, dbinderData->tokenid, dbinderData->target_name,
        dbinderData->local_name);
    return ERR_NONE;
}

int DBinderCallbackStub::GetAndSaveDBinderData(pid_t pid, uid_t uid)
{
    if (uid < 0 || pid < 0) {
        ZLOGE(LOG_LABEL, "uid(%{public}d) or pid(%{public}d) is invalid", uid, pid);
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_GET_UID_OR_PID_FAIL, __FUNCTION__);
        return DBINDER_CALLBACK_FILL_DATA_ERR;
    }

    sptr<IRemoteObject> object = IPCProcessSkeleton::GetCurrent()->GetSAMgrObject();
    if (object == nullptr) {
        ZLOGE(LOG_LABEL, "GetSAMgrObject failed");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_GET_SA_OBJECT_NULL, __FUNCTION__);
        return DBINDER_CALLBACK_FILL_DATA_ERR;
    }
    IPCObjectProxy *samgr = reinterpret_cast<IPCObjectProxy *>(object.GetRefPtr());
    std::string sessionName = samgr->GetSessionNameForPidUid(uid, pid);
    if (sessionName.empty()) {
        ZLOGE(LOG_LABEL, "GetSessionNameForPidUid failed");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_GET_SESSION_NAME_FAIL, __FUNCTION__);
        return DBINDER_CALLBACK_FILL_DATA_ERR;
    }

    int ret = AddDBinderCommAuth(pid, uid, sessionName);
    if (ret != ERR_NONE) {
        ZLOGE(LOG_LABEL, "AddDBinderCommAuth failed");
        return ret;
    }

    ret = SaveDBinderData(sessionName);
    if (ret != ERR_NONE) {
        ZLOGE(LOG_LABEL, "SaveDBinderData failed");
        return ret;
    }
    return ERR_NONE;
}
} // namespace OHOS
