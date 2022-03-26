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
#include "sys_binder.h"
#include "string_ex.h"
#include "dbinder_log.h"
#include "dbinder_service.h"
#include "dbinder_death_recipient.h"
#include "ipc_skeleton.h"

namespace OHOS {
DBinderServiceStub::DBinderServiceStub(const std::string &service, const std::string &device, binder_uintptr_t object)
    : IPCObjectStub(Str8ToStr16(device + service)), serviceName_(service), deviceID_(device), binderObject_(object)
{
    DBINDER_LOGI("new DBinderServiceStub created");
}

DBinderServiceStub::~DBinderServiceStub()
{
    DBINDER_LOGI("DBinderServiceStub delete");
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
    int result = ERR_NONE;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        DBINDER_LOGE("DBinderService is nullptr");
        return DBINDER_SERVICE_PROCESS_PROTO_ERR;
    }
    auto session = dBinderService->QuerySessionObject(reinterpret_cast<binder_uintptr_t>(this));
    if (session == nullptr) {
        DBINDER_LOGE("client find session is null");
        return DBINDER_SERVICE_PROCESS_PROTO_ERR;
    }

    DBINDER_LOGI("stubIndex = %" PRIu64 ", socketFd = %" PRIu32 "", session->stubIndex, session->socketFd);
    DBINDER_LOGI("serviceName = %s", session->serviceName.c_str());

    int uid = IPCSkeleton::GetCallingUid();
    int pid = IPCSkeleton::GetCallingPid();
    if (uid < 0 || pid < 0) {
        DBINDER_LOGE("uid or pid err");
        return DBINDER_SERVICE_PROCESS_PROTO_ERR;
    }

    std::string localBusName = dBinderService->CreateDatabusName(uid, pid);
    if (localBusName.empty()) {
        DBINDER_LOGE("local busname nil");
        return DBINDER_SERVICE_PROCESS_PROTO_ERR;
    }

    switch (session->type) {
        case IRemoteObject::DATABUS_TYPE: {
            if (!reply.WriteUint32(IRemoteObject::IF_PROT_DATABUS) || !reply.WriteUint64(session->stubIndex) ||
                !reply.WriteString(session->serviceName) || !reply.WriteString(session->deviceIdInfo.toDeviceId) ||
                !reply.WriteString(session->deviceIdInfo.fromDeviceId) || !reply.WriteString(localBusName)) {
                DBINDER_LOGE("write to parcel fail");
                return DBINDER_SERVICE_PROCESS_PROTO_ERR;
            }
            break;
        }
        default: {
            DBINDER_LOGE("Invalid Type");
            return DBINDER_SERVICE_PROCESS_PROTO_ERR;
        }
    }

    return result;
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
            result = ProcessDeathRecipient(data, reply);
            break;
        }
        default: {
            DBINDER_LOGI("unknown code = %{public}u", code);
            result = DBINDER_SERVICE_UNKNOW_TRANS_ERR;
            break;
        }
    }

    return result;
}

int32_t DBinderServiceStub::ProcessDeathRecipient(MessageParcel &data, MessageParcel &reply)
{
    int32_t processType = data.ReadInt32();
    if (processType == IRemoteObject::DeathRecipient::ADD_DEATH_RECIPIENT) {
        return AddDbinderDeathRecipient(data, reply);
    }

    if (processType == IRemoteObject::DeathRecipient::REMOVE_DEATH_RECIPIENT) {
        return RemoveDbinderDeathRecipient(data, reply);
    }

    return DBINDER_SERVICE_UNKNOW_TRANS_ERR;
}

int32_t DBinderServiceStub::AddDbinderDeathRecipient(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        DBINDER_LOGE("received proxy is null");
        return DBINDER_SERVICE_INVALID_DATA_ERR;
    }

    IPCObjectProxy *callbackProxy = reinterpret_cast<IPCObjectProxy *>(object.GetRefPtr());
    sptr<IRemoteObject::DeathRecipient> death(new DbinderDeathRecipient());

    // If the client dies, notify DBS to delete information of callbackProxy
    if (!callbackProxy->AddDeathRecipient(death)) {
        DBINDER_LOGE("fail to add death recipient");
        return DBINDER_SERVICE_ADD_DEATH_ERR;
    }

    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        DBINDER_LOGE("dBinder service is null");
        return DBINDER_SERVICE_ADD_DEATH_ERR;
    }

    if (!dBinderService->AttachDeathRecipient(object, death)) {
        DBINDER_LOGE("fail to attach death recipient");
        return DBINDER_SERVICE_ADD_DEATH_ERR;
    }

    if (!dBinderService->AttachCallbackProxy(object, this)) {
        DBINDER_LOGE("fail to attach callback proxy");
        return DBINDER_SERVICE_ADD_DEATH_ERR;
    }

    return ERR_NONE;
}

int32_t DBinderServiceStub::RemoveDbinderDeathRecipient(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        DBINDER_LOGE("received proxy is null");
        return DBINDER_SERVICE_REMOVE_DEATH_ERR;
    }

    IPCObjectProxy *callbackProxy = reinterpret_cast<IPCObjectProxy *>(object.GetRefPtr());

    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        DBINDER_LOGE("dBinder service is null");
        return DBINDER_SERVICE_REMOVE_DEATH_ERR;
    }

    sptr<IRemoteObject::DeathRecipient> death = dBinderService->QueryDeathRecipient(object);
    if (death != nullptr) {
        // Continue to clear subsequent data
        callbackProxy->RemoveDeathRecipient(death);
    }

    if (!dBinderService->DetachDeathRecipient(object)) {
        DBINDER_LOGE("fail to detach death recipient");
        return DBINDER_SERVICE_REMOVE_DEATH_ERR;
    }

    if (!dBinderService->DetachCallbackProxy(object)) {
        DBINDER_LOGE("fail to detach callback proxy");
        return DBINDER_SERVICE_REMOVE_DEATH_ERR;
    }

    return ERR_NONE;
}
} // namespace OHOS
