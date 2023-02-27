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

#include "ipc_object_stub.h"

#include <cstdint>
#include <ctime>
#include <string>

#include "hilog/log_c.h"
#include "hilog/log_cpp.h"
#include "iosfwd"
#include "ipc_debug.h"
#include "ipc_process_skeleton.h"
#include "ipc_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "ipc_types.h"
#include "iremote_invoker.h"
#include "iremote_object.h"
#include "log_tags.h"
#include "message_option.h"
#include "message_parcel.h"
#include "refbase.h"
#include "string_ex.h"
#include "sys_binder.h"
#include "unistd.h"
#include "vector"

#ifndef CONFIG_IPC_SINGLE
#include "accesstoken_kit.h"
#include "access_token_adapter.h"
#include "dbinder_databus_invoker.h"
#include "dbinder_error_code.h"
#include "rpc_feature_set.h"
#include "ISessionService.h"
#endif

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
using namespace IPC_SINGLE;
static constexpr int HIDUMPER_SERVICE_UID = 1212;
#endif

using namespace OHOS::HiviewDFX;
static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "IPCObjectStub" };
#ifndef CONFIG_IPC_SINGLE
using namespace OHOS::Security;
// Authentication information can be added only for processes with system permission.
static constexpr pid_t ALLOWED_UID = 10000;
static constexpr int APL_BASIC = 2;
// Only the samgr can obtain the UID and PID.
static const std::string SAMGR_PROCESS_NAME = "samgr";
#endif
static constexpr int SHELL_UID = 2000;

IPCObjectStub::IPCObjectStub(std::u16string descriptor) : IRemoteObject(descriptor)
{
}

IPCObjectStub::~IPCObjectStub()
{
    ZLOGD(LABEL, "destroy, desc: %{public}s", Str16ToStr8(descriptor_).c_str());
}

bool IPCObjectStub::IsDeviceIdIllegal(const std::string &deviceID)
{
    if (deviceID.empty() || deviceID.length() > DEVICEID_LENGTH) {
        return true;
    }
    return false;
}

int32_t IPCObjectStub::GetObjectRefCount()
{
    int kRefCount = 0;
    int refCount = GetSptrRefCount();
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DEFAULT);
    if (invoker != nullptr) {
        kRefCount = invoker->GetObjectRefCount(this);
    }

    /* the kernel has already acquire the reference
     * on this object, so we need to decrement by 1.
     */
    if (kRefCount > 0) {
        refCount += kRefCount - 1;
    }

    return refCount;
}

int IPCObjectStub::Dump(int fd, const std::vector<std::u16string> &args)
{
    const size_t numArgs = args.size();
    ZLOGE(LABEL, "Invalid call on Stub:fd:%d, args:%zu", fd, numArgs);
    return ERR_NONE;
}

int IPCObjectStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int result = ERR_NONE;
    switch (code) {
#ifndef CONFIG_IPC_SINGLE
        case DBINDER_OBITUARY_TRANSACTION: {
            ZLOGW(LABEL, "%{public}s: recv DBINDER_OBITUARY_TRANSACTION", __func__);
            if (!IsSamgrCall(IPCSkeleton::GetCallingTokenID())) {
                ZLOGE(LABEL, "%s: DBINDER_OBITUARY_TRANSACTION unauthenticated user ", __func__);
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
            if (data.ReadInt32() == IRemoteObject::DeathRecipient::NOTICE_DEATH_RECIPIENT) {
                result = NoticeServiceDie(data, reply, option);
            } else {
                result = IPC_STUB_INVALID_DATA_ERR;
            }
            break;
        }
#endif
        default:
            result = IPC_STUB_UNKNOW_TRANS_ERR;
            ZLOGD(LABEL, "unknown OnRemoteRequest code = %{public}u", code);
            break;
    }

    return result;
}

int IPCObjectStub::OnRemoteDump(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int result = ERR_NONE;
    int fd = data.ReadFileDescriptor();
    std::vector<std::u16string> args;
    if (fd != INVALID_FD) {
        if (data.ReadString16Vector(&args)) {
            result = Dump(fd, args);
        }
        ::close(fd);
    } else {
        result = IPC_STUB_INVALID_DATA_ERR;
    }
    return result;
}

int IPCObjectStub::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int result = ERR_NONE;
    switch (code) {
        case PING_TRANSACTION: {
            if (!reply.WriteInt32(ERR_NONE)) {
                result = IPC_STUB_WRITE_PARCEL_ERR;
            }
            break;
        }
        case INTERFACE_TRANSACTION: {
            std::u16string descriptor = GetObjectDescriptor();
            if (!reply.WriteString16(descriptor)) {
                ZLOGE(LABEL, "write to parcel fail");
                result = IPC_STUB_WRITE_PARCEL_ERR;
            }
            break;
        }
        case SYNCHRONIZE_REFERENCE: {
            int refCount = GetObjectRefCount();
            // when handle transaction the invoker would try to acquire
            // the object's reference to defense the object being released
            // so the actual we should decrement the temporary reference.
            --refCount;
            reply.WriteInt32(refCount);
            break;
        }
        case DUMP_TRANSACTION: {
            pid_t uid = IPCSkeleton::GetCallingUid();
#ifndef CONFIG_IPC_SINGLE
            uint32_t calllingTokenID = IPCSkeleton::GetFirstTokenID();
            calllingTokenID = calllingTokenID == 0 ? IPCSkeleton::GetCallingTokenID() : calllingTokenID;
            if (!IPCSkeleton::IsLocalCalling() ||
                (uid != 0 && uid != SHELL_UID && !HasDumpPermission(calllingTokenID))) {
#else
            if (!IPCSkeleton::IsLocalCalling() || (uid != 0 && uid != SHELL_UID && uid != HIDUMPER_SERVICE_UID)) {
#endif
                ZLOGE(LABEL, "do not allow dump");
                break;
            }
            result = OnRemoteDump(code, data, reply, option);
            break;
        }
        case GET_PROTO_INFO: {
            result = ProcessProto(code, data, reply, option);
            break;
        }
#ifndef CONFIG_IPC_SINGLE
        case INVOKE_LISTEN_THREAD: {
            if (!IPCSkeleton::IsLocalCalling() || IPCSkeleton::GetCallingUid() >= ALLOWED_UID) {
                ZLOGE(LABEL, "%s: INVOKE_LISTEN_THREAD unauthenticated user ", __func__);
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
            result = InvokerThread(code, data, reply, option);
            break;
        }
        case DBINDER_INCREFS_TRANSACTION: {
            if (IPCSkeleton::IsLocalCalling()) {
                ZLOGE(LABEL, "%s: cannot be called in same device", __func__);
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
            result = IncStubRefs(data, reply);
            break;
        }
        case DBINDER_DECREFS_TRANSACTION: {
            if (IPCSkeleton::IsLocalCalling()) {
                ZLOGE(LABEL, "%s: cannot be called in same device", __func__);
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
            result = DecStubRefs(data, reply);
            break;
        }
        case DBINDER_ADD_COMMAUTH:
        case DBINDER_TRANS_COMMAUTH: {
            if (IPCSkeleton::IsLocalCalling() || IPCSkeleton::GetCallingUid() >= ALLOWED_UID) {
                ZLOGE(LABEL, "%s: DBINDER_ADD_COMMAUTH unauthenticated user ", __func__);
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
            result = AddAuthInfo(data, reply, code);
            break;
        }
        case GET_UIDPID_INFO: {
            if (!IPCSkeleton::IsLocalCalling()) {
                ZLOGE(LABEL, "GET_UIDPID_INFO message is not from sa manager");
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
            int32_t systemAbilityId = data.ReadInt32();
            std::string sessionName = GetDataBusName(systemAbilityId);
            if (sessionName.empty()) {
                ZLOGE(LABEL, "sessionName is empty");
                result = IPC_STUB_CREATE_BUS_SERVER_ERR;
                break;
            }
            if (!reply.WriteString(sessionName)) {
                ZLOGE(LABEL, "write to parcel fail");
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
            break;
        }
        case GRANT_DATABUS_NAME: {
            if (!IPCSkeleton::IsLocalCalling() || !IsSamgrCall((uint32_t)RpcGetSelfTokenID())) {
                ZLOGE(LABEL, "GRANT_DATABUS_NAME message is excluded in sa manager");
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
            result = GrantDataBusName(code, data, reply, option);
            break;
        }
        case TRANS_DATABUS_NAME: {
            if (!IPCSkeleton::IsLocalCalling() || !IsSamgrCall((uint32_t)RpcGetSelfTokenID())) {
                ZLOGE(LABEL, "TRANS_DATABUS_NAME message is excluded in sa manager");
                result = IPC_STUB_INVALID_DATA_ERR;
                break;
            }
            result = TransDataBusName(code, data, reply, option);
            break;
        }
#endif
        default:
            result = OnRemoteRequest(code, data, reply, option);
            break;
    }

    return result;
}

void IPCObjectStub::OnFirstStrongRef(const void *objectId)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();

    if (current != nullptr) {
        current->AttachObject(this);
    }
}

void IPCObjectStub::OnLastStrongRef(const void *objectId)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();

    if (current != nullptr) {
        current->DetachObject(this);
#ifndef CONFIG_IPC_SINGLE
        current->DetachStubRecvRefInfo(this);
        current->DetachStubSendRefInfo(this);
        (void)current->DetachStubRefTimes(this);
        current->DetachCommAuthInfoByStub(this);
        uint64_t stubIndex = current->EraseStubIndex(reinterpret_cast<IRemoteObject *>(this));
        current->DetachAppInfoToStubIndex(stubIndex);
#endif
    }
}

bool IPCObjectStub::AddDeathRecipient(const sptr<DeathRecipient> &recipient)
{
    (void)recipient;
    return false;
}

bool IPCObjectStub::RemoveDeathRecipient(const sptr<DeathRecipient> &recipient)
{
    return false;
}

pid_t IPCObjectStub::GetCallingPid()
{
    return IPCSkeleton::GetCallingPid();
}

pid_t IPCObjectStub::GetCallingUid()
{
    return IPCSkeleton::GetCallingUid();
}

uint32_t IPCObjectStub::GetCallingTokenID()
{
    return IPCSkeleton::GetCallingTokenID();
}

uint32_t IPCObjectStub::GetFirstTokenID()
{
    return IPCSkeleton::GetFirstTokenID();
}

int IPCObjectStub::GetObjectType() const
{
    return OBJECT_TYPE_NATIVE;
}

int32_t IPCObjectStub::ProcessProto(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int result = ERR_NONE;
    ZLOGD(LABEL, "IPCObjectStub::ProcessProto called, type = 0, normal stub object");
    if (!reply.WriteUint32(IRemoteObject::IF_PROT_BINDER)) {
        ZLOGE(LABEL, "write to parcel fail");
        result = IPC_STUB_WRITE_PARCEL_ERR;
    }
    return result;
}

#ifndef CONFIG_IPC_SINGLE
int32_t IPCObjectStub::InvokerThread(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    switch (data.ReadUint32()) {
        case IRemoteObject::DATABUS_TYPE: {
            if (InvokerDataBusThread(data, reply) != ERR_NONE) {
                ZLOGE(LABEL, "Invoker databus thread fail");
                return IPC_STUB_INVOKE_THREAD_ERR;
            }
            break;
        }
        default: {
            ZLOGE(LABEL, "InvokerThread Invalid Type");
            return IPC_STUB_INVALID_DATA_ERR;
        }
    }

    return ERR_NONE;
}

int32_t IPCObjectStub::InvokerDataBusThread(MessageParcel &data, MessageParcel &reply)
{
    std::string deviceId = data.ReadString();
    uint32_t remotePid = data.ReadUint32();
    uint32_t remoteUid = data.ReadUint32();
    std::string remoteDeviceId = data.ReadString();
    std::string sessionName = data.ReadString();
    uint32_t featureSet = data.ReadUint32();
    uint32_t tokenId = 0;

    std::shared_ptr<FeatureSetData> feature = std::make_shared<FeatureSetData>();
    if (feature == nullptr) {
        ZLOGE(LABEL, "%s: feature null", __func__);
        return IPC_STUB_INVALID_DATA_ERR;
    }
    feature->featureSet = featureSet;
    feature->tokenId = tokenId;
    if (IsDeviceIdIllegal(deviceId) || IsDeviceIdIllegal(remoteDeviceId) || sessionName.empty()) {
        ZLOGE(LABEL, "%s: device ID is invalid or session name nil", __func__);
        return IPC_STUB_INVALID_DATA_ERR;
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "IPCProcessSkeleton is nullptr");
        return IPC_STUB_CURRENT_NULL_ERR;
    }
    if (!current->CreateSoftbusServer(sessionName)) {
        ZLOGE(LABEL, "%s: fail to create databus server", __func__);
        return IPC_STUB_CREATE_BUS_SERVER_ERR;
    }

    uint64_t stubIndex = current->AddStubByIndex(this);
    if (stubIndex == 0) {
        ZLOGE(LABEL, "%s: add stub fail", __func__);
        return IPC_STUB_INVALID_DATA_ERR;
    }
    if (!reply.WriteUint64(stubIndex) || !reply.WriteString(sessionName) || !reply.WriteString(deviceId)) {
        ZLOGE(LABEL, "%s: write to parcel fail", __func__);
        return IPC_STUB_INVALID_DATA_ERR;
    }
    if (!current->AttachAppInfoToStubIndex(remotePid, remoteUid, remoteDeviceId, stubIndex)) {
        ZLOGE(LABEL, "fail to attach appinfo to stubIndex, maybe attach already");
    }
    if (!current->AttachCommAuthInfo(this, (int32_t)remotePid, (int32_t)remoteUid, remoteDeviceId, feature)) {
        ZLOGE(LABEL, "fail to attach comm auth info");
    }

    return ERR_NONE;
}

int32_t IPCObjectStub::NoticeServiceDie(MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ZLOGE(LABEL, "%{public}s enter, desc:%{public}s", __func__, Str16ToStr8(descriptor_).c_str());
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "%s: current is null", __func__);
        return IPC_STUB_CURRENT_NULL_ERR;
    }

    IPCObjectProxy *ipcProxy = current->QueryCallbackProxy(this);
    if (ipcProxy == nullptr) {
        ZLOGE(LABEL, "%s: ipc proxy is null", __func__);
        return IPC_STUB_INVALID_DATA_ERR;
    }

    ipcProxy->SendObituary();

    if (!current->DetachCallbackStub(this)) {
        ZLOGE(LABEL, "%s: fail to detach callback stub", __func__);
        // do nothing, RemoveDeathRecipient can delete this too
    }

    return ERR_NONE;
}

int32_t IPCObjectStub::IncStubRefs(MessageParcel &data, MessageParcel &reply)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "%s: current is null", __func__);
        return IPC_STUB_CURRENT_NULL_ERR;
    }
    std::string deviceId = IPCSkeleton::GetCallingDeviceID();
    if (deviceId.empty()) {
        ZLOGE(LABEL, "%s: calling error", __func__);
        return IPC_STUB_INVALID_DATA_ERR;
    }
    if (!current->AttachStubRecvRefInfo(this, IPCSkeleton::GetCallingPid(), deviceId)) {
        ZLOGE(LABEL, "%s: attach stub ref info err, already in", __func__);
        return ERR_NONE;
    }
    if (!current->DecStubRefTimes(this)) {
        this->IncStrongRef(this);
    }
    return ERR_NONE;
}

int32_t IPCObjectStub::DecStubRefs(MessageParcel &data, MessageParcel &reply)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "%s: current is null", __func__);
        return IPC_STUB_CURRENT_NULL_ERR;
    }

    std::string deviceId = IPCSkeleton::GetCallingDeviceID();
    current->DetachStubRefInfo(this, IPCSkeleton::GetCallingPid(), deviceId);
    return ERR_NONE;
}

int32_t IPCObjectStub::AddAuthInfo(MessageParcel &data, MessageParcel &reply, uint32_t code)
{
    uint32_t remotePid = data.ReadUint32();
    uint32_t remoteUid = data.ReadUint32();
    std::string remoteDeviceId = data.ReadString();
    uint32_t remoteFeature = data.ReadUint32();
    uint32_t tokenId = 0;

    std::shared_ptr<FeatureSetData> feature = nullptr;
    feature.reset(reinterpret_cast<FeatureSetData *>(::operator new(sizeof(FeatureSetData))));
    if (feature == nullptr) {
        ZLOGE(LABEL, "%s: feature null", __func__);
        return IPC_STUB_INVALID_DATA_ERR;
    }
    feature->featureSet = remoteFeature;
    feature->tokenId = tokenId;
    if (IsDeviceIdIllegal(remoteDeviceId)) {
        ZLOGE(LABEL, "%s: remote deviceId is null", __func__);
        return IPC_STUB_INVALID_DATA_ERR;
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "%s: current is null", __func__);
        return IPC_STUB_CURRENT_NULL_ERR;
    }

    if (!current->AttachCommAuthInfo(this, (int32_t)remotePid, (int32_t)remoteUid, remoteDeviceId, feature)) {
        ZLOGE(LABEL, "fail to attach comm auth info fail");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    if (code == DBINDER_TRANS_COMMAUTH) {
        uint64_t stubIndex = data.ReadUint64();
        if (stubIndex == 0) {
            ZLOGE(LABEL, "fail to attach comm auth info fail");
            return BINDER_CALLBACK_STUBINDEX_ERR;
        }
        if (!current->AttachAppInfoToStubIndex(remotePid, remoteUid, remoteDeviceId, stubIndex)) {
            ZLOGE(LABEL, "fail to add appinfo and stubIndex, maybe attach already");
        }
    }
    return ERR_NONE;
}

std::string IPCObjectStub::GetDataBusName(int32_t systemAbilityId)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "get current is null");
        return std::string("");
    }
    sptr<IRemoteObject> object = current->GetSAMgrObject();
    if (object == nullptr) {
        ZLOGE(LABEL, "get object is null");
        return std::string("");
    }

    IPCObjectProxy *samgr = reinterpret_cast<IPCObjectProxy *>(object.GetRefPtr());
    return samgr->GetDataBusName(systemAbilityId);
}

int32_t IPCObjectStub::GrantDataBusName(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int pid = IPCSkeleton::GetCallingPid();
    int uid = IPCSkeleton::GetCallingUid();
    int systemAbilityId = data.ReadInt32();
    std::string sessionName = CreateDatabusName(uid, pid, systemAbilityId);
    if (sessionName.empty()) {
        ZLOGE(LABEL, "pid/uid is invalid, pid = {public}%d, uid = {public}%d", pid, uid);
        return IPC_STUB_INVALID_DATA_ERR;
    }
    if (!reply.WriteUint32(IRemoteObject::IF_PROT_DATABUS) || !reply.WriteString(sessionName)) {
        ZLOGE(LABEL, "write to parcel fail");
        return IPC_STUB_INVALID_DATA_ERR;
    }

    return ERR_NONE;
}

int32_t IPCObjectStub::TransDataBusName(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    uint32_t remotePid = data.ReadUint32();
    uint32_t remoteUid = data.ReadUint32();
    if (remotePid == static_cast<uint32_t>(IPCSkeleton::GetCallingPid())) {
        ZLOGE(LABEL, "pid/uid is invalid, pid = {public}%d, uid = {public}%d", remotePid, remoteUid);
        return IPC_STUB_INVALID_DATA_ERR;
    }
    std::string sessionName = CreateDatabusName(remoteUid, remotePid, 0);
    if (sessionName.empty()) {
        ZLOGE(LABEL, "pid/uid is invalid, pid = {public}%d, uid = {public}%d", remotePid, remoteUid);
        return IPC_STUB_INVALID_DATA_ERR;
    }
    if (!reply.WriteUint32(IRemoteObject::IF_PROT_DATABUS) || !reply.WriteString(sessionName)) {
        ZLOGE(LABEL, "write to parcel fail");
        return IPC_STUB_INVALID_DATA_ERR;
    }

    return ERR_NONE;
}

std::string IPCObjectStub::CreateDatabusName(int uid, int pid, int systemAbilityId)
{
    std::shared_ptr<ISessionService> softbusManager = ISessionService::GetInstance();
    if (softbusManager == nullptr) {
        ZLOGE(LABEL, "fail to get softbus service");
        return "";
    }

    std::string sessionName = "DBinder" + std::to_string(uid) + std::string("_") + std::to_string(pid);
    if (systemAbilityId > 0) {
        sessionName += std::string("_") + std::to_string(systemAbilityId);
    }
    if (softbusManager->GrantPermission(uid, pid, sessionName) != ERR_NONE) {
        ZLOGE(LABEL, "fail to Grant Permission softbus name");
        return "";
    }

    return sessionName;
}

bool IPCObjectStub::IsSamgrCall(uint32_t accessToken)
{
    auto tokenType = AccessToken::AccessTokenKit::GetTokenTypeFlag(accessToken);
    if (tokenType != AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
        ZLOGE(LABEL, "not native call");
        return false;
    }
    AccessToken::NativeTokenInfo nativeTokenInfo;
    int32_t result = AccessToken::AccessTokenKit::GetNativeTokenInfo(accessToken, nativeTokenInfo);
    if (result == ERR_NONE && nativeTokenInfo.processName == SAMGR_PROCESS_NAME) {
        return true;
    }
    ZLOGE(LABEL, "not samgr called, processName:%{private}s", nativeTokenInfo.processName.c_str());
    return false;
}

bool IPCObjectStub::HasDumpPermission(uint32_t accessToken) const
{
    int res = AccessToken::AccessTokenKit::VerifyAccessToken(accessToken, "ohos.permission.DUMP");
    if (res == AccessToken::PermissionState::PERMISSION_GRANTED) {
        return true;
    }
    bool ret = false;
    auto tokenType = AccessToken::AccessTokenKit::GetTokenTypeFlag(accessToken);
    if (tokenType == AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
        AccessToken::NativeTokenInfo nativeTokenInfo;
        int32_t result = AccessToken::AccessTokenKit::GetNativeTokenInfo(accessToken, nativeTokenInfo);
        ret =  (result == ERR_NONE && nativeTokenInfo.apl >= APL_BASIC);
    } else if (tokenType == AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        AccessToken::HapTokenInfo hapTokenInfo;
        int32_t result = AccessToken::AccessTokenKit::GetHapTokenInfo(accessToken, hapTokenInfo);
        ret =  (result == ERR_NONE && hapTokenInfo.apl >= APL_BASIC);
    }
    if (!ret) {
        ZLOGD(LABEL, "No dump permission, please check!");
    }
    return ret;
}
#endif
} // namespace OHOS
