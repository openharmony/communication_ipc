/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "napi_remote_object.h"
#include <mutex>
#include <set>
#include <cstring>
#include <thread>
#include <unistd.h>
#include <uv.h>
#include "hilog/log.h"
#include "ipc_object_proxy.h"
#include "ipc_object_stub.h"
#include "ipc_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "ipc_types.h"
#include "log_tags.h"
#include "napi_message_option.h"
#include "napi_message_parcel.h"
#include "string_ex.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC, "napi_remoteObject" };
#ifndef TITLE
#define TITLE __PRETTY_FUNCTION__
#endif
#define DBINDER_LOGE(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Error(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)
#define DBINDER_LOGI(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Info(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)

/*
 * The native DeathRecipient container.
 * As an recipient of obituary of service death,
 * and pass the message to js Layer.
 */
class NAPIDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit NAPIDeathRecipient(napi_env env, napi_value jsRecipient);

    void OnRemoteDied(const wptr<IRemoteObject> &object) override;

    bool Matches(napi_value jsRecipient);

protected:
    virtual ~NAPIDeathRecipient();

private:
    std::mutex mutex_;
    napi_env env_ = nullptr;
    napi_ref deathRecipientRef_ = nullptr;
};

NAPIDeathRecipient::NAPIDeathRecipient(napi_env env, napi_value jsDeathRecipient)
{
    env_ = env;
    napi_status status = napi_create_reference(env_, jsDeathRecipient, 1, &deathRecipientRef_);
    NAPI_ASSERT_RETURN_VOID(env, status == napi_ok, "failed to create ref to js death recipient");
}

NAPIDeathRecipient::~NAPIDeathRecipient()
{
    if (env_ != nullptr) {
        if (deathRecipientRef_ != nullptr) {
            napi_status status = napi_delete_reference(env_, deathRecipientRef_);
            NAPI_ASSERT_RETURN_VOID(env_, status == napi_ok, "failed to delete ref to js death recipient");
            deathRecipientRef_ = nullptr;
        }
    }
}

void NAPIDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    DBINDER_LOGI("OnRemoteDied called");
    if (deathRecipientRef_ == nullptr) {
        DBINDER_LOGE("js death recipient has already removed");
        return;
    }
    napi_value jsDeathRecipient = nullptr;
    napi_get_reference_value(env_, deathRecipientRef_, &jsDeathRecipient);
    NAPI_ASSERT_RETURN_VOID(env_, jsDeathRecipient != nullptr, "failed to get js death recipient");
    napi_value onRemoteDied = nullptr;
    napi_get_named_property(env_, jsDeathRecipient, "onRemoteDied", &onRemoteDied);
    NAPI_ASSERT_RETURN_VOID(env_, onRemoteDied != nullptr, "failed to get property onRemoteDied");
    napi_value return_val = nullptr;
    napi_status status = napi_call_function(env_, jsDeathRecipient, onRemoteDied, 0, nullptr, &return_val);
    NAPI_ASSERT_RETURN_VOID(env_, status == napi_ok, "failed to call function onRemoteDied");

    std::lock_guard<std::mutex> lockGuard(mutex_);
    napi_delete_reference(env_, deathRecipientRef_);
    deathRecipientRef_ = nullptr;
}

bool NAPIDeathRecipient::Matches(napi_value object)
{
    bool result = false;
    if (object != nullptr) {
        std::lock_guard<std::mutex> lockGuard(mutex_);
        if (deathRecipientRef_ != nullptr) {
            napi_value jsDeathRecipient = nullptr;
            napi_get_reference_value(env_, deathRecipientRef_, &jsDeathRecipient);
            napi_status status = napi_strict_equals(env_, object, jsDeathRecipient, &result);
            if (status != napi_ok) {
                DBINDER_LOGI("compares death recipients failed");
            }
        }
    }
    return result;
}

/*
 * List of native NAPIDeathRecipient
 */
class NAPIDeathRecipientList : public RefBase {
public:
    NAPIDeathRecipientList();

    ~NAPIDeathRecipientList();

    bool Add(const sptr<NAPIDeathRecipient> &recipient);

    bool Remove(const sptr<NAPIDeathRecipient> &recipient);

    sptr<NAPIDeathRecipient> Find(napi_value jsRecipient);
private:
    std::mutex mutex_;
    std::set<sptr<NAPIDeathRecipient>> set_;
};

NAPIDeathRecipientList::NAPIDeathRecipientList() {}

NAPIDeathRecipientList::~NAPIDeathRecipientList()
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    set_.clear();
}

bool NAPIDeathRecipientList::Add(const sptr<NAPIDeathRecipient> &recipient)
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    auto ret = set_.insert(recipient);
    return ret.second;
}

bool NAPIDeathRecipientList::Remove(const sptr<NAPIDeathRecipient> &recipient)
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    return (set_.erase(recipient) > 0);
}

sptr<NAPIDeathRecipient> NAPIDeathRecipientList::Find(napi_value jsRecipient)
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    for (auto it = set_.begin(); it != set_.end(); it++) {
        if ((*it)->Matches(jsRecipient)) {
            return *it;
        }
    }
    return nullptr;
}

class NAPIRemoteProxyHolder {
public:
    NAPIRemoteProxyHolder();
    ~NAPIRemoteProxyHolder();
    sptr<NAPIDeathRecipientList> list_;
    sptr<IRemoteObject> object_;
};

NAPIRemoteProxyHolder::NAPIRemoteProxyHolder() : list_(nullptr), object_(nullptr) {}

NAPIRemoteProxyHolder::~NAPIRemoteProxyHolder()
{
    list_ = nullptr;
    object_ = nullptr;
}

napi_value RemoteProxy_JS_Constructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    // new napi proxy holder instance
    auto proxyHolder = new NAPIRemoteProxyHolder();
    // connect native object to js thisVar
    napi_status status = napi_wrap(
        env, thisVar, proxyHolder,
        [](napi_env env, void *data, void *hint) {
            DBINDER_LOGI("proxy holder destructed by js callback");
            delete (reinterpret_cast<NAPIRemoteProxyHolder *>(data));
        },
        nullptr, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "wrap js RemoteProxy and native holder failed");
    return thisVar;
}

EXTERN_C_START
/*
 * function for module exports
 */
napi_value NAPIRemoteProxyExport(napi_env env, napi_value exports)
{
    const std::string className = "RemoteProxy";
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("sendRequest", NAPI_RemoteProxy_sendRequest),
        DECLARE_NAPI_FUNCTION("addDeathRecipient", NAPI_RemoteProxy_addDeathRecipient),
        DECLARE_NAPI_FUNCTION("removeDeathRecipient", NAPI_RemoteProxy_removeDeathRecipient),
        DECLARE_NAPI_FUNCTION("getInterfaceDescriptor", NAPI_RemoteProxy_getInterfaceDescriptor),
        DECLARE_NAPI_FUNCTION("isObjectDead", NAPI_RemoteProxy_isObjectDead),
        DECLARE_NAPI_FUNCTION("getHandle", NAPI_RemoteProxy_getHandle),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, className.c_str(), className.length(), RemoteProxy_JS_Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    NAPI_ASSERT(env, constructor != nullptr, "define js class RemoteProxy failed");
    napi_status status = napi_set_named_property(env, exports, "RemoteProxy", constructor);
    NAPI_ASSERT(env, status == napi_ok, "set property RemoteProxy to exports failed");
    napi_value global = nullptr;
    status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    status = napi_set_named_property(env, global, "IPCProxyConstructor_", constructor);
    NAPI_ASSERT(env, status == napi_ok, "set proxy constructor failed");
    return exports;
}
EXTERN_C_END

/*
 * The native NAPIRemoteObject act as bridger between js and native.
 * It received the request from client and pass it js Layer.
 */
class NAPIRemoteObject : public IPCObjectStub {
public:
    NAPIRemoteObject(napi_env env, napi_value thisVar, const std::u16string &descriptor);

    ~NAPIRemoteObject() override;

    bool CheckObjectLegality() const override;

    int GetObjectType() const override;

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    napi_ref GetJsObjectRef() const;
private:
    napi_env env_ = nullptr;
    napi_value thisVar_ = nullptr;
    napi_ref thisVarRef_ = nullptr;
    struct ThreadLockInfo {
        std::mutex mutex;
        std::condition_variable condition;
        bool ready = false;
    };
    struct CallbackParam {
        napi_env env;
        napi_ref thisVarRef;
        uint32_t code;
        MessageParcel *data;
        MessageParcel *reply;
        MessageOption *option;
        pid_t callingPid;
        pid_t callingUid;
        std::string callingDeviceID;
        std::string localDeviceID;
        ThreadLockInfo *lockInfo;
        int result;
    };
    int OnJsRemoteRequest(CallbackParam *param);
};

/*
 * To ensure a better consistency of the life time of
 * js RemoteObject and native object, we designed
 * a container to save the native object.
 */
class NAPIRemoteObjectHolder : public RefBase {
public:
    explicit NAPIRemoteObjectHolder(napi_env env, const std::u16string &descriptor);
    ~NAPIRemoteObjectHolder();
    sptr<NAPIRemoteObject> Get(napi_value object);
    void Set(sptr<NAPIRemoteObject> object);
private:
    std::mutex mutex_;
    napi_env env_ = nullptr;
    std::u16string descriptor_;
    sptr<NAPIRemoteObject> cachedObject_;
};

NAPIRemoteObjectHolder::NAPIRemoteObjectHolder(napi_env env, const std::u16string &descriptor)
    : env_(env), descriptor_(descriptor), cachedObject_(nullptr)
{}

NAPIRemoteObjectHolder::~NAPIRemoteObjectHolder()
{
    // free the reference of object.
    cachedObject_ = nullptr;
}

sptr<NAPIRemoteObject> NAPIRemoteObjectHolder::Get(napi_value jsRemoteObject)
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    // grab an strong reference to the object,
    // so it will not be freed util this reference released.
    sptr<NAPIRemoteObject> remoteObject = nullptr;
    if (cachedObject_ != nullptr) {
        remoteObject = cachedObject_;
    }

    if (remoteObject == nullptr) {
        remoteObject = new NAPIRemoteObject(env_, jsRemoteObject, descriptor_);
        cachedObject_ = remoteObject;
    }
    return remoteObject;
}

void NAPIRemoteObjectHolder::Set(sptr<NAPIRemoteObject> object)
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    cachedObject_ = object;
}

napi_value RemoteObject_JS_Constructor(napi_env env, napi_callback_info info)
{
    // new napi remote object
    size_t argc = 2;
    size_t expectedArgc = 2;
    napi_value argv[2] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == expectedArgc, "requires 2 parameter");

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_string, "type mismatch for parameter 1");

    napi_typeof(env, argv[1], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 2");

    uint32_t stringLength = 0;
    uint32_t maxStrLen = 40960;
    napi_get_value_uint32(env, argv[1], &stringLength);
    NAPI_ASSERT(env, stringLength < maxStrLen, "string length too large");

    char stringValue[stringLength];
    size_t jsStringLength = 0;
    napi_get_value_string_utf8(env, argv[0], stringValue, stringLength, &jsStringLength);
    NAPI_ASSERT(env, jsStringLength == stringLength, "string length wrong");
    std::string descriptor = stringValue;

    auto holder = new NAPIRemoteObjectHolder(env, Str8ToStr16(descriptor));
    // connect native object to js thisVar
    napi_status status = napi_wrap(
        env, thisVar, holder,
        [](napi_env env, void *data, void *hint) {
            DBINDER_LOGI("NAPIRemoteObjectHolder destructed by js callback");
            delete (reinterpret_cast<NAPIRemoteObjectHolder *>(data));
        },
        nullptr, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "wrap js RemoteObject and native holder failed");
    return thisVar;
}

EXTERN_C_START
/*
 * function for module exports
 */
napi_value NAPIRemoteObjectExport(napi_env env, napi_value exports)
{
    const std::string className = "RemoteObject";
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getCallingPid", NAPI_RemoteObject_getCallingPid),
        DECLARE_NAPI_FUNCTION("getCallingUid", NAPI_RemoteObject_getCallingUid),
        DECLARE_NAPI_FUNCTION("sendRequest", NAPI_RemoteObject_sendRequest),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, className.c_str(), className.length(), RemoteObject_JS_Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    NAPI_ASSERT(env, constructor != nullptr, "define js class RemoteObject failed");
    napi_status status = napi_set_named_property(env, exports, "RemoteObject", constructor);
    NAPI_ASSERT(env, status == napi_ok, "set property RemoteObject to exports failed");
    napi_value global = nullptr;
    status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    status = napi_set_named_property(env, global, "IPCStubConstructor_", constructor);
    NAPI_ASSERT(env, status == napi_ok, "set stub constructor failed");
    return exports;
}
EXTERN_C_END

NAPIRemoteObject::NAPIRemoteObject(napi_env env, napi_value thisVar, const std::u16string &descriptor)
    : IPCObjectStub(descriptor)
{
    env_ = env;
    thisVar_ = thisVar;
    napi_create_reference(env, thisVar_, 1, &thisVarRef_);
    NAPI_ASSERT_RETURN_VOID(env, thisVarRef_ != nullptr, "failed to create ref to js RemoteObject");
}

NAPIRemoteObject::~NAPIRemoteObject()
{
    DBINDER_LOGI("NAPIRemoteObject Destructor");
    if (thisVarRef_ != nullptr) {
        napi_status status = napi_delete_reference(env_, thisVarRef_);
        NAPI_ASSERT_RETURN_VOID(env_, status == napi_ok, "failed to delete ref to js RemoteObject");
        thisVarRef_ = nullptr;
    }
}

bool NAPIRemoteObject::CheckObjectLegality() const
{
    return true;
}

int NAPIRemoteObject::GetObjectType() const
{
    return OBJECT_TYPE_JAVASCRIPT;
}

napi_ref NAPIRemoteObject::GetJsObjectRef() const
{
    return thisVarRef_;
}

int NAPIRemoteObject::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    DBINDER_LOGI("enter OnRemoteRequest");
    if (code == DUMP_TRANSACTION) {
        DBINDER_LOGE("DUMP_TRANSACTION data size:%zu", data.GetReadableBytes());
    }
    pid_t callingPid = IPCSkeleton::GetCallingPid();
    pid_t callingUid = IPCSkeleton::GetCallingUid();
    std::string callingDeviceID = IPCSkeleton::GetCallingDeviceID();
    std::string localDeviceID = IPCSkeleton::GetLocalDeviceID();
    DBINDER_LOGI("callingPid:%{public}u, callingUid:%{public}u, callingDeviceID:%{public}s, localDeviceId:%{public}s",
        callingPid, callingUid, callingDeviceID.c_str(), localDeviceID.c_str());
    std::shared_ptr<struct ThreadLockInfo> lockInfo = std::make_shared<struct ThreadLockInfo>();
    CallbackParam *param = new CallbackParam {
        .env = env_,
        .thisVarRef = thisVarRef_,
        .code = code,
        .data = &data,
        .reply = &reply,
        .option = &option,
        .callingPid = callingPid,
        .callingUid = callingUid,
        .callingDeviceID = callingDeviceID,
        .localDeviceID = localDeviceID,
        .lockInfo = lockInfo.get(),
        .result = 0
    };
    int ret = OnJsRemoteRequest(param);
    DBINDER_LOGI("OnJsRemoteRequest done, ret:%{public}d", ret);
    return ret;
}

int NAPIRemoteObject::OnJsRemoteRequest(CallbackParam *jsParam)
{
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);

    uv_work_t *work = new(std::nothrow) uv_work_t;
    if (work == nullptr) {
        DBINDER_LOGE("failed to new uv_work_t");
        delete jsParam;
        return -1;
    }
    work->data = reinterpret_cast<void *>(jsParam);
    DBINDER_LOGI("start nv queue work loop");
    uv_queue_work(loop, work, [](uv_work_t *work) {}, [](uv_work_t *work, int status) {
        DBINDER_LOGI("enter thread pool");
        CallbackParam *param = reinterpret_cast<CallbackParam *>(work->data);
        napi_value onRemoteRequest = nullptr;
        napi_value thisVar = nullptr;
        napi_get_reference_value(param->env, param->thisVarRef, &thisVar);
        if (thisVar == nullptr) {
            DBINDER_LOGE("thisVar is null");
            param->result = -1;
            std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
            param->lockInfo->ready = true;
            param->lockInfo->condition.notify_all();
            return;
        }
        napi_get_named_property(param->env, thisVar, "onRemoteRequest", &onRemoteRequest);
        if (onRemoteRequest == nullptr) {
            DBINDER_LOGE("get founction onRemoteRequest failed");
            param->result = -1;
            std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
            param->lockInfo->ready = true;
            param->lockInfo->condition.notify_all();
            return;
        }
        napi_value jsCode;
        napi_create_uint32(param->env, param->code, &jsCode);

        napi_value global = nullptr;
        napi_get_global(param->env, &global);
        if (global == nullptr) {
            DBINDER_LOGE("get napi global failed");
            param->result = -1;
            std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
            param->lockInfo->ready = true;
            param->lockInfo->condition.notify_all();
            return;
        }
        napi_value jsOptionConstructor = nullptr;
        napi_get_named_property(param->env, global, "IPCOptionConstructor_", &jsOptionConstructor);
        if (jsOptionConstructor == nullptr) {
            DBINDER_LOGE("jsOption constructor is null");
            param->result = -1;
            std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
            param->lockInfo->ready = true;
            param->lockInfo->condition.notify_all();
            return;
        }
        napi_value jsOption;
        size_t argc = 2;
        napi_value flags = nullptr;
        napi_create_int32(param->env, param->option->GetFlags(), &flags);
        napi_value waittime = nullptr;
        napi_create_int32(param->env, param->option->GetWaitTime(), &waittime);
        napi_value argv[2] = { flags, waittime };
        napi_new_instance(param->env, jsOptionConstructor, argc, argv, &jsOption);
        if (jsOption == nullptr) {
            DBINDER_LOGE("new jsOption failed");
            param->result = -1;
            std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
            param->lockInfo->ready = true;
            param->lockInfo->condition.notify_all();
            return;
        }
        napi_value jsParcelConstructor = nullptr;
        napi_get_named_property(param->env, global, "IPCParcelConstructor_", &jsParcelConstructor);
        if (jsParcelConstructor == nullptr) {
            DBINDER_LOGE("jsParcel constructor is null");
            param->result = -1;
            std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
            param->lockInfo->ready = true;
            param->lockInfo->condition.notify_all();
            return;
        }
        napi_value jsData;
        DBINDER_LOGI("native data parcel:%{public}p", param->data);
        napi_value dataParcel;
        napi_create_int64(param->env, reinterpret_cast<int64_t>(param->data), &dataParcel);
        if (dataParcel == nullptr) {
            DBINDER_LOGE("create js object for data parcel address failed");
            param->result = -1;
            std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
            param->lockInfo->ready = true;
            param->lockInfo->condition.notify_all();
            return;
        }
        size_t argc3 = 1;
        napi_value argv3[1] = { dataParcel };
        napi_new_instance(param->env, jsParcelConstructor, argc3, argv3, &jsData);
        if (jsData == nullptr) {
            DBINDER_LOGE("create js data parcel failed");
            param->result = -1;
            std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
            param->lockInfo->ready = true;
            param->lockInfo->condition.notify_all();
            return;
        }
        DBINDER_LOGI("native reply parcel:%{public}p", param->reply);
        napi_value jsReply;
        napi_value replyParcel;
        napi_create_int64(param->env, reinterpret_cast<int64_t>(param->reply), &replyParcel);
        if (replyParcel == nullptr) {
            DBINDER_LOGE("create js object for reply parcel address failed");
            param->result = -1;
            std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
            param->lockInfo->ready = true;
            param->lockInfo->condition.notify_all();
            return;
        }
        size_t argc4 = 1;
        napi_value argv4[1] = { replyParcel };
        napi_new_instance(param->env, jsParcelConstructor, argc4, argv4, &jsReply);
        if (jsReply == nullptr) {
            DBINDER_LOGE("create js reply parcel failed");
            param->result = -1;
            std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
            param->lockInfo->ready = true;
            param->lockInfo->condition.notify_all();
            return;
        }
        // save old calling pid, uid, device id
        napi_get_global(param->env, &global);
        napi_value oldPid;
        napi_get_named_property(param->env, global, "callingPid_", &oldPid);
        napi_value oldUid;
        napi_get_named_property(param->env, global, "callingUid_", &oldUid);
        napi_value oldCallingDeviceID;
        napi_get_named_property(param->env, global, "callingDeviceID_", &oldCallingDeviceID);
        napi_value oldLocalDeviceID;
        napi_get_named_property(param->env, global, "localDeviceID_", &oldLocalDeviceID);

        // set new calling pid, uid, device id
        napi_value newPid;
        napi_create_int32(param->env, static_cast<int32_t>(param->callingPid), &newPid);
        napi_set_named_property(param->env, global, "callingPid_", newPid);
        napi_value newUid;
        napi_create_int32(param->env, static_cast<int32_t>(param->callingUid), &newUid);
        napi_set_named_property(param->env, global, "callingUid_", newUid);
        napi_value newDeviceID;
        napi_create_string_utf8(param->env, param->callingDeviceID.c_str(), NAPI_AUTO_LENGTH, &newDeviceID);
        napi_set_named_property(param->env, global, "callingDeviceID_", newDeviceID);
        napi_value newLocalDeviceID;
        napi_create_string_utf8(param->env, param->localDeviceID.c_str(), NAPI_AUTO_LENGTH, &newLocalDeviceID);
        napi_set_named_property(param->env, global, "localDeviceID_", newLocalDeviceID);

        // start to call onRemoteRequest
        size_t argc2 = 4;
        napi_value argv2[] = { jsCode, jsData, jsReply, jsOption };
        napi_value return_val;
        napi_status ret = napi_call_function(param->env, thisVar, onRemoteRequest, argc2, argv2, &return_val);
        DBINDER_LOGI("call js onRemoteRequest done");
        if (ret != napi_ok) {
            DBINDER_LOGE("OnRemoteRequest got exception");
            param->result = ERR_UNKNOWN_TRANSACTION;
        } else {
            bool result;
            napi_get_value_bool(param->env, return_val, &result);
            if (!result) {
                DBINDER_LOGE("OnRemoteRequest res:%{public}s", result ? "true" : "false");
                param->result = ERR_UNKNOWN_TRANSACTION;
            } else {
                param->result = ERR_NONE;
            }
        }

        napi_set_named_property(param->env, global, "callingPid_", oldPid);
        napi_set_named_property(param->env, global, "callingUid_", oldUid);
        napi_set_named_property(param->env, global, "callingDeviceID_", oldCallingDeviceID);
        napi_set_named_property(param->env, global, "localDeviceID_", oldLocalDeviceID);
        std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
        param->lockInfo->ready = true;
        param->lockInfo->condition.notify_all();
    });
    std::unique_lock<std::mutex> lock(jsParam->lockInfo->mutex);
    jsParam->lockInfo->condition.wait(lock, [&jsParam] { return jsParam->lockInfo->ready; });
    int ret = jsParam->result;
    delete jsParam;
    delete work;
    return ret;
}

NAPIRemoteProxyHolder *NAPI_ohos_rpc_getRemoteProxyHolder(napi_env env, napi_value jsRemoteProxy)
{
    NAPIRemoteProxyHolder *proxyHolder = nullptr;
    napi_unwrap(env, jsRemoteProxy, (void **)&proxyHolder);
    NAPI_ASSERT(env, proxyHolder != nullptr, "failed to get napi remote proxy holder");
    return proxyHolder;
}

napi_value NAPI_ohos_rpc_CreateJsRemoteObject(napi_env env, const sptr<IRemoteObject> target)
{
    if (target == nullptr) {
        DBINDER_LOGE("RemoteObject is null");
        return nullptr;
    }

    if (target->CheckObjectLegality()) {
        IPCObjectStub *tmp = static_cast<IPCObjectStub *>(target.GetRefPtr());
        DBINDER_LOGI("object type:%{public}d", tmp->GetObjectType());
        if (tmp->GetObjectType() == IPCObjectStub::OBJECT_TYPE_JAVASCRIPT) {
            DBINDER_LOGI("napi create js remote object");
            sptr<NAPIRemoteObject> object = static_cast<NAPIRemoteObject *>(target.GetRefPtr());
            // retrieve js remote object constructor
            napi_value global = nullptr;
            napi_status status = napi_get_global(env, &global);
            NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
            napi_value constructor = nullptr;
            status = napi_get_named_property(env, global, "IPCStubConstructor_", &constructor);
            NAPI_ASSERT(env, status == napi_ok, "set stub constructor failed");
            NAPI_ASSERT(env, constructor != nullptr, "failed to get js RemoteObject constructor");
            // retrieve descriptor and it's length
            std::u16string descriptor = object->GetObjectDescriptor();
            std::string desc = Str16ToStr8(descriptor);
            napi_value jsDesc = nullptr;
            napi_create_string_utf8(env, desc.c_str(), desc.length(), &jsDesc);
            napi_value len = nullptr;
            napi_create_int32(env, desc.length(), &len);
            // create a new js remote object
            size_t argc = 2;
            napi_value argv[2] = { jsDesc, len };
            napi_value jsRemoteObject;
            status = napi_new_instance(env, constructor, argc, argv, &jsRemoteObject);
            NAPI_ASSERT(env, status == napi_ok, "failed to  construct js RemoteObject");
            // retrieve holder and set object
            NAPIRemoteObjectHolder *holder = nullptr;
            napi_unwrap(env, jsRemoteObject, (void **)&holder);
            NAPI_ASSERT(env, holder != nullptr, "failed to get napi remote object holder");
            holder->Set(object);
            return jsRemoteObject;
        }
    }

    napi_value global = nullptr;
    napi_status status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    napi_value constructor = nullptr;
    status = napi_get_named_property(env, global, "IPCProxyConstructor_", &constructor);
    NAPI_ASSERT(env, status == napi_ok, "get proxy constructor failed");
    napi_value jsRemoteProxy;
    status = napi_new_instance(env, constructor, 0, nullptr, &jsRemoteProxy);
    NAPI_ASSERT(env, status == napi_ok, "failed to  construct js RemoteProxy");
    NAPIRemoteProxyHolder *proxyHolder = NAPI_ohos_rpc_getRemoteProxyHolder(env, jsRemoteProxy);
    proxyHolder->object_ = target;
    proxyHolder->list_ = new NAPIDeathRecipientList();

    return jsRemoteProxy;
}

sptr<IRemoteObject> NAPI_ohos_rpc_getNativeRemoteObject(napi_env env, napi_value object)
{
    if (object != nullptr) {
        napi_value global = nullptr;
        napi_status status = napi_get_global(env, &global);
        NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
        napi_value stubConstructor = nullptr;
        status = napi_get_named_property(env, global, "IPCStubConstructor_", &stubConstructor);
        NAPI_ASSERT(env, status == napi_ok, "get stub constructor failed");
        bool instanceOfStub = false;
        status = napi_instanceof(env, object, stubConstructor, &instanceOfStub);
        NAPI_ASSERT(env, status == napi_ok, "failed to check js object type");
        if (instanceOfStub) {
            NAPIRemoteObjectHolder *holder = nullptr;
            napi_unwrap(env, object, (void **)&holder);
            NAPI_ASSERT(env, holder != nullptr, "failed to get napi remote object holder");
            return holder != nullptr ? holder->Get(object) : nullptr;
        }

        napi_value proxyConstructor = nullptr;
        status = napi_get_named_property(env, global, "IPCProxyConstructor_", &proxyConstructor);
        NAPI_ASSERT(env, status == napi_ok, "get proxy constructor failed");
        bool instanceOfProxy = false;
        status = napi_instanceof(env, object, proxyConstructor, &instanceOfProxy);
        NAPI_ASSERT(env, status == napi_ok, "failed to check js object type");
        if (instanceOfProxy) {
            NAPIRemoteProxyHolder *holder = NAPI_ohos_rpc_getRemoteProxyHolder(env, object);
            return holder != nullptr ? holder->object_ : nullptr;
        }
    }
    return nullptr;
}

napi_value NAPI_IPCSkeleton_getContextObject(napi_env env, napi_callback_info info)
{
    sptr<IRemoteObject> object = IPCSkeleton::GetContextObject();
    if (object == nullptr) {
        DBINDER_LOGE("fatal error, could not get registry object");
        return nullptr;
    }
    return NAPI_ohos_rpc_CreateJsRemoteObject(env, object);
}

napi_value NAPI_IPCSkeleton_getCallingPid(napi_env env, napi_callback_info info)
{
    napi_value global;
    napi_get_global(env, &global);
    napi_value callingPid;
    napi_get_named_property(env, global, "callingPid_", &callingPid);
    return callingPid;
}

napi_value NAPI_IPCSkeleton_getCallingUid(napi_env env, napi_callback_info info)
{
    napi_value global;
    napi_get_global(env, &global);
    napi_value callingUid;
    napi_get_named_property(env, global, "callingUid_", &callingUid);
    return callingUid;
}

napi_value NAPI_IPCSkeleton_getCallingDeviceID(napi_env env, napi_callback_info info)
{
    napi_value global;
    napi_get_global(env, &global);
    napi_value callingDeviceID;
    napi_get_named_property(env, global, "callingDeviceID_", &callingDeviceID);
    return callingDeviceID;
}

napi_value NAPI_IPCSkeleton_getLocalDeviceID(napi_env env, napi_callback_info info)
{
    napi_value global;
    napi_get_global(env, &global);
    napi_value localDeviceID;
    napi_get_named_property(env, global, "localDeviceID_", &localDeviceID);
    return localDeviceID;
}

napi_value NAPI_IPCSkeleton_isLocalCalling(napi_env env, napi_callback_info info)
{
    bool isLocal = IPCSkeleton::IsLocalCalling();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, isLocal, &napiValue));
    return napiValue;
}

napi_value NAPI_IPCSkeleton_flushCommands(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "type mismatch for parameter 1");

    sptr<IRemoteObject> target = NAPI_ohos_rpc_getNativeRemoteObject(env, argv[0]);
    int32_t result = IPCSkeleton::FlushCommands(target);
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_IPCSkeleton_resetCallingIdentity(napi_env env, napi_callback_info info)
{
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, identity.c_str(), identity.length(), &napiValue));
    return napiValue;
}

napi_value NAPI_IPCSkeleton_setCallingIdentity(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    size_t expectedArgc = 2;
    napi_value argv[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == expectedArgc, "requires 2 parameter");

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_string, "type mismatch for parameter 1");

    napi_typeof(env, argv[1], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 2");

    uint32_t stringLength = 0;
    uint32_t maxStrLen = 40960;
    napi_get_value_uint32(env, argv[1], &stringLength);
    NAPI_ASSERT(env, stringLength < maxStrLen, "string length too large");

    char stringValue[stringLength];
    size_t jsStringLength = 0;
    napi_get_value_string_utf8(env, argv[0], stringValue, stringLength, &jsStringLength);
    NAPI_ASSERT(env, jsStringLength == stringLength, "string length wrong");
    std::string identity = stringValue;
    bool result = IPCSkeleton::SetCallingIdentity(identity);
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_RemoteObject_getCallingPid(napi_env env, napi_callback_info info)
{
    napi_value result;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, 0, nullptr, &thisVar, nullptr);
    sptr<IRemoteObject> nativeObject = NAPI_ohos_rpc_getNativeRemoteObject(env, thisVar);
    if ((nativeObject != nullptr) && (!nativeObject->IsProxyObject())) {
        IPCObjectStub *target = reinterpret_cast<IPCObjectStub *>(nativeObject.GetRefPtr());
        uint32_t pid = target->GetCallingPid();
        napi_create_uint32(env, pid, &result);
        return result;
    }
    uint32_t pid = getpid();
    napi_create_uint32(env, pid, &result);
    return result;
}

napi_value NAPI_RemoteObject_getCallingUid(napi_env env, napi_callback_info info)
{
    napi_value result;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, 0, nullptr, &thisVar, nullptr);
    sptr<IRemoteObject> nativeObject = NAPI_ohos_rpc_getNativeRemoteObject(env, thisVar);
    if ((nativeObject != nullptr) && (!nativeObject->IsProxyObject())) {
        IPCObjectStub *target = reinterpret_cast<IPCObjectStub *>(nativeObject.GetRefPtr());
        uint32_t uid = target->GetCallingUid();
        napi_create_uint32(env, uid, &result);
        return result;
    }
    uint32_t uid = getuid();
    napi_create_uint32(env, uid, &result);
    return result;
}

void ExecuteSendRequest(napi_env env, SendRequestParam *param)
{
    param->errCode = param->target->SendRequest(param->code,
        *(param->data.get()), *(param->reply.get()), param->option);
    DBINDER_LOGI("execute sendRequest done, errCode:%{public}d", param->errCode);

    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env, &loop);
    uv_work_t *work = new uv_work_t;
    work->data = reinterpret_cast<void *>(param);
    uv_queue_work(loop, work, [](uv_work_t *work) {}, [](uv_work_t *work, int status) {
        DBINDER_LOGI("enter main loop");
        SendRequestParam *param = reinterpret_cast<SendRequestParam *>(work->data);
        napi_value result = nullptr;
        napi_create_int32(param->env, param->errCode, &result);
        if (param->errCode == 0) {
            napi_resolve_deferred(param->env, param->deferred, result);
        } else {
            napi_reject_deferred(param->env, param->deferred, result);
        }
        delete param;
        delete work;
    });
}

napi_value StubSendRequestPromise(napi_env env, sptr<IRemoteObject> target, uint32_t code,
    std::shared_ptr<MessageParcel> data, std::shared_ptr<MessageParcel> reply, MessageOption &option)
{
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    SendRequestParam *sendRequestParam = new SendRequestParam {
        .target = target,
        .code = code,
        .data = data,
        .reply = reply,
        .option = option,
        .asyncWork = nullptr,
        .deferred = deferred,
        .errCode = -1,
        .env = env
    };
    std::thread t(ExecuteSendRequest, env, sendRequestParam);
    t.detach();
    DBINDER_LOGI("sendRequest and returns promise");
    return promise;
}

napi_value NAPI_RemoteObject_sendRequest(napi_env env, napi_callback_info info)
{
    DBINDER_LOGI("remote object send request starts");
    size_t argc = 4;
    size_t expectedArgc = 4;
    napi_value argv[4] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == expectedArgc, "requires 4 parameter");
    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");
    napi_typeof(env, argv[1], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "type mismatch for parameter 2");
    napi_typeof(env, argv[2], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "type mismatch for parameter 3");
    napi_typeof(env, argv[3], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "type mismatch for parameter 4");

    NAPI_MessageParcel *data = nullptr;
    napi_status status = napi_unwrap(env, argv[1], (void **)&data);
    NAPI_ASSERT(env, status == napi_ok, "failed to get data message parcel");
    NAPI_MessageParcel *reply = nullptr;
    status = napi_unwrap(env, argv[2], (void **)&reply);
    NAPI_ASSERT(env, status == napi_ok, "failed to get reply message parcel");
    MessageOption *option = nullptr;
    status = napi_unwrap(env, argv[3], (void **)&option);
    NAPI_ASSERT(env, option != nullptr, "failed to get message option");

    int32_t code = 0;
    napi_get_value_int32(env, argv[0], &code);

    sptr<IRemoteObject> target = NAPI_ohos_rpc_getNativeRemoteObject(env, thisVar);
    return StubSendRequestPromise(env, target, code, data->GetMessageParcel(), reply->GetMessageParcel(), *option);
}

// This method runs on a worker thread, no access to the JavaScript
void ExecuteSendRequest(napi_env env, void *data)
{
    SendRequestParam *param = reinterpret_cast<SendRequestParam *>(data);
    param->errCode = param->target->SendRequest(param->code,
        *(param->data.get()), *(param->reply.get()), param->option);
    DBINDER_LOGI("sendRequest done, errCode:%{public}d", param->errCode);
}

// This method runs on the main thread after 'ExecuteSendRequest' exits
void SendRequestComplete(napi_env env, napi_status status, void *data)
{
    SendRequestParam *param = reinterpret_cast<SendRequestParam *>(data);
    napi_value result = nullptr;
    napi_create_int32(env, param->errCode, &result);
    DBINDER_LOGI("sendRequest complete, errCode:%{public}d", param->errCode);
    if (param->errCode == 0) {
        napi_resolve_deferred(env, param->deferred, result);
    } else {
        napi_reject_deferred(env, param->deferred, result);
    }
    napi_delete_async_work(env, param->asyncWork);
    delete param;
}

napi_value SendRequestPromise(napi_env env, sptr<IRemoteObject> target, uint32_t code,
    std::shared_ptr<MessageParcel> data, std::shared_ptr<MessageParcel> reply, MessageOption &option)
{
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    SendRequestParam *sendRquestParam = new SendRequestParam {
        .target = target,
        .code = code,
        .data = data,
        .reply = reply,
        .option = option,
        .asyncWork = nullptr,
        .deferred = deferred,
        .errCode = -1,
        .env = nullptr
    };
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, ExecuteSendRequest, SendRequestComplete,
        (void *)sendRquestParam, &sendRquestParam->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, sendRquestParam->asyncWork));
    DBINDER_LOGI("sendRequest and returns promise");
    return promise;
}

napi_value NAPI_RemoteProxy_sendRequest(napi_env env, napi_callback_info info)
{
    DBINDER_LOGI("send request starts");
    size_t argc = 4;
    size_t expectedArgc = 4;
    napi_value argv[4] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == expectedArgc, "requires 4 parameter");
    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");
    napi_typeof(env, argv[1], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "type mismatch for parameter 2");
    napi_typeof(env, argv[2], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "type mismatch for parameter 3");
    napi_typeof(env, argv[3], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "type mismatch for parameter 4");

    NAPI_MessageParcel *data = nullptr;
    napi_status status = napi_unwrap(env, argv[1], (void **)&data);
    NAPI_ASSERT(env, status == napi_ok, "failed t0 get data message parcel");
    NAPI_MessageParcel *reply = nullptr;
    status = napi_unwrap(env, argv[2], (void **)&reply);
    NAPI_ASSERT(env, status == napi_ok, "failed t0 get reply message parcel");
    MessageOption *option = nullptr;
    status = napi_unwrap(env, argv[3], (void **)&option);
    NAPI_ASSERT(env, option != nullptr, "failed to get message option");

    int32_t code = 0;
    napi_get_value_int32(env, argv[0], &code);

    NAPIRemoteProxyHolder *proxyHolder = nullptr;
    status = napi_unwrap(env, thisVar, (void **)&proxyHolder);
    NAPI_ASSERT(env, status == napi_ok, "failed to get proxy holder");
    if (proxyHolder == nullptr) {
        DBINDER_LOGE("proxy holder is null");
        napi_value undefined;
        napi_get_undefined(env, &undefined);
        return undefined;
    }

    sptr<IRemoteObject> target = proxyHolder->object_;
    if (target == nullptr) {
        DBINDER_LOGE("Invalid proxy object");
        napi_value undefined;
        napi_get_undefined(env, &undefined);
        return undefined;
    }
    return SendRequestPromise(env, target, code, data->GetMessageParcel(), reply->GetMessageParcel(), *option);
}

napi_value NAPI_RemoteProxy_addDeathRecipient(napi_env env, napi_callback_info info)
{
    DBINDER_LOGI("add death recipient");
    size_t argc = 2;
    size_t expectedArgc = 2;
    napi_value argv[2] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == expectedArgc, "requires 2 parameter");
    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "type mismatch for parameter 1");
    napi_typeof(env, argv[1], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 2");
    int32_t flag = 0;
    napi_get_value_int32(env, argv[1], &flag);

    napi_value result;
    if (argv[0] == nullptr) {
        napi_get_boolean(env, false, &result);
        return result;
    }

    NAPIRemoteProxyHolder *proxyHolder = nullptr;
    napi_status status = napi_unwrap(env, thisVar, (void **)&proxyHolder);
    NAPI_ASSERT(env, status == napi_ok, "failed to get proxy holder");
    if (proxyHolder == nullptr) {
        napi_get_boolean(env, false, &result);
        return result;
    }
    sptr<IRemoteObject> target = proxyHolder->object_;
    if ((target == nullptr) || !target->IsProxyObject()) {
        DBINDER_LOGE("could not add recipient from invalid target");
        napi_get_boolean(env, false, &result);
        return result;
    }

    sptr<NAPIDeathRecipient> nativeRecipient = new NAPIDeathRecipient(env, argv[0]);
    if (target->AddDeathRecipient(nativeRecipient)) {
        NAPIDeathRecipientList *list = proxyHolder->list_;
        if (list->Add(nativeRecipient)) {
            napi_get_boolean(env, true, &result);
            return result;
        }
    }
    napi_get_boolean(env, false, &result);
    return result;
}

napi_value NAPI_RemoteProxy_removeDeathRecipient(napi_env env, napi_callback_info info)
{
    DBINDER_LOGI("remove death recipient");
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    size_t expectedArgc = 2;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == expectedArgc, "requires 2 parameter");
    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "type mismatch for parameter 1");
    napi_typeof(env, argv[1], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 2");
    napi_value result;
    if (argv[0] == nullptr) {
        napi_get_boolean(env, false, &result);
        return result;
    }
    int32_t flag = 0;
    napi_get_value_int32(env, argv[1], &flag);

    NAPIRemoteProxyHolder *proxyHolder = nullptr;
    napi_status status = napi_unwrap(env, thisVar, (void **)&proxyHolder);
    NAPI_ASSERT(env, status == napi_ok, "failed to get proxy holder");
    if (proxyHolder == nullptr) {
        napi_get_boolean(env, false, &result);
        return result;
    }
    sptr<IRemoteObject> target = proxyHolder->object_;
    if ((target == nullptr) || !target->IsProxyObject()) {
        DBINDER_LOGE("could not remove recipient from invalid target");
        napi_get_boolean(env, false, &result);
        return result;
    }
    sptr<NAPIDeathRecipientList> list = proxyHolder->list_;
    sptr<NAPIDeathRecipient> nativeRecipient = list->Find(argv[0]);
    if (nativeRecipient == nullptr) {
        DBINDER_LOGE("recipient not found");
        napi_get_boolean(env, false, &result);
        return result;
    }
    target->RemoveDeathRecipient(nativeRecipient);
    if (list->Remove(nativeRecipient)) {
        napi_get_boolean(env, true, &result);
        return result;
    } else {
        napi_get_boolean(env, false, &result);
        return result;
    }
}

napi_value NAPI_RemoteProxy_getInterfaceDescriptor(napi_env env, napi_callback_info info)
{
    DBINDER_LOGI("get inteface descriptor");
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, 0, 0, &thisVar, nullptr);
    NAPIRemoteProxyHolder *holder = nullptr;
    napi_status status = napi_unwrap(env, thisVar, (void **)&holder);
    NAPI_ASSERT(env, status == napi_ok, "failed to get proxy holder");
    napi_value result;
    if (holder == nullptr) {
        napi_create_string_utf8(env, "", 0, &result);
        return result;
    }
    IPCObjectProxy *target = reinterpret_cast<IPCObjectProxy *>(holder->object_.GetRefPtr());
    if (target == nullptr) {
        DBINDER_LOGE("Invalid proxy object");
        napi_create_string_utf8(env, "", 0, &result);
        return result;
    }
    std::u16string remoteDescriptor = target->GetInterfaceDescriptor();
    napi_create_string_utf8(env, Str16ToStr8(remoteDescriptor).c_str(), NAPI_AUTO_LENGTH, &result);
    return result;
}

napi_value NAPI_RemoteProxy_isObjectDead(napi_env env, napi_callback_info info)
{
    DBINDER_LOGI("call isObjectDead");
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, 0, 0, &thisVar, nullptr);
    NAPIRemoteProxyHolder *holder = nullptr;
    napi_status status = napi_unwrap(env, thisVar, (void **)&holder);
    NAPI_ASSERT(env, status == napi_ok, "failed to get proxy holder");
    napi_value result;
    if (holder == nullptr) {
        napi_get_boolean(env, false, &result);
        return result;
    }
    IPCObjectProxy *target = reinterpret_cast<IPCObjectProxy *>(holder->object_.GetRefPtr());
    if (target == nullptr) {
        DBINDER_LOGE("Invalid proxy object");
        napi_get_boolean(env, false, &result);
        return result;
    }

    if (target->IsObjectDead()) {
        napi_get_boolean(env, true, &result);
        return result;
    } else {
        napi_get_boolean(env, false, &result);
        return result;
    }
}

napi_value NAPI_RemoteProxy_getHandle(napi_env env, napi_callback_info info)
{
    DBINDER_LOGI("call get handle");
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, 0, 0, &thisVar, nullptr);
    NAPIRemoteProxyHolder *holder = nullptr;
    napi_status status = napi_unwrap(env, thisVar, (void **)&holder);
    NAPI_ASSERT(env, status == napi_ok, "failed to get proxy holder");
    napi_value result;
    if (holder == nullptr) {
        napi_create_uint32(env, 0, &result);
        return result;
    }
    IPCObjectProxy *target = reinterpret_cast<IPCObjectProxy *>(holder->object_.GetRefPtr());
    if (target == nullptr) {
        DBINDER_LOGE("Invalid proxy object");
        napi_create_uint32(env, 0, &result);
        return result;
    }
    uint32_t handle = target->GetHandle();
    napi_create_uint32(env, handle, &result);
    return result;
}

napi_value NAPIIPCSkeleton_JS_Constructor(napi_env env, napi_callback_info info)
{
    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisArg, &data);
    napi_value global = nullptr;
    napi_get_global(env, &global);
    return thisArg;
}

EXTERN_C_START
/*
 * function for module exports
 */
napi_value NAPIIPCSkeletonExport(napi_env env, napi_value exports)
{
    DBINDER_LOGI("napi_moudule IPCSkeleton Init start...");
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_FUNCTION("getContextObject", NAPI_IPCSkeleton_getContextObject),
        DECLARE_NAPI_STATIC_FUNCTION("getCallingPid", NAPI_IPCSkeleton_getCallingPid),
        DECLARE_NAPI_STATIC_FUNCTION("getCallingUid", NAPI_IPCSkeleton_getCallingUid),
        DECLARE_NAPI_STATIC_FUNCTION("getCallingDeviceID", NAPI_IPCSkeleton_getCallingDeviceID),
        DECLARE_NAPI_STATIC_FUNCTION("getLocalDeviceID", NAPI_IPCSkeleton_getLocalDeviceID),
        DECLARE_NAPI_STATIC_FUNCTION("isLocalCalling", NAPI_IPCSkeleton_isLocalCalling),
        DECLARE_NAPI_STATIC_FUNCTION("flushCommands", NAPI_IPCSkeleton_flushCommands),
        DECLARE_NAPI_STATIC_FUNCTION("resetCallingIdentity", NAPI_IPCSkeleton_resetCallingIdentity),
        DECLARE_NAPI_STATIC_FUNCTION("setCallingIdentity", NAPI_IPCSkeleton_setCallingIdentity),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    napi_value result = nullptr;
    napi_define_class(env, "IPCSkeleton", NAPI_AUTO_LENGTH, NAPIIPCSkeleton_JS_Constructor, nullptr,
        sizeof(desc) / sizeof(desc[0]), desc, &result);
    napi_status status = napi_set_named_property(env, exports, "IPCSkeleton", result);
    NAPI_ASSERT(env, status == napi_ok, "create ref to js RemoteObject constructor failed");
    DBINDER_LOGI("napi_moudule IPCSkeleton Init end...");
    return exports;
}
EXTERN_C_END


napi_value NAPIMessageOption_JS_Constructor(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc >= 0, "invalid parameter number");
    int flags = 0;
    int waittime = 0;
    if (argc == 0) {
        flags = MessageOption::TF_SYNC;
        waittime = MessageOption::TF_WAIT_TIME;
    } else if (argc == 1) {
        napi_valuetype valueType;
        napi_typeof(env, argv[0], &valueType);
        NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");
        int32_t jsFlags = 0;
        napi_get_value_int32(env, argv[1], &jsFlags);
        flags = jsFlags;
        waittime = MessageOption::TF_WAIT_TIME;
    } else {
        napi_valuetype valueType;
        napi_typeof(env, argv[0], &valueType);
        NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");
        napi_typeof(env, argv[1], &valueType);
        NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 2");
        int32_t jsFlags = 0;
        napi_get_value_int32(env, argv[0], &jsFlags);
        int32_t jsWaittime = 0;
        napi_get_value_int32(env, argv[1], &jsWaittime);
        flags = jsFlags;
        waittime = jsWaittime;
    }

    auto messageOption = new MessageOption(flags, waittime);
    // connect native message option to js thisVar
    napi_status status = napi_wrap(
        env, thisVar, messageOption,
        [](napi_env env, void *data, void *hint) {
            DBINDER_LOGI("NAPIMessageOption destructed by js callback");
            delete (reinterpret_cast<MessageOption *>(data));
        },
        nullptr, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "wrap js MessageOption and native option failed");
    return thisVar;
}

EXTERN_C_START
/*
 * function for module exports
 */
napi_value NAPIMessageOptionExport(napi_env env, napi_value exports)
{
    const std::string className = "MessageOption";
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getFlags", NapiOhosRpcMessageOptionGetFlags),
        DECLARE_NAPI_FUNCTION("setFlags", NapiOhosRpcMessageOptionSetFlags),
        DECLARE_NAPI_FUNCTION("getWaitTime", NapiOhosRpcMessageOptionGetWaittime),
        DECLARE_NAPI_FUNCTION("setWaitTime", NapiOhosRpcMessageOptionSetWaittime),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, className.c_str(), className.length(), NAPIMessageOption_JS_Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    NAPI_ASSERT(env, constructor != nullptr, "define js class MessageOption failed");
    napi_status status = napi_set_named_property(env, exports, "MessageOption", constructor);
    NAPI_ASSERT(env, status == napi_ok, "set property MessageOption to exports failed");
    napi_value global = nullptr;
    status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    status = napi_set_named_property(env, global, "IPCOptionConstructor_", constructor);
    NAPI_ASSERT(env, status == napi_ok, "set message option constructor failed");
    return exports;
}
EXTERN_C_END
} // namespace OHOS
