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

#include "ohos_rpc_remote_object.h"
#include <mutex>
#include <set>
#include "ipc_debug.h"
#include "jni_helper.h"
#include "ohos_utils_parcel.h"
#include "ohos_rpc_message_option.h"
#include "ohos_rpc_message_parcel.h"
#include "ipc_object_stub.h"
#include "ipc_object_proxy.h"
#include "ipc_thread_skeleton.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "log_tags.h"
#include "jkit_utils.h"

using namespace OHOS;
using namespace OHOS::HiviewDFX;

namespace OHOS {
static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "IPCJni" };

class JDeathRecipientList;
class JRemoteObjectHolder;
struct JRemoteObjectDesc {
    jclass klass;
    jmethodID methodDispatchRequest;
    jfieldID fieldNativeHolder;
    jmethodID methodDispatchDump;
};

struct JRemoteProxyDesc {
    jclass klass;
    jmethodID methodGetInstance;
    jmethodID methodSendObituary;
    jfieldID fieldNativeData;
};

class JRemoteProxyHolder {
public:
    JRemoteProxyHolder();
    ~JRemoteProxyHolder();
    sptr<JDeathRecipientList> list_;
    sptr<IRemoteObject> object_;
};
/*
 * the native RemoteObject act as bridger between java and native.
 * It received the request from client and pass it Java Layer.
 */
class JRemoteObject : public IPCObjectStub {
public:
    JRemoteObject(jobject object, const std::u16string &descriptor);

    ~JRemoteObject() override;

    bool CheckObjectLegality() const override;

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    int OnRemoteDump(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    jobject GetJObject() const;

private:
    jobject object_;
};

/*
 * To ensure a better consistency of the life time of
 * Java IPC Object and native object we designed
 * a container to save the native object.
 */
class JRemoteObjectHolder : public RefBase {
public:
    explicit JRemoteObjectHolder(const std::u16string &descriptor);
    ~JRemoteObjectHolder();
    sptr<JRemoteObject> Get(jobject object);

private:
    std::mutex mutex_;
    std::u16string descriptor_;
    sptr<JRemoteObject> cachedObject_;
};

/*
 * the native DeathRecipient container.
 * As an recipient of Obituary of service death.
 * and pass the message to Java Layer.
 */
class JDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit JDeathRecipient(jobject object);

    void OnRemoteDied(const wptr<IRemoteObject> &object) override;

    bool Matches(jobject object);

protected:
    virtual ~JDeathRecipient();

private:
    std::mutex mutex_;
    jobject refObject_;
    jweak weakRefObject_ {};
};

/*
 * the native DeathRecipient container
 */
class JDeathRecipientList : public RefBase {
    std::set<sptr<JDeathRecipient>> set_;
    std::mutex mutex_;

public:
    JDeathRecipientList();

    ~JDeathRecipientList();

    bool Add(const sptr<JDeathRecipient> &recipient);

    bool Remove(const sptr<JDeathRecipient> &recipient);

    sptr<JDeathRecipient> Find(jobject recipient);
};

// Global variable definition.
static JRemoteProxyHolder *g_cachedProxyHolder;
static struct JRemoteObjectDesc g_jRemoteStub;
static struct JRemoteProxyDesc g_jRemoteProxy;
static std::mutex g_proxyMutex_;
static bool g_ipcNativeMethodsLoaded = false;

JRemoteObject::JRemoteObject(jobject object, const std::u16string &descriptor) : IPCObjectStub(descriptor)
{
    JNIEnvHelper env;
    if (env.Get() != nullptr && object != nullptr) {
        object_ = env->NewGlobalRef(object);
    } else {
        object_ = nullptr;
    }
}

bool JRemoteObject::CheckObjectLegality() const
{
    return true;
}

JRemoteObject::~JRemoteObject()
{
    JNIEnvHelper env;
    if (env.Get() != nullptr && object_ != nullptr) {
        env->DeleteGlobalRef(object_);
    }
}

jobject JRemoteObject::GetJObject() const
{
    return object_;
}

int JRemoteObject::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    JNIEnvHelper env;
    if (env.Get() == nullptr) {
        return ERR_TRANSACTION_FAILED;
    }

    if (code == DUMP_TRANSACTION) {
        ZLOGE(LABEL, "DUMP_TRANSACTION data size:%zu", data.GetReadableBytes());
    }

    jobject javaOption = JavaOhosRpcMessageOptionNewJavaObject(env.Get(), option.GetFlags(), option.GetWaitTime());
    jboolean res = env->CallBooleanMethod(object_, g_jRemoteStub.methodDispatchRequest, code,
        reinterpret_cast<jlong>(&data), reinterpret_cast<jlong>(&reply), javaOption);

    env->DeleteLocalRef(javaOption);
    if (JniHelperCheckAndClearLocalException(env.Get())) {
        ZLOGE(LABEL, "OnRemoteRequest found exception, res:%{public}d", res);
        return ERR_UNKNOWN_TRANSACTION;
    }
    if (code == SYSPROPS_TRANSACTION) {
        int result = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        if (result != ERR_NONE) {
            ZLOGE(LABEL, "OnRemoteRequest res:%{public}d", result);
            return ERR_INVALID_DATA;
        }
    }
    if (!res) {
        ZLOGE(LABEL, "OnRemoteRequest res:%{public}d", res);
        return ERR_UNKNOWN_TRANSACTION;
    }
    return ERR_NONE;
}

int JRemoteObject::OnRemoteDump(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    JNIEnvHelper env;
    if (env.Get() == nullptr) {
        return ERR_TRANSACTION_FAILED;
    }

    jobject javaOption = JavaOhosRpcMessageOptionNewJavaObject(env.Get(), option.GetFlags(), option.GetWaitTime());
    jboolean res = env->CallBooleanMethod(object_, g_jRemoteStub.methodDispatchDump, code,
        reinterpret_cast<jlong>(&data), reinterpret_cast<jlong>(&reply), javaOption);

    if (JniHelperCheckAndClearLocalException(env.Get())) {
        res = JNI_FALSE;
    }
    env->DeleteLocalRef(javaOption);
    ZLOGI(LABEL, "OnRemoteDump res:%d", res);
    return res ? ERR_NONE : ERR_UNKNOWN_TRANSACTION;
}

JRemoteObjectHolder::JRemoteObjectHolder(const std::u16string &descriptor)
    : descriptor_(descriptor), cachedObject_(nullptr)
{}

JRemoteObjectHolder::~JRemoteObjectHolder()
{
    // free the reference of object.
    cachedObject_ = nullptr;
}

sptr<JRemoteObject> JRemoteObjectHolder::Get(jobject object)
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    // grab an strong reference to the object,
    // so it will not be freed util this reference released.
    sptr<JRemoteObject> remoteObject = nullptr;
    if (cachedObject_ != nullptr) {
        remoteObject = cachedObject_;
    }

    if (remoteObject == nullptr) {
        remoteObject = new JRemoteObject(object, descriptor_);
        cachedObject_ = remoteObject;
    }
    return remoteObject;
}

JRemoteProxyHolder::JRemoteProxyHolder() : list_(nullptr), object_(nullptr) {}

JRemoteProxyHolder::~JRemoteProxyHolder()
{
    list_ = nullptr;
    object_ = nullptr;
}

JDeathRecipient::JDeathRecipient(jobject object)
{
    JNIEnvHelper env;
    if (env.Get() != nullptr) {
        refObject_ = env->NewGlobalRef(object);
    } else {
        refObject_ = nullptr;
    }
}

void JDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    ZLOGI(LABEL, "OnRemoteDied called");
    if (refObject_ == nullptr) {
        ZLOGE(LABEL, "Object has already removed");
        return;
    }

    JNIEnvHelper env;
    if (env.Get() == nullptr) {
        return;
    }

    env->CallStaticVoidMethod(g_jRemoteProxy.klass, g_jRemoteProxy.methodSendObituary, refObject_);
    JniHelperCheckAndClearLocalException(env.Get());

    weakRefObject_ = env->NewWeakGlobalRef(refObject_);
    env->DeleteGlobalRef(refObject_);
    std::lock_guard<std::mutex> lockGuard(mutex_);
    refObject_ = nullptr;
}

bool JDeathRecipient::Matches(jobject object)
{
    JNIEnvHelper env;
    if (env.Get() == nullptr) {
        return false;
    }

    bool result = false;
    if (object != nullptr) {
        std::lock_guard<std::mutex> lockGuard(mutex_);
        if (refObject_ != nullptr) {
            result = env->IsSameObject(object, refObject_);
        }
    } else {
        if (weakRefObject_ == nullptr) {
            return false;
        }
        jobject me = env->NewLocalRef(weakRefObject_);
        result = env->IsSameObject(object, me);
        env->DeleteLocalRef(me);
    }
    return result;
}

JDeathRecipient::~JDeathRecipient()
{
    JNIEnvHelper env;

    if (env.Get() != nullptr) {
        if (refObject_ != nullptr) {
            env->DeleteGlobalRef(refObject_);
        } else {
            if (weakRefObject_ != nullptr) {
                env->DeleteWeakGlobalRef(weakRefObject_);
            }
        }
    }
}

JDeathRecipientList::JDeathRecipientList() {}

JDeathRecipientList::~JDeathRecipientList()
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    set_.clear();
}

bool JDeathRecipientList::Add(const sptr<JDeathRecipient> &recipient)
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    auto ret = set_.insert(recipient);
    return ret.second;
}

bool JDeathRecipientList::Remove(const sptr<JDeathRecipient> &recipient)
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    return (set_.erase(recipient) > 0);
}

sptr<JDeathRecipient> JDeathRecipientList::Find(jobject recipient)
{
    std::lock_guard<std::mutex> lockGuard(mutex_);

    for (auto it = set_.begin(); it != set_.end(); it++) {
        if ((*it)->Matches(recipient)) {
            return *it;
        }
    }
    return nullptr;
}

JRemoteProxyHolder *Java_ohos_rpc_getRemoteProxyHolder(JNIEnv *env, jobject object)
{
    return reinterpret_cast<JRemoteProxyHolder *>(env->GetLongField(object, g_jRemoteProxy.fieldNativeData));
}

jobject Java_ohos_rpc_getJavaRemoteObject(JNIEnv *env, const sptr<IRemoteObject> target)
{
    ZLOGI(LABEL, "%s", __func__);
    if (target == nullptr) {
        ZLOGE(LABEL, "RemoteObject is null");
        return nullptr;
    }

    if (target->CheckObjectLegality()) {
        ZLOGI(LABEL, "native Get RemoteObject");
        auto object = static_cast<JRemoteObject *>(target.GetRefPtr());
        return object->GetJObject();
    }

    std::lock_guard<std::mutex> lockGuard(g_proxyMutex_);
    JRemoteProxyHolder *cachedHolder = g_cachedProxyHolder;
    if (cachedHolder == nullptr) {
        cachedHolder = new JRemoteProxyHolder();
    }

    jobject object = env->CallStaticObjectMethod(g_jRemoteProxy.klass, g_jRemoteProxy.methodGetInstance,
        reinterpret_cast<jlong>(cachedHolder));

    if (JniHelperCheckAndClearLocalException(env)) {
        if (g_cachedProxyHolder == nullptr) {
            delete cachedHolder;
        }
        return nullptr;
    }

    JRemoteProxyHolder *objectHolder = Java_ohos_rpc_getRemoteProxyHolder(env, object);
    // If the objects holder is same as the cached holder it should be a new create holder.
    if (cachedHolder == objectHolder) {
        objectHolder->object_ = target;
        objectHolder->list_ = new JDeathRecipientList();
        g_cachedProxyHolder = nullptr;
    } else {
        g_cachedProxyHolder = cachedHolder;
    }
    return object;
}

sptr<IRemoteObject> Java_ohos_rpc_getNativeRemoteObject(JNIEnv *env, jobject object)
{
    ZLOGI(LABEL, "%s", __func__);
    if (object != nullptr) {
        if (env->IsInstanceOf(object, g_jRemoteStub.klass)) {
            JRemoteObjectHolder *holder =
                reinterpret_cast<JRemoteObjectHolder *>(env->GetLongField(object, g_jRemoteStub.fieldNativeHolder));
            return holder != nullptr ? holder->Get(object) : nullptr;
        }

        if (env->IsInstanceOf(object, g_jRemoteProxy.klass)) {
            JRemoteProxyHolder *holder = Java_ohos_rpc_getRemoteProxyHolder(env, object);
            return holder != nullptr ? holder->object_ : nullptr;
        }
    }
    return nullptr;
}
} // namespace OHOS

/*
 * Class:     ohos.rpc.IPCSkeleton
 * Method:    nativeGetContextObject
 * Signature: ()Lohos/rpc/IRemoteObject;
 */
jobject JNICALL Java_ohos_rpc_IPCSkeleton_nativeGetContextObject(JNIEnv *env, jclass clazz)
{
    ZLOGI(LABEL, "%s", __func__);
    sptr<IRemoteObject> object = IPCSkeleton::GetContextObject();
    if (object == nullptr) {
        ZLOGE(LABEL, "fatal error, could not get registry object");
        return nullptr;
    }
    return Java_ohos_rpc_getJavaRemoteObject(env, object);
}

/*
 * Class:     ohos.rpc.IPCSkeleton
 * Method:    nativeGetCallingPid
 * Signature: ()I;
 */
jint JNICALL Java_ohos_rpc_IPCSkeleton_nativeGetCallingPid(JNIEnv *env, jclass clazz)
{
    pid_t pid = IPCSkeleton::GetCallingPid();
    return static_cast<jint>(pid);
}

/*
 * Class:     ohos.rpc.IPCSkeleton
 * Method:    nativeGetCallingUid
 * Signature: ()I;
 */
jint JNICALL Java_ohos_rpc_IPCSkeleton_nativeGetCallingUid(JNIEnv *env, jclass clazz)
{
    uid_t uid = IPCSkeleton::GetCallingUid();
    return static_cast<jint>(uid);
}

/*
 * Class:     ohos.rpc.IPCSkeleton
 * Method:    nativeGetCallingDeviceID
 * Signature: (V)Ljava/lang/String;
 */
jstring JNICALL Java_ohos_rpc_IPCSkeleton_nativeGetCallingDeviceID(JNIEnv *env, jclass clazz)
{
    std::string deviceId = IPCSkeleton::GetCallingDeviceID();
    return env->NewStringUTF(deviceId.c_str());
}

/*
 * Class:     ohos.rpc.IPCSkeleton
 * Method:    nativeGetLocalDeviceID
 * Signature: (V)Ljava/lang/String;
 */
jstring JNICALL Java_ohos_rpc_IPCSkeleton_nativeGetLocalDeviceID(JNIEnv *env, jclass clazz)
{
    std::string deviceId = IPCSkeleton::GetLocalDeviceID();
    return env->NewStringUTF(deviceId.c_str());
}

/*
 * Class:     ohos.rpc.IPCSkeleton
 * Method:    nativeIsLocalCalling
 * Signature: ()Z;
 */
jboolean JNICALL Java_ohos_rpc_IPCSkeleton_nativeIsLocalCalling(JNIEnv *env, jclass clazz)
{
    return (IPCSkeleton::IsLocalCalling() == true) ? JNI_TRUE : JNI_FALSE;
}

/*
 * Class:     ohos.rpc.IPCSkeleton
 * Method:    nativeIsLocalCalling
 * Signature: (Lohos/rpc/IRemoteObject;)I;
 */
jint JNICALL Java_ohos_rpc_IPCSkeleton_nativeFlushCommands(JNIEnv *env, jclass clazz, jobject object)
{
    sptr<IRemoteObject> target = Java_ohos_rpc_getNativeRemoteObject(env, object);
    return static_cast<jint>(IPCSkeleton::FlushCommands(target));
}

/*
 * Class:     ohos.rpc.IPCSkeleton
 * Method:    nativeResetCallingIdentity
 * Signature: ()Ljava/lang/String;
 */
jstring JNICALL Java_ohos_rpc_IPCSkeleton_nativeResetCallingIdentity(JNIEnv *env, jclass clazz)
{
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    return env->NewStringUTF(identity.c_str());
}

/*
 * Class:     ohos.rpc.IPCSkeleton
 * Method:    nativeSetCallingIdentity
 * Signature: ((Ljava/lang/String;I)Z
 */
jboolean JNICALL Java_ohos_rpc_IPCSkeleton_nativeSetCallingIdentity(JNIEnv *env, jclass clazz, jstring identity,
    jint len)
{
    const char *identityUtf = env->GetStringUTFChars(identity, JNI_FALSE);

    if (identityUtf != nullptr) {
        std::string token = std::string(identityUtf, len);
        env->ReleaseStringUTFChars(identity, identityUtf);

        return (IPCSkeleton::SetCallingIdentity(token) == true) ? JNI_TRUE : JNI_FALSE;
    }

    return JNI_FALSE;
}

/*
 * Class:     ohos.rpc.RemoteObject
 * Method:    nativeGetObjectHolder
 * Signature: (Ljava/lang/String;I)J
 */
jlong JNICALL Java_ohos_rpc_RemoteObject_nativeGetObjectHolder(JNIEnv *env, jclass clazz, jstring value, jint len)
{
    std::u16string descriptor = std::u16string();
    if (value != nullptr) {
        const jchar *jcharStr = env->GetStringCritical(value, 0);
        if (jcharStr != nullptr) {
            descriptor.assign(reinterpret_cast<const char16_t *>(jcharStr), reinterpret_cast<int32_t>(len));
            env->ReleaseStringCritical(value, jcharStr);
        }
    }
    return (jlong)(new JRemoteObjectHolder(descriptor));
}

/*
 * Get calling pid from native.
 * Class:     ohos.rpc.RemoteObject
 * Method:    nativeGetCallingPid
 * Signature: ()I
 */
jint JNICALL Java_ohos_rpc_RemoteObject_nativeGetCallingPid(JNIEnv *env, jclass object)
{
    sptr<IRemoteObject> nativeObject = Java_ohos_rpc_getNativeRemoteObject(env, object);
    if ((nativeObject != nullptr) && (!nativeObject->IsProxyObject())) {
        IPCObjectStub *target = reinterpret_cast<IPCObjectStub *>(nativeObject.GetRefPtr());
        return target->GetCallingPid();
    }
    return getpid();
}

/*
 * Get calling uid from native.
 * Class:     ohos.rpc.RemoteObject
 * Method:    nativeGetCallingUid
 * Signature: ()I
 */
jint JNICALL Java_ohos_rpc_RemoteObject_nativeGetCallingUid(JNIEnv *env, jclass object)
{
    sptr<IRemoteObject> nativeObject = Java_ohos_rpc_getNativeRemoteObject(env, object);
    if ((nativeObject != nullptr) && (!nativeObject->IsProxyObject())) {
        IPCObjectStub *target = reinterpret_cast<IPCObjectStub *>(nativeObject.GetRefPtr());
        return target->GetCallingUid();
    }
    return getuid();
}

/*
 * Free local Object Holder of RemoteObject.
 * Class:     ohos.rpc.RemoteObject
 * Method:    nativeFreeObjectHolder
 * Signature: (J)V
 */
void JNICALL Java_ohos_rpc_RemoteObject_nativeFreeObjectHolder(JNIEnv *env, jclass clazz, jlong holder)
{
    // Delegate sptr to manage memory,
    // it will automatically release managed memory when the life cycle ends.
    ZLOGI(LABEL, "Call Free Object Holder");
    std::unique_ptr<JRemoteObjectHolder> nativeHolder(reinterpret_cast<JRemoteObjectHolder *>(holder));
}

/*
 * Free local Object Holder of RemoteObject.
 * Class:     ohos.rpc.RemoteProxy
 * Method:    nativeFreeProxyHolder
 * Signature: (J)V
 */
void JNICALL Java_ohos_rpc_RemoteProxy_nativeFreeProxyHolder(JNIEnv *env, jclass clazz, jlong holder)
{
    // Delegate sptr to manage memory,
    // it will automatically release managed memory when the life cycle ends.
    ZLOGI(LABEL, "Call Free Proxy Holder");
    std::unique_ptr<JRemoteProxyHolder> nativeHolder(reinterpret_cast<JRemoteProxyHolder *>(holder));
}

/*
 * Class:     ohos.rpc.RemoteProxy
 * Method:    nativeSendRequest
 * Signature: (ILohos/rpc/MessageParcel;Lohos/rpc/Parcel;Lohos/rpc/MessageOption;)Z
 */
jboolean JNICALL Java_ohos_rpc_RemoteProxy_nativeSendRequest(JNIEnv *env, jobject object, jint code, jobject data,
    jobject reply, jobject option)
{
    ZLOGI(LABEL, "%s", __func__);
    MessageParcel *nativeData = JavaOhosRpcMessageParcelGetNative(env, data);
    if (nativeData == nullptr) {
        JniHelperThrowNullPointerException(env, "data field is null");
        return JNI_FALSE;
    }

    MessageParcel *nativeReply = JavaOhosRpcMessageParcelGetNative(env, reply);
    if (nativeReply == nullptr) {
        ZLOGE(LABEL, "Fail to get native parcel for reply");
        return JNI_FALSE;
    }

    MessageOptionPtr nativeOption = JavaOhosRpcMessageOptionGetNative(env, option);
    if (nativeOption == nullptr) {
        ZLOGE(LABEL, "Fail to get native parcel for reply");
        return JNI_FALSE;
    }

    JRemoteProxyHolder *holder = Java_ohos_rpc_getRemoteProxyHolder(env, object);
    if (holder == nullptr) {
        JniHelperThrowIllegalStateException(env, "Proxy has been finalized!");
        return JNI_FALSE;
    }

    sptr<IRemoteObject> target = holder->object_;
    if (target == nullptr) {
        ZLOGE(LABEL, "Invalid proxy object");
        return JNI_FALSE;
    }

    int result = target->SendRequest(code, *nativeData, *nativeReply, *nativeOption.get());
    ZLOGI(LABEL, "nativeSendRequest result %d", result);

    return (result == ERR_NONE) ? JNI_TRUE : JNI_FALSE;
}

/*
 * Class:     ohos.rpc.RemoteProxy
 * Method:    nativeAddDeathRecipient
 * Signature: (Lohos/rpc/IRemoteObject$DeathRecipient;I)Z
 */
jboolean JNICALL Java_ohos_rpc_RemoteProxy_nativeAddDeathRecipient(JNIEnv *env, jobject object, jobject recipient,
    jint flags)
{
    if (recipient == nullptr) {
        JniHelperThrowNullPointerException(env, "the recipient is null");
        return JNI_FALSE;
    }

    JRemoteProxyHolder *holder = Java_ohos_rpc_getRemoteProxyHolder(env, object);
    if (holder == nullptr) {
        JniHelperThrowIllegalStateException(env, "Proxy has been finalized!");
        return JNI_FALSE;
    }

    sptr<IRemoteObject> target = holder->object_;
    if ((target == nullptr) || !target->IsProxyObject()) {
        ZLOGE(LABEL, "could not add recipient from invalid target");
        return JNI_FALSE;
    }

    sptr<JDeathRecipient> nativeRecipient = new JDeathRecipient(recipient);
    if (target->AddDeathRecipient(nativeRecipient)) {
        JDeathRecipientList *list = holder->list_;
        return (list->Add(nativeRecipient) ? JNI_TRUE : JNI_FALSE);
    }

    return JNI_FALSE;
}

/*
 * Class:     ohos.rpc.RemoteProxy
 * Method:    nativeRemoveDeathRecipient
 * Signature: (Lohos/rpc/IRemoteObject$DeathRecipient;I)Z
 */
jboolean JNICALL Java_ohos_rpc_RemoteProxy_nativeRemoveDeathRecipient(JNIEnv *env, jobject object, jobject recipient,
    jint flags)
{
    if (recipient == nullptr) {
        JniHelperThrowNullPointerException(env, "the recipient is null");
        return JNI_FALSE;
    }

    JRemoteProxyHolder *holder = Java_ohos_rpc_getRemoteProxyHolder(env, object);
    if (holder == nullptr) {
        JniHelperThrowIllegalStateException(env, "Proxy has been finalized!");
        return JNI_FALSE;
    }

    sptr<IRemoteObject> target = holder->object_;
    if ((target == nullptr) || !target->IsProxyObject()) {
        ZLOGE(LABEL, "could not remove recipient from invalid target");
        return JNI_FALSE;
    }

    // list should not be null here, it should be alloc at create proxy object.
    sptr<JDeathRecipientList> list = holder->list_;
    sptr<JDeathRecipient> nativeRecipient = list->Find(recipient);
    if (nativeRecipient == nullptr) {
        ZLOGE(LABEL, "recipient not found");
        return JNI_FALSE;
    }

    target->RemoveDeathRecipient(nativeRecipient);
    return (list->Remove(nativeRecipient) ? JNI_TRUE : JNI_FALSE);
}

/*
 * Class:     ohos.rpc.RemoteProxy
 * Method:    nativeGetInterfaceDescriptor
 * Signature: ()Ljava/lang/String;
 */
jstring JNICALL Java_ohos_rpc_RemoteProxy_nativeGetInterfaceDescriptor(JNIEnv *env, jobject object)
{
    JRemoteProxyHolder *holder = Java_ohos_rpc_getRemoteProxyHolder(env, object);
    if (holder == nullptr) {
        JniHelperThrowIllegalStateException(env, "Proxy has been finalized!");
        return env->NewStringUTF("");
    }

    IPCObjectProxy *target = reinterpret_cast<IPCObjectProxy *>(holder->object_.GetRefPtr());
    if (target == nullptr) {
        ZLOGE(LABEL, "Invalid proxy object");
        return env->NewStringUTF("");
    }
    std::u16string remoteDescriptor = target->GetInterfaceDescriptor();

    return env->NewStringUTF(Str16ToStr8(remoteDescriptor).c_str());
}

/*
 * Class:     ohos.rpc.RemoteProxy
 * Method:    nativeIsObjectDead
 * Signature: ()Z
 */
jboolean JNICALL Java_ohos_rpc_RemoteProxy_nativeIsObjectDead(JNIEnv *env, jobject object)
{
    JRemoteProxyHolder *holder = Java_ohos_rpc_getRemoteProxyHolder(env, object);
    if (holder == nullptr) {
        JniHelperThrowIllegalStateException(env, "Proxy has been finalized!");
        return JNI_TRUE;
    }

    IPCObjectProxy *target = reinterpret_cast<IPCObjectProxy *>(holder->object_.GetRefPtr());
    if (target == nullptr) {
        ZLOGE(LABEL, "Invalid proxy object");
        return JNI_TRUE;
    }

    return (target->IsObjectDead() == true) ? JNI_TRUE : JNI_FALSE;
}

/*
 * Class:     ohos.rpc.RemoteProxy
 * Method:    nativeGetHandle
 * Signature: ()J
 */
jlong JNICALL Java_ohos_rpc_RemoteProxy_nativeGetHandle(JNIEnv *env, jobject object)
{
    JRemoteProxyHolder *holder = Java_ohos_rpc_getRemoteProxyHolder(env, object);
    if (holder == nullptr) {
        JniHelperThrowIllegalStateException(env, "Proxy has been finalized!");
        return 0;
    }

    IPCObjectProxy *target = reinterpret_cast<IPCObjectProxy *>(holder->object_.GetRefPtr());
    if (target == nullptr) {
        ZLOGE(LABEL, "Invalid proxy object");
        return 0;
    }

    return (jlong)target->GetHandle();
}

static const JNINativeMethod sMethods[] = {
    /* Name, Signature, FunctionPointer */
    { "nativeGetContextObject", "()Lohos/rpc/IRemoteObject;",
      (void *)Java_ohos_rpc_IPCSkeleton_nativeGetContextObject },
    { "nativeGetCallingPid", "()I", (void *)Java_ohos_rpc_IPCSkeleton_nativeGetCallingPid },
    { "nativeGetCallingUid", "()I", (void *)Java_ohos_rpc_IPCSkeleton_nativeGetCallingUid },
    { "nativeGetCallingDeviceID", "()Ljava/lang/String;", (void *)Java_ohos_rpc_IPCSkeleton_nativeGetCallingDeviceID },
    { "nativeGetLocalDeviceID", "()Ljava/lang/String;", (void *)Java_ohos_rpc_IPCSkeleton_nativeGetLocalDeviceID },
    { "nativeIsLocalCalling", "()Z", (void *)Java_ohos_rpc_IPCSkeleton_nativeIsLocalCalling },
    { "nativeFlushCommands", "(Lohos/rpc/IRemoteObject;)I", (void *)Java_ohos_rpc_IPCSkeleton_nativeFlushCommands },
    { "nativeResetCallingIdentity", "()Ljava/lang/String;",
      (void *)Java_ohos_rpc_IPCSkeleton_nativeResetCallingIdentity },
    { "nativeSetCallingIdentity", "(Ljava/lang/String;I)Z",
      (void *)Java_ohos_rpc_IPCSkeleton_nativeSetCallingIdentity },
};

static const JNINativeMethod sObjectMethods[] = {
    /* Name, Signature, FunctionPointer */
    { "nativeGetObjectHolder", "(Ljava/lang/String;I)J", (void *)Java_ohos_rpc_RemoteObject_nativeGetObjectHolder },
    { "nativeFreeObjectHolder", "(J)V", (void *)Java_ohos_rpc_RemoteObject_nativeFreeObjectHolder },
    { "nativeGetCallingPid", "()I", (void *)Java_ohos_rpc_RemoteObject_nativeGetCallingPid },
    { "nativeGetCallingUid", "()I", (void *)Java_ohos_rpc_RemoteObject_nativeGetCallingUid },
};

static const JNINativeMethod sProxyMethods[] = {
    /* Name, Signature, FunctionPointer */
    { "nativeFreeProxyHolder", "(J)V", (void *)Java_ohos_rpc_RemoteProxy_nativeFreeProxyHolder },
    { "nativeGetInterfaceDescriptor", "()Ljava/lang/String;",
      (void *)Java_ohos_rpc_RemoteProxy_nativeGetInterfaceDescriptor },
    { "nativeSendRequest", "(ILohos/rpc/MessageParcel;Lohos/rpc/MessageParcel;Lohos/rpc/MessageOption;)Z",
      (void *)Java_ohos_rpc_RemoteProxy_nativeSendRequest },
    { "nativeAddDeathRecipient", "(Lohos/rpc/IRemoteObject$DeathRecipient;I)Z",
      (void *)Java_ohos_rpc_RemoteProxy_nativeAddDeathRecipient },
    { "nativeRemoveDeathRecipient", "(Lohos/rpc/IRemoteObject$DeathRecipient;I)Z",
      (void *)Java_ohos_rpc_RemoteProxy_nativeRemoveDeathRecipient },
    { "nativeIsObjectDead", "()Z", (void *)Java_ohos_rpc_RemoteProxy_nativeIsObjectDead },
    { "nativeGetHandle", "()J", (void *)Java_ohos_rpc_RemoteProxy_nativeGetHandle }
};

int JavaOhosRpcIpcSkeletonRegisterNativeMethods(JNIEnv *env)
{
    return JkitRegisterNativeMethods(env, "ohos/rpc/IPCSkeleton", sMethods, NUM_METHODS(sMethods));
}

int JavaOhosRpcRemoteObjectRegisterNativeMethods(JNIEnv *env)
{
    jclass clazz = env->FindClass("ohos/rpc/RemoteObject");
    if (clazz == nullptr) {
        ZLOGE(LABEL, "Could not find class:RemoteObject");
        return -1;
    }

    g_jRemoteStub.klass = (jclass)env->NewGlobalRef(clazz);
    if (g_jRemoteStub.klass == nullptr) {
        ZLOGE(LABEL, "JRemoteObject NewGlobalRef failed");
        return -1;
    }

    g_jRemoteStub.methodDispatchRequest = env->GetMethodID(clazz, "dispatchRequest", "(IJJLohos/rpc/MessageOption;)Z");
    if (g_jRemoteStub.methodDispatchRequest == nullptr) {
        ZLOGE(LABEL, "JRemoteObject get method execTransact failed");
        env->DeleteGlobalRef(g_jRemoteStub.klass);
        return -1;
    }

    g_jRemoteStub.methodDispatchDump = env->GetMethodID(clazz, "dispatchDump", "(IJJLohos/rpc/MessageOption;)Z");
    if (g_jRemoteStub.methodDispatchDump == nullptr) {
        ZLOGE(LABEL, "JRemoteObject get method execTransact failed");
        env->DeleteGlobalRef(g_jRemoteStub.klass);
        return -1;
    }

    g_jRemoteStub.fieldNativeHolder = env->GetFieldID(clazz, "mNativeHolder", "J");
    if (g_jRemoteStub.fieldNativeHolder == nullptr) {
        ZLOGE(LABEL, "JRemoteObject get field mNativeHolder failed");
        env->DeleteGlobalRef(g_jRemoteStub.klass);
        return -1;
    }

    return JkitRegisterNativeMethods(env, "ohos/rpc/RemoteObject", sObjectMethods, NUM_METHODS(sObjectMethods));
}

int JavaOhosRpcRemoteProxyRegisterNativeMethods(JNIEnv *env)
{
    jclass clazz = env->FindClass("ohos/rpc/RemoteProxy");
    if (clazz == nullptr) {
        ZLOGE(LABEL, "Could not find class:RemoteProxy");
        return -1;
    }

    g_jRemoteProxy.klass = (jclass)env->NewGlobalRef(clazz);
    g_jRemoteProxy.methodGetInstance = env->GetStaticMethodID(clazz, "getInstance", "(J)Lohos/rpc/RemoteProxy;");
    if (g_jRemoteProxy.methodGetInstance == nullptr) {
        ZLOGE(LABEL, "JRemoteProxy get method getInstance failed");
        env->DeleteGlobalRef(g_jRemoteProxy.klass);
        return -1;
    }

    g_jRemoteProxy.methodSendObituary =
        env->GetStaticMethodID(clazz, "sendObituary", "(Lohos/rpc/IRemoteObject$DeathRecipient;)V");
    if (g_jRemoteProxy.methodSendObituary == nullptr) {
        env->DeleteGlobalRef(g_jRemoteProxy.klass);
        ZLOGE(LABEL, "JRemoteProxy get method sendObituary failed");
        return -1;
    }

    g_jRemoteProxy.fieldNativeData = env->GetFieldID(clazz, "mNativeData", "J");
    if (g_jRemoteProxy.fieldNativeData == nullptr) {
        env->DeleteGlobalRef(g_jRemoteProxy.klass);
        ZLOGE(LABEL, "JRemoteProxy get field mNativeData failed");
        return -1;
    }

    return JkitRegisterNativeMethods(env, "ohos/rpc/RemoteProxy", sProxyMethods, NUM_METHODS(sProxyMethods));
}

int RegisterJavaRpcNativeMethods(JNIEnv *env)
{
    if (JniHelperRegisterNativeMethods(env) < 0) {
        ZLOGE(LABEL, "Register JniHelper Native Methods failed");
        return -1;
    }

    if (JavaOhosRpcMessageOptionRegisterNativeMethods(env) < 0) {
        ZLOGE(LABEL, "Register MessageOption Native Methods failed");
        return -1;
    }

    if (JavaOhosRpcMessageParcelRegisterNativeMethods(env) < 0) {
        ZLOGE(LABEL, "Register MessageParcel Native Methods failed");
        return -1;
    }

    if (JavaOhosRpcIpcSkeletonRegisterNativeMethods(env) < 0) {
        ZLOGE(LABEL, "Register IPCSkeleton Native Methods failed");
        return -1;
    }

    if (JavaOhosRpcRemoteObjectRegisterNativeMethods(env) < 0) {
        ZLOGE(LABEL, "Register JRemoteObject Native Methods failed");
        return -1;
    }

    if (JavaOhosRpcRemoteProxyRegisterNativeMethods(env) < 0) {
        ZLOGE(LABEL, "Register JRemoteProxy Native Methods failed");
        return -1;
    }

    if (Java_ohos_utils_Parcel_registerNativeMethods(env) < 0) {
        ZLOGE(LABEL, "Register JParcel Native Methods failed");
        return -1;
    }

    return 0;
}

jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    if (vm == nullptr) {
        return -1;
    }
    if (!g_ipcNativeMethodsLoaded) {
        JNIEnv *env = NULL;
        if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_4) != JNI_OK) {
            return -1;
        }

        if (RegisterJavaRpcNativeMethods(env) < 0) {
            return -1;
        }

        JNIEnvHelper::nativeInit(vm);
        g_ipcNativeMethodsLoaded = true;
    }
    return JNI_VERSION_1_4;
}
