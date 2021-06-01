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

#include "ohos_rpc_message_parcel.h"
#include <unistd.h>
#include <securec.h>
#include "ipc_debug.h"
#include "jni_helper.h"
#include "ohos_utils_parcel.h"
#include "ohos_rpc_remote_object.h"
#include "ipc_file_descriptor.h"
#include "log_tags.h"
#include "jkit_utils.h"
#include <ashmem.h>

using namespace OHOS;
using namespace OHOS::HiviewDFX;

namespace OHOS {
struct JMessageParcel {
    jclass klazz;
    jfieldID nativeObject;
    jfieldID nativeObjectOwner;
} g_jMessageParcel;

static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "IPCJni" };

class AshmemSmartPointWrapper {
public:
    explicit AshmemSmartPointWrapper(const sptr<Ashmem> &ashmem) : ashmem_(ashmem)
    {
        if (ashmem == nullptr) {
            ZLOGE(LABEL, "%s: ashmem is null", __func__);
        }
    }
    ~AshmemSmartPointWrapper() = default;

    const sptr<Ashmem> &GetAshmem() const
    {
        return ashmem_;
    }

private:
    // make sure this is immutable
    sptr<Ashmem> const ashmem_;
};

/*
 * Get Native Message Parcel instance of zindaneos/rpc/MessageParcel
 */
MessageParcel *JavaOhosRpcMessageParcelGetNative(JNIEnv *env, jobject object)
{
    ZLOGI(LABEL, "%s", __func__);
    jlong nativeObject = env->GetLongField(object, g_jMessageParcel.nativeObject);
    return reinterpret_cast<MessageParcel *>(nativeObject);
}

sptr<Ashmem> Java_ohos_rpc_Ashmem_getSptrAshmem(JNIEnv *env, jobject object, jlong id)
{
    if (id == 0) {
        return nullptr;
    }
    AshmemSmartPointWrapper *wrapper = reinterpret_cast<AshmemSmartPointWrapper *>(id);
    return wrapper->GetAshmem();
}

static const JNINativeMethod sMethods[] = {
    /* Name, Signature, FunctionPointer */
    { "nativeNewObject", "(J)J", (void *)Java_ohos_rpc_MessageParcel_nativeNewObject },
    { "nativeFreeObject", "(J)V", (void *)Java_ohos_rpc_MessageParcel_nativeFreeObject },
    { "nativeWriteRemoteObject", "(Lohos/rpc/IRemoteObject;)Z",
      (void *)Java_ohos_rpc_MessageParcel_nativeWriteRemoteObject },
    { "nativeReadRemoteObject", "()Lohos/rpc/IRemoteObject;",
      (void *)Java_ohos_rpc_MessageParcel_nativeReadRemoteObject },
    { "nativeWriteFileDescriptor", "(Ljava/io/FileDescriptor;)Z",
      (void *)Java_ohos_rpc_MessageParcel_nativeWriteFileDescriptor },
    { "nativeReadFileDescriptor", "()Ljava/io/FileDescriptor;",
      (void *)Java_ohos_rpc_MessageParcel_nativeReadFileDescriptor },
    { "nativeWriteInterfaceToken", "(Ljava/lang/String;I)Z",
      (void *)Java_ohos_rpc_MessageParcel_nativeWriteInterfaceToken },
    { "nativeReadInterfaceToken", "()Ljava/lang/String;",
      (void *)Java_ohos_rpc_MessageParcel_nativeReadInterfaceToken },
    { "nativeWriteRawData", "([BI)Z", (void *)Java_ohos_rpc_MessageParcel_nativeWriteRawData },
    { "nativeReadRawData", "(I)[B", (void *)Java_ohos_rpc_MessageParcel_nativeReadRawData },
    { "nativeGetRawDataCapacity", "()I", (void *)Java_ohos_rpc_MessageParcel_nativeGetRawDataCapacity },
    { "nativeCloseFileDescriptor", "(Ljava/io/FileDescriptor;)V",
      (void *)Java_ohos_rpc_MessageParcel_nativeCloseFileDescriptor },
    { "nativeDupFileDescriptor", "(Ljava/io/FileDescriptor;)Ljava/io/FileDescriptor;",
      (void *)Java_ohos_rpc_MessageParcel_nativeDupFileDescriptor },
    { "nativeContainFileDescriptors", "()Z", (void *)Java_ohos_rpc_MessageParcel_nativeContainFileDescriptors },
    { "nativeWriteAshmem", "(J)Z", (void *)Java_ohos_rpc_MessageParcel_nativeWriteAshmem },
    { "nativeReadAshmem", "()J", (void *)Java_ohos_rpc_MessageParcel_nativeReadAshmem },
    { "nativeReleaseAshmem", "(J)V", (void *)Java_ohos_rpc_MessageParcel_nativeReleaseAshmem },
};

/*
 * register native methods fopr ohos.rpc.MessageParcel.
 */
int JavaOhosRpcMessageParcelRegisterNativeMethods(JNIEnv *env)
{
    ZLOGI(LABEL, "%s", __func__);
    jclass klazz = (jclass)env->NewGlobalRef(env->FindClass("ohos/rpc/MessageParcel"));
    if (klazz == nullptr) {
        ZLOGE(LABEL, "could not find class for MessageParcel");
        return -1;
    }
    g_jMessageParcel.klazz = (jclass)env->NewGlobalRef(klazz);
    g_jMessageParcel.nativeObject = env->GetFieldID(g_jMessageParcel.klazz, "mNativeObject", "J");
    if (g_jMessageParcel.nativeObject == nullptr) {
        ZLOGE(LABEL, "could not Get mNativeObject field for MessageParcel");
        if (g_jMessageParcel.klazz != nullptr) {
            env->DeleteGlobalRef(g_jMessageParcel.klazz);
        }
        env->DeleteGlobalRef(klazz);
        return -1;
    }
    g_jMessageParcel.nativeObjectOwner = env->GetFieldID(g_jMessageParcel.klazz, "mOwnsNativeObject", "Z");
    if (g_jMessageParcel.nativeObjectOwner == nullptr) {
        ZLOGE(LABEL, "could not Get mOwnsNativeObject field for MessageParcel");
        if (g_jMessageParcel.klazz != nullptr) {
            env->DeleteGlobalRef(g_jMessageParcel.klazz);
        }
        env->DeleteGlobalRef(klazz);
        return -1;
    }
    return JkitRegisterNativeMethods(env, "ohos/rpc/MessageParcel", sMethods, NUM_METHODS(sMethods));
}
} // namespace OHOS

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeWriteRemoteObject
 * Signature: (Lohos/rpc/IRemoteObject;)Z
 */
jboolean JNICALL Java_ohos_rpc_MessageParcel_nativeWriteRemoteObject(JNIEnv *env, jobject parcel, jobject object)
{
    ZLOGI(LABEL, "%s", __func__);
    MessageParcel *nativeParcel = JavaOhosRpcMessageParcelGetNative(env, parcel);
    if (nativeParcel == nullptr) {
        ZLOGE(LABEL, "could not get native parcel for marshalling");
        return JNI_FALSE;
    }

    sptr<IRemoteObject> target = Java_ohos_rpc_getNativeRemoteObject(env, object);
    if (target != nullptr) {
        if (nativeParcel->WriteRemoteObject(target)) {
            return JNI_TRUE;
        }
    }
    return JNI_FALSE;
}

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeReadRemoteObject
 * Signature: ()Lohos/rpc/IRemoteObject;
 */
jobject JNICALL Java_ohos_rpc_MessageParcel_nativeReadRemoteObject(JNIEnv *env, jobject object)
{
    ZLOGI(LABEL, "%s", __func__);
    MessageParcel *nativeParcel = JavaOhosRpcMessageParcelGetNative(env, object);
    if (nativeParcel == nullptr) {
        ZLOGE(LABEL, "could not get native parcel for unmarshalling");
        return nullptr;
    }

    return Java_ohos_rpc_getJavaRemoteObject(env, nativeParcel->ReadRemoteObject());
}

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeWriteFileDescriptor
 * Signature: (Ljava/io/FileDescriptor;)Z
 */
jboolean JNICALL Java_ohos_rpc_MessageParcel_nativeWriteFileDescriptor(JNIEnv *env, jobject object, jobject descriptor)
{
    ZLOGI(LABEL, "%s", __func__);
    MessageParcel *nativeParcel = JavaOhosRpcMessageParcelGetNative(env, object);
    if (nativeParcel == nullptr) {
        ZLOGE(LABEL, "could not get native parcel for marshalling");
        return JNI_FALSE;
    }

    int fd = JniHelperJavaIoGetFdFromFileDescriptor(env, descriptor);
    return fd > 0 ? nativeParcel->WriteFileDescriptor(fd) : JNI_FALSE;
}

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeReadFileDescriptor
 * Signature: ()Ljava/io/FileDescriptor;
 */
jobject JNICALL Java_ohos_rpc_MessageParcel_nativeReadFileDescriptor(JNIEnv *env, jobject object)
{
    ZLOGI(LABEL, "%s", __func__);
    MessageParcel *nativeParcel = JavaOhosRpcMessageParcelGetNative(env, object);
    if (nativeParcel == nullptr) {
        ZLOGE(LABEL, "unable to get native parcel");
        return nullptr;
    }

    int fd = nativeParcel->ReadFileDescriptor();
    if (fd != INVALID_FD) {
        return JniHelperJavaIoCreateFileDescriptor(env, fd);
    }

    ZLOGE(LABEL, "Got invalid fd from parcel");
    return nullptr;
}

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeContainFileDescriptors
 * Signature: ()Z;
 */
jboolean JNICALL Java_ohos_rpc_MessageParcel_nativeContainFileDescriptors(JNIEnv *env, jobject object)
{
    ZLOGI(LABEL, "%s", __func__);
    MessageParcel *nativeParcel = JavaOhosRpcMessageParcelGetNative(env, object);
    if (nativeParcel == nullptr) {
        ZLOGE(LABEL, "unable to get native parcel");
        return JNI_FALSE;
    }

    bool result = nativeParcel->ContainFileDescriptors();
    return result ? JNI_TRUE : JNI_FALSE;
}

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeWriteInterfaceToken
 * Signature: (Ljava/lang/String;I)Z
 */
jboolean JNICALL Java_ohos_rpc_MessageParcel_nativeWriteInterfaceToken(JNIEnv *env, jobject object, jstring name,
    jint len)
{
    ZLOGI(LABEL, "%s", __func__);
    MessageParcel *nativeParcel = JavaOhosRpcMessageParcelGetNative(env, object);
    if (nativeParcel == nullptr) {
        ZLOGE(LABEL, "could not get native parcel for marshalling");
        return JNI_FALSE;
    }

    bool result = false;
    const jchar *u16chars = env->GetStringCritical(name, 0);
    if (u16chars != nullptr) {
        const auto *u16Str = reinterpret_cast<const char16_t *>(u16chars);
        result = nativeParcel->WriteInterfaceToken(std::u16string(u16Str, len));
        env->ReleaseStringCritical(name, u16chars);
    }

    return result ? JNI_TRUE : JNI_FALSE;
}

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeReadInterfaceToken
 * Signature: ()Ljava/lang/String;
 */
jobject JNICALL Java_ohos_rpc_MessageParcel_nativeReadInterfaceToken(JNIEnv *env, jobject object)
{
    ZLOGI(LABEL, "%s", __func__);
    MessageParcel *nativeParcel = JavaOhosRpcMessageParcelGetNative(env, object);
    if (nativeParcel == nullptr) {
        ZLOGE(LABEL, "could not get native parcel for marshalling");
        return JNI_FALSE;
    }

    std::u16string name = nativeParcel->ReadInterfaceToken();
    return env->NewString(reinterpret_cast<const jchar *>(name.data()), name.size());
}

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeWriteRawData
 * Signature: ([BI)Z
 */
jboolean JNICALL Java_ohos_rpc_MessageParcel_nativeWriteRawData(JNIEnv *env, jobject object, jobject rawData, jint size)
{
    MessageParcel *nativeParcel = JavaOhosRpcMessageParcelGetNative(env, object);
    if (nativeParcel == nullptr) {
        ZLOGE(LABEL, "could not get native parcel for raw data");
        return JNI_FALSE;
    }

    jbyte *ptr = static_cast<jbyte *>(env->GetPrimitiveArrayCritical(static_cast<jarray>(rawData), 0));
    if (ptr == nullptr) {
        return JNI_FALSE;
    }
    bool result = nativeParcel->WriteRawData(ptr, size);
    env->ReleasePrimitiveArrayCritical(static_cast<jarray>(rawData), ptr, 0);
    return result ? JNI_TRUE : JNI_FALSE;
}

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeReadRawData
 * Signature: (I)[B
 */
jbyteArray JNICALL Java_ohos_rpc_MessageParcel_nativeReadRawData(JNIEnv *env, jobject object, jint size)
{
    MessageParcel *nativeParcel = JavaOhosRpcMessageParcelGetNative(env, object);
    if (nativeParcel == nullptr) {
        ZLOGE(LABEL, "could not get native parcel for rawData");
        return nullptr;
    }

    const void *rawData = nativeParcel->ReadRawData(size);
    if (rawData == nullptr) {
        ZLOGE(LABEL, "read raw data failed");
        return nullptr;
    }
    jbyteArray bytes = env->NewByteArray(size);
    if (bytes == nullptr) {
        ZLOGE(LABEL, "NewByteArray failed");
        return nullptr;
    }
    jbyte *ptr = static_cast<jbyte *>(env->GetPrimitiveArrayCritical(bytes, 0));
    if (ptr != nullptr) {
        int result = memcpy_s(ptr, size, rawData, size);
        env->ReleasePrimitiveArrayCritical(bytes, ptr, 0);
        if (result != 0) {
            ZLOGE(LABEL, "copy raw data failed");
            env->DeleteLocalRef(bytes);
            return nullptr;
        }
    }
    return bytes;
}


/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeGetRawDataCapacity
 * Signature: ()I;
 */
jint JNICALL Java_ohos_rpc_MessageParcel_nativeGetRawDataCapacity(JNIEnv *env, jobject object)
{
    MessageParcel *nativeParcel = JavaOhosRpcMessageParcelGetNative(env, object);
    if (nativeParcel == nullptr) {
        ZLOGE(LABEL, "could not get native parcel for rawData");
        return 0;
    }

    return static_cast<jint>(nativeParcel->GetRawDataCapacity());
}

/*
 * Set mOwnsNativeObject filed to ohos.rpc.MessageParcel
 */
void JavaOhosRpcMessageOptionSetNativeObjectOwner(JNIEnv *env, jobject object, jboolean value)
{
    ZLOGI(LABEL, "%s", __func__);
    env->SetBooleanField(object, g_jMessageParcel.nativeObjectOwner, value);
}

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeNewObject
 * Signature: (J)J;
 */
jlong JNICALL Java_ohos_rpc_MessageParcel_nativeNewObject(JNIEnv *env, jobject object, jlong nativeObject)
{
    ZLOGI(LABEL, "%s", __func__);
    MessageParcel *nativeMessageParcel = nullptr;
    if (nativeObject != 0) {
        nativeMessageParcel = reinterpret_cast<MessageParcel *>(nativeObject);
        JavaOhosRpcMessageOptionSetNativeObjectOwner(env, object, JNI_FALSE);
    } else {
        JavaOhosRpcMessageOptionSetNativeObjectOwner(env, object, JNI_TRUE);
        nativeMessageParcel = new MessageParcel();
    }

    if (nativeMessageParcel == nullptr) {
        return 0L;
    }
    jclass superClass = env->GetSuperclass(g_jMessageParcel.klazz);
    if (superClass == nullptr) {
        ZLOGE(LABEL, "get supper class for MessageParcel failed");
        delete nativeMessageParcel;
        return 0L;
    }

    jmethodID superInit = env->GetMethodID(superClass, "<init>", "(J)V");
    if (superInit == nullptr) {
        ZLOGE(LABEL, "get supper method for MessageParcel failed");
        delete nativeMessageParcel;
        return 0L;
    }
    Parcel *nativeParcel = static_cast<Parcel *>(nativeMessageParcel);
    ZLOGI(LABEL, "intSuperClass's native holder:%s", __func__);
    env->CallNonvirtualVoidMethod(object, superClass, superInit, reinterpret_cast<jlong>(nativeParcel));

    return reinterpret_cast<jlong>(nativeMessageParcel);
}

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeFreeObject
 * Signature: (J)V;
 */
void JNICALL Java_ohos_rpc_MessageParcel_nativeFreeObject(JNIEnv *env, jobject object, jlong nativeObject)
{
    ZLOGI(LABEL, "%s", __func__);
    std::unique_ptr<MessageParcel> nativeParcel(reinterpret_cast<MessageParcel *>(nativeObject));
}

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeCloseFileDescriptor
 * Signature: (Ljava/io/FileDescriptor;)V
 */
void JNICALL Java_ohos_rpc_MessageParcel_nativeCloseFileDescriptor(JNIEnv *env, jobject object, jobject descriptor)
{
    ZLOGI(LABEL, "%s", __func__);
    if (descriptor != nullptr) {
        int fd = JniHelperJavaIoGetFdFromFileDescriptor(env, descriptor);
        if (fd != INVALID_FD) {
            close(fd);
            JniHelperJavaIoSetFdToFileDescriptor(env, descriptor, INVALID_FD);
        }
    }
}

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeDupFileDescriptor
 * Signature: (Ljava/io/FileDescriptor;)Ljava/io/FileDescriptor;
 */
jobject JNICALL Java_ohos_rpc_MessageParcel_nativeDupFileDescriptor(JNIEnv *env, jobject object, jobject descriptor)
{
    ZLOGI(LABEL, "%s", __func__);
    if (descriptor != nullptr) {
        int fd = JniHelperJavaIoGetFdFromFileDescriptor(env, descriptor);
        int dupFd = INVALID_FD;
        if (fd != INVALID_FD) {
            dupFd = dup(fd);
        }
        if (dupFd != INVALID_FD) {
            return JniHelperJavaIoCreateFileDescriptor(env, dupFd);
        }
    }
    return nullptr;
}

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeWriteAshmem
 * Signature: (J)Z
 */
jboolean JNICALL Java_ohos_rpc_MessageParcel_nativeWriteAshmem(JNIEnv *env, jobject object, jlong id)
{
    ZLOGI(LABEL, "%s", __func__);
    MessageParcel *nativeParcel = JavaOhosRpcMessageParcelGetNative(env, object);
    if (nativeParcel == nullptr) {
        ZLOGE(LABEL, "could not get native parcel for raw data");
        return JNI_FALSE;
    }

    sptr<Ashmem> ashmem = Java_ohos_rpc_Ashmem_getSptrAshmem(env, object, id);
    if (ashmem == nullptr) {
        ZLOGE(LABEL, "%s: ashmem=null", __func__);
        return JNI_FALSE;
    }

    bool result = nativeParcel->WriteAshmem(ashmem);
    return result ? JNI_TRUE : JNI_FALSE;
}

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeReadAshmem
 * Signature: (V)J
 */
jlong JNICALL Java_ohos_rpc_MessageParcel_nativeReadAshmem(JNIEnv *env, jobject object)
{
    ZLOGI(LABEL, "%s", __func__);
    MessageParcel *nativeParcel = JavaOhosRpcMessageParcelGetNative(env, object);
    if (nativeParcel == nullptr) {
        ZLOGE(LABEL, "could not get native parcel for rawData");
        return 0;
    }

    sptr<Ashmem> nativeAshmem = nativeParcel->ReadAshmem();
    if (nativeAshmem == nullptr) {
        ZLOGE(LABEL, "read raw data failed");
        return 0;
    }

    // memory is released in Java_ohos_rpc_MessageParcel_nativeReleaseAshmem
    AshmemSmartPointWrapper *wrapper = new AshmemSmartPointWrapper(nativeAshmem);
    return reinterpret_cast<jlong>(wrapper);
}

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeReleaseAshmem
 * Signature: (J)V
 */
void JNICALL Java_ohos_rpc_MessageParcel_nativeReleaseAshmem(JNIEnv *env, jobject object, jlong id)
{
    ZLOGI(LABEL, "%s", __func__);
    if (id == 0) {
        return;
    }
    std::unique_ptr<AshmemSmartPointWrapper> nativeParcel(reinterpret_cast<AshmemSmartPointWrapper *>(id));
}
