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

#include "jni_helper.h"
#include "ipc_debug.h"
#include "jni_help.h"
#include "ohos_rpc_remote_object.h"
#include "log_tags.h"

namespace OHOS {
using namespace OHOS::HiviewDFX;

struct JFileDescriptor {
    jclass klazz;
    jmethodID fileDescriptorCtor;
    jfieldID descriptorField;
} g_jFileDescriptor;

static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "IPCJniHelper" };

JavaVM *JNIEnvHelper::javaVm_ = nullptr;
// The JavaVM is a representation of the virtual machine on the JNI layer,
// one process has only one JavaVM, and all the threads share a JavaVM.
// JNIEnv is in effect only on the thread that it is created,
// cannot be passed across threads, different threads are independent of each other.
// In order to implement cross-threading calls, we need to transform between JNIENV and JavaVM
JNIEnvHelper::JNIEnvHelper() : env_ { nullptr }, nativeThread_ { false }
{
    if (javaVm_->GetEnv(reinterpret_cast<void **>(&env_), JNI_VERSION_1_4) == JNI_EDETACHED) {
        javaVm_->AttachCurrentThread(reinterpret_cast<void **>(&env_), nullptr);
        nativeThread_ = true;
    }
}

void JNIEnvHelper::nativeInit(JavaVM *vm)
{
    if (javaVm_ != nullptr) {
        ZLOGE(LABEL, "Failed to init vm, javaVm_ has been initialized");
        return;
    }

    javaVm_ = vm;
}

JNIEnvHelper::~JNIEnvHelper()
{
    if (nativeThread_) {
        javaVm_->DetachCurrentThread();
    }
}

JNIEnv *JNIEnvHelper::Get()
{
    return env_;
}

JNIEnv *JNIEnvHelper::operator->()
{
    return env_;
}

void JniHelperThrowException(JNIEnv *env, const char *className, const char *msg)
{
    jclass clazz = env->FindClass(className);
    if (!clazz) {
        ZLOGE(LABEL, "Unable to find exception class %s", className);
        /* ClassNotFoundException now pending */
        return;
    }

    if (env->ThrowNew(clazz, msg) != JNI_OK) {
        ZLOGE(LABEL, "Failed throwing '%s' '%s'", className, msg);
        /* an exception, most likely OOM, will now be pending */
    }

    env->DeleteLocalRef(clazz);
}

void JniHelperThrowNullPointerException(JNIEnv *env, const char *msg)
{
    JniHelperThrowException(env, "java/lang/NullPointerException", msg);
}

void JniHelperThrowIllegalStateException(JNIEnv *env, const char *msg)
{
    JniHelperThrowException(env, "java/lang/IllegalStateException", msg);
}

/*
 * Get an int file descriptor from a java.io.FileDescriptor
 */
int JniHelperJavaIoGetFdFromFileDescriptor(JNIEnv *env, jobject fileDescriptor)
{
    return env->GetIntField(fileDescriptor, g_jFileDescriptor.descriptorField);
}

/*
 * Set the descriptor of a java.io.FileDescriptor
 */
void JniHelperJavaIoSetFdToFileDescriptor(JNIEnv *env, jobject fileDescriptor, int value)
{
    env->SetIntField(fileDescriptor, g_jFileDescriptor.descriptorField, value);
}

/*
 * JNI may throws exception when native code call java scenario.
 * we should convert local exception to native status code.
 * Check and clear local exception.
 */
jboolean JniHelperCheckAndClearLocalException(JNIEnv *env)
{
    jthrowable exception = env->ExceptionOccurred();
    if (exception != nullptr) {
        ZLOGE(LABEL, "clean up JNI local ref");
        // clean up JNI local ref -- we don't return to Java code
        env->ExceptionDescribe(); // for debug perpose.
        env->ExceptionClear();
        env->DeleteLocalRef(exception);
        return JNI_TRUE;
    }

    return JNI_FALSE;
}

/*
 * Create a java.io.FileDescriptor given an integer fd
 */
jobject JniHelperJavaIoCreateFileDescriptor(JNIEnv *env, int fd)
{
    jobject descriptor = env->NewObject(g_jFileDescriptor.klazz, g_jFileDescriptor.fileDescriptorCtor);
    JniHelperJavaIoSetFdToFileDescriptor(env, descriptor, fd);
    return descriptor;
}

int JniHelperRegisterNativeMethods(JNIEnv *env)
{
    g_jFileDescriptor.klazz = (jclass)env->NewGlobalRef(env->FindClass("java/io/FileDescriptor"));
    if (g_jFileDescriptor.klazz == nullptr) {
        return -1;
    }

    g_jFileDescriptor.fileDescriptorCtor = env->GetMethodID(g_jFileDescriptor.klazz, "<init>", "()V");
    if (g_jFileDescriptor.fileDescriptorCtor == nullptr) {
        env->DeleteGlobalRef(g_jFileDescriptor.klazz);
        return -1;
    }

    g_jFileDescriptor.descriptorField = env->GetFieldID(g_jFileDescriptor.klazz, "descriptor", "I");
    if (g_jFileDescriptor.descriptorField == nullptr) {
        env->DeleteGlobalRef(g_jFileDescriptor.klazz);
        return -1;
    }

    return 0;
}

jobject JNIHelperGetJavaRemoteObject(JNIEnv *env, const sptr<IRemoteObject> &target)
{
    if (env == nullptr) {
        return nullptr;
    }
    return Java_ohos_rpc_getJavaRemoteObject(env, target);
}
} // namespace OHOS
