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

#include "ohos_rpc_test_testhelper.h"
#include <codecvt>
#include "ipc_debug.h"
#include "jni_helper.h"
#include "ipc_test_helper.h"
#include "log_tags.h"

using namespace OHOS;
using namespace OHOS::HiviewDFX;
static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "IPCTestHelperJNI" };

static bool g_isTestHelperMethodRegistered = false;
static struct ParcelDesc {
    jclass klass;
    jfieldID fieldNativeInstance;
} g_jTestHelper;

/*
 * Class:     ohos_rpc_test_TestHelper
 * Method:    nativeNewInstance
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_ohos_rpc_test_TestHelper_nativeNewInstance(
    JNIEnv *env, jclass classz)
{
    IPCTestHelper *helper = new IPCTestHelper();
    return (jlong)helper;
}

/*
 * Class:     ohos_rpc_test_TestHelper
 * Method:    nativeFreeInstance
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_ohos_rpc_test_TestHelper_nativeFreeInstance(
    JNIEnv *env, jobject object, jlong instance)
{
    IPCTestHelper *nativeHolder = reinterpret_cast<IPCTestHelper *>(instance);
    delete nativeHolder;
}

/*
 * Class:     ohos_rpc_test_TestHelper
 * Method:    nativePrepareTestSuite
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_ohos_rpc_test_TestHelper_nativePrepareTestSuite(
    JNIEnv *env, jobject object)
{
    IPCTestHelper *helper = reinterpret_cast<IPCTestHelper *>(
        env->GetLongField(object, g_jTestHelper.fieldNativeInstance));

    if (helper != nullptr) {
        return (jboolean)helper->PrepareTestSuite();
    }

    return JNI_FALSE;
}

/*
 * Class:     ohos_rpc_test_TestHelper
 * Method:    nativeTearDownTestSuite
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_ohos_rpc_test_TestHelper_nativeTearDownTestSuite(
    JNIEnv *env, jobject object)
{
    IPCTestHelper *helper = reinterpret_cast<IPCTestHelper *>(
        env->GetLongField(object, g_jTestHelper.fieldNativeInstance));

    if (helper != nullptr) {
        return (jboolean)helper->TearDownTestSuite();
    }

    return JNI_FALSE;
}

/*
 * Class:     ohos_rpc_test_TestHelper
 * Method:    nativeStartTestServer
 * Signature: (I)Z
 */
JNIEXPORT jboolean JNICALL Java_ohos_rpc_test_TestHelper_nativeStartTestApp(
    JNIEnv *env, jobject object, jint appId, jint commandId)
{
    IPCTestHelper *helper = reinterpret_cast<IPCTestHelper *>(
        env->GetLongField(object, g_jTestHelper.fieldNativeInstance));

    if (helper == nullptr) {
        return JNI_FALSE;
    }

    return (jboolean)helper->StartTestApp(appId, commandId);
}

/*
 * Class:     ohos_rpc_test_TestHelper
 * Method:    StopTestApp
 * Signature: (I)Z
 */
JNIEXPORT jboolean JNICALL Java_ohos_rpc_test_TestHelper_nativeStopTestApp(
    JNIEnv *env, jobject object, jlong appId)
{
    IPCTestHelper *helper = reinterpret_cast<IPCTestHelper *>(
        env->GetLongField(object, g_jTestHelper.fieldNativeInstance));

    if (helper != nullptr) {
        return (jboolean)helper->StopTestApp(appId);
    }

    return JNI_FALSE;
}

/*
 * Class:     ohos_rpc_test_TestHelper
 * Method:    nativeGetTestServerPid
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_ohos_rpc_test_TestHelper_nativeGetTestAppPid(
    JNIEnv *env, jobject object, jint appId)
{
    jint pid = 0;
    IPCTestHelper *helper = reinterpret_cast<IPCTestHelper *>(
        env->GetLongField(object, g_jTestHelper.fieldNativeInstance));

    if (helper != nullptr) {
        pid = (jint)helper->GetTestAppPid(appId);
    }

    ZLOGI(LABEL, "nativeGetTestAppPid:%d", pid);
    return pid;
}

/*
 * Class:     ohos_rpc_test_TestHelper
 * Method:    nativeGetUid
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_ohos_rpc_test_TestHelper_nativeGetUid(
    JNIEnv *env, jobject object)
{
    ZLOGE(LABEL, "Java_ohos_rpc_test_TestHelper_nativeGetUid");

    jint uid = 0;
    IPCTestHelper *helper = reinterpret_cast<IPCTestHelper *>(
        env->GetLongField(object, g_jTestHelper.fieldNativeInstance));

    if (helper != nullptr) {
        uid = static_cast<jint>(helper->GetUid());
    }

    return uid;
}

/*
 * Class:     ohos_rpc_test_TestHelper
 * Method:    nativeGetPid
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_ohos_rpc_test_TestHelper_nativeGetPid(
    JNIEnv *env, jobject object)
{
    jint pid = 0;
    IPCTestHelper *helper = reinterpret_cast<IPCTestHelper *>(
        env->GetLongField(object, g_jTestHelper.fieldNativeInstance));

    if (helper != nullptr) {
        pid = static_cast<jint>(helper->GetPid());
    }

    return pid;
}

/*
 * Class:     ohos.rpc.test.TestHelper
 * Method:    nativeStartExecutable
 * Signature: (Ljava/lang/String;I)Z
 */
JNIEXPORT jboolean JNICALL Java_ohos_rpc_test_TestHelper_nativeStartExecutable(
    JNIEnv *env, jobject object, jstring string, jint length)
{
    IPCTestHelper *helper = reinterpret_cast<IPCTestHelper *>(
        env->GetLongField(object, g_jTestHelper.fieldNativeInstance));

    const char *utfString = env->GetStringUTFChars(string, 0);

    if (utfString != nullptr) {
        std::string exectubeFile = std::string(utfString, length);
        ZLOGI(LABEL, "StartExecutable:%s", exectubeFile.c_str());
        helper->StartExecutable(exectubeFile);
        env->ReleaseStringUTFChars(string, utfString);
        return JNI_TRUE;
    }

    return JNI_FALSE;
}

/*
 * Class:     ohos.rpc.test.TestHelper
 * Method:    nativeStopExecutable
 * Signature: (Ljava/lang/String;I)Z
 */
JNIEXPORT jboolean JNICALL Java_ohos_rpc_test_TestHelper_nativeStopExecutable(
    JNIEnv *env, jobject object, jstring string, jint length)
{
    IPCTestHelper *helper = reinterpret_cast<IPCTestHelper *>(
        env->GetLongField(object, g_jTestHelper.fieldNativeInstance));

    const char *utfString = env->GetStringUTFChars(string, 0);

    if (utfString != nullptr) {
        std::string exectubeFile = std::string(utfString, length);
        ZLOGI(LABEL, "StopExecutable:%s", exectubeFile.c_str());
        helper->StopExecutable(exectubeFile);
        env->ReleaseStringUTFChars(string, utfString);
        return JNI_TRUE;
    }

    return JNI_FALSE;
}

/*
 * Class:     ohos_rpc_test_TestHelper
 * Method:    nativeRunCommand
 * Signature: (Ljava/lang/String;I)Z
 */
JNIEXPORT jboolean JNICALL Java_ohos_rpc_test_TestHelper_nativeRunCommand(
    JNIEnv *env, jobject object, jstring string, jint length)
{
    const char *utfString = env->GetStringUTFChars(string, 0);

    if (utfString != nullptr) {
        std::string shellCommand = std::string(utfString, length);
        ZLOGI(LABEL, "StartExecutable:%s", shellCommand.c_str());
        system(shellCommand.c_str());
        env->ReleaseStringUTFChars(string, utfString);
        return JNI_TRUE;
    }

    return JNI_FALSE;
}

int JTestHelpertRegisterNativeMethods(JNIEnv *env)
{
    jclass clazz;
    clazz = env->FindClass("ohos/rpc/test/TestHelper");
    if (clazz == nullptr) {
        ZLOGI(LABEL, "Could not find class:TestHelper");
        return -1;
    }

    g_jTestHelper.klass = (jclass)env->NewGlobalRef(clazz);
    g_jTestHelper.fieldNativeInstance = env->GetFieldID(clazz, "mNativeInstance", "J");

    if (g_jTestHelper.fieldNativeInstance == nullptr) {
        ZLOGE(LABEL, "TestHelper get field mNativeInstance failed");
        return -1;
    }

    ZLOGI(LABEL, "TestHelper Register Native Methods success\n");
    return 0;
}

jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    if (vm == nullptr) {
        return -1;
    }
    if (g_isTestHelperMethodRegistered) {
        return JNI_VERSION_1_4;
    }

    JNIEnv *env = nullptr;

    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_4) != JNI_OK) {
        return -1;
    }

    if (JTestHelpertRegisterNativeMethods(env) < 0) {
        return -1;
    }

    ZLOGI(LABEL, "JNI_OnLoad success\n");
    g_isTestHelperMethodRegistered = true;
    return JNI_VERSION_1_4;
}
