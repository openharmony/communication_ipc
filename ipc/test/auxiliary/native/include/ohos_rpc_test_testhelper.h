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

#ifndef OHOS_RPC_TEST_TESTHELP_H
#define OHOS_RPC_TEST_TESTHELP_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     ohos_rpc_test_TestHelper
 * Method:    nativeNewInstance
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_ohos_rpc_test_TestHelper_nativeNewInstance(
    JNIEnv *env, jclass clazz);

/*
 * Class:     ohos_rpc_test_TestHelper
 * Method:    nativeFreeInstance
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_ohos_rpc_test_TestHelper_nativeFreeInstance(
    JNIEnv *env, jobject object, jlong);

/*
 * Class:     ohos_rpc_test_TestHelper
 * Method:    nativePrepareTestSuite
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_ohos_rpc_test_TestHelper_nativePrepareTestSuite(
    JNIEnv *env, jobject object);

/*
 * Class:     ohos_rpc_test_TestHelper
 * Method:    nativeTearDownTestSuite
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_ohos_rpc_test_TestHelper_nativeTearDownTestSuite(
    JNIEnv *env, jobject object);

/*
 * Class:     ohos_rpc_test_TestHelper
 * Method:    nativeStartTestServer
 * Signature: (I)Z
 */
JNIEXPORT jboolean JNICALL Java_ohos_rpc_test_TestHelper_nativeStartTestApp(
    JNIEnv *env, jobject object, jint appId, jint commandId);

/*
 * Class:     ohos_rpc_test_TestHelper
 * Method:    StopTestApp
 * Signature: (I)Z
 */
JNIEXPORT jboolean JNICALL Java_ohos_rpc_test_TestHelper_nativeStopTestApp(
    JNIEnv *env, jobject object, jlong appId);

/*
 * Class:     ohos_rpc_test_TestHelper
 * Method:    nativeGetTestServerPid
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_ohos_rpc_test_TestHelper_nativeGetTestAppPid(
    JNIEnv *env, jobject object, jint appId);

/*
 * Class:     ohos_rpc_test_TestHelper
 * Method:    nativeGetUid
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_ohos_rpc_test_TestHelper_nativeGetUid(
    JNIEnv *env, jobject object);
/*
 * Class:     ohos_rpc_test_TestHelper
 * Method:    nativeGetPid
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_ohos_rpc_test_TestHelper_nativeGetPid(
    JNIEnv *env, jobject object);

/*
 * Class:     ohos_rpc_test_TestHelper
 * Method:    nativeStartExecutable
 * Signature: (Ljava/lang/String;I)Z
 */
JNIEXPORT jboolean JNICALL Java_ohos_rpc_test_TestHelper_nativeStartExecutable(
    JNIEnv *env, jobject object, jstring, jint);

/*
 * Class:     ohos_rpc_test_TestHelper
 * Method:    nativeStopExecutable
 * Signature: (Ljava/lang/String;I)Z
 */
JNIEXPORT jboolean JNICALL Java_ohos_rpc_test_TestHelper_nativeStopExecutable(
    JNIEnv *env, jobject object, jstring string, jint length);

/*
 * Class:     ohos_rpc_test_TestHelper
 * Method:    nativeRunCommand
 * Signature: (Ljava/lang/String;I)Z
 */
JNIEXPORT jboolean JNICALL Java_ohos_rpc_test_TestHelper_nativeRunCommand(
    JNIEnv *env, jobject object, jstring string, jint length);

#ifdef __cplusplus
}
#endif
#endif // OHOS_RPC_TEST_TESTHELP_H
