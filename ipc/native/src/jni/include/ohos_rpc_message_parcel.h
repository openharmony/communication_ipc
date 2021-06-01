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

#ifndef OHOS_IPC_JNI_MESSAGE_PARCEL_H
#define OHOS_IPC_JNI_MESSAGE_PARCEL_H

#include <jni.h>
#include "message_parcel.h"

namespace OHOS {
/*
 * register native methods for ohos.rpc.MessageParcel.
 */
int JavaOhosRpcMessageParcelRegisterNativeMethods(JNIEnv *env);
/*
 * Get Native Message Parcel instance of ohos/rpc/MessageParcel
 */
MessageParcel *JavaOhosRpcMessageParcelGetNative(JNIEnv *env, jobject object);
} // namespace OHOS

#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeNewObject
 * Signature: (J)J;
 */
jlong JNICALL Java_ohos_rpc_MessageParcel_nativeNewObject(JNIEnv *env, jobject object, jlong nativeObject);

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeFreeObject
 * Signature: (J)V;
 */
void JNICALL Java_ohos_rpc_MessageParcel_nativeFreeObject(JNIEnv *env, jobject object, jlong nativeObject);
/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeWriteRemoteObject
 * Signature: (Lohos/rpc/IRemoteObject)Z
 */
jboolean JNICALL Java_ohos_rpc_MessageParcel_nativeWriteRemoteObject(JNIEnv *env, jobject parcel, jobject object);

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeReadRemoteObject
 * Signature: ()Lohos/rpc/IRemoteObject;
 */
jobject JNICALL Java_ohos_rpc_MessageParcel_nativeReadRemoteObject(JNIEnv *env, jobject object);

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeWriteFileDescriptor
 * Signature: (LJava/io/FileDescriptor;)Z
 */
jboolean JNICALL Java_ohos_rpc_MessageParcel_nativeWriteFileDescriptor(JNIEnv *env, jobject object, jobject descriptor);

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeReadFileDescriptor
 * Signature: ()LJava/io/FileDescriptor;
 */
jobject JNICALL Java_ohos_rpc_MessageParcel_nativeReadFileDescriptor(JNIEnv *env, jobject object);

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeWriteInterfaceToken
 * Signature: (LJava/io/String;)Z
 */
jboolean JNICALL Java_ohos_rpc_MessageParcel_nativeWriteInterfaceToken(JNIEnv *env, jobject object, jstring name,
    jint len);

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeReadInterfaceToken
 * Signature: ()LJava/io/String;
 */
jobject JNICALL Java_ohos_rpc_MessageParcel_nativeReadInterfaceToken(JNIEnv *env, jobject object);

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeWriteRawData
 * Signature: ()LJava/io/String;
 */
jboolean JNICALL Java_ohos_rpc_MessageParcel_nativeWriteRawData(JNIEnv *env, jobject object, jobject rawData,
    jint size);

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeReadRawData
 * Signature: ()LJava/io/String;
 */
jbyteArray JNICALL Java_ohos_rpc_MessageParcel_nativeReadRawData(JNIEnv *env, jobject object, jint size);

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeGetRawDataCapacity
 * Signature: (V)I;
 */
jint JNICALL Java_ohos_rpc_MessageParcel_nativeGetRawDataCapacity(JNIEnv *env, jobject object);

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeCloseFileDescriptor
 * Signature: (LJava/io/FileDescriptor;)V
 */
void JNICALL Java_ohos_rpc_MessageParcel_nativeCloseFileDescriptor(JNIEnv *env, jobject object, jobject descriptor);

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeDupFileDescriptor
 * Signature: (LJava/io/FileDescriptor;)LJava/io/FileDescriptor;
 */
jobject JNICALL Java_ohos_rpc_MessageParcel_nativeDupFileDescriptor(JNIEnv *env, jobject object, jobject descriptor);

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeContainFileDescriptors
 * Signature: ()Z;
 */
jboolean JNICALL Java_ohos_rpc_MessageParcel_nativeContainFileDescriptors(JNIEnv *env, jobject object);

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeWriteAshmem
 * Signature: (J)Z
 */
jboolean JNICALL Java_ohos_rpc_MessageParcel_nativeWriteAshmem(JNIEnv *env, jobject object, jlong id);

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeReadAshmem
 * Signature: (V)J
 */
jlong JNICALL Java_ohos_rpc_MessageParcel_nativeReadAshmem(JNIEnv *env, jobject object);

/*
 * Class:     ohos.rpc.MessageParcel
 * Method:    nativeReleaseAshmem
 * Signature: (J)V
 */
void JNICALL Java_ohos_rpc_MessageParcel_nativeReleaseAshmem(JNIEnv *env, jobject object, jlong id);
#ifdef __cplusplus
}
#endif
#endif // OHOS_IPC_JNI_MESSAGE_PARCEL_H
