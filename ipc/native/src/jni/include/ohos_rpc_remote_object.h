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

#ifndef OHOS_IPC_JNI_REMOTE_OBJECT_H
#define OHOS_IPC_JNI_REMOTE_OBJECT_H

#include <jni.h>
#include "refbase.h"
#include "iremote_object.h"

#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     ohos.rpc.IPCSkeleton
 * Method:    nativeGetContextObject
 * Signature: (V)Lohos/rpc/IRemoteObject;
 */
jobject JNICALL Java_ohos_rpc_IPCSkeleton_nativeGetContextObject(JNIEnv *env, jclass clazz);

/*
 * Class:     ohos.rpc.IPCSkeleton
 * Method:    nativeGetCallingPid
 * Signature: (V)I
 */
jint JNICALL Java_ohos_rpc_IPCSkeleton_nativeGetCallingPid(JNIEnv *env, jclass clazz);

/*
 * Class:     ohos.rpc.IPCSkeleton
 * Method:    nativeGetCallingUid
 * Signature: (V)I
 */
jint JNICALL Java_ohos_rpc_IPCSkeleton_nativeGetCallingUid(JNIEnv *env, jclass clazz);

/*
 * Class:     ohos.rpc.IPCSkeleton
 * Method:    nativeGetCallingDeviceID
 * Signature: (V)Lohos/rpc/IRemoteObject;
 */
jstring JNICALL Java_ohos_rpc_IPCSkeleton_nativeGetCallingDeviceID(JNIEnv *env, jclass clazz);

/*
 * Class:     ohos.rpc.IPCSkeleton
 * Method:    nativeGetLocalDeviceID
 * Signature: (V)Lohos/rpc/IRemoteObject;
 */
jstring JNICALL Java_ohos_rpc_IPCSkeleton_nativeGetLocalDeviceID(JNIEnv *env, jclass clazz);

/*
 * Class:     ohos.rpc.IPCSkeleton
 * Method:    nativeIsLocalCalling
 * Signature: (V)Z
 */
jboolean JNICALL Java_ohos_rpc_IPCSkeleton_nativeIsLocalCalling(JNIEnv *env, jclass clazz);

/*
 * Class:     ohos.rpc.IPCSkeleton
 * Method:    nativeFlushCommands
 * Signature: (Lohos/rpc/IRemoteObject;)I;
 */
jint JNICALL Java_ohos_rpc_IPCSkeleton_nativeFlushCommands(JNIEnv *env, jclass clazz, jobject object);

/*
 * Class:     ohos.rpc.IPCSkeleton
 * Method:    nativeResetCallingIdentity
 * Signature: (Lohos/rpc/IRemoteObject;)I;
 */
jstring JNICALL Java_ohos_rpc_IPCSkeleton_nativeResetCallingIdentity(JNIEnv *env, jclass clazz);

/*
 * Class:     ohos.rpc.IPCSkeleton
 * Method:    nativeSetCallingIdentity
 * Signature: (Lohos/rpc/IRemoteObject;)I;
 */
jboolean JNICALL Java_ohos_rpc_IPCSkeleton_nativeSetCallingIdentity(JNIEnv *env, jclass clazz, jstring identity,
    jint len);

/*
 * Class:     ohos.rpc.RemoteObject
 * Method:    nativeGetObjectHolder
 * Signature: (Ljava/lang/String;I)J
 */
jlong JNICALL Java_ohos_rpc_RemoteObject_nativeGetObjectHolder(JNIEnv *env, jclass clazz, jstring value, jint len);

/*
 * Free local Object Holder of RemoteObject.
 * Class:     ohos.rpc.RemoteObject
 * Method:    nativeFreeObjectHolder
 * Signature: (J)V
 */
void JNICALL Java_ohos_rpc_RemoteObject_nativeFreeObjectHolder(JNIEnv *env, jclass clazz, jlong holder);

/*
 * Get calling pid from native.
 * Class:     ohos.rpc.RemoteObject
 * Method:    nativeGetCallingPid
 * Signature: (V)I
 */
jint JNICALL Java_ohos_rpc_RemoteObject_nativeGetCallingPid(JNIEnv *env, jclass object);

/*
 * Get calling UID from native.
 * Class:     ohos.rpc.RemoteObject
 * Method:    nativeGetCallingUid
 * Signature: (V)I
 */
jint JNICALL Java_ohos_rpc_RemoteObject_nativeGetCallingUid(JNIEnv *env, jclass object);

/*
 * Class:     ohos_rpc_RemoteProxy
 * Method:    nativeFreeProxyHolder
 * Signature: (J)V
 */
void JNICALL Java_ohos_rpc_RemoteProxy_nativeFreeProxyHolder(JNIEnv *env, jclass clazz, jlong holder);

/*
 * Class:     ohos.rpc.RemoteProxy
 * Method:    nativeSendRequest
 * Signature: (ILohos/rpc/MessageParcel;Lohos/rpc/Parcel;Lohos/rpc/MessageOption;)Z
 */
jboolean JNICALL Java_ohos_rpc_RemoteProxy_nativeSendRequest(JNIEnv *env, jobject object, jint code, jobject data,
    jobject reply, jobject option);

/*
 * Class:     ohos.rpc.RemoteProxy
 * Method:    nativeAddDeathRecipient
 * Signature: (Lohos/rpc/IRemoteObject$DeathRecipient;I)Z
 */
jboolean JNICALL Java_ohos_rpc_RemoteProxy_nativeAddDeathRecipient(JNIEnv *env, jobject clazz, jobject recipient,
    jint flags);

/*
 * Class:     ohos.rpc.RemoteProxy
 * Method:    nativeRemoveDeathRecipient
 * Signature: (Lohos/rpc/IRemoteObject$DeathRecipient;I)Z
 */
jboolean JNICALL Java_ohos_rpc_RemoteProxy_nativeRemoveDeathRecipient(JNIEnv *env, jobject clazz, jobject recipient,
    jint flags);

/*
 * Class:     ohos_rpc_RemoteProxy
 * Method:    nativeGetInterfaceDescriptor
 * Signature: ()Ljava/lang/String;
 */
jstring JNICALL Java_ohos_rpc_RemoteProxy_nativeGetInterfaceDescriptor(JNIEnv *env, jobject clazz);

/*
 * Class:     ohos.rpc.RemoteProxy
 * Method:    nativeIsObjectDead
 * Signature: (V)Z
 */
jboolean JNICALL Java_ohos_rpc_RemoteProxy_nativeIsObjectDead(JNIEnv *env, jobject object);

/*
 * Class:     ohos.rpc.RemoteProxy
 * Method:    nativeGetHandle
 * Signature: (V)J
 */
jlong JNICALL Java_ohos_rpc_RemoteProxy_nativeGetHandle(JNIEnv *env, jobject object);

#ifdef __cplusplus
}
#endif
namespace OHOS {
sptr<IRemoteObject> Java_ohos_rpc_getNativeRemoteObject(JNIEnv *env, jobject object);

jobject Java_ohos_rpc_getJavaRemoteObject(JNIEnv *env, const sptr<IRemoteObject> target);
} // namespace OHOS
#endif // OHOS_IPC_JNI_REMOTE_OBJECT_H
