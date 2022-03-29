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

#ifndef OHOS_IPC_JNI_MESSAGE_OPTION_H
#define OHOS_IPC_JNI_MESSAGE_OPTION_H

#include <jni.h>
#include <memory>
#include "message_option.h"

namespace OHOS {
/*
 * Get flags field from ohos.rpc.MessageOption.
 */
int JavaOhosRpcMessageOptionGetFlags(JNIEnv *env, jobject object);

/*
 * Set flags to ohos.rpc.MessageOption
 */
void JavaOhosRpcMessageOptionSetFlags(JNIEnv *env, jobject object, int flags);

/*
 * Get wait time field from ohos.rpc.MessageOption.
 */
int JavaOhosRpcMessageOptionGetWaitTime(JNIEnv *env, jobject object);

/*
 * Set wait time to ohos.rpc.MessageOption
 */
void JavaOhosRpcMessageOptionSetWaitTime(JNIEnv *env, jobject object, int waitTime);

/*
 * Create java object for ohos.rpc.MessageOption.
 */
jobject JavaOhosRpcMessageOptionNewJavaObject(JNIEnv *env, int flags, int waitTime);

/*
 * Get and create native instance of ohos.rpc.MessageOption.
 */
MessageOptionPtr JavaOhosRpcMessageOptionGetNative(JNIEnv *env, jobject object);

/*
 * register native methods for ohos.rpc.MessageOption.
 */
int JavaOhosRpcMessageOptionRegisterNativeMethods(JNIEnv *env);
} // namespace OHOS
#endif // OHOS_IPC_JNI_MESSAGE_OPTION_H