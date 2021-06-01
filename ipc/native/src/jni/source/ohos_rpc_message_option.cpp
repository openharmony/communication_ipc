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

#include "ohos_rpc_message_option.h"
#include "ipc_debug.h"
#include "log_tags.h"

namespace OHOS {
struct JMessageOption {
    jclass klazz;
    jfieldID flagsField;
    jfieldID waitTimeField;
    jmethodID initMethod;
} g_jMessageOption;

static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "IPCJni" };
/*
 * Get flags field from ohos.rpc.MessageOption.
 */
int JavaOhosRpcMessageOptionGetFlags(JNIEnv *env, jobject object)
{
    ZLOGI(LABEL, "%s", __func__);
    if (g_jMessageOption.flagsField != nullptr) {
        return env->GetIntField(object, g_jMessageOption.flagsField);
    }
    return 0;
}

/*
 * Get wait time field from ohos.rpc.MessageOption.
 */
int JavaOhosRpcMessageOptionGetWaitTime(JNIEnv *env, jobject object)
{
    ZLOGI(LABEL, "%s", __func__);
    if (g_jMessageOption.waitTimeField != nullptr) {
        return env->GetIntField(object, g_jMessageOption.waitTimeField);
    }
    return 0;
}

/*
 * Set flags to ohos.rpc.MessageOption
 */
void JavaOhosRpcMessageOptionSetFlags(JNIEnv *env, jobject object, int flags)
{
    ZLOGI(LABEL, "%s", __func__);
    env->SetIntField(object, g_jMessageOption.flagsField, flags);
}

/*
 * Set wait time to ohos.rpc.MessageOption
 */
void JavaOhosRpcMessageOptionSetWaitTime(JNIEnv *env, jobject object, int waitTime)
{
    ZLOGI(LABEL, "%s", __func__);
    env->SetIntField(object, g_jMessageOption.waitTimeField, waitTime);
}

/*
 * Create java object for ohos.rpc.MessageOption.
 */
jobject JavaOhosRpcMessageOptionNewJavaObject(JNIEnv *env, int flags, int waitTime)
{
    ZLOGI(LABEL, "%s", __func__);
    jobject option = env->NewObject(g_jMessageOption.klazz, g_jMessageOption.initMethod, flags, waitTime);
    return option;
}

/*
 * Get and create native instance of ohos.rpc.MessageOption.
 */
MessageOptionPtr JavaOhosRpcMessageOptionGetNative(JNIEnv *env, jobject object)
{
    ZLOGI(LABEL, "%s", __func__);
    int flags = JavaOhosRpcMessageOptionGetFlags(env, object);
    int waitTime = JavaOhosRpcMessageOptionGetWaitTime(env, object);
    auto option = std::make_shared<MessageOption>();
    option->SetFlags(flags);
    option->SetWaitTime(waitTime);
    return option;
}

/*
 * register native methods fopr ohos.rpc.MessageOption.
 */
int JavaOhosRpcMessageOptionRegisterNativeMethods(JNIEnv *env)
{
    ZLOGI(LABEL, "%s", __func__);
    jclass klazz = (jclass)env->NewGlobalRef(env->FindClass("ohos/rpc/MessageOption"));
    if (klazz == nullptr) {
        ZLOGE(LABEL, "could not find class for MessageOption");
        return -1;
    }
    g_jMessageOption.klazz = (jclass)env->NewGlobalRef(klazz);
    g_jMessageOption.initMethod = env->GetMethodID(g_jMessageOption.klazz, "<init>", "(II)V");
    if (g_jMessageOption.initMethod == nullptr) {
        ZLOGE(LABEL, "could not get initMethod from MessageOption");
        if (g_jMessageOption.klazz != nullptr) {
            env->DeleteGlobalRef(g_jMessageOption.klazz);
        }
        env->DeleteGlobalRef(klazz);
        return -1;
    }

    g_jMessageOption.flagsField = env->GetFieldID(g_jMessageOption.klazz, "mFlags", "I");
    if (g_jMessageOption.flagsField == nullptr) {
        ZLOGE(LABEL, "could not get flags fields from MessageOption");
        if (g_jMessageOption.klazz != nullptr) {
            env->DeleteGlobalRef(g_jMessageOption.klazz);
        }
        env->DeleteGlobalRef(klazz);
        return -1;
    }

    g_jMessageOption.waitTimeField = env->GetFieldID(g_jMessageOption.klazz, "mWaitTime", "I");
    if (g_jMessageOption.waitTimeField == nullptr) {
        ZLOGE(LABEL, "could not get mWaitTime fields from MessageOption");
        if (g_jMessageOption.klazz != nullptr) {
            env->DeleteGlobalRef(g_jMessageOption.klazz);
        }
        env->DeleteGlobalRef(klazz);
        return -1;
    }
    return 0;
}
} // namespace OHOS