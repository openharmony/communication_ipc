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

#ifndef OHOS_IPC_JNI_HELPERS_H
#define OHOS_IPC_JNI_HELPERS_H

#include <jni.h>

namespace OHOS {
class JNIEnvHelper {
public:
    JNIEnvHelper();
    ~JNIEnvHelper();
    JNIEnv *Get();
    JNIEnv *operator->();
    static void nativeInit(JavaVM *vm);

private:
    JNIEnvHelper(const JNIEnvHelper &) = delete;
    JNIEnvHelper &operator = (const JNIEnvHelper &) = delete;

private:
    JNIEnv *env_;
    bool nativeThread_;
    static JavaVM *javaVm_;
};
void JniHelperThrowException(JNIEnv *env, const char *className, const char *msg);
void JniHelperThrowNullPointerException(JNIEnv *env, const char *msg);
void JniHelperThrowIllegalStateException(JNIEnv *env, const char *msg);


/*
 * JNI may throws exception when native code call java scenario.
 * we should convert local exception to native status code.
 * Check and clear local exception.
 */
jboolean JniHelperCheckAndClearLocalException(JNIEnv *env);

/*
 * Get an int file descriptor from a java.io.FileDescriptor
 */
int JniHelperJavaIoGetFdFromFileDescriptor(JNIEnv *env, jobject fileDescriptor);

/*
 * Set the descriptor of a java.io.FileDescriptor
 */
void JniHelperJavaIoSetFdToFileDescriptor(JNIEnv *env, jobject fileDescriptor, int value);

/*
 * Create a java.io.FileDescriptor given an integer fd
 */
jobject JniHelperJavaIoCreateFileDescriptor(JNIEnv *env, int fd);

int JniHelperRegisterNativeMethods(JNIEnv *env);
} // namespace OHOS
#endif // OHOS_IPC_JNI_HELPERS_H
