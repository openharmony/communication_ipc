/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_ANI_ERROR_H
#define OHOS_ANI_ERROR_H

#include <ani.h>
#include <string>
#include <unordered_map>

namespace OHOS {
enum errorCode : int32_t {
    PROXY_OR_REMOTE_OBJECT_INVALID_ERROR = 1900008,
    WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR = 1900009,
    READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR = 1900010,
    CALL_JS_METHOD_ERROR = 1900012
};

class AniError {
public:
    AniError() = default;
    static void ThrowError(ani_env *env, int errCode);

private:
    inline static const std::unordered_map<int32_t, std::string> aniErrMap_ {
        {PROXY_OR_REMOTE_OBJECT_INVALID_ERROR, "proxy or remote object is invalid"},
        {WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR, "write data to message sequence failed"},
        {READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, "read data from message sequence failed"},
        {CALL_JS_METHOD_ERROR, "call js method failed"}
    };
}; // AniError
} // namespace OHOS
#endif // OHOS_ANI_ERROR_H
