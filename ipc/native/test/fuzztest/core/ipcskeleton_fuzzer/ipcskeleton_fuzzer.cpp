/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "ipcskeleton_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include "iremote_object.h"
#include "ipc_skeleton.h"

namespace OHOS {
    void GetCallingTokenIDTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return;
        }

        IPCSkeleton skeleton = IPCSkeleton::GetInstance();
        skeleton.GetCallingTokenID();
    }

    void GetFirstTokenIDTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return;
        }

        IPCSkeleton skeleton = IPCSkeleton::GetInstance();
        skeleton.GetFirstTokenID();
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetCallingTokenIDTest(data, size);
    OHOS::GetFirstTokenIDTest(data, size);
    return 0;
}