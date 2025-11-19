/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "noticeservicedie_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <securec.h>
#include "dbinder_service.h"

namespace OHOS {

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return true;
        }
        std::u16string serviceName;
        char tmp[SESSION_NAME_SIZE_MAX] = {0};
        if (memcpy_s(tmp, sizeof(tmp) - 1, data, size) != EOK) {
            return false;
        }
        
        std::string deviceID = tmp;
        sptr<DBinderService>dBinderService_ = DBinderService::GetInstance();
        if (dBinderService_ == nullptr) {
            return false;
        }

        int32_t ret = dBinderService_->NoticeServiceDie(serviceName, deviceID);
        if (ret == 0) {
            return false;
        }

        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}

