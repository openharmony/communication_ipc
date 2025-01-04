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

#include "message_option.h"

namespace OHOS {
static constexpr int MAX_WAIT_TIME = 3000;
MessageOption::MessageOption(int flags, int waitTime) : flags_(static_cast<uint32_t>(flags)), waitTime_(waitTime) {}
void MessageOption::SetFlags(int flags)
{
    flags_ |= static_cast<uint32_t>(flags);
}

int MessageOption::GetFlags() const
{
    return flags_;
}

void MessageOption::SetWaitTime(int waitTime)
{
    if (waitTime <= 0) {
        waitTime_ = TF_WAIT_TIME;
    } else if (waitTime > MAX_WAIT_TIME) {
        waitTime_ = MAX_WAIT_TIME;
    } else {
        waitTime_ = waitTime;
    }
}

int MessageOption::GetWaitTime() const
{
    return waitTime_;
}
} // namespace OHOS
