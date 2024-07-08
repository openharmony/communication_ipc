/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_IPC_MESSAGE_OPTION_H
#define OHOS_IPC_MESSAGE_OPTION_H

#include <memory>
namespace OHOS {
class MessageOption {
public:
    enum {
        TF_SYNC = 0x00,
        TF_ASYNC = 0x01,
        TF_STATUS_CODE = 0x08,
        TF_ACCEPT_FDS = 0x10,
        TF_WAIT_TIME = 0x8,
        TF_ASYNC_WAKEUP_LATER = 0x100000,
    };
    MessageOption(int flags = TF_SYNC, int waitTime = TF_WAIT_TIME);
    ~MessageOption() = default;

    /**
     * @brief Sets flags.
     * @param flags Indicates the identity to set.
     * @return void
     * @since 9
     */
    void SetFlags(int flags);

    /**
     * @brief Gets flags.
     * @return Returns the resulting flags.
     * @since 9
     */
    int GetFlags() const;

    /**
     * @brief Sets the wait time.
     * @param waitTime Indicates the wait time to set.
     * @return void
     * @since 9
     */
    void SetWaitTime(int waitTime);

    /**
     * @brief Gets the wait time.
     * @return Returns the resulting wait time.
     * @since 9
     */
    int GetWaitTime() const;

private:
    uint32_t flags_;
    int waitTime_;
};
using MessageOptionPtr = std::shared_ptr<MessageOption>;
} // namespace OHOS
#endif // OHOS_IPC_MESSAGE_OPTION_H