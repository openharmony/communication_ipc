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

#ifndef OHOS_IPC_TAIHE_MESSAGE_OPTION_H
#define OHOS_IPC_TAIHE_MESSAGE_OPTION_H

#include "ohos.rpc.rpc.proj.hpp"
#include "ohos.rpc.rpc.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

#include <cinttypes>
#include <set>
#include <string>
#include <unistd.h>
#include <vector>
#include "napi/native_api.h"

#include "message_option.h"

namespace OHOS {

class MessageOptionImpl {
public:
    MessageOptionImpl(int32_t syncFlags, int32_t waitTime);

    bool IsAsync();

    void SetAsync(bool isAsync);

    int32_t GetFlags();

    void SetFlags(int32_t flags);

    int32_t GetWaitTime();

    void SetWaitTime(int32_t waitTime);

    int64_t GetNativePtr();

    void AddJsObjWeakRef(::ohos::rpc::rpc::weak::MessageOption obj);

    static ::ohos::rpc::rpc::MessageOption CreateMessageOption_WithTwoParam(int32_t syncFlags, int32_t waitTime);
    static ::ohos::rpc::rpc::MessageOption CreateMessageOption_WithOneParam(bool isAsync);
    static ::ohos::rpc::rpc::MessageOption CreateMessageOption_WithOneIntParam(int32_t syncFlags);
    static ::ohos::rpc::rpc::MessageOption CreateMessageOption();

    static ::ohos::rpc::rpc::MessageOption RpcTransferStaticOption(uintptr_t input);
    static uintptr_t RpcTransferDynamicOption(::ohos::rpc::rpc::MessageOption obj);
    static uintptr_t TransferDynamicOption(MessageOption* messageOption, napi_env jsenv, napi_value jsMessageOption);
    static int32_t GetTfSync();
    static int32_t GetTfAsync();
    static int32_t GetTfAcceptFds();
    static int32_t GetTfWaitTime();
private:
    std::shared_ptr<OHOS::MessageOption> messageOption_ = nullptr;
    std::optional<::ohos::rpc::rpc::weak::MessageOption> jsObjRef_;
};

} // namespace

#endif // OHOS_IPC_TAIHE_MESSAGE_OPTION_H