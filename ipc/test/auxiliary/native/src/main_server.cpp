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

#include "ipc_debug.h"
#include "ipc_skeleton.h"
#include "test_service.h"
#include "log_tags.h"
#include <nativetoken_kit.h>
#include <token_setproc.h>

using namespace OHOS;
using namespace OHOS::HiviewDFX;

[[maybe_unused]]static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_TEST, "IPCTestServer" };

static void InitTokenId(void)
{
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 0,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = NULL,
        .acls = NULL,
        .processName = "com.ipc.test",
        .aplStr = "normal",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
}

int main(int argc, char *argv[])
{
    bool isEnableSerialInvokeFlag = false;
    if (argc > 1) {
        isEnableSerialInvokeFlag = true;
    }
    InitTokenId();
    TestService::Instantiate(isEnableSerialInvokeFlag);
    ZLOGD(LABEL, "call  StartThreadPool");
    IPCSkeleton::JoinWorkThread();
}
