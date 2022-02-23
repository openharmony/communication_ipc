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

#include "rpc_bytrace.h"
#include <stddef.h>
#include "rpc_bytrace_inner.h"

static const uint64_t BYTRACE_TAG_RPC = (1ULL << 46); // RPC and IPC tag.
void RpcStartTrace(const char *value)
{
    if (value == NULL) {
        return;
    }
    RpcStartTraceInner(BYTRACE_TAG_RPC, value);
}

void RpcFinishTrace(void)
{
    RpcFinishTraceInner(BYTRACE_TAG_RPC);
}

void RpcStartAsyncTrace(const char *value, int32_t traceId)
{
    if (value == NULL) {
        return;
    }
    RpcStartAsyncTraceInner(BYTRACE_TAG_RPC, value, traceId);
}

void RpcFinishAsyncTrace(const char *value, int32_t traceId)
{
    if (value == NULL) {
        return;
    }
    RpcFinishAsyncTraceInner(BYTRACE_TAG_RPC, value, traceId);
}

void RpcMiddleTrace(const char *beforeValue, const char *afterValue)
{
    if (beforeValue == NULL || afterValue == NULL) {
        return;
    }
    RpcMiddleTraceInner(BYTRACE_TAG_RPC, beforeValue, afterValue);
}