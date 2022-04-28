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

#include "rpc_bytrace_inner.h"
#include <cstddef>
#include <cstdint>
#include "hitrace_meter.h"
using namespace std;

void RpcStartTraceInner(uint64_t label, const char *value)
{
    if (value == nullptr) {
        return;
    }
    StartTrace(label, value);
}

void RpcFinishTraceInner(uint64_t label)
{
    FinishTrace(label);
}

void RpcStartAsyncTraceInner(uint64_t label, const char *value, int32_t traceId)
{
    if (value == nullptr) {
        return;
    }
    StartAsyncTrace(label, value, traceId);
}

void RpcFinishAsyncTraceInner(uint64_t label, const char *value, int32_t traceId)
{
    if (value == nullptr) {
        return;
    }
    FinishAsyncTrace(label, value, traceId);
}

void RpcMiddleTraceInner(uint64_t label, const char *beforeValue, const char *afterValue)
{
    if (beforeValue == nullptr || afterValue == nullptr) {
        return;
    }
    MiddleTrace(label, beforeValue, afterValue);
}
