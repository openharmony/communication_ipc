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

#ifndef RPC_BYTRACE_INNER_H
#define RPC_BYTRACE_INNER_H

#ifdef __cplusplus
extern "C" {
#endif

void RpcStartTraceInner(uint64_t label, const char *value);
void RpcFinishTraceInner(uint64_t label);
void RpcStartAsyncTraceInner(uint64_t label, const char *value, int32_t TraceId);
void RpcFinishAsyncTraceInner(uint64_t label, const char *value, int32_t TraceId);
void RpcMiddleTraceInner(uint64_t label, const char *beforeValue, const char *afterValue);
#ifdef __cplusplus
}
#endif
#endif