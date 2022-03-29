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

#ifndef OHOS_IPC_HITRACE_INVOKER_H
#define OHOS_IPC_HITRACE_INVOKER_H

#include "hitrace/trace.h"
#include "iremote_object.h"
namespace OHOS {
class HitraceInvoker {
public:
    static bool IsClientTraced(int32_t handle, uint32_t flags, const HiviewDFX::HiTraceId &traceId);

    static HiviewDFX::HiTraceId TraceClientSend(int32_t handle, uint32_t code, Parcel &data, uint32_t &flags,
        const HiviewDFX::HiTraceId &traceId);

    static void TraceClientReceieve(int32_t handle, uint32_t code, uint32_t flags, const HiviewDFX::HiTraceId &traceId,
        const HiviewDFX::HiTraceId &childId);

    static void RecoveryDataAndFlag(Parcel &data, uint32_t &flags, size_t oldReadPosition, uint8_t idLen);

    static bool TraceServerReceieve(int32_t handle, uint32_t code, Parcel &data, uint32_t &flags);

    static void TraceServerSend(int32_t handle, uint32_t code, bool isServerTraced, uint32_t flags);

private:
    static const int PADDED_SIZE_OF_PARCEL = 4;
};
} // namespace OHOS
#endif // OHOS_IPC_HITRACE_INVOKER_H