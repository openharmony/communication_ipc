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

#include "hitrace_invoker.h"

#include <sys/types.h>
#include "hilog/log.h"
#include "hitrace/trace.h"
#include "sys_binder.h"
#include "ipc_debug.h"
#include "log_tags.h"

namespace OHOS {
// the value should be equal to the set of parcel
using namespace OHOS::HiviewDFX;
static const HiLogLabel TRACE_LABEL = { LOG_CORE, LOG_ID_IPC, "BinderHiTrace" };

bool HitraceInvoker::IsClientTraced(int32_t handle, uint32_t flags, const HiTraceId &traceId)
{
    return (traceId.IsValid() && (handle != 0) &&
        ((flags & TF_ONE_WAY) ? traceId.IsFlagEnabled(HITRACE_FLAG_INCLUDE_ASYNC) : true));
}

HiTraceId HitraceInvoker::TraceClientSend(int32_t handle, uint32_t code, Parcel &data, uint32_t &flags,
    const HiTraceId &traceId)
{
    HiTraceId childId = traceId;
    bool isClientTraced = IsClientTraced(handle, flags, traceId);
    if (isClientTraced) {
        childId = HiTrace::CreateSpan();
        // add childid to parcel data
        uint8_t idBytes[HITRACE_ID_LEN];
        int idLen = childId.ToBytes(idBytes, HITRACE_ID_LEN);
        if (idLen != HITRACE_ID_LEN) {
            ZLOGE(TRACE_LABEL, "%{public}s:idLen not correct", __func__);
            return childId;
        }

        size_t oldWritePosition = data.GetWritePosition();
        if (!data.WriteBuffer(idBytes, idLen)) {
            ZLOGE(TRACE_LABEL, "%{public}s:Write idBytes fail", __func__);
            // restore Parcel data
            data.RewindWrite(oldWritePosition);
            return childId;
        }

        // padded size of traceid
        if (!data.WriteUint8(data.GetWritePosition() - oldWritePosition)) {
            ZLOGE(TRACE_LABEL, "%{public}s:Write idLen fail", __func__);
            // restore Parcel data
            data.RewindWrite(oldWritePosition);
            return childId;
        }
        // tracepoint: CS(Client Send)
        HiTrace::Tracepoint(HITRACE_TP_CS, childId, "%s handle=%d,code=%u", (flags & TF_ONE_WAY) ? "ASYNC" : "SYNC",
            handle, code);
        flags |= TF_HITRACE;
    }
    return childId;
}

void HitraceInvoker::TraceClientReceieve(int32_t handle, uint32_t code, uint32_t flags, const HiTraceId &traceId,
    const HiTraceId &childId)
{
    if (!(flags & TF_HITRACE)) {
        return;
    }
    bool isClientTraced = IsClientTraced(handle, flags, traceId);
    if (isClientTraced) {
        if (!(flags & TF_ONE_WAY)) {
            // restore thread trace id
            HiTrace::SetId(traceId);
            // tracepoint: CR(Client Receive)
            HiTrace::Tracepoint(HITRACE_TP_CR, childId, "%s handle=%d,code=%u", "SYNC", handle, code);
        }
    }
}

void HitraceInvoker::RecoveryDataAndFlag(Parcel &data, uint32_t &flags, size_t oldReadPosition, uint8_t idLen)
{
    // restore data
    data.RewindRead(oldReadPosition);
    // padded size(4 bytes) of uint8_t
    data.SetDataSize(data.GetDataSize() - PADDED_SIZE_OF_PARCEL - idLen);
    flags &= ~(uint32_t)TF_HITRACE;
}

bool HitraceInvoker::TraceServerReceieve(int32_t handle, uint32_t code, Parcel &data, uint32_t &flags)
{
    bool isServerTraced = (flags & TF_HITRACE) != 0;
    if (isServerTraced) {
        size_t oldReadPosition = data.GetReadPosition();
        // padded size(4 bytes) of uint8_t
        data.RewindRead(data.GetDataSize() - PADDED_SIZE_OF_PARCEL);
        // the padded size of traceid
        uint8_t idLen = data.ReadUint8();
        if (idLen >= sizeof(HiTraceIdStruct)) {
            // padded size(4 bytes) of uint8_t
            data.RewindRead(data.GetDataSize() - PADDED_SIZE_OF_PARCEL - idLen);
            const uint8_t *idBytes = data.ReadUnpadBuffer(sizeof(HiTraceIdStruct));
            if (idBytes == nullptr) {
                ZLOGE(TRACE_LABEL, "%{public}s:idBytes is null", __func__);
                isServerTraced = 0;
                RecoveryDataAndFlag(data, flags, oldReadPosition, idLen);
                return isServerTraced;
            }
            HiTraceId traceId(idBytes, sizeof(HiTraceIdStruct));
            HiTrace::SetId(traceId);
            // tracepoint: SR(Server Receive)
            HiTrace::Tracepoint(HITRACE_TP_SR, traceId, "%s handle=%d,code=%u", (flags & TF_ONE_WAY) ? "ASYNC" : "SYNC",
                handle, code);
        }

        RecoveryDataAndFlag(data, flags, oldReadPosition, idLen);
    }
    return isServerTraced;
}

void HitraceInvoker::TraceServerSend(int32_t handle, uint32_t code, bool isServerTraced, uint32_t flags)
{
    if (isServerTraced) {
        // tracepoint: SS(Server Send)
        HiTrace::Tracepoint(HITRACE_TP_SS, HiTrace::GetId(), "%s handle=%d,code=%u",
            (flags & TF_ONE_WAY) ? "ASYNC" : "SYNC", handle, code);
    }
    HiTrace::ClearId();
}
} // namespace OHOS
