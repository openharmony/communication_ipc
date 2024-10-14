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

#include <cstddef>
#include <cstdint>
#include <cinttypes>

#include "hilog/log_c.h"
#include "hilog/log_cpp.h"
#include "hitrace/trace.h"
#include "ipc_debug.h"
#include "log_tags.h"
#include "message_parcel.h"
#include "process_skeleton.h"
#include "sys_binder.h"

namespace OHOS {
// the value should be equal to the set of parcel
using namespace OHOS::HiviewDFX;
static const HiLogLabel TRACE_LABEL = { LOG_CORE, LOG_ID_IPC_BINDER_INVOKER, "BinderHiTrace" };

bool HitraceInvoker::IsClientTraced(int32_t handle, uint32_t flags, const HiTraceId &traceId)
{
    return (traceId.IsValid() && (handle != 0) &&
        ((flags & TF_ONE_WAY) ? traceId.IsFlagEnabled(HITRACE_FLAG_INCLUDE_ASYNC) : true));
}

HiTraceId HitraceInvoker::TraceClientSend(int32_t handle, uint32_t code, MessageParcel &data, uint32_t &flags,
    const HiTraceId &traceId)
{
    HiTraceId childId = traceId;
    bool isClientTraced = IsClientTraced(handle, flags, traceId);
    if (isClientTraced) {
        childId = HiTraceChain::CreateSpan();
        // add childid to parcel data
        uint8_t idBytes[HITRACE_ID_LEN];
        size_t idLen = (size_t)(childId.ToBytes(idBytes, HITRACE_ID_LEN));
        if (idLen != HITRACE_ID_LEN) {
            ZLOGE(TRACE_LABEL, "idLen not correct");
            return childId;
        }

        size_t oldWritePosition = data.GetWritePosition();
        if (!data.WriteBuffer(idBytes, idLen)) {
            ZLOGE(TRACE_LABEL, "Write idBytes fail");
            // restore Parcel data
            data.RewindWrite(oldWritePosition);
            return childId;
        }

        // padded size of traceid
        if (!data.WriteUint8(data.GetWritePosition() - oldWritePosition)) {
            ZLOGE(TRACE_LABEL, "Write idLen fail");
            // restore Parcel data
            data.RewindWrite(oldWritePosition);
            return childId;
        }
        // tracepoint: CS(Client Send)
        std::u16string desc = data.GetInterfaceToken();
        HiTraceChain::Tracepoint(HITRACE_TP_CS, childId, "%{public}s handle=%{public}d,code=%{public}u,desc=%{public}s",
            (flags & TF_ONE_WAY) ? "ASYNC" : "SYNC", handle, code,
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(desc)).c_str());
        flags |= TF_HITRACE;
    } else {
        if (flags & TF_HITRACE) {
            ZLOGW(TRACE_LABEL, "business set the error flags, traceid is invalid ");
            flags &= ~(uint32_t)TF_HITRACE;
        }
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
            HiTraceChain::SetId(traceId);
            // tracepoint: CR(Client Receive)
            HiTraceChain::Tracepoint(HITRACE_TP_CR, childId,
                "%{public}s handle=%{public}d,code=%{public}u", "SYNC", handle, code);
        }
    }
}

void HitraceInvoker::RecoveryDataAndFlag(Parcel &data, uint32_t &flags, size_t oldReadPosition, uint8_t idLen)
{
    if (data.GetDataSize() < (idLen + PADDED_SIZE_OF_PARCEL)) {
        return;
    }
    // restore data
    data.RewindRead(oldReadPosition);
    // padded size(4 bytes) of uint8_t
    data.SetDataSize(data.GetDataSize() - PADDED_SIZE_OF_PARCEL - idLen);
    flags &= ~(uint32_t)TF_HITRACE;
}

bool HitraceInvoker::TraceServerReceieve(uint64_t handle, uint32_t code, MessageParcel &data, uint32_t &flags)
{
    bool isServerTraced = (flags & TF_HITRACE) != 0;
    if (!isServerTraced) {
        return isServerTraced;
    }
    size_t oldReadPosition = data.GetReadPosition();
    // padded size(4 bytes) of uint8_t
    if (data.GetDataSize() < PADDED_SIZE_OF_PARCEL) {
        ZLOGE(TRACE_LABEL, "The size of the data packet is less than 4");
        return false;
    }
    data.RewindRead(data.GetDataSize() - PADDED_SIZE_OF_PARCEL);
    // the padded size of traceid
    uint8_t idLen = data.ReadUint8();
    if ((idLen >= sizeof(HiTraceIdStruct)) && (idLen <= (data.GetDataSize() - PADDED_SIZE_OF_PARCEL))) {
        // padded size(4 bytes) of uint8_t
        data.RewindRead(data.GetDataSize() - PADDED_SIZE_OF_PARCEL - idLen);
        const uint8_t *idBytes = data.ReadUnpadBuffer(sizeof(HiTraceIdStruct));
        if (idBytes == nullptr) {
            ZLOGE(TRACE_LABEL, "idBytes is null");
            isServerTraced = false;
            RecoveryDataAndFlag(data, flags, oldReadPosition, idLen);
            return isServerTraced;
        }
        HiTraceId traceId(idBytes, sizeof(HiTraceIdStruct));
        HiTraceChain::SetId(traceId);
        // tracepoint: SR(Server Receive)
        data.RewindRead(oldReadPosition);
        std::u16string desc = data.ReadInterfaceToken();
        HiTraceChain::Tracepoint(HITRACE_TP_SR, traceId,
            "%{public}s handle=%{public}" PRIu64 ",code=%{public}u,desc=%{public}s",
            (flags & TF_ONE_WAY) ? "ASYNC" : "SYNC", handle, code,
            ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(desc)).c_str());
    }
    RecoveryDataAndFlag(data, flags, oldReadPosition, idLen);

    return isServerTraced;
}

void HitraceInvoker::TraceServerSend(uint64_t handle, uint32_t code, bool isServerTraced, uint32_t flags)
{
    if (isServerTraced) {
        // tracepoint: SS(Server Send)
        HiTraceChain::Tracepoint(HITRACE_TP_SS, HiTraceChain::GetId(),
            "%{public}s handle=%{public}" PRIu64 ",code=%{public}u",
            (flags & TF_ONE_WAY) ? "ASYNC" : "SYNC", handle, code);
    }
    HiTraceChain::ClearId();
}
} // namespace OHOS
