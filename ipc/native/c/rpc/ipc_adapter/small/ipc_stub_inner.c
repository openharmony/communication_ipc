/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "ipc_stub_inner.h"

#include "securec.h"

#include "dbinder_types.h"
#include "dbinder_invoker.h"
#include "rpc_process_skeleton.h"
#include "rpc_types.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "ipc_proxy_inner.h"
#include "ipc_thread_pool.h"

static int32_t IsDeviceIdIllegal(const char *deviceID, uint32_t len)
{
    if (deviceID == NULL || len > DEVICEID_LENGTH) {
        return ERR_FAILED;
    }
    return ERR_NONE;
}

static int32_t MakeStubCached(IpcIo *reply, OnRemoteRequest func,
    const char *sessionName, const char *deviceID)
{
    RpcSkeleton *current = GetCurrentRpcSkeleton();
    if (current == NULL) {
        RPC_LOG_ERROR("GetCurrentSkeleton failed");
        return ERR_FAILED;
    }

    StubObject *stubObject = (StubObject *)malloc(sizeof(StubObject));
    if (stubObject == NULL) {
        return ERR_FAILED;
    }
    uint64_t stubIndex = GetNewStubIndex();
    stubObject->stubIndex = stubIndex;
    stubObject->func = func;
    if (AddStubByIndex(stubObject) != ERR_NONE) {
        free(stubObject);
        return ERR_FAILED;
    }

    WriteUint64(reply, stubIndex);
    WriteString(reply, sessionName);
    WriteString(reply, deviceID);
    return ERR_NONE;
}

static int32_t InvokerDataBusThread(IpcIo *data, IpcIo *reply, OnRemoteRequest func)
{
    size_t deviceIDLen;
    const char *deviceID = (const char*)ReadString(data, &deviceIDLen);
    uint32_t remotePid;
    if (!ReadUint32(data, &remotePid)) {
        return ERR_FAILED;
    }

    uint32_t remoteUid;
    if (!ReadUint32(data, &remoteUid)) {
        return ERR_FAILED;
    }

    size_t remoteDeviceIDLen;
    const char *remoteDeviceID = (const char*)ReadString(data, &remoteDeviceIDLen);
    size_t sessionNameLen;
    const char *sessionName = (const char*)ReadString(data, &sessionNameLen);
    if (IsDeviceIdIllegal(deviceID, deviceIDLen) != ERR_NONE ||
        IsDeviceIdIllegal(remoteDeviceID, remoteDeviceIDLen) != ERR_NONE || sessionName == NULL) {
        RPC_LOG_ERROR("deviceID invalid or session name is null");
        return ERR_FAILED;
    }

    RpcSkeleton *current = GetCurrentRpcSkeleton();
    if (current == NULL) {
        RPC_LOG_ERROR("GetCurrentSkeleton failed");
        return ERR_FAILED;
    }
    if (CreateTransServer(sessionName) != ERR_NONE) {
        return ERR_FAILED;
    }

    if (current->sessionName != NULL) {
        free(current->sessionName);
        current->sessionName = NULL;
    }
    if (sessionNameLen == 0 || sessionNameLen > SERVICENAME_LENGTH) {
        RPC_LOG_ERROR("sessionNameLen invalid");
        return ERR_FAILED;
    }
    current->sessionName = (char *)malloc(sessionNameLen + 1);
    if (current->sessionName == NULL) {
        return ERR_FAILED;
    }
    if (strcpy_s(current->sessionName, sessionNameLen + 1, sessionName) != EOK) {
        free(current->sessionName);
        return ERR_FAILED;
    }

    return MakeStubCached(reply, func, sessionName, deviceID);
}

int32_t InvokerListenThreadStub(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option, OnRemoteRequest func)
{
    uint16_t type;
    if (!ReadUint16(data, &type)) {
        return ERR_FAILED;
    }
    switch (type) {
        case DATABUS_TYPE: {
            if (InvokerDataBusThread(data, reply, func) != 0) {
                RPC_LOG_ERROR("Invoker databus thread fail");
                return ERR_FAILED;
            }
            break;
        }
        default: {
            RPC_LOG_ERROR("InvokerThread Invalid Type");
            return ERR_FAILED;
        }
    }
    return ERR_NONE;
}

int32_t GetPidAndUidInfoStub(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
{
    int32_t result;

    char *sessionName = GetDataBusName();
    if (sessionName == NULL || strlen(sessionName) == 0) {
        RPC_LOG_ERROR("GetDataBusName failed");
        result = ERR_FAILED;
    } else {
        WriteString(reply, sessionName);
        free(sessionName);
        sessionName = NULL;
        result = ERR_NONE;
    }
    return result;
}

static int32_t GetDigits(int32_t number)
{
    int32_t n = 0;
    while (number > 0) {
        n++;
        number /= ID_DIGITS;
    }
    if (n == 0) {
        n++;
    }
    return n;
}

int32_t GrantDataBusNameStub(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
{
    int32_t pid = (int32_t)GetCallingPid();
    int32_t pidLen = GetDigits(pid);
    int32_t uid = (int32_t)GetCallingUid();
    int32_t uidLen = GetDigits(uid);

    uint32_t sessionNameLen = SESSION_NAME_LEGNTH + pidLen + uidLen;
    char *sessionName = (char *)malloc(sessionNameLen + 1);
    if (sessionName == NULL) {
        RPC_LOG_ERROR("sessionName mallo failed");
        return ERR_FAILED;
    }
    if (sprintf_s(sessionName, sessionNameLen + 1, "DBinder%d_%d", uid, pid) == -1) {
        RPC_LOG_ERROR("sessionName sprintf failed");
        free(sessionName);
        return ERR_FAILED;
    }

    WriteInt32(reply, IF_PROT_DATABUS);
    WriteString(reply, sessionName);
    free(sessionName);
    return ERR_NONE;
}