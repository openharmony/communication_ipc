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

#ifndef OHOS_IPC_DBINDER_ERROR_CODE_H
#define OHOS_IPC_DBINDER_ERROR_CODE_H

#include <string>
#include "hisysevent.h"

namespace OHOS {
class DbinderErrorCode {
public:
    static const int SYSTEM_ENVIRONMENT_ERROR = 950000601;
    static const int NETWORK_ERROR = 950000602;
    static const int SKELETON_ERROR = 950000603;
    static const int DBINDER_SERVICE_ERROR = 950000604;
    static const int TRANSMISSION_ERROR = 950000605;
    static const int COMMON_DRIVER_ERROR = 950000606;
    static const int KERNEL_DRIVER_ERROR = 950000607;
    static const int SOCKET_DRIVER_ERROR = 950000608;

    static constexpr char DSOFTBUS_DOMAIN[] = "DSOFTBUS";
    static constexpr char DSOFTBUS_EVENT_NAME[] = "IPC_BEHAVIOR";
    static constexpr char DSOFTBUS_PKG_NAME[] = "dsoftbus_ipc";

    inline static constexpr const char *ERROR_TYPE = "ErrType";
    inline static constexpr const char *ERROR_CODE = "ErrCode";

    // 601
    enum SystemEnvironmentError {
        CREATE_EPOLL = 1,
        BIND_EPOLL,
        REMOVE_EPOLL,
    };

    // 602
    enum NetworkError {
        WRONG_DEVICE_ID = 1,
        WRONG_SUBSCRIPTION,
    };

    // 603
    enum SkeletonError {
        WRONG_KERNEL_DRIVER = 1,
        WRONG_SOCKET_DRIVER,
        WRONG_TYPE_PROXY,
        UPDATE_SESSION_FAILURE,
        RELEASE_FD_FAILURE,
        RELEASE_SESSION_FAILURE,
        UNKNOWN_CMD,
    };

    // 604
    enum DbinderServiceError {
        START_DBS_FAILURE = 1,
        CLOSE_DBS_FAILURE,
        WRONG_INPUT_PARAMETER,
        LOCAL_OBJECT_SEND_MESSAGE_FAILURE,
        RECEIVE_MESSAGE_FAILURE,
        INVOKE_LISTENER_FAILURE,
        ALLOCATE_INDEX_FAILURE,
        REMOTE_OBJECT_SEND_MESSAGE_FAILURE,
        INITIATE_DATABUS_FAILURE,
        DATABUS_SEND_FAILURE,
        DATABUS_RECEIVE_FAILURE,
        CLOSE_DATABUS_FAILURE,
        OPERATE_MESSAGE_FAILURE,
    };

    // 605
    enum TransmissionError {
        RECEIVE_PKT_LOSS = 1,
        SEND_PKT_LOSS,
        HANDLE_OVERMUCH_THREADS,
        OVERSIZE_PKT,
    };

    // 606
    enum CommonDriverType {
        IPC_DRIVER = 1,
        RPC_DRIVER,
    };
    enum CommonDriverError {
        TRANSACT_DATA_FAILURE = 1,
        HANDLE_RECV_DATA_FAILURE,
        SET_DEATH_RECIPIENT_FAILURE,
        REMOVE_DEATH_RECIPIENT_FAILURE,
        HANDLE_DEATH_RECIPIENT_FAILURE,
        FLATTEN_OBJECT_FAILURE,
        UNFLATTEN_OBJECT_FAILURE,
    };

    // 607
    enum KernelDriverError {
        INITIATE_IPC_DRIVER_FAILURE = 1,
        OPEN_IPC_DRIVER_FAILURE,
        WRITE_IPC_DRIVER_FAILURE,
    };

    // 608
    enum SocketDriverError {
        OPEN_RPC_DRIVER_FAILURE = 1,
        CONNECT_RPC_REMOTE_FAILURE,
        SEND_RPC_DATA_FAILURE,
        RECEIVE_RPC_DATA_FAILURE,
        INVOKE_RPC_THREAD_FAILURE,
    };

    // BIZ_SCENE
    enum IpcEventScene {
        IPC_COMMUNICATION = 1,
    };

    // BIZ_STAGE
    enum IpcEventStage {
        IPC_MESSAGE_RPOCESS = 1,
    };

    // BIZ_STATE
    enum IpcEventState {
        IPC_START = 1,
        IPC_END,
    };

    // STAGE_RES
    enum IpcEventResult {
        IPC_RESULT_IDLE = 0,
        IPC_RESULT_OK,
        IPC_RESULT_FAILED,
        IPC_RESULT_CANCELED,
        IPC_RESULT_UNKNOWN,
    };
};

inline void ReportEvent(int code, const std::string &type, int num, const char *func)
{
    if (code == 0 || type.empty() || num == 0) {
        return;
    }
    HiSysEventWrite(DbinderErrorCode::DSOFTBUS_DOMAIN, DbinderErrorCode::DSOFTBUS_EVENT_NAME,
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "ORG_PKG", DbinderErrorCode::DSOFTBUS_PKG_NAME, "BIZ_SCENE",
        DbinderErrorCode::IPC_COMMUNICATION, "BIZ_STAGE", DbinderErrorCode::IPC_MESSAGE_RPOCESS, "STAGE_RES",
        DbinderErrorCode::IPC_RESULT_FAILED, "BIZ_STATE", DbinderErrorCode::IPC_END, "FUNC", func, "ERROR_CODE", num);
}

inline void ReportDriverEvent(int code, const std::string &type, int num, const std::string &errorType, int errorNum,
    const char *func)
{
    if (code == 0 || type.empty() || num == 0 || errorType.empty() || errorNum == 0) {
        return;
    }
    HiSysEventWrite(DbinderErrorCode::DSOFTBUS_DOMAIN, DbinderErrorCode::DSOFTBUS_EVENT_NAME,
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "ORG_PKG", DbinderErrorCode::DSOFTBUS_PKG_NAME, "BIZ_SCENE",
        DbinderErrorCode::IPC_COMMUNICATION, "BIZ_STAGE", DbinderErrorCode::IPC_MESSAGE_RPOCESS, "STAGE_RES",
        DbinderErrorCode::IPC_RESULT_FAILED, "BIZ_STATE", DbinderErrorCode::IPC_END, "FUNC", func, "ERROR_CODE",
        errorNum, "TYPE", num);
}

} // namespace OHOS
#endif // OHOS_IPC_DBINDER_ERROR_CODE_H
