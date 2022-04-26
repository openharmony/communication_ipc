/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef _LITE_IPC_H
#define _LITE_IPC_H
#include <stdint.h>
#include <sys/ioctl.h>
#include "serializer.h"
#include "ipc_types.h"
#include "utils_list.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

typedef enum {
    MT_REQUEST,
    MT_REPLY,
    MT_FAILED_REPLY,
    MT_DEATH_NOTIFY,
    MT_NUM
} MsgType;

typedef enum {
    CMS_GEN_HANDLE,
    CMS_REMOVE_HANDLE,
    CMS_ADD_ACCESS
} CmsCmd;

typedef struct {
    CmsCmd cmd;
    uint32_t taskID;
    uint32_t serviceHandle;
} CmsCmdContent;

typedef struct {
    MsgType type;          /**< cmd type, decide the data structure below*/
    SvcIdentity target;    /**< serviceHandle or targetTaskId, depending on type */
    uint32_t code;         /**< service function code */
    uint32_t flag;
    uint64_t timestamp;
    uint32_t dataSz;       /**< size of data */
    void *data;
    uint32_t spObjNum;
    void *offsets;
    uint32_t processID;    /**< filled by kernel, processId of sender/reciever */
    uint32_t taskID;       /**< filled by kernel, taskId of sender/reciever */
    uint32_t userID;
    uint32_t gid;
} IpcMsg;

#define SEND (1 << 0)
#define RECV (1 << 1)
#define BUFF_FREE (1 << 2)

typedef struct {
    uint32_t flag;          /**< size of writeData */
    IpcMsg *outMsg;         /**< data to send to target */
    IpcMsg *inMsg;          /**< data reply by target */
    void *buffToFree;
} IpcContent;

typedef struct {
    int32_t driverVersion;
} IpcVersion;

/* lite ipc ioctl */
#define IPC_IOC_MAGIC       'i'
#define IPC_SET_CMS         _IO(IPC_IOC_MAGIC, 1)
#define IPC_CMS_CMD         _IOWR(IPC_IOC_MAGIC, 2, CmsCmdContent)
#define IPC_SET_IPC_THREAD  _IO(IPC_IOC_MAGIC, 3)
#define IPC_SEND_RECV_MSG   _IOWR(IPC_IOC_MAGIC, 4, IpcContent)
#define IPC_GET_VERSION     _IOR(IPC_IOC_MAGIC, 5, IpcVersion)

typedef enum {
    OBJ_FD,
    OBJ_PTR,
    OBJ_SVC
} ObjType;

typedef union {
    uint32_t fd;
    SvcIdentity svc;
} ObjContent;

typedef struct {
    ObjType type;
    ObjContent content;
} SpecialObj;

typedef struct {
    pthread_mutex_t mutex;
    int32_t handleId;
    bool threadWorking;
    UTILS_DL_LIST apis;
} IpcCallback;

typedef struct {
    uint32_t num;
    void *msg;
    IpcIo io;
    IpcObjectStub *cbs;
    bool useFlag;
} HdlerArg;

typedef struct {
    UTILS_DL_LIST list;
    uint32_t token;
    IpcObjectStub hdlerPair;
} AnonymousApi;

int32_t StartCallbackDispatch(void);
IpcCallback *GetIpcCb(void);
uint32_t GetThreadId(void);
uintptr_t GetObjectStub(uintptr_t cookie);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
