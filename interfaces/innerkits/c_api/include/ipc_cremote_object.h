/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef CAPI_INCLUDE_IPC_CREMOTE_OBJECT_H
#define CAPI_INCLUDE_IPC_CREMOTE_OBJECT_H

/**
 * @addtogroup OHIPCRemoteObject
 * @{
 *
 * @brief 提供远端对象创建、销毁、数据发送、远端对象死亡状态监听等功能C接口.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @since 12
 */

/**
 * @file ipc_cremote_object.h
 *
 * @brief 提供远端对象创建、销毁、数据发送、远端对象死亡状态监听等功能C接口.
 *
 * @library libipc_capi.so
 * @since 12
 */

#include <stdint.h>

#include "ipc_cparcel.h"

#ifdef __cplusplus
extern "C" {
#endif

struct OHIPCDeathRecipient;

/**
 * @brief Stub端用于处理远端数据请求的回调函数.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param code 用户自定义通讯命令字，范围:[0x01, 0x00ffffff].
 * @param data 请求数据对象指针，不会为空，函数内不允许释放.
 * @param reply 回应数据对象指针，不会为空，函数内不允许释放. \n
 *              如果函数返回错误，该值不允许写入数据.
 * @param userData 用户私有数据，可以为空.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         否则返回用户自定义错误码或系统错误码，自定义错误码范围:[1909001, 1909999]. \n
 *         如果用户自定义错误码超出范围，将返回{@link OH_IPC_ErrorCode#OH_IPC_INVALID_USER_ERROR_CODE}.
 * @since 12
 */
typedef int (*OH_OnRemoteRequestCallback)(uint32_t code, const OHIPCParcel *data,
    OHIPCParcel *reply, void *userData);

/**
 * @brief Stub端用于监听对象销毁的回调函数.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param userData 用户私有数据，可以为空.
 * @since 12
 */
typedef void (*OH_OnRemoteDestroyCallback)(void *userData);

/**
 * @brief 创建OHIPCRemoteStub对象.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param descriptor OHIPCRemoteStub对象描述符，不能为空.
 * @param requestCallback 数据请求处理函数，不能为空.
 * @param destroyCallback 对象销毁回调函数，可以为空.
 * @param userData 用户私有数据，可以为空.
 * @return 成功返回OHIPCRemoteStub对象指针，否则返回NULL.
 * @since 12
 */
OHIPCRemoteStub* OH_IPCRemoteStub_Create(const char *descriptor, OH_OnRemoteRequestCallback requestCallback,
    OH_OnRemoteDestroyCallback destroyCallback, void *userData);

/**
 * @brief 销毁OHIPCRemoteStub对象.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param stub 要销毁的OHIPCRemoteStub对象指针.
 * @since 12
 */
void OH_IPCRemoteStub_Destroy(OHIPCRemoteStub *stub);

/**
 * @brief 销毁OHIPCRemoteProxy对象.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param proxy 要销毁的OHIPCRemoteProxy对象指针.
 * @since 12
 */
void OH_IPCRemoteProxy_Destroy(OHIPCRemoteProxy *proxy);

/**
 * @brief IPC请求模式定义
 *
 * @since 12
 */
enum OH_IPC_RequestMode {
    /**
     * 同步请求模式
     */
    OH_IPC_REQUEST_MODE_SYNC = 0,
    /**
     * 异步请求模式
     */
    OH_IPC_REQUEST_MODE_ASYNC = 1,
};

/**
 * @brief IPC消息选项定义.
 *
 * @since 12
 */
#pragma pack(4)
struct OH_IPC_MessageOption {
    /**
     * 消息请求模式
     */
    OH_IPC_RequestMode mode;
    /**
     * RPC预留参数，该参数对IPC无效
     */
    uint32_t timeout;
    /**
     * 保留参数，必须为空
     */
    void* reserved;
};
#pragma pack()

/**
 * @brief IPC消息发送函数.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param proxy OHIPCRemoteProxy对象指针，不能为空.
 * @param code 用户定义的IPC命令字，范围:[0x01,0x00ffffff].
 * @param data 请求数据对象指针，不能为空.
 * @param reply 回应数据对象指针，同步请求时，不能为空；异步请求时，可以为空.
 * @param option 消息选项指针，可以为空，为空时按同步处理.
 * @return 发送成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数不合法时返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         远端OHIPCRemoteStub对象死亡返回{@link OH_IPC_ErrorCode#OH_IPC_DEAD_REMOTE_OBJECT}. \n
 *         code超出范围返回{@link OH_IPC_ErrorCode#OH_IPC_CODE_OUT_OF_RANGE}. \n
 *         其它返回{@link OH_IPC_ErrorCode#OH_IPC_INNER_ERROR}或用户自定义错误码.
 * @since 12
 */
int OH_IPCRemoteProxy_SendRequest(const OHIPCRemoteProxy *proxy, uint32_t code, const OHIPCParcel *data,
    OHIPCParcel *reply, const OH_IPC_MessageOption *option);

/**
 * @brief 从Stub端获取接口描述符.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param proxy OHIPCRemoteProxy对象指针，不能为空.
 * @param descriptor 用于存储描述符的内存地址，该内存由用户提供的分配器进行内存分配，用户使用完后需要主动释放，不能为空. \n
 *                   接口返回失败时，用户依然需要判断该内存是否为空，并主动释放，否则会造成内存泄漏.
 * @param len 写入descriptor的数据长度，包含结束符，不能为空.
 * @param allocator 用户指定的用来分配descriptor的内存分配器，不能为空.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数错误返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         远端OHIPCRemoteStub对象死亡返回{@link OH_IPC_ErrorCode#OH_IPC_DEAD_REMOTE_OBJECT}. \n
 *         内存分配失败返回{@link OH_IPC_ErrorCode#OH_IPC_MEM_ALLOCATOR_ERROR}. \n
 *         序列化读失败返回{@link OH_IPC_ErrorCode#OH_IPC_PARCEL_READ_ERROR}.
 * @since 12
 */
int OH_IPCRemoteProxy_GetInterfaceDescriptor(OHIPCRemoteProxy *proxy, char **descriptor, int32_t *len,
    OH_IPC_MemAllocator allocator);

/**
 * @brief 远端OHIPCRemoteStub对象死亡通知的回调函数类型.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param userData 用户私有数据指针，可以为空.
 * @since 12
 */
typedef void (*OH_OnDeathRecipientCallback)(void *userData);

/**
 * @brief OHIPCDeathRecipient对象销毁回调函数类型.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param userData 用户私有数据指针，可以为空.
 * @since 12
 */
typedef void (*OH_OnDeathRecipientDestroyCallback)(void *userData);

/**
 * @brief 创建远端OHIPCRemoteStub对象死亡通知对象OHIPCDeathRecipient.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param deathRecipientCallback 远端OHIPCRemoteStub对象死亡通知的回调处理函数，不能为空.
 * @param destroyCallback 对象销毁回调处理函数，可以为空.
 * @param userData 用户私有数据指针，可以为空.
 * @return 成功返回OHIPCDeathRecipient对象指针;否则返回NULL.
 * @since 12
 */
OHIPCDeathRecipient* OH_IPCDeathRecipient_Create(OH_OnDeathRecipientCallback deathRecipientCallback,
    OH_OnDeathRecipientDestroyCallback destroyCallback, void *userData);

/**
 * @brief 销毁OHIPCDeathRecipient对象.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param recipient 要销毁的OHIPCDeathRecipient对象指针.
 * @since 12
 */
void OH_IPCDeathRecipient_Destroy(OHIPCDeathRecipient *recipient);

/**
 * @brief 向OHIPCRemoteProxy对象添加死亡监听，用于接收远端OHIPCRemoteStub对象死亡的回调通知.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param proxy 需要添加死亡通知的OHIPCRemoteProxy对象指针，不能为空.
 * @param recipient 用于接收远程对象死亡通知的死亡对象指针，不能为空.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数错误返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         其它{@link OH_IPC_ErrorCode#OH_IPC_INNER_ERROR}.
 * @since 12
 */
int OH_IPCRemoteProxy_AddDeathRecipient(OHIPCRemoteProxy *proxy, OHIPCDeathRecipient *recipient);

/**
 * @brief 移除向OHIPCRemoteProxy对象已经添加的死亡监听.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param proxy 需要移除死亡通知的OHIPCRemoteProxy对象指针，不能为空.
 * @param recipient 用于接收远程对象死亡通知的死亡对象指针，不能为空.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数错误返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         其它{@link OH_IPC_ErrorCode#OH_IPC_INNER_ERROR}.
 * @since 12
 */
int OH_IPCRemoteProxy_RemoveDeathRecipient(OHIPCRemoteProxy *proxy, OHIPCDeathRecipient *recipient);

/**
 * @brief 判断OHIPCRemoteProxy对象对应的远端OHIPCRemoteStub对象是否死亡.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param proxy 需要判断远端是否死亡的OHIPCRemoteProxy对象指针，不能为空.
 * @return 远端OHIPCRemoteStub对象死亡返回1; 否则，返回0. 参数非法时，说明其远端OHIPCRemoteStub对象不存在，返回1.
 * @since 12
 */
int OH_IPCRemoteProxy_IsRemoteDead(const OHIPCRemoteProxy *proxy);

#ifdef __cplusplus
}
#endif

/** @} */
#endif
