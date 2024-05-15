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

#ifndef CAPI_INCLUDE_IPC_CSKELETON_H
#define CAPI_INCLUDE_IPC_CSKELETON_H

/**
 * @addtogroup OHIPCSkeleton
 * @{
 *
 * @brief 提供IPC框架tokenId、凭据、PID/UID、线程池配置等功能C接口.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @since 12
 */

/**
 * @file ipc_cskeleton.h
 *
 * @brief 提供IPC框架tokenId、凭据、PID/UID、线程池配置等功能C接口.
 *
 * @library libipc_capi.so
 * @since 12
 */

#include <stdint.h>

#include "ipc_cparcel.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 当前线程加入IPC工作线程池.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @since 12
 */
void OH_IPCSkeleton_JoinWorkThread(void);

/**
 * @brief 当前线程退出IPC工作线程池.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @since 12
 */
void OH_IPCSkeleton_StopWorkThread(void);

/**
 * @brief 获取调用方TokenId.该接口需要在IPC上下文中调用，否则返回自身TokenId.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @return 返回调用方TokenId.
 * @since 12
 */
uint64_t OH_IPCSkeleton_GetCallingTokenId(void);

/**
 * @brief 获取首调者TokenId.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @return 返回首调者TokenId.
 * @since 12
 */
uint64_t OH_IPCSkeleton_GetFirstTokenId(void);

/**
 * @brief 获取自身TokenId.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @return 返回自身TokenId.
 * @since 12
 */
uint64_t OH_IPCSkeleton_GetSelfTokenId(void);

/**
 * @brief 获取调用方进程ID.该接口需要在IPC上下文中调用，否则返当前进程ID.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @return 返回调用方进程ID.
 * @since 12
 */
uint64_t OH_IPCSkeleton_GetCallingPid(void);

/**
 * @brief 获取调用方用户ID.该接口需要在IPC上下文中调用，否则返当前用户ID.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @return 返回调用方用户ID.
 * @since 12
 */
uint64_t OH_IPCSkeleton_GetCallingUid(void);

/**
 * @brief 判断是否正在进行本地调用.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @return 正在进行本地调用，返回1；否则，返回0.
 * @since 12
 */
int OH_IPCSkeleton_IsLocalCalling(void);

/**
 * @brief 设置最大工作线程数.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param maxThreadNum 最大工作线程数，默认16，范围[1, 32].
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数错误返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         其它情况返回{@link OH_IPC_ErrorCode#OH_IPC_INNER_ERROR}.
 * @since 12
 */
int OH_IPCSkeleton_SetMaxWorkThreadNum(const int maxThreadNum);

/**
 * @brief 重置调用方身份凭证为自身进程的身份凭证（包括tokenid、UID和PID信息），并返回调用方的凭证信息.
 *        该信息主要用于OH_IPCSkeleton_SetCallingIdentity接口调用.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param identity 用于存储调凭证的内存地址，该内存由用户提供的分配器进行内存分配，用户使用完后需要主动释放，不能为空.
 * @param len 写入identity的数据长度，不能为空.
 * @param allocator 用户指定的用来分配identity的内存分配器，不能为空.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数错误返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         内存分配失败返回{@link OH_IPC_ErrorCode#OH_IPC_MEM_ALLOCATOR_ERROR}. \n
 *         其它情况返回{@link OH_IPC_ErrorCode#OH_IPC_INNER_ERROR}.
 * @since 12
 */
int OH_IPCSkeleton_ResetCallingIdentity(char **identity, int32_t *len, OH_IPC_MemAllocator allocator);

/**
 * @brief 恢复调用方凭证信息至IPC上下文中.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param identity 调用方凭证，不能为空.来源于OH_IPCSkeleton_ResetCallingIdentity的返回值.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数错误返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         其它情况返回{@link OH_IPC_ErrorCode#OH_IPC_INNER_ERROR}.
 * @since 12
 */
int OH_IPCSkeleton_SetCallingIdentity(const char *identity);

/**
 * @brief 是否正在处理IPC请求.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @return 正在处理IPC请求，返回1；否则，返回0.
 * @since 12
 */
int OH_IPCSkeleton_IsHandlingTransaction(void);

#ifdef __cplusplus
}
#endif

/** @} */
#endif
