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

#ifndef CAPI_INCLUDE_IPC_ERROR_CODE_H
#define CAPI_INCLUDE_IPC_ERROR_CODE_H

/**
 * @addtogroup OHIPCErrorCode
 * @{
 *
 * @brief Provides IPC error code define.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @since 12
 */

/**
 * @file ipc_error_code.h
 *
 * @brief Provides IPC error code define.
 *
 * @library libipc_capi.so
 * @since 12
 */

/**
 * @brief IPC错误码定义. \n
 *
 * @since 12
 */
enum OH_IPC_ErrorCode {
    /**
     * 执行成功
     */
    OH_IPC_SUCCESS = 0,
    /**
     * 错误码区间起始值
     */
    OH_IPC_ERROR_CODE_BASE = 1901000,
    /**
     * 参数错误
     */
    OH_IPC_CHECK_PARAM_ERROR = OH_IPC_ERROR_CODE_BASE,
    /**
     * 序列化对象写入数据失败
     */
    OH_IPC_PARCEL_WRITE_ERROR = OH_IPC_ERROR_CODE_BASE + 1,
    /**
     * 序列化对象读取数据失败
     */
    OH_IPC_PARCEL_READ_ERROR = OH_IPC_ERROR_CODE_BASE + 2,
    /**
     * 内存分配失败
     */
    OH_IPC_MEM_ALLOCATOR_ERROR = OH_IPC_ERROR_CODE_BASE + 3,
    /**
     * 命令字超出定义范围[0x01,0x00ffffff]
     */
    OH_IPC_CODE_OUT_OF_RANGE = OH_IPC_ERROR_CODE_BASE + 4,
    /**
     * 远端对象死亡
     */
    OH_IPC_DEAD_REMOTE_OBJECT = OH_IPC_ERROR_CODE_BASE + 5,
    /**
     * 用户自定义错误码超出范围[1900001, 1999999]
     */
    OH_IPC_INVALID_USER_ERROR_CODE = OH_IPC_ERROR_CODE_BASE + 6,
    /**
     * IPC内部错误
     */
    OH_IPC_INNER_ERROR = OH_IPC_ERROR_CODE_BASE + 7,
    /**
     * 错误码区间最大值
     */
    OH_IPC_ERROR_CODE_MAX = OH_IPC_ERROR_CODE_BASE + 1000,
    /**
     * 用户自定义错误码最小值
     */
    OH_IPC_USER_ERROR_CODE_MIN = 1909000,
    /**
     * 用户自定义错误码最大值
     */
    OH_IPC_USER_ERROR_CODE_MAX = 1909999,
};

/** @} */
#endif