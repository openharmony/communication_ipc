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

#ifndef CAPI_INCLUDE_IPC_CPARCEL_H
#define CAPI_INCLUDE_IPC_CPARCEL_H

/**
 * @addtogroup OHIPCParcel
 * @{
 *
 * @brief 提供IPC序列化/反序列化C接口.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @since 12
 */

/**
 * @file ipc_cparcel.h
 *
 * @brief 提供IPC序列化/反序列化C接口.
 *
 * @library libipc_capi.so
 * @since 12
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct OHIPCParcel;
struct OHIPCRemoteProxy;
struct OHIPCRemoteStub;

/**
 * @brief 内存分配函数类型.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param len 分配内存长度.
 * @return 成功返回分配的内存地址；失败返回NULL.
 * @since 12
 */
typedef void* (*OH_IPC_MemAllocator)(int32_t len);

/**
 * @brief 创建OHIPCParcel对象，对象可序列化大小不能超过204800字节.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @return 成功返回OHIPCParcel对象指针；失败返回NULL.
 * @since 12
 */
OHIPCParcel* OH_IPCParcel_Create(void);

/**
 * @brief 销毁OHIPCParcel对象.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel 需要销毁OHIPCParcel对象的指针.
 * @since 12
 */
void OH_IPCParcel_Destroy(OHIPCParcel *parcel);

/**
 * @brief 获取OHIPCParcel对象包含的数据的大小.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @return 返回数据大小，参数不合法时返回-1.
 * @since 12
 */
int OH_IPCParcel_GetDataSize(const OHIPCParcel *parcel);

/**
 * @brief 获取OHIPCParcel对象可以写入的字节数.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @return 返回可写字节数大小，参数不合法时返回-1.
 * @since 12
 */
int OH_IPCParcel_GetWritableBytes(const OHIPCParcel *parcel);

/**
 * @brief 获取OHIPCParcel对象还可以读取的字节数.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @return 返回可读字节数大小，参数不合法时返回-1.
 * @since 12
 */
int OH_IPCParcel_GetReadableBytes(const OHIPCParcel *parcel);

/**
 * @brief 获取OHIPCParcel对象当前读取位置.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @return 返回当前读位置，参数不合法时返回-1
 * @since 12
 */
int OH_IPCParcel_GetReadPosition(const OHIPCParcel *parcel);

/**
 * @brief 获取OHIPCParcel对象当前写入位置.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @return 返回当前写入位置，参数不合法时返回-1.
 * @since 12
 */
int OH_IPCParcel_GetWritePosition(const OHIPCParcel *parcel);

/**
 * @brief 重置OHIPCParcel对象读取位置.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @param newReadPos 新的读取位置，范围:[0, 当前数据大小].
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数不合法时返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}.
 * @since 12
 */
int OH_IPCParcel_RewindReadPosition(OHIPCParcel *parcel, uint32_t newReadPos);

/**
 * @brief 重置OHIPCParcel对象写入位置.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @param newWritePos 新的写入位置，范围:[0, 当前数据大小].
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数不合法时返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}.
 * @since 12
 */
int OH_IPCParcel_RewindWritePosition(OHIPCParcel *parcel, uint32_t newWritePos);

/**
 * @brief 向OHIPCParcel对象写入int8_t值.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @param value 要写入的值.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数不合法时返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         写入失败返回{@link OH_IPC_ErrorCode#OH_IPC_PARCEL_WRITE_ERROR}.
 * @since 12
 */
int OH_IPCParcel_WriteInt8(OHIPCParcel *parcel, int8_t value);

/**
 * @brief 从OHIPCParcel对象读取int8_t值.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @param value 存储读取数据的指针，不能为空.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数不合法时返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         读取失败返回{@link OH_IPC_ErrorCode#OH_IPC_PARCEL_READ_ERROR}.
 * @since 12
 */
int OH_IPCParcel_ReadInt8(const OHIPCParcel *parcel, int8_t *value);

/**
 * @brief 向OHIPCParcel对象写入int16_t值.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @param value 要写入的值.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数不合法时返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         写入失败返回{@link OH_IPC_ErrorCode#OH_IPC_PARCEL_WRITE_ERROR}.
 * @since 12
 */
int OH_IPCParcel_WriteInt16(OHIPCParcel *parcel, int16_t value);

/**
 * @brief 从OHIPCParcel对象读取int16_t值.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @param value 存储读取数据的指针，不能为空.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数不合法时返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         读取失败返回{@link OH_IPC_ErrorCode#OH_IPC_PARCEL_READ_ERROR}.
 * @since 12
 */
int OH_IPCParcel_ReadInt16(const OHIPCParcel *parcel, int16_t *value);

/**
 * @brief 向OHIPCParcel对象写入int32_t值.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @param value 要写入的值.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数不合法时返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         写入失败返回{@link OH_IPC_ErrorCode#OH_IPC_PARCEL_WRITE_ERROR}.
 * @since 12
 */
int OH_IPCParcel_WriteInt32(OHIPCParcel *parcel, int32_t value);

/**
 * @brief 从OHIPCParcel对象读取int32_t值.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @param value 存储读取数据的指针，不能为空.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数不合法时返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         读取失败返回{@link OH_IPC_ErrorCode#OH_IPC_PARCEL_READ_ERROR}.
 * @since 12
 */
int OH_IPCParcel_ReadInt32(const OHIPCParcel *parcel, int32_t *value);

/**
 * @brief 向OHIPCParcel对象写入int64_t值.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @param value 要写入的值.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数不合法时返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         写入失败返回{@link OH_IPC_ErrorCode#OH_IPC_PARCEL_WRITE_ERROR}.
 * @since 12
 */
int OH_IPCParcel_WriteInt64(OHIPCParcel *parcel, int64_t value);

/**
 * @brief 从OHIPCParcel对象读取int64_t值.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @param value 存储读取数据的指针，不能为空.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数不合法时返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         读取失败返回{@link OH_IPC_ErrorCode#OH_IPC_PARCEL_READ_ERROR}.
 * @since 12
 */
int OH_IPCParcel_ReadInt64(const OHIPCParcel *parcel, int64_t *value);

/**
 * @brief 向OHIPCParcel对象写入float值.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @param value 要写入的值.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数不合法时返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         写入失败返回{@link OH_IPC_ErrorCode#OH_IPC_PARCEL_WRITE_ERROR}.
 * @since 12
 */
int OH_IPCParcel_WriteFloat(OHIPCParcel *parcel, float value);

/**
 * @brief 从OHIPCParcel对象读取float值.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @param value 存储读取数据的指针，不能为空.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数不合法时返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         读取失败返回{@link OH_IPC_ErrorCode#OH_IPC_PARCEL_READ_ERROR}.
 * @since 12
 */
int OH_IPCParcel_ReadFloat(const OHIPCParcel *parcel, float *value);

/**
 * @brief 向OHIPCParcel对象写入double值.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @param value 要写入的值.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数不合法时返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         写入失败返回{@link OH_IPC_ErrorCode#OH_IPC_PARCEL_WRITE_ERROR}.
 * @since 12
 */
int OH_IPCParcel_WriteDouble(OHIPCParcel *parcel, double value);

/**
 * @brief 从OHIPCParcel对象读取double值.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @param value 存储读取数据的指针，不能为空.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数不合法时返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         读取失败返回{@link OH_IPC_ErrorCode#OH_IPC_PARCEL_READ_ERROR}.
 * @since 12
 */
int OH_IPCParcel_ReadDouble(const OHIPCParcel *parcel, double *value);

/**
 * @brief 向OHIPCParcel对象写入字符串，包含字符串结束符.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @param str 写入字符串，不能为空.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数不合法时返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         写入失败返回{@link OH_IPC_ErrorCode#OH_IPC_PARCEL_WRITE_ERROR}.
 * @since 12
 */
int OH_IPCParcel_WriteString(OHIPCParcel *parcel, const char *str);

/**
 * @brief 从OHIPCParcel对象读取字符串，用户可通过strlen获取字符串长度。
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空。
 * @return 成功返回读取字符串地址；参数不合法或读取失败时返回NULL。
 * @since 12
 */
const char* OH_IPCParcel_ReadString(const OHIPCParcel *parcel);

/**
 * @brief 向OHIPCParcel对象写入指定长度的内存信息.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @param buffer 写入内存信息地址.
 * @param len 写入信息长度.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数不合法时返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         写入失败返回{@link OH_IPC_ErrorCode#OH_IPC_PARCEL_WRITE_ERROR}.
 * @since 12
 */
int OH_IPCParcel_WriteBuffer(OHIPCParcel *parcel, const uint8_t *buffer, int32_t len);

/**
 * @brief 从OHIPCParcel对象读取指定长度内存信息。
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空。
 * @param len 读取内存的长度。
 * @return 成功返回读取到的内存地址；参数不合法或len超过parcel可读长度时返回NULL。
 * @since 12
 */
const uint8_t* OH_IPCParcel_ReadBuffer(const OHIPCParcel *parcel, int32_t len);

/**
 * @brief 向OHIPCParcel对象写入OHIPCRemoteStub对象.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @param stub 需要写入的OHIPCRemoteStub对象指针，不能为空.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数不合法时返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         写入失败返回{@link OH_IPC_ErrorCode#OH_IPC_PARCEL_WRITE_ERROR}.
 * @since 12
 */
int OH_IPCParcel_WriteRemoteStub(OHIPCParcel *parcel, const OHIPCRemoteStub *stub);

/**
 * @brief 从OHIPCParcel对象读取OHIPCRemoteStub对象.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @return 成功返回OHIPCRemoteStub对象指针；失败返回NULL.
 * @since 12
 */
OHIPCRemoteStub* OH_IPCParcel_ReadRemoteStub(const OHIPCParcel *parcel);

/**
 * @brief 向OHIPCParcel对象写入OHIPCRemoteProxy对象.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @param proxy 需要写入的OHIPCRemoteProxy对象指针，不能为空.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数不合法时返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         写入失败返回{@link OH_IPC_ErrorCode#OH_IPC_PARCEL_WRITE_ERROR}.
 * @since 12
 */
int OH_IPCParcel_WriteRemoteProxy(OHIPCParcel *parcel, const OHIPCRemoteProxy *proxy);

/**
 * @brief 从OHIPCParcel对象读取OHIPCRemoteProxy对象.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @return 成功返回OHIPCRemoteProxy对象指针；失败返回NULL.
 * @since 12
 */
OHIPCRemoteProxy* OH_IPCParcel_ReadRemoteProxy(const OHIPCParcel *parcel);

/**
 * @brief 向OHIPCParcel对象写入文件描述符
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @param fd 要写入的文件描述符.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数不合法时返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         写入失败返回{@link OH_IPC_ErrorCode#OH_IPC_PARCEL_WRITE_ERROR}.
 * @since 12
 */
int OH_IPCParcel_WriteFileDescriptor(OHIPCParcel *parcel, int32_t fd);

/**
 * @brief 从OHIPCParcel对象读取文件描述符.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @param fd 存储读取文件描述符的指针，不能为空.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数不合法时返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         读取失败返回{@link OH_IPC_ErrorCode#OH_IPC_PARCEL_READ_ERROR}.
 * @since 12
 */
int OH_IPCParcel_ReadFileDescriptor(const OHIPCParcel *parcel, int32_t *fd);

/**
 * @brief OHIPCParcel对象数据拼接.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel 拼接目标OHIPCParcel对象的指针，不能为空.
 * @param data 源OHIPCParcel对象的指针，不能为空.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数不合法时返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         拼接失败返回{@link OH_IPC_ErrorCode#OH_IPC_PARCEL_WRITE_ERROR}.
 * @since 12
 */
int OH_IPCParcel_Append(OHIPCParcel *parcel, const OHIPCParcel *data);

/**
 * @brief 向OHIPCParcel对象写入接口描述符，用于接口身份校验.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @param token 需要写入的接口描述符信息，不能为空.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数不合法时返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         写入失败返回{@link OH_IPC_ErrorCode#OH_IPC_PARCEL_WRITE_ERROR}.
 * @since 12
 */
int OH_IPCParcel_WriteInterfaceToken(OHIPCParcel *parcel, const char *token);

/**
 * @brief 从OHIPCParcel对象读取接口描述符信息，用于接口身份校验.
 *
 * @syscap SystemCapability.Communication.IPC.Core
 * @param parcel OHIPCParcel对象的指针，不能为空.
 * @param token 用于存储接口描述符信息的内存地址，该内存由用户提供的分配器进行内存分配，用户使用完后需要主动释放，不能为空. \n
 *              接口返回失败时，用户依然需要判断该内存是否为空，并主动释放，否则会造成内存泄漏.
 * @param len 存储读取接口描述符的长度，包含结束符，不能为空.
 * @param allocator 用户指定的用来分配token的内存分配器，不能为空.
 * @return 成功返回{@link OH_IPC_ErrorCode#OH_IPC_SUCCESS}. \n
 *         参数不合法时返回{@link OH_IPC_ErrorCode#OH_IPC_CHECK_PARAM_ERROR}. \n
 *         读取失败返回{@link OH_IPC_ErrorCode#OH_IPC_PARCEL_READ_ERROR}.
 * @since 12
 */
int OH_IPCParcel_ReadInterfaceToken(const OHIPCParcel *parcel, char **token, int32_t *len,
    OH_IPC_MemAllocator allocator);

#ifdef __cplusplus
}
#endif

#endif
