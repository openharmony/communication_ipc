/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_IPC_TEST_SMALL_COMMON_H
#define OHOS_IPC_TEST_SMALL_COMMON_H

#define IPC_BUFFER_SIZE 2048
#define OBJ_NUM 20
// deviceManager permission @permossion_lite
#ifdef __LITEOS_A__
#define IPC_TEST_SMALL "dev_mgr_svc"
#else
#define IPC_TEST_SMALL "ai_service"
#endif

enum DataType {
    TYPE_START = 0,
    REGISTER_ON_SERVICE,
    ON_RECV_SERVER,
    // base type
    BOOL_TYPE,
    INT8_TYPE,
    INT16_TYPE,
    INT32_TYPE,
    INT64_TYPE,
    UINT8_TYPE,
    UINT16_TYPE,
    UINT32_TYPE,
    UINT64_TYPE,
    FLOAT_TYPE,
    DOUBLE_TYPE,
    // vector
    VECTOR_INT8_TYPE,
    VECTOR_INT16_TYPE,
    VECTOR_INT32_TYPE,
    VECTOR_INT64_TYPE,
    VECTOR_UINT8_TYPE,
    VECTOR_UINT16_TYPE,
    VECTOR_UINT32_TYPE,
    VECTOR_UINT64_TYPE,
    VECTOR_FLOAT_TYPE,
    VECTOR_DOUBLE_TYPE,
    // string
    CHAR_TYPE,
    // fileDescriptor
    FD_TYPE,
    // rawData
    RAW_DATA_TYPE,
    // buffer
    BUFFER_TYPE,
    TYPE_END,
};

typedef struct {
    enum DataType id;
} Reply;

#endif // OHOS_IPC_TEST_SMALL_COMMON_H