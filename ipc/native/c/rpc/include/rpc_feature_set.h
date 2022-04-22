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

#ifndef OHOS_RPC_FEATURE_SET_H
#define OHOS_RPC_FEATURE_SET_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t magicNum;
    uint32_t tag;
    uint32_t tokenId;
} FeatureTransData;

typedef struct {
    uint32_t featureSet;
    uint32_t tokenId;
} FeatureSetData;

uint32_t GetLocalRpcFeature(void);
uint32_t GetRpcFeatureAck(void);
bool IsATEnable(uint32_t featureSet);
bool IsFeatureAck(uint32_t featureSet);
uint32_t GetTokenIdSize(void);
uint32_t GetFeatureSize(void);
bool SetFeatureTransData(FeatureTransData *data, uint32_t size);
uint32_t GetTokenFromData(FeatureTransData *data, uint32_t size);

#ifdef __cplusplus
}
#endif
#endif // OHOS_RPC_FEATURE_SET_H