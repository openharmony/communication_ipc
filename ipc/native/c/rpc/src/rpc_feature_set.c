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

#include "rpc_feature_set.h"

#define RPC_FEATURE_LAST 43
#define RPC_ACCESS_TOKEN_FLAG 0x1

static const uint32_t RPC_FEATURE_MAGIC_NUM = ('R' << 24) | ('F' << 16) | ('S' << 8) | RPC_FEATURE_LAST;
static const uint32_t RPC_ACCESS_TOKEN = 0;
static const uint32_t RPC_FEATURE_FLAG = 0x1;
static const uint32_t TOKEN_ID_SIZE = 4;
static const uint32_t RPC_FEATURE_ACK = 0x80000000;

uint32_t GetFeatureMagicNumber(void)
{
    return RPC_FEATURE_MAGIC_NUM;
}

uint32_t GetFeatureATTag(void)
{
    return RPC_ACCESS_TOKEN;
}

uint32_t GetLocalRpcFeature(void)
{
    return RPC_FEATURE_FLAG;
}

uint32_t GetRpcFeatureAck(void)
{
    return RPC_FEATURE_ACK;
}

bool IsATEnable(uint32_t featureSet)
{
    return (featureSet & RPC_ACCESS_TOKEN_FLAG) > 0;
}

bool IsFeatureAck(uint32_t featureSet)
{
    return (featureSet & RPC_FEATURE_ACK) > 0;
}

size_t GetATSize(uint32_t featureSet)
{
    size_t atSize = 0;
    if (IsATEnable(featureSet) == true) {
        atSize += sizeof(AccessTokenData);
    }
    return atSize;
}

uint32_t GetTokenIdSize(void)
{
    return TOKEN_ID_SIZE;
}