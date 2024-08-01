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

#ifndef FUZZ_DATA_GENERATOR_H
#define FUZZ_DATA_GENERATOR_H

#include <cstdint>
#include <string>
#include <vector>

#include "parcel.h"

class DataGenerator {
public:
    static const size_t MAX_WRITE_SIZE = 200 * 1024;
    static void Write(const uint8_t *data, size_t size)
    {
        size_t writeSize = (size > MAX_WRITE_SIZE) ? MAX_WRITE_SIZE : size;
        DataGenerator::parcel_.WriteBuffer(data, writeSize);
        DataGenerator::parcel_.RewindRead(0);
    }

    static void Clear()
    {
        DataGenerator::parcel_.FlushBuffer();
    }

    static OHOS::Parcel &GetInstance()
    {
        return DataGenerator::parcel_;
    }

private:
    static inline OHOS::Parcel parcel_;
};

template <typename T>
static inline bool GenerateFromList(T &value, const std::vector<T> &candidateValues)
{
    if (candidateValues.empty()) {
        return false;
    }
    uint8_t rawData = 0;
    if (!DataGenerator::GetInstance().ReadUint8(rawData)) {
        return false;
    }
    value = candidateValues[rawData % candidateValues.size()];
    return true;
}

static inline bool GenerateBool(bool &value)
{
    return DataGenerator::GetInstance().ReadBool(value);
}

static inline bool GenerateInt8(int8_t &value)
{
    return DataGenerator::GetInstance().ReadInt8(value);
}

static inline bool GenerateInt16(int16_t &value)
{
    return DataGenerator::GetInstance().ReadInt16(value);
}

static inline bool GenerateInt32(int32_t &value)
{
    return DataGenerator::GetInstance().ReadInt32(value);
}

static inline bool GenerateInt64(int64_t &value)
{
    return DataGenerator::GetInstance().ReadInt64(value);
}

static inline bool GenerateUint8(uint8_t &value)
{
    return DataGenerator::GetInstance().ReadUint8(value);
}

static inline bool GenerateUint16(uint16_t &value)
{
    return DataGenerator::GetInstance().ReadUint16(value);
}

static inline bool GenerateUint32(uint32_t &value)
{
    return DataGenerator::GetInstance().ReadUint32(value);
}

static inline bool GenerateUint64(uint64_t &value)
{
    return DataGenerator::GetInstance().ReadUint64(value);
}

static inline bool GenerateFloat(float &value)
{
    return DataGenerator::GetInstance().ReadFloat(value);
}

static inline bool GenerateDouble(double &value)
{
    return DataGenerator::GetInstance().ReadDouble(value);
}

static inline bool GenerateString(std::string &value)
{
    return DataGenerator::GetInstance().ReadString(value);
}

#endif // FUZZ_DATA_GENERATOR_H