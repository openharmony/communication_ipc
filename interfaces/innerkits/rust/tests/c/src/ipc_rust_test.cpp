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

#include "ipc_rust_test.h"

#include <climits>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "ipc_skeleton.h"
#include "message_parcel.h"
#include "refbase.h"

namespace OHOS {
const int VEC_NUM = 3;

const int TEST_BUFFER_LENGTH = 4;
const float TEST_FLOAT = 7.02;
const double TEST_DOUBLE = 7.03;

template<typename T> void WriteTestVector(Parcel *parcel, T testValue, bool (Parcel::*Write)(const std::vector<T> &))
{
    std::vector<T> v;
    for (int i = 0; i < VEC_NUM; i++) {
        v.push_back(testValue);
    }
    (parcel->*Write)(v);
}

void WriteTestVec(MessageParcel *parcel)
{
    WriteTestVector(parcel, true, &Parcel::WriteBoolVector);
    WriteTestVector<uint8_t>(parcel, UCHAR_MAX, &Parcel::WriteUInt8Vector);
    WriteTestVector<uint16_t>(parcel, USHRT_MAX, &Parcel::WriteUInt16Vector);
    WriteTestVector<uint32_t>(parcel, UINT_MAX, &Parcel::WriteUInt32Vector);
    WriteTestVector<uint64_t>(parcel, ULLONG_MAX, &Parcel::WriteUInt64Vector);

    WriteTestVector<int8_t>(parcel, SCHAR_MAX, &Parcel::WriteInt8Vector);
    WriteTestVector<int16_t>(parcel, SHRT_MAX, &Parcel::WriteInt16Vector);
    WriteTestVector<int32_t>(parcel, INT_MAX, &Parcel::WriteInt32Vector);
    WriteTestVector<int64_t>(parcel, LLONG_MAX, &Parcel::WriteInt64Vector);

    WriteTestVector<int8_t>(parcel, SCHAR_MIN, &Parcel::WriteInt8Vector);
    WriteTestVector<int16_t>(parcel, SHRT_MIN, &Parcel::WriteInt16Vector);
    WriteTestVector<int32_t>(parcel, INT_MIN, &Parcel::WriteInt32Vector);
    WriteTestVector<int64_t>(parcel, LLONG_MIN, &Parcel::WriteInt64Vector);

    WriteTestVector<float>(parcel, TEST_FLOAT, &Parcel::WriteFloatVector);
    WriteTestVector<double>(parcel, TEST_DOUBLE, &Parcel::WriteDoubleVector);

    WriteTestVector<std::string>(parcel, "TEST", &Parcel::WriteStringVector);
    WriteTestVector<std::u16string>(parcel, u"TEST", &Parcel::WriteString16Vector);
}

MessageParcel *GetTestMessageParcel()
{
    MessageParcel *parcel = new MessageParcel();
    std::u16string interface = std::u16string(u"TEST");
    parcel->WriteInterfaceToken(interface);

    auto data = std::string("TEST");

    parcel->WriteBuffer(data.data(), data.size());

    parcel->WriteBool(true);

    parcel->WriteUint8(UCHAR_MAX);
    parcel->WriteUint16(USHRT_MAX);
    parcel->WriteUint32(UINT_MAX);
    parcel->WriteUint64(ULLONG_MAX);

    parcel->WriteInt8(SCHAR_MAX);
    parcel->WriteInt16(SHRT_MAX);
    parcel->WriteInt32(INT_MAX);
    parcel->WriteInt64(LLONG_MAX);

    parcel->WriteInt8(SCHAR_MIN);
    parcel->WriteInt16(SHRT_MIN);
    parcel->WriteInt32(INT_MIN);
    parcel->WriteInt64(LLONG_MIN);

    parcel->WriteFloat(TEST_FLOAT);
    parcel->WriteDouble(TEST_DOUBLE);

    WriteTestVec(parcel);
    return parcel;
}

template<typename T>
void ReadAndWriteV(MessageParcel *parcel, MessageParcel &data, bool (Parcel::*Write)(const std::vector<T> &),
    bool (Parcel::*Read)(std::vector<T> *))
{
    std::vector<T> v;
    (data.*Read)(&v);
    (parcel->*Write)(v);
}

MessageParcel *ReadAndWrite(MessageParcel &data)
{
    MessageParcel *parcel = new MessageParcel();

    parcel->WriteInterfaceToken(data.ReadInterfaceToken());
    parcel->WriteBuffer(data.ReadBuffer(TEST_BUFFER_LENGTH), TEST_BUFFER_LENGTH);

    parcel->WriteBool(data.ReadBool());
    parcel->WriteUint8(data.ReadUint8());
    parcel->WriteUint16(data.ReadUint16());
    parcel->WriteUint32(data.ReadUint32());
    parcel->WriteUint64(data.ReadUint64());

    parcel->WriteInt8(data.ReadInt8());
    parcel->WriteInt16(data.ReadInt16());
    parcel->WriteInt32(data.ReadInt32());
    parcel->WriteInt64(data.ReadInt64());

    parcel->WriteInt8(data.ReadInt8());
    parcel->WriteInt16(data.ReadInt16());
    parcel->WriteInt32(data.ReadInt32());
    parcel->WriteInt64(data.ReadInt64());

    parcel->WriteFloat(data.ReadFloat());
    parcel->WriteDouble(data.ReadDouble());

    ReadAndWriteV(parcel, data, &Parcel::WriteBoolVector, &Parcel::ReadBoolVector);
    ReadAndWriteV(parcel, data, &Parcel::WriteUInt8Vector, &Parcel::ReadUInt8Vector);
    ReadAndWriteV(parcel, data, &Parcel::WriteUInt16Vector, &Parcel::ReadUInt16Vector);
    ReadAndWriteV(parcel, data, &Parcel::WriteUInt32Vector, &Parcel::ReadUInt32Vector);
    ReadAndWriteV(parcel, data, &Parcel::WriteUInt64Vector, &Parcel::ReadUInt64Vector);

    ReadAndWriteV(parcel, data, &Parcel::WriteInt8Vector, &Parcel::ReadInt8Vector);
    ReadAndWriteV(parcel, data, &Parcel::WriteInt16Vector, &Parcel::ReadInt16Vector);
    ReadAndWriteV(parcel, data, &Parcel::WriteInt32Vector, &Parcel::ReadInt32Vector);
    ReadAndWriteV(parcel, data, &Parcel::WriteInt64Vector, &Parcel::ReadInt64Vector);

    ReadAndWriteV(parcel, data, &Parcel::WriteInt8Vector, &Parcel::ReadInt8Vector);
    ReadAndWriteV(parcel, data, &Parcel::WriteInt16Vector, &Parcel::ReadInt16Vector);
    ReadAndWriteV(parcel, data, &Parcel::WriteInt32Vector, &Parcel::ReadInt32Vector);
    ReadAndWriteV(parcel, data, &Parcel::WriteInt64Vector, &Parcel::ReadInt64Vector);

    ReadAndWriteV(parcel, data, &Parcel::WriteFloatVector, &Parcel::ReadFloatVector);
    ReadAndWriteV(parcel, data, &Parcel::WriteDoubleVector, &Parcel::ReadDoubleVector);

    ReadAndWriteV(parcel, data, &Parcel::WriteStringVector, &Parcel::ReadStringVector);
    ReadAndWriteV(parcel, data, &Parcel::WriteString16Vector, &Parcel::ReadString16Vector);

    return parcel;
}

CStringWrapper::CStringWrapper(std::string *s) : raw(s->data()), len(s->length())
{
}

CStringWrapper *GetCallingDeviceID()
{
    auto s = new std::string;
    *s = IPCSkeleton::GetCallingDeviceID();
    return new CStringWrapper(s);
}

uint64_t GetCallingFullTokenID()
{
    return IPCSkeleton::GetCallingFullTokenID();
}
uint64_t GetCallingPid()
{
    return IPCSkeleton::GetCallingPid();
}
uint64_t GetCallingRealPid()
{
    return IPCSkeleton::GetCallingRealPid();
}
uint32_t GetCallingTokenID()
{
    return IPCSkeleton::GetCallingTokenID();
}
uint64_t GetCallingUid()
{
    return IPCSkeleton::GetCallingUid();
}
uint64_t GetFirstFullTokenID()
{
    return IPCSkeleton::GetFirstFullTokenID();
}

uint32_t GetFirstTokenID()
{
    return IPCSkeleton::GetFirstTokenID();
}

uint64_t SelfTokenID()
{
    return IPCSkeleton::GetSelfTokenID();
}

bool IsLocalCalling()
{
    return IPCSkeleton::IsLocalCalling();
}
CStringWrapper *LocalDeviceID()
{
    auto s = new std::string;
    *s = IPCSkeleton::GetLocalDeviceID();
    return new CStringWrapper(s);
}
CStringWrapper *ResetCallingIdentity()
{
    auto s = new std::string;
    *s = IPCSkeleton::ResetCallingIdentity();
    return new CStringWrapper(s);
}

} // namespace OHOS