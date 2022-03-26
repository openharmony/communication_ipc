/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "ipc_types.h"
#include "assist_test_service.h"

namespace OHOS {
AssistTestServiceProxy::AssistTestServiceProxy(const sptr<IRemoteObject>& object)
    : IRemoteProxy<IAssistTestService>(object)
{
}

AssistTestServiceProxy::~AssistTestServiceProxy()
{
}

bool AssistTestServiceProxy::TestParcelBool(bool value)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteBool(value);
    int res = Remote()->SendRequest(TEST_PARCEL_BOOL, data, reply, option);
    return (res == ERR_NONE) ? reply.ReadBool() : false;
}

int16_t AssistTestServiceProxy::TestParcelChar(int16_t value)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInt16(value);
    int res = Remote()->SendRequest(TEST_PARCEL_CHAR, data, reply, option);
    return (res == ERR_NONE) ? reply.ReadInt16() : 0;
}

int32_t AssistTestServiceProxy::TestParcelInt32(int32_t value)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInt32(value);
    int res = Remote()->SendRequest(TEST_PARCEL_INT32, data, reply, option);
    return (res == ERR_NONE) ? reply.ReadInt32() : 0;
}

int64_t AssistTestServiceProxy::TestParcelInt64(int64_t value)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInt64(value);
    int res = Remote()->SendRequest(TEST_PARCEL_INT64, data, reply, option);
    return (res == ERR_NONE) ? reply.ReadInt64() : 0;
}

uint8_t AssistTestServiceProxy::TestParcelByte(uint8_t value)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteUint8(value);
    int res = Remote()->SendRequest(TEST_PARCEL_BYTE, data, reply, option);
    return (res == ERR_NONE) ? reply.ReadUint8() : 0;
}

uint32_t AssistTestServiceProxy::TestParcelUint32(uint32_t value)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteUint32(value);
    int res = Remote()->SendRequest(TEST_PARCEL_UINT32, data, reply, option);
    return (res == ERR_NONE) ? reply.ReadUint32() : 0;
}

uint64_t AssistTestServiceProxy::TestParcelUint64(uint64_t value)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteUint64(value);
    int res = Remote()->SendRequest(TEST_PARCEL_UINT64, data, reply, option);
    return (res == ERR_NONE) ? reply.ReadUint64() : 0;
}

float AssistTestServiceProxy::TestParcelFloat(float value)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteFloat(value);
    int res = Remote()->SendRequest(TEST_PARCEL_FLOAT, data, reply, option);
    return (res == ERR_NONE) ? reply.ReadFloat() : 0;
}

double AssistTestServiceProxy::TestParcelDouble(double value)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteDouble(value);
    int res = Remote()->SendRequest(TEST_PARCEL_DOUBLE, data, reply, option);
    return (res == ERR_NONE) ? reply.ReadDouble() : 0;
}

const char *AssistTestServiceProxy::TestParcelCString(const char *value)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteCString(value);
    int res = Remote()->SendRequest(TEST_PARCEL_CSTRING, data, reply, option);
    return (res == ERR_NONE) ? reply.ReadCString() : nullptr;
}

const std::string AssistTestServiceProxy::TestParcelString(const std::string& value)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteString(value);
    int res = Remote()->SendRequest(TEST_PARCEL_STRING8, data, reply, option);
    return (res == ERR_NONE) ? reply.ReadString() : std::string();
}

const std::u16string AssistTestServiceProxy::TestParcelString16(const std::u16string& value)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteString16(value);
    int res = Remote()->SendRequest(TEST_PARCEL_STRING16, data, reply, option);
    return (res == ERR_NONE) ? reply.ReadString16() : std::u16string();
}

bool AssistTestServiceProxy::TestParcelBoolVector()
{
    MessageParcel data, reply;
    MessageOption option;
    std::vector<bool> readBoolVector;
    std::vector<bool> writeBoolVector = { false, false, true, false, true };
    data.WriteBoolVector(writeBoolVector);

    if (Remote()->SendRequest(TEST_PARCEL_BOOL_VECTOR, data, reply, option) != ERR_NONE) {
        return false;
    }

    if (!reply.ReadBoolVector(&readBoolVector)) {
        return false;
    }

    for (size_t i = 0; i < writeBoolVector.size(); i++) {
        if (writeBoolVector[i] != readBoolVector[i]) {
            bool write = writeBoolVector[i];
            bool read = readBoolVector[i];
            printf("index:%zu write:%d, read:%d\n", i, write, read);
            return false;
        }
    }

    return true;
}

bool AssistTestServiceProxy::TestParcelInt8Vector()
{
    MessageParcel data, reply;
    MessageOption option;
    std::vector<int8_t> readInt8Vector;
    std::vector<int8_t> writeInt8Vector = { 0x01, 0x10, -0x20, 0x30, 0x40 };
    data.WriteInt8Vector(writeInt8Vector);
    int res = Remote()->SendRequest(TEST_PARCEL_INT8_VECTOR, data, reply, option);
    if (res != ERR_NONE) {
        return false;
    }

    if (!reply.ReadInt8Vector(&readInt8Vector)) {
        return false;
    }

    for (size_t i = 0; i < writeInt8Vector.size(); i++) {
        if (writeInt8Vector[i] != readInt8Vector[i]) {
            return false;
        }
    }

    return true;
}

bool AssistTestServiceProxy::TestParcelUint8Vector()
{
    MessageParcel data, reply;
    MessageOption option;
    std::vector<uint8_t> readUint8Vector;
    std::vector<uint8_t> writeUint8Vector = { 0xA1, 0xA1, 0xA2, 0x30, 0x40 };
    data.WriteUInt8Vector(writeUint8Vector);

    if (Remote()->SendRequest(TEST_PARCEL_UINT8_VECTOR, data, reply, option) != ERR_NONE) {
        return false;
    }

    if (!reply.ReadUInt8Vector(&readUint8Vector)) {
        return false;
    }

    for (size_t i = 0; i < writeUint8Vector.size(); i++) {
        if (writeUint8Vector[i] != readUint8Vector[i]) {
            return false;
        }
    }

    return true;
}

bool AssistTestServiceProxy::TestParcelCharVector()
{
    MessageParcel data, reply;
    MessageOption option;
    std::vector<int16_t> readInt16Vector;
    std::vector<int16_t> writeInt16Vector = { 0x1234, -0x2345, 0x3456, -0x4567, 0x5678 };
    data.WriteInt16Vector(writeInt16Vector);

    if (Remote()->SendRequest(TEST_PARCEL_CHAR_VECTOR, data, reply, option)  != ERR_NONE) {
        return false;
    }

    if (!reply.ReadInt16Vector(&readInt16Vector)) {
        return false;
    }

    for (size_t i = 0; i < writeInt16Vector.size(); i++) {
        if (writeInt16Vector[i] != readInt16Vector[i]) {
            return false;
        }
    }

    return true;
}

bool AssistTestServiceProxy::TestParcelInt64Vector()
{
    MessageParcel data, reply;
    MessageOption option;
    std::vector<int64_t> readInt64Vector;
    std::vector<int64_t> writeInt64Vector = { 0x1234567887654321, -0x2345678998765432 };
    data.WriteInt64Vector(writeInt64Vector);

    if (Remote()->SendRequest(TEST_PARCEL_INT64_VECTOR, data, reply, option) != ERR_NONE) {
        return false;
    }

    if (!reply.ReadInt64Vector(&readInt64Vector)) {
        return false;
    }

    for (size_t i = 0; i < writeInt64Vector.size(); i++) {
        if (writeInt64Vector[i] != readInt64Vector[i]) {
            return false;
        }
    }

    return true;
}

bool AssistTestServiceProxy::TestParcelUint64Vector()
{
    MessageParcel data, reply;
    MessageOption option;
    std::vector<uint64_t> readUint64Vector;
    std::vector<uint64_t> writeUint64Vector = { 0x1234567887654321, 0x2345678998765432 };
    data.WriteUInt64Vector(writeUint64Vector);

    if (Remote()->SendRequest(TEST_PARCEL_UINT64_VECTOR, data, reply, option) != ERR_NONE) {
        return false;
    }

    bool result = reply.ReadUInt64Vector(&readUint64Vector);
    if (result != true) {
        return false;
    }

    for (size_t i = 0; i < writeUint64Vector.size(); i++) {
        if (writeUint64Vector[i] != readUint64Vector[i]) {
            return false;
        }
    }

    return true;
}

bool AssistTestServiceProxy::TestParcelInt32Vector()
{
    MessageParcel data, reply;
    MessageOption option;
    std::vector<int32_t> readInt32Vector;
    std::vector<int32_t> writeInt32Vector = { 0x12345678, -0x23456789, 0x34567890, -0x45678901 };;
    data.WriteInt32Vector(writeInt32Vector);

    if (Remote()->SendRequest(TEST_PARCEL_INT32_VECTOR, data, reply, option) != ERR_NONE) {
        return false;
    }

    if (!reply.ReadInt32Vector(&readInt32Vector)) {
        return false;
    }

    for (size_t i = 0; i < writeInt32Vector.size(); i++) {
        if (writeInt32Vector[i] != readInt32Vector[i]) {
            return false;
        }
    }

    return true;
}

bool AssistTestServiceProxy::TestParcelFloatVector()
{
    MessageParcel data, reply;
    MessageOption option;
    std::vector<float> readFloatVector;
    std::vector<float> writeFloatVector{ 11221.132313, 11221.45678 };
    data.WriteFloatVector(writeFloatVector);

    if (Remote()->SendRequest(TEST_PARCEL_FLOAT_VECTOR, data, reply, option) != ERR_NONE) {
        return false;
    }

    if (!reply.ReadFloatVector(&readFloatVector)) {
        return false;
    }

    for (size_t i = 0; i < writeFloatVector.size(); i++) {
        if (writeFloatVector[i] != readFloatVector[i]) {
            return false;
        }
    }

    return true;
}

bool AssistTestServiceProxy::TestParcelDoubleVector()
{
    MessageParcel data, reply;
    MessageOption option;
    std::vector<double> readDoubleVector;
    std::vector<double> writeDoubleVector{ 1122.132313, 1122.45678 };
    data.WriteDoubleVector(writeDoubleVector);

    if (Remote()->SendRequest(TEST_PARCEL_DOUBLE_VECTOR, data, reply, option) != ERR_NONE) {
        return false;
    }

    if (!reply.ReadDoubleVector(&readDoubleVector)) {
        return false;
    }

    for (size_t i = 0; i < writeDoubleVector.size(); i++) {
        if (writeDoubleVector[i] != readDoubleVector[i]) {
            return false;
        }
    }

    return true;
}

bool AssistTestServiceProxy::TestParcelString16Vector()
{
    MessageParcel data, reply;
    MessageOption option;
    std::vector<std::u16string> readString16Vector;
    std::vector<std::u16string> writeString16Vector{
        u"test", u"test for", u"test for write", u"test for write vector"
    };
    data.WriteString16Vector(writeString16Vector);
    if (Remote()->SendRequest(TEST_PARCEL_STRING16_VECTOR, data, reply, option) != ERR_NONE) {
        return false;
    }

    if (!reply.ReadString16Vector(&readString16Vector))  {
        return false;
    }

    for (size_t i = 0; i < writeString16Vector.size(); i++) {
        if (writeString16Vector[i].compare(readString16Vector[i])) {
            return false;
        }
    }

    return true;
}
} // namespace OHOS