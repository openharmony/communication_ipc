/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "parcel_wrapper.h"

#include <securec.h>
#include <sys/types.h>

#include <codecvt>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "ashmem.h"
#include "cxx.h"
#include "message_option.h"
#include "message_parcel.h"
#include "parcel.h"
#include "remote/wrapper.rs.h"
#include "string_ex.h"

namespace OHOS {
namespace IpcRust {
std::unique_ptr<MessageParcel> NewMessageParcel()
{
    return std::make_unique<MessageParcel>();
}

std::unique_ptr<MessageOption> NewMessageOption()
{
    return std::make_unique<MessageOption>();
}

Parcel const *AsParcel(const MessageParcel &msgParcel)
{
    auto msgParcelMut = const_cast<MessageParcel *>(&msgParcel);
    return reinterpret_cast<Parcel *>(msgParcelMut);
}

Parcel *AsParcelMut(MessageParcel &msgParcel)
{
    return reinterpret_cast<Parcel *>(&msgParcel);
}

bool WriteInterfaceToken(MessageParcel &msgParcel, rust::str name)
{
    std::u16string s = Str8ToStr16(std::string(name));
    return msgParcel.WriteInterfaceToken(s);
}

rust::string ReadInterfaceToken(MessageParcel &msgParcel)
{
    return msgParcel.ReadInterfaceToken().data();
}

bool WriteRemoteObject(MessageParcel &msgParcel, std::unique_ptr<IRemoteObjectWrapper> object)
{
    if (object->is_raw_) {
        return false;
    } else {
        return msgParcel.WriteRemoteObject(object->sptr_);
    }
}

std::unique_ptr<IRemoteObjectWrapper> ReadRemoteObject(MessageParcel &msgParcel)
{
    sptr<IRemoteObject> remote = msgParcel.ReadRemoteObject();
    if (remote == nullptr) {
        return nullptr;
    }
    auto wrapper = std::make_unique<IRemoteObjectWrapper>();
    wrapper->is_raw_ = false;
    wrapper->sptr_ = std::move(remote);
    return wrapper;
}

bool WriteBuffer(MessageParcel &msgParcel, rust::slice<const uint8_t> buffer)
{
    return msgParcel.WriteBuffer(buffer.data(), buffer.size());
}

bool ReadBuffer(MessageParcel &msgParcel, size_t len, rust::vec<uint8_t> &buffer)
{
    if (len == 0) {
        return true;
    }
    const uint8_t *data = msgParcel.ReadBuffer(len);
    if (data == nullptr) {
        return false;
    }
    if (memcpy_s(buffer.data(), len, data, len) != EOK) {
        return false;
    }
    return true;
}

bool ReadString(Parcel &parcel, rust::string &val)
{
    std::string v;
    if (parcel.ReadString(v)) {
        val = v;
        return true;
    } else {
        return false;
    }
}

bool WriteString(Parcel &parcel, const rust::str val)
{
    auto s = std::string(val);
    return parcel.WriteString(s);
}

bool WriteString16(Parcel &parcel, const rust::str val)
{
    std::u16string u16string = Str8ToStr16(std::string(val));
    return parcel.WriteString16(u16string);
}
rust::string ReadString16(Parcel &parcel)
{
    std::u16string u16string;
    parcel.ReadString16(u16string);
    return rust::string(u16string.data());
}

template<typename T> std::vector<T> RustVec2CppVec(rust::slice<const T> val)
{
    std::vector<T> v;
    for (auto i : val) {
        v.push_back(i);
    }
    return v;
}

bool WriteBoolVector(Parcel &parcel, rust::slice<const bool> val)
{
    return parcel.WriteBoolVector(RustVec2CppVec(val));
}

bool WriteInt8Vector(Parcel &parcel, rust::slice<const int8_t> val)
{
    return parcel.WriteInt8Vector(RustVec2CppVec(val));
}

bool WriteInt16Vector(Parcel &parcel, rust::slice<const int16_t> val)
{
    return parcel.WriteInt16Vector(RustVec2CppVec(val));
}
bool WriteInt32Vector(Parcel &parcel, rust::slice<const int32_t> val)
{
    return parcel.WriteInt32Vector(RustVec2CppVec(val));
}
bool WriteInt64Vector(Parcel &parcel, rust::slice<const int64_t> val)
{
    return parcel.WriteInt64Vector(RustVec2CppVec(val));
}
bool WriteUInt8Vector(Parcel &parcel, rust::slice<const uint8_t> val)
{
    return parcel.WriteUInt8Vector(RustVec2CppVec(val));
}
bool WriteUInt16Vector(Parcel &parcel, rust::slice<const uint16_t> val)
{
    return parcel.WriteUInt16Vector(RustVec2CppVec(val));
}
bool WriteUInt32Vector(Parcel &parcel, rust::slice<const uint32_t> val)
{
    return parcel.WriteUInt32Vector(RustVec2CppVec(val));
}
bool WriteUInt64Vector(Parcel &parcel, rust::slice<const uint64_t> val)
{
    return parcel.WriteUInt64Vector(RustVec2CppVec(val));
}
bool WriteFloatVector(Parcel &parcel, rust::slice<const float> val)
{
    return parcel.WriteFloatVector(RustVec2CppVec(val));
}
bool WriteDoubleVector(Parcel &parcel, rust::slice<const double> val)
{
    return parcel.WriteDoubleVector(RustVec2CppVec(val));
}

bool WriteStringVector(Parcel &parcel, rust::slice<const rust::string> val)
{
    std::vector<std::string> v;
    for (auto rust_s : val) {
        v.push_back(std::string(rust_s));
    }
    return parcel.WriteStringVector(v);
}

bool WriteString16Vector(Parcel &parcel, rust::slice<const rust::string> val)
{
    std::vector<std::u16string> v;
    for (auto rust_s : val) {
        std::u16string u16string = Str8ToStr16(std::string(rust_s));
        v.push_back(u16string);
    }
    return parcel.WriteString16Vector(v);
}

template<typename T> bool ReadVector(Parcel &parcel, rust::vec<T> &val, bool (Parcel::*ReadVec)(std::vector<T> *))
{
    std::vector<T> v;
    if (!(parcel.*ReadVec)(&v)) {
        return false;
    }
    for (auto i : v) {
        val.push_back(i);
    }
    return true;
}

bool ReadBoolVector(Parcel &parcel, rust::vec<bool> &val)
{
    return ReadVector(parcel, val, &Parcel::ReadBoolVector);
}
bool ReadInt8Vector(Parcel &parcel, rust::vec<int8_t> &val)
{
    return ReadVector(parcel, val, &Parcel::ReadInt8Vector);
}
bool ReadInt16Vector(Parcel &parcel, rust::vec<int16_t> &val)
{
    return ReadVector(parcel, val, &Parcel::ReadInt16Vector);
}
bool ReadInt32Vector(Parcel &parcel, rust::vec<int32_t> &val)
{
    return ReadVector(parcel, val, &Parcel::ReadInt32Vector);
}
bool ReadInt64Vector(Parcel &parcel, rust::vec<int64_t> &val)
{
    return ReadVector(parcel, val, &Parcel::ReadInt64Vector);
}
bool ReadUInt8Vector(Parcel &parcel, rust::vec<uint8_t> &val)
{
    return ReadVector(parcel, val, &Parcel::ReadUInt8Vector);
}
bool ReadUInt16Vector(Parcel &parcel, rust::vec<uint16_t> &val)
{
    return ReadVector(parcel, val, &Parcel::ReadUInt16Vector);
}
bool ReadUInt32Vector(Parcel &parcel, rust::vec<uint32_t> &val)
{
    return ReadVector(parcel, val, &Parcel::ReadUInt32Vector);
}
bool ReadUInt64Vector(Parcel &parcel, rust::vec<uint64_t> &val)
{
    return ReadVector(parcel, val, &Parcel::ReadUInt64Vector);
}
bool ReadFloatVector(Parcel &parcel, rust::vec<float> &val)
{
    return ReadVector(parcel, val, &Parcel::ReadFloatVector);
}
bool ReadDoubleVector(Parcel &parcel, rust::vec<double> &val)
{
    return ReadVector(parcel, val, &Parcel::ReadDoubleVector);
}

bool ReadStringVector(Parcel &parcel, rust::vec<rust::string> &val)
{
    std::vector<std::string> v;
    if (!parcel.ReadStringVector(&v)) {
        return false;
    }
    for (auto s : v) {
        val.push_back(s.data());
    }
    return true;
}

bool ReadString16Vector(Parcel &parcel, rust::vec<rust::string> &val)
{
    std::vector<std::u16string> v;
    if (!parcel.ReadString16Vector(&v)) {
        return false;
    }
    for (auto i : v) {
        val.push_back(i.data());
    }
    return true;
}

} // namespace IpcRust
} // namespace OHOS