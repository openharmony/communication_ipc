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

#ifndef IPC_RUST_CXX_PARCEL_H
#define IPC_RUST_CXX_PARCEL_H

#include <cstddef>
#include <cstdint>
#include <memory>

#include "cxx.h"
#include "message_option.h"
#include "message_parcel.h"
#include "remote_object_wrapper.h"

namespace OHOS {

namespace IpcRust {

std::unique_ptr<MessageParcel> NewMessageParcel();
std::unique_ptr<MessageOption> NewMessageOption();

Parcel const *AsParcel(const MessageParcel &msgParcel);

Parcel *AsParcelMut(MessageParcel &msgParcel);

bool WriteInterfaceToken(MessageParcel &msgParcel, const rust::str name);
rust::string ReadInterfaceToken(MessageParcel &msgParcel);

bool WriteBuffer(MessageParcel &msgParcel, rust::slice<const uint8_t> buffer);
bool ReadBuffer(MessageParcel &msgParcel, size_t len, rust::vec<uint8_t> &buffer);

bool WriteString(Parcel &parcel, const rust::str val);
bool ReadString(Parcel &parcel, rust::string &val);

bool WriteString16(Parcel &parcel, const rust::str val);
rust::string ReadString16(Parcel &parcel);

bool WriteString16Vec(Parcel &parcel, const rust::vec<rust::string &> &v);
rust::vec<rust::string> ReadString16Vec(Parcel &parcel);

bool WriteBoolVector(Parcel &parcel, rust::slice<const bool> val);
bool WriteInt8Vector(Parcel &parcel, rust::slice<const int8_t> val);
bool WriteInt16Vector(Parcel &parcel, rust::slice<const int16_t> val);
bool WriteInt32Vector(Parcel &parcel, rust::slice<const int32_t> val);
bool WriteInt64Vector(Parcel &parcel, rust::slice<const int64_t> val);
bool WriteUInt8Vector(Parcel &parcel, rust::slice<const uint8_t> val);
bool WriteUInt16Vector(Parcel &parcel, rust::slice<const uint16_t> val);
bool WriteUInt32Vector(Parcel &parcel, rust::slice<const uint32_t> val);
bool WriteUInt64Vector(Parcel &parcel, rust::slice<const uint64_t> val);
bool WriteFloatVector(Parcel &parcel, rust::slice<const float> val);
bool WriteDoubleVector(Parcel &parcel, rust::slice<const double> val);
bool WriteStringVector(Parcel &parcel, rust::slice<const rust::string> val);
bool WriteString16Vector(Parcel &parcel, rust::slice<const rust::string> val);

bool ReadBoolVector(Parcel &parcel, rust::vec<bool> &val);
bool ReadInt8Vector(Parcel &parcel, rust::vec<int8_t> &val);
bool ReadInt16Vector(Parcel &parcel, rust::vec<int16_t> &val);
bool ReadInt32Vector(Parcel &parcel, rust::vec<int32_t> &val);
bool ReadInt64Vector(Parcel &parcel, rust::vec<int64_t> &val);
bool ReadUInt8Vector(Parcel &parcel, rust::vec<uint8_t> &val);
bool ReadUInt16Vector(Parcel &parcel, rust::vec<uint16_t> &val);
bool ReadUInt32Vector(Parcel &parcel, rust::vec<uint32_t> &val);
bool ReadUInt64Vector(Parcel &parcel, rust::vec<uint64_t> &val);
bool ReadFloatVector(Parcel &parcel, rust::vec<float> &val);
bool ReadDoubleVector(Parcel &parcel, rust::vec<double> &val);
bool ReadStringVector(Parcel &parcel, rust::vec<rust::string> &val);
bool ReadString16Vector(Parcel &parcel, rust::vec<rust::string> &val);

bool WriteRemoteObject(MessageParcel &msgParcel, std::unique_ptr<IRemoteObjectWrapper> object);
std::unique_ptr<IRemoteObjectWrapper> ReadRemoteObject(MessageParcel &msgParcel);

} // namespace IpcRust
} // namespace OHOS

#endif
