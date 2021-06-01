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

#ifndef OHOS_ASSIST_TEST_SERVICE_H
#define OHOS_ASSIST_TEST_SERVICE_H

#include "iremote_broker.h"
#include "iremote_proxy.h"

namespace OHOS {
class IAssistTestService : public IRemoteBroker {
public:
    enum {
        TEST_PARCEL_INT32 = 0,
        TEST_PARCEL_UINT32,
        TEST_PARCEL_INT64,
        TEST_PARCEL_UINT64,
        TEST_PARCEL_FLOAT,
        TEST_PARCEL_DOUBLE,
        TEST_PARCEL_UINTPTR,
        TEST_PARCEL_BOOL,
        TEST_PARCEL_CHAR,
        TEST_PARCEL_BYTE,
        TEST_PARCEL_CSTRING = 10,
        TEST_PARCEL_STRING8,
        TEST_PARCEL_STRING16,
        TEST_PARCEL_STRONGBINDER,
        TEST_PARCEL_WEAKBINDER,
        TEST_PARCEL_UINT8_FROM_UINT16,
        WRITE_BYTEVECTOR_UNIQUE_PRT_INT8_CODE,
        TEST_PARCEL_INT8_VECTOR,
        WRITE_BYTEVECTOR_UNIQUE_PRT_U_INT8_CODE,
        TEST_PARCEL_UINT8_VECTOR,
        WRITE_INT32_VECTOR_UNIQUE_PRT_CODE = 20,
        TEST_PARCEL_INT32_VECTOR,
        WRITE_INT64_VECTOR_UNIQUE_PRT_CODE,
        TEST_PARCEL_INT64_VECTOR,
        WRITE_UINT64_VECTOR_UNIQUE_PRT_CODE,
        TEST_PARCEL_UINT64_VECTOR,
        WRITE_FLOAT_UNIQUE_PTR_CODE,
        TEST_PARCEL_FLOAT_VECTOR,
        WRITE_DOUBLE_UNIQUE_PTR_CODE,
        TEST_PARCEL_DOUBLE_VECTOR,
        WRITE_BOOL_UNIQUE_PTR_CODE = 30,
        TEST_PARCEL_BOOL_VECTOR,
        WRITE_CHAR_UNIQUE_PTR_CODE,
        TEST_PARCEL_CHAR_VECTOR,
        WRITE_STRING16_VECTOR_UNIQUE_PTR_CODE,
        TEST_PARCEL_STRING16_VECTOR,
        WRITE_UTF8_VECTOR_FROM_UNT16_VECTOR_UNIQUE_PTR_CODE,
        WRITE_UTF8_VECTOR_FROM_UNT16_VECTOR_VECTOR_CODE,
        WRITE_STRONGBINDERVECTOR_UNIQUE_PTR_CODE,
        WRITE_STRONGBINDERVECTOR_VECTOR_CODE,
        WRITE_MAP_CODE = 40,
        WRITE_NULLABLE_MAP_CODE,
        WRITE_NATIVE_HANDLE_CODE,
        WRITE_EXCEPTION_CODE,
        WRITE_FILE_DESCRIPTOR_CODE,
        WRITE_PARCEL_FILE_DESCRIPTOR_CODE,
        WRITE_UNIQUE_FILE_DESCRIPTOR_CODE,
        WRITE_UNIQUE_FILE_DESCRIPTOR_VECTOR_UNIQUE_PTR_CODE,
        WRITE_UNIQUE_FILE_DESCRIPTOR_VECTOR_VECTOR_CODE = 48,
        WRITE_INVALID,
    };
public:
    IAssistTestService() = default;
    virtual ~IAssistTestService() = default;
    virtual bool TestParcelBool(bool value) = 0;
    virtual int16_t TestParcelChar(int16_t value) = 0;
    virtual int32_t TestParcelInt32(int32_t value) = 0;
    virtual int64_t TestParcelInt64(int64_t value) = 0;
    virtual uint8_t TestParcelByte(uint8_t value) = 0;
    virtual uint32_t TestParcelUint32(uint32_t value) = 0;
    virtual uint64_t TestParcelUint64(uint64_t value) = 0;
    virtual float TestParcelFloat(float value) = 0;
    virtual double TestParcelDouble(double value) = 0;
    virtual const char *TestParcelCString(const char *value) = 0;
    virtual const std::string TestParcelString(const std::string& value) = 0;
    virtual const std::u16string TestParcelString16(const std::u16string& val) = 0;
    virtual bool TestParcelBoolVector() = 0;
    virtual bool TestParcelInt8Vector() = 0;
    virtual bool TestParcelUint8Vector() = 0;
    virtual bool TestParcelCharVector() = 0;
    virtual bool TestParcelInt64Vector() = 0;
    virtual bool TestParcelUint64Vector() = 0;
    virtual bool TestParcelInt32Vector() = 0;
    virtual bool TestParcelFloatVector() = 0;
    virtual bool TestParcelDoubleVector() = 0;
    virtual bool TestParcelString16Vector() = 0;
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"test.ipc.IAssistTestService");
};

class AssistTestServiceProxy : public IRemoteProxy<IAssistTestService> {
public:
    explicit AssistTestServiceProxy(const sptr<IRemoteObject>& object);
    ~AssistTestServiceProxy();

    bool TestParcelBool(bool value) override;
    int16_t TestParcelChar(int16_t value) override;
    int32_t TestParcelInt32(int32_t value) override;
    int64_t TestParcelInt64(int64_t value) override;
    uint8_t TestParcelByte(uint8_t value) override;
    uint32_t TestParcelUint32(uint32_t value) override;
    uint64_t TestParcelUint64(uint64_t value) override;
    float TestParcelFloat(float value) override;
    double TestParcelDouble(double value) override;
    const char *TestParcelCString(const char *value) override;
    const std::string TestParcelString(const std::string& value) override;
    const std::u16string TestParcelString16(const std::u16string& val) override;
    bool TestParcelBoolVector() override;
    bool TestParcelInt8Vector() override;
    bool TestParcelUint8Vector() override;
    bool TestParcelCharVector() override;
    bool TestParcelInt64Vector() override;
    bool TestParcelUint64Vector() override;
    bool TestParcelInt32Vector() override;
    bool TestParcelFloatVector() override;
    bool TestParcelDoubleVector() override;
    bool TestParcelString16Vector() override;
private:
    static inline BrokerDelegator<AssistTestServiceProxy> delegator_;
};
} // namespace OHOS
#endif // OHOS_ASSIST_TEST_SERVICE_H
