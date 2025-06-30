/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

import rpc from "@ohos.rpc";
import { BusinessError } from "@ohos.base"
//import common from '@ohos.app.ability.common';
import fileIo from "@ohos.file.fs";

function testMessageSequence_WriteAndRead_Int() {
    console.log(`into func testMessageSequence_WriteAndRead_Int`);
    let data = rpc.MessageSequence.create();
    console.log(`data gen`);
    try {
        data.writeInt(123);
        console.log(`writeInt success`);
        let res = data.readInt();
        console.log(`readInt success, res is `, res);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }
    console.log(`out func testMessageSequence_WriteAndRead_Int`);
}

function testMessageSequence_WriteAndRead_InterfaceToken() {
    console.log(`into func testMessageSequence_WriteAndRead_InterfaceToken`);
    let data = rpc.MessageSequence.create();
    console.log(`data gen`);
    try {
        data.writeInterfaceToken("this is message in readInterfaceToken");
        console.log(`writeInterfaceToken success`);
        let res = data.readInterfaceToken();
        console.log(`readInterfaceToken success, res is `, res);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }
    console.log(`out func testMessageSequence_WriteAndRead_InterfaceToken`);
}

function testMessageSequence_WriteAndRead_Capacity() {
    console.log(`into func testMessageSequence_WriteAndRead_Capacity`);
    let data = rpc.MessageSequence.create();
    console.log(`data gen`);
    try {
        data.setCapacity(666);
        console.log(`setCapacity success`);
        let res = data.getCapacity();
        console.log(`getCapacity success, res is `, res);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }
    console.log(`out func testMessageSequence_WriteAndRead_Capacity`);
}

function testMessageSequence_WriteAndRead_Exception() {
    console.log(`into func testMessageSequence_WriteAndRead_Exception`);
    let data = rpc.MessageSequence.create();
    console.log(`data gen`);
    try {
        data.writeNoException();
        console.log(`writeNoException success`);
        data.readException();
        console.log(`readException success`);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }
    console.log(`out func testMessageSequence_WriteAndRead_Exception`);
}

function testMessageSequence_WriteAndRead_Long() {
    console.log(`into func testMessageSequence_WriteAndRead_Long`);
    let data = rpc.MessageSequence.create();
    console.log(`data gen`);
    try {
        data.writeLong(9999999999);
        console.log(`writeLong success`);
        let res = data.readLong();
        console.log(`readLong success, res is `, res);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }
    console.log(`out func testMessageSequence_WriteAndRead_Long`);
}

function testMessageSequence_WriteAndRead_Boolean() {
    console.log(`into func testMessageSequence_WriteAndRead_Boolean`);
    let data = rpc.MessageSequence.create();
    console.log(`data gen`);
    try {
        data.writeBoolean(true);
        console.log(`writeBoolean success`);
        let res1 = data.readBoolean();
        console.log(`readBoolean success, res1 is `, res1);
        data.writeBoolean(false);
        console.log(`writeBoolean success`);
        let res2 = data.readBoolean();
        console.log(`readBoolean success, res2 is `, res2);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }
    console.log(`out func testMessageSequence_WriteAndRead_Boolean`);
}

function testMessageSequence_WriteAndRead_String() {
    console.log(`into func testMessageSequence_WriteAndRead_String`);
    let data = rpc.MessageSequence.create();
    console.log(`data gen`);
    try {
        data.writeString("this is in write string");
        console.log(`writeString success`);
        let res = data.readString();
        console.log(`readString success, res is `, res);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }
    console.log(`out func testMessageSequence_WriteAndRead_String`);
}

function testMessageSequence_WriteByteArray() {
    console.log(`into func testMessageSequence_WriteByteArray`);
    let data = rpc.MessageSequence.create();
    console.log(`data gen`);
    try {
        let byteArray: Array<int> = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        data.writeByteArray(byteArray);
        console.log(`writeByteArray success`);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }
    console.log(`out func testMessageSequence_WriteByteArray`);
}

function testMessageSequence_WriteAndRead_IntArray1() {
    console.log(`into func testMessageSequence_WriteAndRead_IntArray1`);
    let data = rpc.MessageSequence.create();
    console.log(`data gen`);
    try {
        let intArray: Array<int> = [11, 22, 33, 44, 55, 66, 77, 88, 99, 100];
        data.writeIntArray(intArray);
        console.log(`writeIntArray success`);
        let res: Array<int> = data.readIntArray();
        console.log(`readIntArray success, res is `, res);
        console.log(`readIntArray success, res.length is `, res.length);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }
    console.log(`out func testMessageSequence_WriteAndRead_IntArray1`);
}

function testMessageSequence_WriteAndRead_IntArray2() {
    console.log(`into func testMessageSequence_WriteAndRead_IntArray2`);
    let data = rpc.MessageSequence.create();
    console.log(`data gen`);
    try {
        let intArray: Array<int> = [121, 212, 323, 414, 525, 616, 77, 88, 99, 100];
        data.writeIntArray(intArray);
        console.log(`writeIntArray success`);
        let array: Array<int> = new Array<int>(intArray.length);
        data.readIntArray(array);
        console.log(`readIntArray success, res is `, array);
        console.log(`readIntArray success, res.length is `, array.length);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }
    console.log(`out func testMessageSequence_WriteAndRead_IntArray2`);
}

function testMessageSequence_WriteAndRead_DoubleArray1() {
    console.log(`into func testMessageSequence_WriteAndRead_DoubleArray1`);
    let data = rpc.MessageSequence.create();
    console.log(`data gen`);
    try {
        let doubleArray: Array<double> = [11.1, 22.2, 33.3, 44.4, 55.5, 66.6, 77.7, 88.8, 99.9, 10.0];
        data.writeDoubleArray(doubleArray);
        console.log(`writeDoubleArray success`);
        let res: Array<double> = data.readDoubleArray();
        console.log(`readDoubleArray success, res is `, res);
        console.log(`readDoubleArray success, res.length is `, res.length);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }
    console.log(`out func testMessageSequence_WriteAndRead_DoubleArray1`);
}

function testMessageSequence_WriteAndRead_DoubleArray2() {
    console.log(`into func testMessageSequence_WriteAndRead_DoubleArray2`);
    let data = rpc.MessageSequence.create();
    console.log(`data gen`);
    try {
        let doubleArray: Array<double> = [121.1, 212.2, 323.3, 414.4, 525.5, 616.6, 77, 88, 99, 100];
        data.writeDoubleArray(doubleArray);
        console.log(`writeDoubleArray success`);
        let array: Array<double> = new Array<double>(doubleArray.length);
        data.readDoubleArray(array);
        console.log(`readDoubleArray success, res is `, array);
        console.log(`readDoubleArray success, res.length is `, array.length);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }
    console.log(`out func testMessageSequence_WriteAndRead_DoubleArray2`);
}

function testMessageSequence_WriteAndRead_StringArray1() {
    console.log(`into func testMessageSequence_WriteAndRead_StringArray1`);
    let data = rpc.MessageSequence.create();
    console.log(`data gen`);
    try {
        let stringArray: Array<string> = ["this ", "is ", "a ", "test ", "string ", "array", "1"];
        data.writeStringArray(stringArray);
        console.log(`writeStringArray success`);
        let res: Array<string> = data.readStringArray();
        console.log(`readStringArray success, res is `, res);
        console.log(`readStringArray success, res.length is `, res.length);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }
    console.log(`out func testMessageSequence_WriteAndRead_StringArray1`);
}

function testMessageSequence_WriteAndRead_StringArray2() {
    console.log(`into func testMessageSequence_WriteAndRead_StringArray2`);
    let data = rpc.MessageSequence.create();
    console.log(`data gen`);
    try {
        let stringArray: Array<string> = ["this ", "is ", "a ", "test ", "string ", "array", "2"];
        data.writeStringArray(stringArray);
        console.log(`writeStringArray success`);
        let array: Array<string> = new Array<string>(stringArray.length);
        data.readStringArray(array);
        console.log(`readStringArray success, res is `, array);
        console.log(`readStringArray success, res.length is `, array.length);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }
    console.log(`out func testMessageSequence_WriteAndRead_StringArray2`);
}


function testMessageSequence_WriteAndRead_BooleanArray1() {
    console.log(`into func testMessageSequence_WriteAndRead_BooleanArray1`);
    let data = rpc.MessageSequence.create();
    console.log(`data gen`);
    try {
        let boolArray: Array<boolean> = [true, false, true, false, true, false, true, false, true, false];
        data.writeBooleanArray(boolArray);
        console.log(`writeBooleanArray success`);
        let res: Array<boolean> = data.readBooleanArray();
        console.log(`readBooleanArray success, res is `, res);
        console.log(`readBooleanArray success, res.length is `, res.length);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }
    console.log(`out func testMessageSequence_WriteAndRead_BooleanArray1`);
}

function testMessageSequence_WriteAndRead_BooleanArray2() {
    console.log(`into func testMessageSequence_WriteAndRead_BooleanArray2`);
    let data = rpc.MessageSequence.create();
    console.log(`data gen`);
    try {
        let boolArray: Array<boolean> = [false, true, false, true, false, true, false, true, false, true];
        data.writeBooleanArray(boolArray);
        console.log(`writeBooleanArray success`);
        let array: Array<boolean> = new Array<boolean>(boolArray.length);
        data.readBooleanArray(array);
        console.log(`readBooleanArray success, res is `, array);
        console.log(`readBooleanArray success, res.length is `, array.length);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }
    console.log(`out func testMessageSequence_WriteAndRead_BooleanArray2`);
}

function testMessageSequence_WriteAndRead_Parcelable() {
    console.log(`into func testMessageSequence_WriteAndRead_Parcelable`);
    class MyParcelable implements rpc.Parcelable {
        num: int = 0;
        str: string = "";
        constructor(num: int, str: string) {
            this.num = num;
            this.str = str;
        }
        marshalling(dataOut: rpc.MessageSequence) {
            dataOut.writeInt(this.num);
            dataOut.writeString(this.str);
            return true;
        }
        unmarshalling(dataIn: rpc.MessageSequence) {
            this.num = dataIn.readInt();
            this.str = dataIn.readString();
            return true;
        }   
    }

    let parcelable = new MyParcelable(1, "this is a test parcelable");
    console.log(`parcelable gen`);
    let data = rpc.MessageSequence.create();
    console.log(`data gen`);
    try {
        data.writeParcelable(parcelable);
        console.log(`writeParcelable success`);
        let res: MyParcelable = new MyParcelable(0, "");
        data.readParcelable(res);
        console.log(`readParcelable success, res.num is `, res.num);
        console.log(`readParcelable success, res.str is `, res.str);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }
    console.log(`out func testMessageSequence_WriteAndRead_Parcelable`);
}

function testMessageSequence_WriteAndRead_ParcelableArray() {
    console.log(`into func testMessageSequence_WriteAndRead_ParcelableArray`);
    class MyParcelable implements rpc.Parcelable {
        num: int = 0;
        str: string = "";
        constructor(num: int, str: string) {
            this.num = num;
            this.str = str;
        }
        marshalling(dataOut: rpc.MessageSequence) {
            dataOut.writeInt(this.num);
            dataOut.writeString(this.str);
            return true;
        }
        unmarshalling(dataIn: rpc.MessageSequence) {
            this.num = dataIn.readInt();
            this.str = dataIn.readString();
            return true;
        }   
    }

    let parcelable1 = new MyParcelable(1, "this is a test parcelable and this is 1");
    let parcelable2 = new MyParcelable(2, "this is a test parcelable and this is 2");
    let parcelable3 = new MyParcelable(3, "this is a test parcelable and this is 3");
    //let a = [parcelable1, parcelable2, parcelable3];
    let a: Array<rpc.Parcelable> = [parcelable1, parcelable2, parcelable3];
    console.log(`parcelable gen`);
    let data = rpc.MessageSequence.create();
    console.log(`data gen`);
    try {
        data.writeParcelableArray(a);
        console.log(`writeParcelableArray success`);
        let b: Array<rpc.Parcelable> = [new MyParcelable(0, ""), new MyParcelable(0, ""), new MyParcelable(0, "")];
        data.readParcelableArray(b);
        console.log(`readParcelable success, b.num is `, b.length);
        console.log(`readParcelable success, b[0].num is `, (b[0] as MyParcelable).num);
        console.log(`readParcelable success, b[0].str is `, (b[0] as MyParcelable).str);
        console.log(`readParcelable success, b[1].num is `, (b[1] as MyParcelable).num);
        console.log(`readParcelable success, b[1].str is `, (b[1] as MyParcelable).str);
        console.log(`readParcelable success, b[2].num is `, (b[2] as MyParcelable).num);
        console.log(`readParcelable success, b[2].str is `, (b[2] as MyParcelable).str);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }
    console.log(`out func testMessageSequence_WriteAndRead_ParcelableArray`);
}

function testMessageSequence_WriteAndRead_RawData_Int32() {
    console.log(`into func testMessageSequence_WriteAndRead_RawData_Int32`);
    let data = rpc.MessageSequence.create();
    console.log(`data gen`);
    let buffer = new ArrayBuffer(4 * 10);
    let int32View = new Int32Array(buffer);
    for (let i = 0; i < int32View.length; i++) {
        int32View[i] = i * 2 + 1;
        if (i % 2 != 0) {
            int32View[i] = -int32View[i];
        }
    }
    let size: int = buffer.byteLength as int;
    console.log(`buffer.byteLength is : `, size);
    
    try {
        data.writeRawDataBuffer(buffer, size);
        console.log(`writeRawDataBuffer success`);
        console.log(`write data is :`, int32View);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }

    try {
        let result = data.readRawDataBuffer(size);
        let readInt32View = new Int32Array(result);
        console.log(`readRawDataBuffer success`);
        console.log(`read data is :`, readInt32View);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }

    console.log(`out func testMessageSequence_WriteAndRead_RawData_Int32`);
}

function testMessageSequence_WriteAndRead_RawData_Uint8() {
    console.log(`into func testMessageSequence_WriteAndRead_RawData_Uint8`);
    let data = rpc.MessageSequence.create();
    console.log(`data gen`);
    let buffer = new ArrayBuffer(1 * 10);
    let uint8View = new Uint8Array(buffer);
    for (let i = 0; i < uint8View.length; i++) {
        uint8View[i] = i * 2 + 1;
    }
    let size: int = buffer.byteLength as int;
    console.log(`buffer.byteLength is : `, size);
    
    try {
        data.writeRawDataBuffer(buffer, size);
        console.log(`writeRawDataBuffer success`);
        console.log(`write data is :`, uint8View);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }

    try {
        let result = data.readRawDataBuffer(size);
        let readUint8View = new Uint8Array(result);
        console.log(`readRawDataBuffer success`);
        console.log(`read data is :`, readUint8View);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }

    console.log(`out func testMessageSequence_WriteAndRead_RawData_Uint8`);
}

function testMessageSequence_WriteAndRead_RawData_Int8() {
    console.log(`into func testMessageSequence_WriteAndRead_RawData_Int8`);
    let data = rpc.MessageSequence.create();
    console.log(`data gen`);
    let buffer = new ArrayBuffer(1 * 10);
    let int8View = new Int8Array(buffer);
    for (let i = 0; i < int8View.length; i++) {
        int8View[i] = i * 2 + 1;
        if (i % 2 != 0) {
            int8View[i] = -int8View[i];
        }
    }
    let size: int = buffer.byteLength as int;
    console.log(`buffer.byteLength is : `, size);
    
    try {
        data.writeRawDataBuffer(buffer, size);
        console.log(`writeRawDataBuffer success`);
        console.log(`write data is :`, int8View);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }

    try {
        let result = data.readRawDataBuffer(size);
        let readInt8View = new Int8Array(result);
        console.log(`readRawDataBuffer success`);
        console.log(`read data is :`, readInt8View);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }

    console.log(`out func testMessageSequence_WriteAndRead_RawData_Int8`);
}

function testMessageSequence_WriteAndRead_RawData_Float32() {
    console.log(`into func testMessageSequence_WriteAndRead_RawData_Float32`);
    let data = rpc.MessageSequence.create();
    console.log(`data gen`);
    let buffer = new ArrayBuffer(4 * 10);
    let float32View = new Float32Array(buffer);
    for (let i = 0; i < float32View.length; i++) {
        float32View[i] = i * 2 + i * 1.0 / 10;
        if (i % 2 != 0) {
            float32View[i] = -float32View[i];
        }
    }
    let size: int = buffer.byteLength as int;
    console.log(`buffer.byteLength is : `, size);
    
    try {
        data.writeRawDataBuffer(buffer, size);
        console.log(`writeRawDataBuffer success`);
        console.log(`write data is :`, float32View);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }

    try {
        let result = data.readRawDataBuffer(size);
        let readFloat32View = new Float32Array(result);
        console.log(`readRawDataBuffer success`);
        console.log(`read data is :`, readFloat32View);
    } catch (err) {
        let error: BusinessError = err as BusinessError;
        console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
    }

    console.log(`out func testMessageSequence_WriteAndRead_RawData_Float32`);
}

function testMessageSequence_WriteAndRead_Ashmem() {
    console.log(`into func testMessageSequence_WriteAndRead_Ashmem`);
    let data = rpc.MessageSequence.create();
    console.log(`data gen`);
    try {
        let ashmem = rpc.Ashmem.create("ashmem", 1024*1024);
        let size = ashmem.getAshmemSize();
        console.log(`ashmem.getAshmemSize() is : `, size);
        data.writeAshmem(ashmem);
        console.log(`writeAshmem success`);
    } catch (err) {
        //let error: BusinessError = err as BusinessError;
        //console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
        console.log(`catch error`, err);
    }

    try {
        let res = data.readAshmem();
        console.log(`readAshmem success`);
        console.log(`res size is :`, res.getAshmemSize());
    } catch (err) {
        //let error: BusinessError = err as BusinessError;
        //console.log(`catch error, code is ${error.code}, msg is ${error.message}`);
        console.log(`catch error`, err);
    }

    console.log(`out func testMessageSequence_WriteAndRead_Ashmem`);
}

function testMessageOption() {
    console.log(`into func testMessageOption`);
    let option1 = new rpc.MessageOption();
    let res1 = option1.isAsync();
    console.log(`res1 is : `, res1);// false

    let option2 = new rpc.MessageOption(true);
    let res2 = option2.isAsync();
    console.log(`res2 is : `, res2);// true
/*
    try {
        console.log(`rpc.MessageOption.TF_SYNC`, rpc.MessageOption.tF_SYNC);
        console.log(`rpc.MessageOption.TF_ASYNC`, rpc.MessageOption.tF_ASYNC);
        console.log(`rpc.MessageOption.TF_WAIT_TIME`, rpc.MessageOption.tF_WAIT_TIME);
        let option3 = new rpc.MessageOption(rpc.MessageOption.tF_SYNC, rpc.MessageOption.tF_WAIT_TIME);
        let res3 = option3.isAsync();
        console.log(`res3 is : `, res3);// false
    } catch (err) {
        console.log(`err: `, err);
    }

    try {
        let option4 = new rpc.MessageOption(rpc.MessageOption.tF_ASYNC, rpc.MessageOption.tF_WAIT_TIME);
        let res4 = option4.isAsync();
        console.log(`res4 is : `, res4);// true
    } catch (err) {
        console.log(`err: `, err);
    }
*/
    console.log(`out func testMessageOption`);
}

function testAshmem() {
    console.log(`into func testAshmem`);

    let ashmem1 = rpc.Ashmem.create("ashmem", 1024*1024);
    let ashmem2 = rpc.Ashmem.create(ashmem1);
    let size1 = ashmem1.getAshmemSize();
    console.log(`size1 is : `, size1);
    let size2 = ashmem2.getAshmemSize();
    console.log(`size2 is : `, size2);

    ashmem1.mapReadWriteAshmem();

    console.log(`out func testAshmem`);
}

function testIPCSkeleton_getCallingPid() {
    console.log(`into func testIPCSkeleton_getCallingPid`);

    let callerPid = rpc.IPCSkeleton.getCallingPid();
    console.log(`callerPid is : `, callerPid);

    console.log(`out func testIPCSkeleton_getCallingPid`);
}

function testIPCSkeleton_getCallingUid() {
    console.log(`into func testIPCSkeleton_getCallingUid`);

    let callerUid = rpc.IPCSkeleton.getCallingUid();
    console.log(`callerUid is : `, callerUid);

    console.log(`out func testIPCSkeleton_getCallingUid`);
}

function testIPCSkeleton_getCallingTokenId() {
    console.log(`into func testIPCSkeleton_getCallingTokenId`);

    let callerTokenId = rpc.IPCSkeleton.getCallingTokenId();
    console.log(`callerTokenId is : `, callerTokenId);

    console.log(`out func testIPCSkeleton_getCallingTokenId`);
}

function testMessageSequence_WriteAndRead_FileDescriptor() {
    console.log(`into func testMessageSequence_WriteAndRead_FileDescriptor`);
    let data = rpc.MessageSequence.create();
    console.log(`data gen`);
    try {
        //const context = getContext(this) as common.UIAbilityContext;
        //let basePath = context.fileDir;
        //console.log(`basePath is : `, basePath);
        //let fileP = "/file.txt";
        //console.log(`fileP is : `, fileP);
        //let filePath = basePath + fileP;
        //console.log(`filePath is : `, filePath);
        //let file = fileIo.openSync(filePath, fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.CREATE);
        //console.log(`open file success`);
        //console.log(`file is : `, file);
        //console.log(`file descriptor is : `, file.fd);
        //let fd = file.fd;
        //data.writeFileDescriptor(fd);
        //console.log(`writeFileDescriptor success`);
    } catch (err) {
        console.log(`catch error:`, err);
    }

    try {
        //let res = data.readFileDescriptor();
        //console.log(`readFileDescriptor success`);
        //console.log(`res fd is : `, res);
    } catch (err) {
        console.log(`catch read error:`, err);
    }

    console.log(`out func testMessageSequence_WriteAndRead_FileDescriptor`);
}

function testMessageSequence_closeFileDescriptor() {
    console.log(`into func testMessageSequence_closeFileDescriptor`);
    let data = rpc.MessageSequence.create();
    console.log(`data gen`);
    try {
        let filePath = "/data/local/tmp/file.txt";
        console.log(`filePath is : `, filePath);
        let file = fileIo.openSync(filePath, fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.CREATE);
        console.log(`open file success`);
        console.log(`file is : `, file);
        //console.log(`file descriptor is : `, file.fd);
        rpc.MessageSequence.closeFileDescriptor(4);
        console.log(`closeFileDescriptor success`)
    } catch (err) {
        console.log(`catch error:`, err);
    }

    console.log(`out func testMessageSequence_closeFileDescriptor`);
}

function testMessageSequence_WriteAndRead_RemoteObject() {
    console.log(`into func testMessageSequence_WriteAndRead_RemoteObject`);

    class TestRemoteObject extends rpc.RemoteObject {
        constructor(descriptor: string) {
            super(descriptor);
        }
    }
    try {
        let data = rpc.MessageSequence.create();
        console.log(`data gen`);
        let testRemtoeObject = new TestRemoteObject("testObject");
        console.log(`testRemoteObject gen`);
        data.writeRemoteObject(testRemtoeObject);
        console.log(`writeRemoteObject success`);
        let res = data.readRemoteObject();
        console.log(`readRemoteObject success, res is : `, res);
    } catch (err) {
        console.log(`catch error:`, err);
    }
    console.log(`out func testMessageSequence_WriteAndRead_RemoteObject`);
}

function test_getcallxxx_in_remoteObject() {
    console.log(`into func test_getcallxxx_in_remoteObject`);

    class TestRemoteObject extends rpc.RemoteObject {
        constructor(descriptor: string) {
            super(descriptor);
        }
    }
    try {
        console.log(`tyr to zhijie on`);
        let testRemtoeObject = new TestRemoteObject("testObject");
        console.log(`get RemoteObject getDescriptor is `, testRemtoeObject.getDescriptor());
        console.log(`get RemoteObject getCallingPid is `, testRemtoeObject.getCallingPid());
        console.log(`get RemoteObject getCallingUid is `, testRemtoeObject.getCallingUid());
    } catch (err) {
        console.log(`catch error:`, err);
    }
    console.log(`out func test_getcallxxx_in_remoteObject`);
}

function testMessageSequence_WriteAndRead_Proxy() {
    console.log(`into func testMessageSequence_WriteAndRead_Proxy`);

    
    console.log(`out func testMessageSequence_WriteAndRead_Proxy`);
}

function test_registerDeathRecipient() {
    console.log(`into func test_registerDeathRecipient`);

    class MyDeathRecipient implements rpc.DeathRecipient {
        onRemoteDied(): void {
            console.log(`into MyDeathRecipient onRemoteDied in js`);
        }
    }

    try {
        console.log(`new MyDeathRecipient`);
        let deathRecipient = new MyDeathRecipient();
        console.log(`new MyDeathRecipient success`);

        let samgr = rpc.IPCSkeleton.getContextObject();
        console.log(`get samgr success`);

        console.log(`before into registerDeathRecipient`);
        samgr.registerDeathRecipient(deathRecipient, 0);
        console.log(`after into registerDeathRecipient`);
        samgr.unregisterDeathRecipient(deathRecipient, 0);
        console.log(`after into unregisterDeathRecipient`);
    } catch (err) {
        console.log(`catch error:`, err);
    }
    
    console.log(`out func test_registerDeathRecipient`);
}

function test_RemoteObject_SendMessageRequest() {
    console.log(`into func test_RemoteObject_SendMessageRequest`);

    class TestRemoteObject extends rpc.RemoteObject {
        constructor(descriptor: string) {
            super(descriptor);
        }

        onRemoteMessageRequest(code: int, data: rpc.MessageSequence, reply: rpc.MessageSequence, options: rpc.MessageOption): boolean {
            console.log(`into onRemoteMessageRequest`);
            if (code == 1) {
                console.log(`code is 1`);
                let res = data.readInt();
                console.log(`in onRemoteMessageRequest readInt success, res is : `, res);
                reply.writeInt(999);
                console.log(`in onRemoteMessageRequest writeInt success`);
                return true;
            } else {
                console.log(`code others: `, code);
                return false;
            }
        }
    }

    

    try {
        let testRemtoeObject = new TestRemoteObject("testObject");
        console.log(`testRemoteObject gen`);
        console.log(`begin to send`);
        let data = rpc.MessageSequence.create();
        console.log(`data gen`);
        data.writeInt(123);
        console.log(`writeInt success`);
        let reply = rpc.MessageSequence.create();
        let option = new rpc.MessageOption();
        console.log(`MessageOption gen`);

        await testRemtoeObject.sendMessageRequest(1, data, reply, option)
        .then((ret: rpc.RequestResult) => {
            console.log(`sendMessageRequest success, errCode is : `, ret.errCode);
            console.log(`sendMessageRequest success, ret is : `, ret);
        }).catch((err) => {
            console.log(`err in catch: `, err);
        });
    } catch (err) {
        console.log(`catch error:`, err);
    }
    
    console.log(`out func test_RemoteObject_SendMessageRequest`);
}

function main() {
    console.log(`into main`);
    console.log(`*************************************************`);
    testMessageSequence_WriteAndRead_Int();
    console.log(`*************************************************`);
    testMessageSequence_WriteAndRead_InterfaceToken();
    console.log(`*************************************************`);
    testMessageSequence_WriteAndRead_Capacity();
    console.log(`*************************************************`);
    testMessageSequence_WriteAndRead_Exception();
    console.log(`*************************************************`);
    testMessageSequence_WriteAndRead_Long();
    console.log(`*************************************************`);
    testMessageSequence_WriteAndRead_Boolean();
    console.log(`*************************************************`);
    testMessageSequence_WriteAndRead_String();
    console.log(`*************************************************`);
    testMessageSequence_WriteByteArray();
    console.log(`*************************************************`);
    testMessageSequence_WriteAndRead_IntArray1();
    console.log(`*************************************************`);
    testMessageSequence_WriteAndRead_IntArray2();
    console.log(`*************************************************`);
    testMessageSequence_WriteAndRead_DoubleArray1();
    console.log(`*************************************************`);
    testMessageSequence_WriteAndRead_DoubleArray2();
    console.log(`*************************************************`);
    testMessageSequence_WriteAndRead_StringArray1();
    console.log(`*************************************************`);
    testMessageSequence_WriteAndRead_StringArray2();
    console.log(`*************************************************`);
    testMessageSequence_WriteAndRead_BooleanArray1();
    console.log(`*************************************************`);
    testMessageSequence_WriteAndRead_BooleanArray2();
    console.log(`*************************************************`);
    testMessageSequence_WriteAndRead_Parcelable();
    console.log(`*************************************************`);
    testMessageSequence_WriteAndRead_ParcelableArray();
    console.log(`*************************************************`);
    testMessageSequence_WriteAndRead_RawData_Int32();
    console.log(`*************************************************`);
    testMessageSequence_WriteAndRead_RawData_Uint8();
    console.log(`*************************************************`);
    testMessageSequence_WriteAndRead_RawData_Int8();
    console.log(`*************************************************`);
    testMessageSequence_WriteAndRead_RawData_Float32();
    console.log(`*************************************************`);
    testMessageSequence_WriteAndRead_Ashmem();
    console.log(`*************************************************`);
    testMessageOption();
    console.log(`*************************************************`);
    testAshmem();
    console.log(`*************************************************`);
    testIPCSkeleton_getCallingPid();
    console.log(`*************************************************`);
    testIPCSkeleton_getCallingUid();
    console.log(`*************************************************`);
    testIPCSkeleton_getCallingTokenId();
    console.log(`*************************************************`);
    //testMessageSequence_WriteAndRead_FileDescriptor();
    console.log(`*************************************************`);
    //testMessageSequence_closeFileDescriptor();
    console.log(`out main`);
}