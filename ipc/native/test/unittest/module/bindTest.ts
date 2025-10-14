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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect, TestType, Size, Level } from '@ohos/hypium';
import { rpc } from '@kit.IPCKit';
import TestService from "./testService";
import { BusinessError } from '@kit.BasicServicesKit';
import { fileIo } from '@kit.CoreFileKit';
import { common } from '@kit.AbilityKit';

let logTag = "[IpcClient_log:]";
let gIRemoteObject: rpc.IRemoteObject;

function checkResult(num:number, str:string) {
  console.info(logTag + "checkResult is success");
  expect(num).assertEqual(123);
  expect(str).assertEqual("rpcListenerTest");
};

class TestListener extends rpc.RemoteObject {
  checkResult:Function;
  constructor(descriptor: string, checkResult: Function) {
    super(descriptor);
    this.checkResult = checkResult;
  }
  onRemoteMessageRequest(code: number, data: rpc.MessageSequence, reply: rpc.MessageSequence, option: rpc.MessageOption): boolean | Promise<boolean> {
    let result = false;
    if (code === 1) {
      console.info(logTag + "onRemoteRequest called, descriptor: " + this.getDescriptor());
      result = true;
    } else {
      console.info(logTag + "unknown code: " + code);
    }
    let _checkResult: Function = this.checkResult;
    let _num: number = data.readInt();
    let _str: string = data.readString();
    _checkResult(_num, _str);
    console.info(logTag + "result:" + result);
    return result;
  }
}

class TestRemoteObject extends rpc.RemoteObject {
  constructor(descriptor: string) {
    super(descriptor);
    this.modifyLocalInterface(this, descriptor);
  }
  asObject(): rpc.IRemoteObject {
    return this;
  }
}

class MySequenceable implements rpc.Parcelable {
  num: number = 0;
  str: string = '';
  constructor(num: number, str: string) {
    this.num = num;
    this.str = str;
  }
  marshalling(messageSequence: rpc.MessageSequence): boolean {
    messageSequence.writeInt(this.num);
    messageSequence.writeString(this.str);
    return true;
  }
  unmarshalling(messageSequence: rpc.MessageSequence): boolean {
    this.num = messageSequence.readInt();
    this.str = messageSequence.readString();
    return true;
  }
}

function isEqualArray(arr1: number[] | boolean[] | string[], arr2: number[] | boolean[] | string[]){
  return Array.isArray(arr1) &&
  Array.isArray(arr2) &&
    arr1.length === arr2.length &&
    JSON.stringify(arr1) === JSON.stringify(arr2)
}

function isEqualArrayBuffer(
    arr1: Int8Array | Uint8Array | Int16Array | Uint16Array | Int32Array | Uint32Array | Float32Array | Float64Array,
    arr2: Int8Array | Uint8Array | Int16Array | Uint16Array | Int32Array | Uint32Array | Float32Array | Float64Array
): boolean {
    // 检查两个参数是否都是 TypedArray
    if (!ArrayBuffer.isView(arr1) || !ArrayBuffer.isView(arr2)) {
        return false;
    }

    // 检查长度是否相同
    if (arr1.length !== arr2.length) {
        return false;
    }

    // 直接比较底层字节数据
    const view1 = new Uint8Array(arr1.buffer, arr1.byteOffset, arr1.byteLength);
    const view2 = new Uint8Array(arr2.buffer, arr2.byteOffset, arr2.byteLength);

    // 逐个字节比较
    for (let i = 0; i < view1.length; i++) {
        if (view1[i] !== view2[i]) {
            return false;
        }
    }
    return true;
}

class TestProxy {
  remote: rpc.IRemoteObject;
  constructor(remote: rpc.IRemoteObject) {
    this.remote = remote;
  }
  asObject() {
    return this.remote;
  }
}

class MyregisterDeathRecipient implements rpc.DeathRecipient {
  onRemoteDied() {
    console.info("server died");
  }
}

export default function ActsRpcClientEtsTest() {
  describe('ActsRpcClientEtsTest', () => {
    console.info("-----------------------SUB_DSoftbus_IPC_API_Stage_MessageSequence_Test is starting-----------------------");
    const K = 1024;
    const M = 1024 * 1024;
    const G = 1024 * 1024 * 1024;
    const CODE_INTERFACETOKEN = 1;
    const CODE_WRITE_STRING = 2;
    const CODE_WRITE_INT = 3;
    const CODE_ALL_TYPE = 4;
    const CODE_WRITE_BYTE = 5;
    const CODE_WRITE_BYTE_MULTI = 6;
    const CODE_WRITE_SHORT = 7;
    const CODE_WRITE_SHORT_MULTI = 8;
    const CODE_WRITE_INT_MULTI = 9;
    const CODE_WRITE_LONG = 10;
    const CODE_WRITE_FLOAT = 11;
    const CODE_WRITE_DOUBLE = 12;
    const CODE_WRITE_BOOLEAN = 13;
    const CODE_WRITE_CHAR = 14;
    const CODE_WRITE_SEQUENCEABLE = 15;
    const CODE_WRITE_BYTEARRAY = 16;
    const CODE_WRITE_SHORTARRAY = 17;
    const CODE_WRITE_INTARRAY = 18;
    const CODE_WRITE_LONGARRAY = 20;
    const CODE_WRITE_FLOATARRAY = 21;
    const CODE_WRITE_DOUBLEARRAY = 22;
    const CODE_WRITE_BOOLEANARRAY = 23
    const CODE_WRITE_CHARARRAY = 24;
    const CODE_WRITE_STRINGARRAY = 25;
    const CODE_WRITE_NOEXCEPTION= 26;
    const CODE_WRITE_SEQUENCEABLEARRAY = 27;
    const CODE_ALL_ARRAY_TYPE = 28;
    const CODE_WRITE_REMOTEOBJECTARRAY = 29;
    const CODE_WRITE_REMOTEOBJECTARRAY_1 = 30;
    const CODE_WRITE_REMOTEOBJECTARRAY_2 = 31;
    const CODE_FILESDIR = 32;
    const CODE_WRITE_ARRAYBUFFER = 33;

    beforeAll(async () => {
      console.info(logTag + 'beforeAll called');
      let testservice = new TestService();
      await testservice.toConnectAbility();
      gIRemoteObject = testservice.getRemoteproxy();
      console.info(logTag + 'toConnectAbility is getRemoteproxy success' + gIRemoteObject);
    })
    beforeEach(() => {
      console.info(logTag + 'beforeEach called');
    })
    afterEach(() => {
      console.info(logTag + 'afterEach called');
    })
    afterAll(() => {
      console.info(logTag + 'afterAll called');
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1270
    * @tc.name    : test Test the cross process transmission of messageparcel.
    *             After receiving the reply message in promise, read various types of arrays in order
    * @tc.desc    : Function test
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1270", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1270---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            console.info("SUB_DSoftbus_IPC_API_MessageParcel_1270: create object successfully.");
            var reply = rpc.MessageParcel.create();
            var option = new rpc.MessageOption();
            expect(data.writeByteArray([1, 2, 3])).assertTrue();
            expect(data.writeShortArray([4, 5, 6])).assertTrue();
            expect(data.writeIntArray([7, 8, 9])).assertTrue();
            expect(data.writeLongArray([10, 11, 12])).assertTrue();
            expect(data.writeFloatArray([1.1, 1.2, 1.3])).assertTrue();
            expect(data.writeDoubleArray([2.1, 2.2, 2.3])).assertTrue();
            expect(data.writeBooleanArray([true, true, false])).assertTrue();
            expect(data.writeCharArray([10, 20, 30])).assertTrue();
            expect(data.writeStringArray(['abc', 'seggg'])).assertTrue();
            let a = [new MySequenceable(1, "aaa"), new MySequenceable(2, "bbb"),
            new MySequenceable(3, "ccc")];
            expect(data.writeSequenceableArray(a)).assertTrue();
            gIRemoteObject.sendRequest(CODE_ALL_ARRAY_TYPE, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                assertArrayElementEqual(result.reply.readByteArray(),[1, 2, 3]);
                assertArrayElementEqual(result.reply.readShortArray(),[4, 5, 6]);
                assertArrayElementEqual(result.reply.readIntArray(),[7, 8, 9]);
                assertArrayElementEqual(result.reply.readLongArray(),[10, 11, 12]);
                assertArrayElementEqual(result.reply.readFloatArray(),[1.1, 1.2, 1.3]);
                assertArrayElementEqual(result.reply.readDoubleArray(),[2.1, 2.2, 2.3]);
                assertArrayElementEqual(result.reply.readBooleanArray(),[true, true, false]);
                assertArrayElementEqual(result.reply.readCharArray(),[65, 97, 122]);
                assertArrayElementEqual(result.reply.readStringArray(),['abc', 'seggg']);
                let b = [new MySequenceable(null, null), new MySequenceable(null, null),
                new MySequenceable(null, null)];
                result.reply.readSequenceableArray(b);
                for (let i = 0; i < b.length; i++) {
                    expect(b[i].str).assertEqual(a[i].str);
                    expect(b[i].num).assertEqual(a[i].num);
                }
            });
            data.reclaim();
            reply.reclaim();
            done();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel_1270:error = " + error);
        }
        sleep(2000);
        data.reclaim();
        reply.reclaim();
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1270---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1280
    * @tc.name    : test Test messageparcel cross process delivery. After receiving the reply message in promise,
    *             the client constructs an empty array in sequence and reads the data from the reply message
    *             into the corresponding array
    * @tc.desc    : Function test
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1280", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1280---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            console.info("SUB_DSoftbus_IPC_API_MessageParcel_1280: create object successfully.");
            var reply = rpc.MessageParcel.create();
            var option = new rpc.MessageOption();
            expect(data.writeByteArray([1, 2, 3])).assertTrue();
            expect(data.writeShortArray([4, 5, 6])).assertTrue();
            expect(data.writeIntArray([7, 8, 9])).assertTrue();
            expect(data.writeLongArray([10, 11, 12])).assertTrue();
            expect(data.writeFloatArray([1.1, 1.2, 1.3])).assertTrue();
            expect(data.writeDoubleArray([2.1, 2.2, 2.3])).assertTrue();
            expect(data.writeBooleanArray([true, true, false])).assertTrue();
            expect(data.writeCharArray([10, 20, 30])).assertTrue();
            expect(data.writeStringArray(['abc', 'seggg'])).assertTrue();
            let a = [new MySequenceable(1, "aaa"), new MySequenceable(2, "bbb"),
            new MySequenceable(3, "ccc")];
            expect(data.writeSequenceableArray(a)).assertTrue();
            gIRemoteObject.sendRequest(CODE_ALL_ARRAY_TYPE, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                let ByteArray = new Array();
                result.reply.readByteArray(ByteArray);
                assertArrayElementEqual(ByteArray,[1, 2, 3]);
                let ShortArray = new Array();
                result.reply.readShortArray(ShortArray);
                assertArrayElementEqual(ShortArray,[4, 5, 6]);
                let IntArray = new Array();
                result.reply.readIntArray(IntArray);
                    assertArrayElementEqual(IntArray,[7, 8, 9]);
                let LongArray = new Array();
                result.reply.readLongArray(LongArray);
                    assertArrayElementEqual(LongArray,[10, 11, 12]);
                let FloatArray = new Array();
                result.reply.readFloatArray(FloatArray);
                assertArrayElementEqual(FloatArray,[1.1, 1.2, 1.3]);
                let DoubleArray = new Array();
                result.reply.readDoubleArray(DoubleArray);
                assertArrayElementEqual(DoubleArray,[2.1, 2.2, 2.3]);
                let BooleanArray = new Array();
                result.reply.readBooleanArray(BooleanArray);
                assertArrayElementEqual(BooleanArray,[true, true, false]);
                let CharArray = new Array();
                result.reply.readCharArray(CharArray);
                assertArrayElementEqual(CharArray,[65, 97, 122]);
                let StringArray = new Array();
                result.reply.readStringArray(StringArray);
                assertArrayElementEqual(StringArray,['abc', 'seggg']);
                let b = [new MySequenceable(null, null), new MySequenceable(null, null),
                new MySequenceable(null, null)];
                result.reply.readSequenceableArray(b);
                for (let i = 0; i < b.length; i++) {
                    expect(b[i].str).assertEqual(a[i].str);
                    expect(b[i].num).assertEqual(a[i].num);
                };
            });
            data.reclaim();
            reply.reclaim();
            done();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel_1280:error = " + error);
        }
        sleep(2000);
        data.reclaim();
        reply.reclaim();
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1280---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1290
    * @tc.name    : test Test messageparcel to pass an object of type iremoteobject across processes
    * @tc.desc    : Function test
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1290", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1290---------------------------");
        function checkResult(num, str) {
            expect(num).assertEqual(123);
            expect(str).assertEqual("rpcListenerTest");
            done();
        }
        try {
            let option = new rpc.MessageOption();
            var data = rpc.MessageParcel.create();
            var reply = rpc.MessageParcel.create();
            let listener = new TestListener("rpcListener", checkResult);
            let result = data.writeRemoteObject(listener);
            expect(result == true).assertTrue();
            expect(data.writeInt(123)).assertTrue();
            expect(data.writeString("rpcListenerTest")).assertTrue();
            await gIRemoteObject.sendRequest(CODE_WRITE_REMOTEOBJECT, data, reply, option)
                .then((result) => {
                    expect(result.errCode).assertEqual(0);
                    result.reply.readException();
                })
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1290---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1300
    * @tc.name    : test Test messageparcel to pass an array of iremoteobject objects across processes
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1300---------------------------");

        let count = 0;
        function checkResult(num, str) {
            expect(num).assertEqual(123);
            expect(str).assertEqual("rpcListenerTest");
            count++;
            console.info("check result done, count: " + count);
            if (count == 3) {
                done();
            }
        }
        try {
            let option = new rpc.MessageOption();
            var data = rpc.MessageParcel.create();
            var reply = rpc.MessageParcel.create();
            let listeners = [new TestListener("rpcListener", checkResult),
            new TestListener("rpcListener2", checkResult),
            new TestListener("rpcListener3", checkResult)];
            let result = data.writeRemoteObjectArray(listeners);
            expect(result == true).assertTrue();
            expect(data.writeInt(123)).assertTrue();
            expect(data.writeString("rpcListenerTest")).assertTrue();
            await gIRemoteObject.sendRequest(CODE_WRITE_REMOTEOBJECTARRAY_1, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                result.reply.readException();
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error = null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1300---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1310
    * @tc.name    : test Test messageparcel to pass the array of iremoteobject objects across processes. The server
    *             constructs an empty array in onremoterequest and reads it from messageparcel
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1310", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1310---------------------------");
        let count = 0;
        function checkResult(num, str) {
            expect(num).assertEqual(123);
            expect(str).assertEqual("rpcListenerTest");
            count++;
            console.info("check result done, count: " + count);
            if (count == 3) {
                done();
            }
        }
        try {
            let option = new rpc.MessageOption();
            var data = rpc.MessageParcel.create();
            var reply = rpc.MessageParcel.create();
            let listeners = [new TestListener("rpcListener", checkResult),
            new TestListener("rpcListener2", checkResult),
            new TestListener("rpcListener3", checkResult)];
            let result = data.writeRemoteObjectArray(listeners);
            expect(result == true).assertTrue();
            expect(data.writeInt(123)).assertTrue();
            expect(data.writeString("rpcListenerTest")).assertTrue();
            await gIRemoteObject.sendRequest(CODE_WRITE_REMOTEOBJECTARRAY_2, data, reply, option)
                .then((result) => {
                    console.info("SUB_DSoftbus_IPC_API_MessageParcel_1310 sendRequest done, error code: " + result.errCode);
                    expect(result.errCode).assertEqual(0);
                    result.reply.readException();
                })
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1310---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1320
    * @tc.name    : test Invoke the rewindRead interface, write the POS, and read the offset value
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1320", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1320---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let option = new rpc.MessageOption();
            var reply = rpc.MessageParcel.create();
            data.writeInt(12);
            data.writeString("parcel");
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendRequest(CODE_WRITE_INT, data, reply, option).then((result) => {
                expect(result.errCode == 0).assertTrue();
                let number1 = result.reply.readInt();
                expect(number1).assertEqual(12);
                expect(result.reply.rewindRead(0)).assertTrue();
                let number2 = result.reply.readInt();
                expect(number2).assertEqual(12);
                let reString = result.reply.readString();
                expect(reString).assertEqual("");
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1320---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1330
    * @tc.name    : test Invoke the rewindRead interface, write the POS, and read the offset value
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1330", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1330---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let option = new rpc.MessageOption();
            var reply = rpc.MessageParcel.create();
            data.writeInt(12);
            data.writeString("parcel");
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendRequest(CODE_WRITE_INT, data, reply, option).then((result) => {
                expect(result.errCode == 0).assertTrue();
                let number1 = result.reply.readInt();
                expect(result.reply.rewindRead(1)).assertTrue();
                let number2 = result.reply.readInt();
                expect(number1).assertEqual(12);
                expect(number2).assertEqual(0);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1330---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1340
    * @tc.name    : test Invoke the rewindWrite interface, write the POS, and read the offset value
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1340", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1180---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let option = new rpc.MessageOption();
            var reply = rpc.MessageParcel.create();
            data.writeInt(4);
            data.rewindWrite(0);
            data.writeInt(5);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendRequest(CODE_WRITE_INT, data, reply, option).then((result) => {
                expect(result.errCode == 0).assertTrue();
                let number = result.reply.readInt();
                expect(number).assertEqual(5);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1340---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1350
    * @tc.name    : test Invoke the rewindWrite interface, write the POS, and read the offset value
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1350", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1350---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let option = new rpc.MessageOption();
            var reply = rpc.MessageParcel.create();
            data.writeInt(4);
            data.rewindWrite(1);
            data.writeInt(5);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendRequest(CODE_WRITE_INT, data, reply, option).then((result) => {
                expect(result.errCode == 0).assertTrue();
                let number = result.reply.readInt();
                expect(number != 5).assertTrue();
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1350---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1360
    * @tc.name    : test setCapacity Sets the storage capacity of the MessageParcel instance. The getCapacity 
    *               obtains the current MessageParcel capacity
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1360", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1360---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let option = new rpc.MessageOption();
            var reply = rpc.MessageParcel.create();
            expect(data.getCapacity()).assertEqual(0);
            let setMePaCapacity = data.setCapacity(100);
            expect(setMePaCapacity).assertTrue();
            expect(data.writeString("constant")).assertTrue();
            expect(data.getCapacity()).assertEqual(100);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
                expect(result.errCode == 0).assertTrue();
                let getMePaCapacity = result.reply.getCapacity();
                expect(getMePaCapacity).assertEqual("constant".length * 8);
                expect(result.reply.readString()).assertEqual("constant");
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1360---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1370
    * @tc.name    : test setCapacity Sets the storage capacity of the MessageParcel instance. The getCapacity
    *              obtains the current MessageParcel capacity
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1370", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1370---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let option = new rpc.MessageOption();
            var reply = rpc.MessageParcel.create();
            expect(data.writeString("constant")).assertTrue();
            expect(data.setCapacity(100)).assertTrue();
            expect(data.getCapacity()).assertEqual(100);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
                expect(result.errCode == 0).assertTrue();
                expect(result.reply.readString()).assertEqual("constant");
                let getMeCa = result.reply.getCapacity();
                expect(getMeCa).assertEqual("constant".length * 8);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1370---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1380
    * @tc.name    : test SetCapacity Tests the storage capacity threshold of the MessageParcel instance
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1380", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1380---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let getCapacitydata0 = data.getCapacity();
            expect(data.writeString("constant")).assertTrue();
            let getSizedata = data.getSize();
            let getCapacitydata = data.getCapacity();
            let setCapacitydata1 = data.setCapacity(getSizedata + 1);
            expect(setCapacitydata1).assertTrue();
            expect(data.getCapacity()).assertEqual((getSizedata + 1));
            let setCapacitydata2 = data.setCapacity(getSizedata);
            expect(setCapacitydata2).assertEqual(false);
            expect(data.getCapacity()).assertEqual((getSizedata + 1));
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1380---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1390
    * @tc.name    : test SetCapacity Tests the storage capacity threshold of the MessageParcel instance
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1390", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1390---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let option = new rpc.MessageOption();
            var reply = rpc.MessageParcel.create();
            expect(data.writeString("constant")).assertTrue();
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
                expect(result.errCode == 0).assertTrue();
                let getSizeresult = result.reply.getSize();
                let setCapacityresult = result.reply.getCapacity();
                expect(setCapacityresult).assertEqual("constant".length * 8);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1390---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1400
    * @tc.name    : test SetCapacity Tests the storage capacity threshold of the MessageParcel instance
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1400---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let getSizedata = data.getSize();
            expect(getSizedata).assertEqual(0);
            let setMeCapacity = data.setCapacity(M);
            expect(setMeCapacity).assertTrue();
            let getCapacitydata = data.getCapacity();
            expect(getCapacitydata).assertEqual(M);
            let setMeCapacity1 = data.setCapacity(4 * G);
            expect(setMeCapacity1).assertEqual(false);
            let getCapacitydata1 = data.getCapacity();
            expect(getCapacitydata1).assertEqual(M);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1400---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1410
    * @tc.name    : test setCapacity Sets the storage capacity of the MessageParcel instance to decrease by one.
    *               The getCapacity obtains the current MessageParcel capacity
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1410", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1410---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let option = new rpc.MessageOption();
            var reply = rpc.MessageParcel.create();
            expect(data.getSize()).assertEqual(0);
            let setSizedata = data.setSize(0);
            expect(setSizedata).assertTrue();
            expect(data.writeString("constant")).assertTrue();
            let getSizedata = data.getSize();
            expect(getSizedata).assertEqual(("constant".length * 2) + 8);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
                expect(result.errCode == 0).assertTrue();
                let getSizeresult = result.reply.getSize();
                expect(getSizeresult).assertEqual(("constant".length * 2) + 8);
                expect(result.reply.readString()).assertEqual("constant");
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1410---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1420
    * @tc.name    : test setSize Sets the size of the data contained in the MessageParcel instance. The getSize command
    *              reads the data
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1420", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1420---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let option = new rpc.MessageOption();
            var reply = rpc.MessageParcel.create();
            expect(data.writeString("constant")).assertTrue();
            expect(data.getSize()).assertEqual(("constant".length * 2) + 8);
            expect(data.setSize(0)).assertTrue();
            let getSizedata = data.getSize();
            expect(getSizedata).assertEqual(0);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
                expect(result.errCode == 0).assertTrue();
                let getSizeresult = result.reply.getSize();
                expect(getSizeresult).assertEqual(8);
                let writeresult = result.reply.readString();
                expect(writeresult).assertEqual("");
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1420---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1430
    * @tc.name    : test SetSize: Increases the value of the data contained in the MessageParcel instance by 1,Write setSize
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1430", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1430---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            expect(data.getSize()).assertEqual(0);
            expect(data.writeString("constant")).assertTrue();
            expect(data.getSize()).assertEqual(("constant".length * 2) + 8);
            let getCapacitydata = data.getCapacity();
            let setSizedata1 = data.setSize(getCapacitydata);
            expect(setSizedata1).assertTrue();
            expect(data.getSize()).assertEqual(getCapacitydata);
            let setSizedata2 = data.setSize(getCapacitydata + 1);
            expect(setSizedata2).assertEqual(false);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1430---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1440
    * @tc.name    : test SetSize: Increases the value of the data contained in the MessageParcel instance by 1,
    *               Write the setSize boundary value
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1440", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1440---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let option = new rpc.MessageOption();
            var reply = rpc.MessageParcel.create();
            expect(data.writeString("constant")).assertTrue();
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
                expect(result.errCode == 0).assertTrue();
                expect(result.reply.readString()).assertEqual("constant");
                expect(result.reply.getSize()).assertEqual(("constant".length * 2) + 8);
                let getCapacityresult = result.reply.getCapacity();
                let setSizeresult1 = result.reply.setSize(getCapacityresult);
                expect(setSizeresult1).assertTrue();
                expect(result.reply.getSize()).assertEqual(getCapacityresult);
                let setSizeresult2 = result.reply.setSize(getCapacityresult + 1);
                expect(setSizeresult2).assertEqual(false);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1440---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1450
    * @tc.name    : test Validate the setSize boundary value in the MessageParcel instance
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1450", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1450---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let getCapacitydata = data.getCapacity();
            expect(getCapacitydata).assertEqual(0);
            let setSizedata1 = data.setSize(4 * G);
            expect(setSizedata1).assertTrue();
            let getSizedata1 = data.getSize();
            expect(getSizedata1).assertEqual(0);
            let setSizedata = data.setSize(4 * G - 1);
            expect(setSizedata).assertEqual(false);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1450---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1460
    * @tc.name    : test Verify that setSize is out of bounds in a MessageParcel instance
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1460", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1460---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let setSizedata = data.setSize(0);
            expect(setSizedata).assertTrue();
            expect(data.getSize()).assertEqual(0);
            let setSizedata1 = data.setSize(2 * 4 * G);
            expect(setSizedata1).assertTrue();
            expect(data.getSize()).assertEqual(0);
            let setSizedata2 = data.setSize(2 * G);
            expect(setSizedata2).assertEqual(false);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1460---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1470
    * @tc.name    : test Obtaining the Writable and Readable Byte Spaces of MessageParcel
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1470", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1470---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let option = new rpc.MessageOption();
            var reply = rpc.MessageParcel.create();
            expect(data.getWritableBytes()).assertEqual(0);
            data.writeInt(10);
            expect(data.getWritableBytes()).assertEqual(60);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendRequest(CODE_WRITE_INT, data, reply, option).then((result) => {
                expect(result.errCode == 0).assertTrue();
                expect(result.reply.getReadableBytes()).assertEqual(4);
                let readint = result.reply.readInt();
                expect(readint).assertEqual(10);
                let getrbyte2 = result.reply.getReadableBytes();
                expect(getrbyte2).assertEqual(0);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1470---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1480
    * @tc.name    : test Obtains the writeable and readable byte space and read position of the MessageParcel
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1480", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1480---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let option = new rpc.MessageOption();
            var reply = rpc.MessageParcel.create();
            data.writeInt(10);
            let getwPos = data.getWritePosition();
            let getwbyte = data.getWritableBytes();
            expect(getwbyte).assertEqual(60);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendRequest(CODE_WRITE_INT, data, reply, option).then((result) => {
                expect(result.errCode == 0).assertTrue();
                let getrbyte = result.reply.getReadableBytes();
                expect(getrbyte).assertEqual(4);
                let readint = result.reply.readInt();
                expect(readint).assertEqual(10);
                let getrPos = result.reply.getReadPosition();
                expect(getrPos).assertEqual(getwPos);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1480---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1490
    * @tc.name    : test Obtains the writeable and readable byte space and read position of the MessageParcel
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1490", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1490---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let option = new rpc.MessageOption();
            var reply = rpc.MessageParcel.create();
            data.writeInt(10);
            let getwPos = data.getWritePosition();
            let getwbyte = data.getWritableBytes();
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendRequest(CODE_WRITE_INT, data, reply, option).then((result) => {
                expect(result.errCode == 0).assertTrue();
                let readint = result.reply.readInt();
                expect(readint).assertEqual(10);
                let getrPos = result.reply.getReadPosition();
                expect(getrPos).assertEqual(4);
                let getrbyte = result.reply.getReadableBytes();
                expect(getrbyte).assertEqual(0);
                let getrPos1 = result.reply.getReadPosition();
                expect(getrPos1).assertEqual(getwPos);
                let getrbyte1 = result.reply.getReadableBytes();
                expect(getrbyte1).assertEqual(0);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1490---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1500
    * @tc.name    : test Test fixed MessageParcel space size to pass rawData data
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1500---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let rawdata = [1, 2, 3];
            let option = new rpc.MessageOption();
            var reply = rpc.MessageParcel.create();
            expect(data.writeInt(rawdata.length)).assertTrue();
            let result = data.writeRawData(rawdata, rawdata.length);
            expect(result).assertTrue();
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendRequest(CODE_WRITE_RAWDATA, data, reply, option).then((result) => {
                expect(result.errCode == 0).assertTrue();
                let size = result.reply.readInt();
                let newReadResult = result.reply.readRawData(size);
                expect(newReadResult != rawdata).assertTrue();
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1500---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1510
    * @tc.name    : test Obtains the write and read positions of the MessageParcel
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1510", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1510---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let option = new rpc.MessageOption();
            var reply = rpc.MessageParcel.create();
            let getwPos1 = data.getWritePosition();
            expect(data.writeInt(10)).assertTrue();
            let getwPos2 = data.getWritePosition();
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendRequest(CODE_WRITE_INT, data, reply, option).then((result) => {
                expect(result.errCode == 0).assertTrue();
                let getrPos1 = result.reply.getReadPosition();
                let readint = result.reply.readInt();
                expect(readint).assertEqual(10);
                let getrPos2 = result.reply.getReadPosition();
                expect(getwPos1).assertEqual(getrPos1);
                expect(getwPos2).assertEqual(getrPos2);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1510---------------------------");
    });


    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1520
    * @tc.name    : test Test messageparcel delivery file descriptor object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1520", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1520---------------------------");
        try {
            let testab = new TestProxy(gIRemoteObject).asObject();
            expect(testab != null).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1520---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1530
    * @tc.name    : test Test messageparcel delivery file descriptor object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1530", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1530---------------------------");
        try {
            let testRemoteObject = new TestRemoteObject("testObject");
            expect(testRemoteObject != null).assertTrue();
            let testab = testRemoteObject.asObject();
            expect(testab != null).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1530---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1540
    * @tc.name    : test MessageParcel sendMessageRequest API test
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1540", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1540---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            let Capacity = data.getRawDataCapacity()
            let rawdata = [1, 2, 3];
            let option = new rpc.MessageOption();
            var reply = rpc.MessageSequence.create();
            data.writeInt(rawdata.length);
            data.writeRawData(rawdata, rawdata.length);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_RAWDATA, data, reply, option).then((result) => {
                expect(result.errCode == 0).assertTrue();
                let size = result.reply.readInt();
                let newReadResult = result.reply.readRawData(size);
                expect(newReadResult != rawdata).assertTrue();
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1540---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1550
    * @tc.name    : test Invoke the writestring interface to write data to the messageparcel instance SendRequest Asynchronous
    *               Authentication onRemoteMessageRequest Server Processing
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1550", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1550---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            var reply = rpc.MessageParcel.create();
            let option = new rpc.MessageOption();
            let token = 'onRemoteMessageRequest invoking';
            let result = data.writeString(token);
            expect(result == true).assertTrue();
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
                var replyReadResult = result.reply.readString();
                expect(replyReadResult).assertEqual(token);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1550---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1560
    * @tc.name    : test Invoke the writestring interface to write data to the messageparcel instance sendMessageRequest Asynchronous
    *               Authentication onRemoteMessageRequest Server Processing
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1560", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1560---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let token = 'onRemoteMessageRequest invoking';
            data.writeString(token);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                var replyReadResult = result.reply.readString();
                expect(replyReadResult).assertEqual(token);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1560---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1570
    * @tc.name    : test Invoke the writestring interface to write data to the messageparcel instance. SendRequest asynchronously
    *               verifies the priority processing levels of onRemoteMessageRequest and onRemoteRequest
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1570", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1570---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            var reply = rpc.MessageParcel.create();
            let option = new rpc.MessageOption();
            let token = "onRemoteRequest or onRemoteMessageRequest invoking";
            let result = data.writeString(token);
            expect(result == true).assertTrue();
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendRequest(CODE_ONREMOTEMESSAGE_OR_ONREMOTE, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                var replyReadResult = result.reply.readString();
                expect(replyReadResult).assertEqual("onRemoteMessageRequest invoking");
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1570---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1580
    * @tc.name   Invoke the writestring interface to write data to the messageparcel instance. sendMessageRequest asynchronously verifies
    *               the priority processing levels of onRemoteMessageRequest and onRemoteRequest
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1580", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1580---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let token = 'onRemoteRequest or onRemoteMessageRequest invoking';
            data.writeString(token);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_ONREMOTEMESSAGE_OR_ONREMOTE, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                var replyReadResult = result.reply.readString();
                expect(replyReadResult).assertEqual("onRemoteMessageRequest invoking");
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1580---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1590
    * @tc.name    : test Call the 401 interface to set the writeString of MessageSequence
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1590", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1590---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            let token = '';
            for (let i = 0; i < 40 * K; i++) {
                token += 'a';
            };
            let result = data.writeString(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            let errCode = `${rpc.ErrorCode.CHECK_PARAM_ERROR}`;
            expect(error.code == errCode).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1590---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1600
    * @tc.name    : test Call the 1900011 interface, write the interface descriptor, and read interfacetoken
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1600---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            data.setSize(0);
            data.setCapacity(0);
            let token = "hello ruan zong xian";
            data.writeInterfaceToken(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error.code == 1900011).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1600---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1610
    * @tc.name    : test Call the 1900009 interface, write the interface descriptor, and read interfacetoken
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1610", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1610---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            data.setSize(true);
            data.setCapacity(true);
            let token = "hello ruan zong xian";
            data.writeInterfaceToken(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            let errCode = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
            expect(error.code != errCode).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1610---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1620
    * @tc.name    : test Call the setcapacity interface to set the capacity of messageparcel
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1620", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1620---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            let sequenceable = new MySequenceable(1, "aaa");
            data.writeParcelable(sequenceable);
            let ret = new MySequenceable(0, "");
            data.setCapacity(0);
            data.readParcelable(ret);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            let errCode = `${rpc.ErrorCode.PARCEL_MEMORY_ALLOC_ERROR}`;
            expect(error.code == errCode).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1620---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1630
    * @tc.name    : test Call the 1900008 interface to serialize the remote object and pass in the empty object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3   
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1630", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1630---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            console.info("SUB_DSoftbus_IPC_API_MessageParcel_1630: create object successfully.");
            let token = {}
            data.writeRemoteObject(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error.code == 1900008).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1630---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1640
    * @tc.name    : test Call the writeparcelable 1900012 interface to write the custom serialized
    *             object to the MessageSequence instance
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1640", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1640---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            let sequenceable = new MySequenceable(1, "aaa");
            data.writeParcelable(sequenceable);
            data.setCapacity(0);
            data.setSize(0);
            let ret = new MySequenceable(1, "");
            data.readParcelable(ret);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            let errCode = `${rpc.ErrorCode.CALL_JS_METHOD_ERROR}`;
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1640---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1650
    * @tc.name    : test Call the writeinterfacetoken interface, write the interface descriptor, and read interfacetoken
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1650", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1650---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            let token = "hello ruan zong xian";
            data.writeInterfaceToken(token);
            data.setCapacity(0);
            data.setSize(0);
            data.readInterfaceToken();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            let errCode = `${rpc.ErrorCode.READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR}`;
            expect(error.message != null).assertTrue();
            expect(error.code != errCode).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1650---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1660
    * @tc.name    : test Test 1900013 messageparcel delivery file descriptor object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1660", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1660---------------------------");
        try {
            let filePath = "path/to/file";
            let fd = fileio.openSync(filePath, null);
            rpc.MessageSequence.dupFileDescriptor(fd);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            let errCode = `${rpc.ErrorCode.OS_DUP_ERROR}`;
            expect(error.code != errCode).assertTrue();
            expect(error.message != null).assertTrue();
        }
        done();
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1660---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1670
    * @tc.name    : test The readRemoteObjectArray interface directly reads parameters
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1670", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1670---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let listeners = [new TestRemoteObject("rpcListener"),
            new TestRemoteObject("rpcListener2"),
            new TestRemoteObject("rpcListener3")];
            let result = data.writeRemoteObjectArray(listeners);
            expect(result == true).assertTrue();
            let rlisteners = data.readRemoteObjectArray();
            expect(rlisteners != null).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1670---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1680
    * @tc.name    : test The readRemoteObjectArray interface reads parameters to an empty array
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1680", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1680---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let listeners = [new TestRemoteObject("rpcListener"),
            new TestRemoteObject("rpcListener2"),
            new TestRemoteObject("rpcListener3")];
            let result = data.writeRemoteObjectArray(listeners);
            expect(result == true).assertTrue();
            let rlisteners = new Array(3);
            data.readRemoteObjectArray(rlisteners);
            expect(rlisteners != null).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1680---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1670
    * @tc.name    : test The readRemoteObjectArray interface directly reads parameters
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1670", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1670---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let listeners = [new TestRemoteObject("rpcListener"),
            new TestRemoteObject("rpcListener2"),
            new TestRemoteObject("rpcListener3")];
            let result = data.writeRemoteObjectArray(listeners);
            expect(result == true).assertTrue();
            let rlisteners = data.readRemoteObjectArray();
            expect(rlisteners != null).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1670---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1680
    * @tc.name    : test The readRemoteObjectArray interface reads parameters to an empty array
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1680", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1680---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let listeners = [new TestRemoteObject("rpcListener"),
            new TestRemoteObject("rpcListener2"),
            new TestRemoteObject("rpcListener3")];
            let result = data.writeRemoteObjectArray(listeners);
            expect(result == true).assertTrue();
            let rlisteners = new Array(3);
            data.readRemoteObjectArray(rlisteners);
            expect(rlisteners != null).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1680---------------------------");
    });        

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0010
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0010", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0010---------------------------");
        try {
            let option = new rpc.MessageOption();
            let time = option.getWaitTime();
            expect(time).assertEqual(rpc.MessageOption.TF_WAIT_TIME);
            option.setWaitTime(16);
            let time2 = option.getWaitTime();
            expect(time2).assertEqual(16);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0010---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0020
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0020", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0020---------------------------");
        try {
            let option = new rpc.MessageOption();
            let time = option.getWaitTime();
            expect(time).assertEqual(rpc.MessageOption.TF_WAIT_TIME);
            option.setWaitTime(0);
            let time2 = option.getWaitTime();
            expect(time2).assertEqual(rpc.MessageOption.TF_WAIT_TIME);
            option.setWaitTime(60);
            let time3 = option.getWaitTime();
            expect(time3).assertEqual(60);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0020---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0030
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0030", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0030---------------------------");
        try {
            let option = new rpc.MessageOption();
            let time = option.getWaitTime();
            expect(time).assertEqual(rpc.MessageOption.TF_WAIT_TIME);
            option.setWaitTime(-1);
            let time2 = option.getWaitTime();
            expect(time2).assertEqual(rpc.MessageOption.TF_WAIT_TIME);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0030---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0040
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0040", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0040---------------------------");
        try {
            let option = new rpc.MessageOption();
            let time = option.getWaitTime();
            expect(time).assertEqual(rpc.MessageOption.TF_WAIT_TIME);
            option.setWaitTime(61);
            let time2 = option.getWaitTime();
            expect(time2).assertEqual(61);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0040---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0050
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0050", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0050---------------------------");
        try {
            let option = new rpc.MessageOption();
            let flog = option.getFlags();
            expect(flog).assertEqual(rpc.MessageOption.TF_SYNC);
            option.setFlags(1);
            let flog2 = option.getFlags();
            expect(flog2).assertEqual(rpc.MessageOption.TF_ASYNC);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0050---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0060
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0060", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0060---------------------------");
        try {
            let option = new rpc.MessageOption();
            let flog = option.getFlags();
            expect(flog).assertEqual(rpc.MessageOption.TF_SYNC);
            option.setFlags(1);
            let flog2 = option.getFlags();
            expect(flog2).assertEqual(rpc.MessageOption.TF_ASYNC);
            option.setFlags(0);
            let flog3 = option.getFlags();
            expect(flog3).assertEqual(rpc.MessageOption.TF_ASYNC);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0060---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0070
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0070", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0070---------------------------");
        try {
            let option = new rpc.MessageOption();
            let flog = option.getFlags();
            expect(flog).assertEqual(rpc.MessageOption.TF_SYNC);
            option.setFlags(-1);
            let flog2 = option.getFlags();
            expect(flog2).assertEqual(-1);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0070---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0040
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0040", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0040---------------------------");
        try {
            let option = new rpc.MessageOption();
            let time = option.getWaitTime();
            expect(time).assertEqual(rpc.MessageOption.TF_WAIT_TIME);
            option.setWaitTime(61);
            let time2 = option.getWaitTime();
            expect(time2).assertEqual(61);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0040---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0050
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0050", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0050---------------------------");
        try {
            let option = new rpc.MessageOption();
            let flog = option.getFlags();
            expect(flog).assertEqual(rpc.MessageOption.TF_SYNC);
            option.setFlags(1);
            let flog2 = option.getFlags();
            expect(flog2).assertEqual(rpc.MessageOption.TF_ASYNC);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0050---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0060
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0060", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0060---------------------------");
        try {
            let option = new rpc.MessageOption();
            let flog = option.getFlags();
            expect(flog).assertEqual(rpc.MessageOption.TF_SYNC);
            option.setFlags(1);
            let flog2 = option.getFlags();
            expect(flog2).assertEqual(rpc.MessageOption.TF_ASYNC);
            option.setFlags(0);
            let flog3 = option.getFlags();
            expect(flog3).assertEqual(rpc.MessageOption.TF_ASYNC);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0060---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0070
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0070", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0070---------------------------");
        try {
            let option = new rpc.MessageOption();
            let flog = option.getFlags();
            expect(flog).assertEqual(rpc.MessageOption.TF_SYNC);
            option.setFlags(-1);
            let flog2 = option.getFlags();
            expect(flog2).assertEqual(-1);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0070---------------------------");
    })

    console.info("-----------------------SUB_DSoftbus_IPC_API_Stage_MessageSequence_Test is end-----------------------");
  })
}