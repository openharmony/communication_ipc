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
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1080
             * @tc.name    : test Call the writeremoteobjectarray interface to write the object array to the MessageSequence
             *             instance, and call readremoteobjectarray to read the data
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1080", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1080---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    var option = new rpc.MessageOption();
                    var listeners = [new TestRemoteObject("rpcListener"),
                    new TestRemoteObject("rpcListener2"),
                    new TestRemoteObject("rpcListener3")];
                    data.writeRemoteObjectArray(listeners);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_REMOTEOBJECTARRAY, data, reply, option).then((result) => {
                        console.info("SUB_DSoftbus_IPC_API_MessageSequence_1080: sendMessageRequest is " + result.errCode);
                        expect(result.errCode).assertEqual(0);
                        expect(result.code).assertEqual(CODE_WRITE_REMOTEOBJECTARRAY);
                        expect(result.data).assertEqual(data);
                        expect(result.reply).assertEqual(reply);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1080---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1100
             * @tc.name    : test Test MessageSequence to deliver the reply message received in promise across processes
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 0
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL0, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1100---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    data.writeByte(2);
                    data.writeShort(3);
                    data.writeInt(4);
                    data.writeLong(5);
                    data.writeFloat(1.2);
                    data.writeDouble(10.2);
                    data.writeBoolean(true);
                    data.writeChar(97);
                    data.writeString("HelloWorld");
                    data.writeParcelable(new MySequenceable(1, "aaa"));
                    await gIRemoteObject.sendMessageRequest(CODE_ALL_TYPE, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readByte()).assertEqual(2);
                        expect(result.reply.readShort()).assertEqual(3);
                        expect(result.reply.readInt()).assertEqual(4);
                        expect(result.reply.readLong()).assertEqual(5);
                        expect(result.reply.readFloat()).assertEqual(1.2);
                        expect(result.reply.readDouble()).assertEqual(10.2);
                        expect(result.reply.readBoolean()).assertTrue();
                        expect(result.reply.readChar()).assertEqual(97)
                        expect(result.reply.readString()).assertEqual("HelloWorld");
                        let s = new MySequenceable(null, null);
                        result.reply.readParcelable(s);
                        expect(s.num).assertEqual(1);
                        expect(s.str).assertEqual("aaa");
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1100---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1110
             * @tc.name    : test Test the cross process delivery of MessageSequence and receive the reply message
             *             in the callback function
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1110", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1110---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    data.writeByte(2);
                    data.writeShort(3);
                    data.writeInt(4);
                    data.writeLong(5);
                    data.writeFloat(1.2);
                    data.writeDouble(10.2);
                    data.writeBoolean(true);
                    data.writeChar(97);
                    data.writeString("HelloWorld");
                    data.writeParcelable(new MySequenceable(1, "aaa"));
                    function sendMessageRequestCallback(result) {
                        try {
                            console.info("sendMessageRequest Callback");
                            expect(result.errCode).assertEqual(0);
                            expect(result.reply.readByte()).assertEqual(2);
                            expect(result.reply.readShort()).assertEqual(3);
                            expect(result.reply.readInt()).assertEqual(4);
                            expect(result.reply.readLong()).assertEqual(5);
                            expect(result.reply.readFloat()).assertEqual(1.2);
                            expect(result.reply.readDouble()).assertEqual(10.2);
                            expect(result.reply.readBoolean()).assertTrue();
                            expect(result.reply.readChar()).assertEqual(97);
                            expect(result.reply.readString()).assertEqual("HelloWorld");
                            let s = new MySequenceable(null, null);
                            result.reply.readParcelable(s);
                            expect(s.num).assertEqual(1);
                            expect(s.str).assertEqual("aaa");
                        } finally {
                            data.reclaim();
                            reply.reclaim();
                            done();
                        }
                    }
                    console.info("start send request");
                    await gIRemoteObject.sendMessageRequest(CODE_ALL_TYPE, data, reply, option, sendMessageRequestCallback);
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                }
                console.info("--------------------end SUB_DSoftbus_IPC_API_MessageSequence_1110--------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1120
             * @tc.name    : test Test the cross process transmission of MessageSequence.
             *             After receiving the reply message in promise, read letious types of arrays in order
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1120", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
                console.info("--------------------start SUB_DSoftbus_IPC_API_MessageSequence_1120--------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    data.writeByteArray([1, 2, 3]);
                    data.writeShortArray([4, 5, 6]);
                    data.writeIntArray([7, 8, 9]);
                    data.writeLongArray([10, 11, 12]);
                    data.writeFloatArray([1.1, 1.2, 1.3]);
                    data.writeDoubleArray([2.1, 2.2, 2.3]);
                    data.writeBooleanArray([true, true, false]);
                    data.writeCharArray([65, 97, 122]);
                    data.writeStringArray(['abc', 'seggg']);
                    let a = [new MySequenceable(1, "aaa"), new MySequenceable(2, "bbb"),
                    new MySequenceable(3, "ccc")]
                    data.writeParcelableArray(a);
                    await gIRemoteObject.sendMessageRequest(CODE_ALL_ARRAY_TYPE, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        assertArrayElementEqual(result.reply.readByteArray(), [1, 2, 3]);
                        assertArrayElementEqual(result.reply.readShortArray(), [4, 5, 6]);
                        assertArrayElementEqual(result.reply.readIntArray(), [7, 8, 9]);
                        assertArrayElementEqual(result.reply.readLongArray(), [10, 11, 12]);
                        assertArrayElementEqual(result.reply.readFloatArray(), [1.1, 1.2, 1.3]);
                        assertArrayElementEqual(result.reply.readDoubleArray(), [2.1, 2.2, 2.3]);
                        assertArrayElementEqual(result.reply.readBooleanArray(), [true, true, false]);
                        assertArrayElementEqual(result.reply.readCharArray(), [65, 97, 122]);
                        assertArrayElementEqual(result.reply.readStringArray(), ['abc', 'seggg']);
                        let b = [new MySequenceable(null, null), new MySequenceable(null, null),
                        new MySequenceable(null, null)];
                        result.reply.readParcelableArray(b);
                        for (let i = 0; i < b.length; i++) {
                            expect(b[i].str).assertEqual(a[i].str);
                            expect(b[i].num).assertEqual(a[i].num);
                        };
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1120---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1130
             * @tc.name    : test Test MessageSequence cross process delivery. After receiving the reply message in promise,
             *             the client constructs an empty array in sequence and reads the data from the reply message
             *             into the corresponding array
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1130", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1130---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    data.writeByteArray([1, 2, 3]);
                    data.writeShortArray([4, 5, 6]);
                    data.writeIntArray([7, 8, 9]);
                    data.writeLongArray([10, 11, 12]);
                    data.writeFloatArray([1.1, 1.2, 1.3]);
                    data.writeDoubleArray([2.1, 2.2, 2.3]);
                    data.writeBooleanArray([true, true, false]);
                    data.writeCharArray([65, 97, 122]);
                    data.writeStringArray(['abc', 'seggg']);
                    let a = [new MySequenceable(1, "aaa"), new MySequenceable(2, "bbb"),
                    new MySequenceable(3, "ccc")]
                    data.writeParcelableArray(a);
                    await gIRemoteObject.sendMessageRequest(CODE_ALL_ARRAY_TYPE, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        let ByteArray = new Array();
                        result.reply.readByteArray(ByteArray);
                        assertArrayElementEqual(ByteArray, [1, 2, 3]);
                        let ShortArray = new Array();
                        result.reply.readShortArray(ShortArray);
                        assertArrayElementEqual(ShortArray, [4, 5, 6]);
                        let IntArray = new Array();
                        result.reply.readIntArray(IntArray);
                        assertArrayElementEqual(IntArray, [7, 8, 9]);
                        let LongArray = new Array();
                        result.reply.readLongArray(LongArray);
                        assertArrayElementEqual(LongArray, [10, 11, 12]);
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
                        result.reply.readParcelableArray(b);
                        for (let i = 0; i < b.length; i++) {
                            expect(b[i].str).assertEqual(a[i].str);
                            expect(b[i].num).assertEqual(a[i].num);
                        };
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1130---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1140
             * @tc.name    : test Test MessageSequence to pass an object of type iremoteobject across processes
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it('SUB_DSoftbus_IPC_API_MessageSequence_1140', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1140---------------------------");
                function checkResult(num, str) {
                    expect(num).assertEqual(123);
                    expect(str).assertEqual("rpcListenerTest");
                    done();
                };
                try {
                    var option = new rpc.MessageOption();
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    let listener = new TestListener("rpcListener", checkResult);
                    data.writeRemoteObject(listener);
                    data.writeInt(123);
                    data.writeString("rpcListenerTest");
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_REMOTEOBJECT, data, reply, option).then((result) => {
                        console.info("SUB_DSoftbus_IPC_API_MessageSequence_1140: sendMessageRequest is " + result.errCode);
                        expect(result.errCode).assertEqual(0);
                        result.reply.readException();
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1140---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1150
             * @tc.name    : test Test MessageSequence to pass an array of iremoteobject objects across processes
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it('SUB_DSoftbus_IPC_API_MessageSequence_1150', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1150---------------------------");
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
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    let listeners = [new TestListener("rpcListener", checkResult),
                    new TestListener("rpcListener2", checkResult),
                    new TestListener("rpcListener3", checkResult)];
                    data.writeRemoteObjectArray(listeners);
                    data.writeInt(123);
                    data.writeString("rpcListenerTest");
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_REMOTEOBJECTARRAY_1, data, reply, option)
                        .then((result) => {
                            expect(result.errCode).assertEqual(0);
                            result.reply.readException();
                        });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1150---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1160
             * @tc.name    : test Test MessageSequence to pass the array of iremoteobject objects across processes. The server
             *             constructs an empty array in onremoterequest and reads it from MessageSequence
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it('SUB_DSoftbus_IPC_API_MessageSequence_1160', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1160---------------------------");
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
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    let listeners = [new TestListener("rpcListener", checkResult),
                    new TestListener("rpcListener2", checkResult),
                    new TestListener("rpcListener3", checkResult)];
                    data.writeRemoteObjectArray(listeners);
                    data.writeInt(123);
                    data.writeString("rpcListenerTest");
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_REMOTEOBJECTARRAY_2, data, reply, option)
                        .then((result) => {
                            console.info("SUB_DSoftbus_IPC_API_MessageSequence_1160: sendMessageRequest is " + result.errCode);
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
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1160---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1170
             * @tc.name    : test Invoke the rewindRead interface,Set 0-bit offset and read the data after offset
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1170", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1170---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    var reply = rpc.MessageSequence.create();
                    data.writeInt(12);
                    data.writeString("parcel");
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_INT, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readInt()).assertEqual(12);
                        result.reply.rewindRead(0);
                        expect(result.reply.readInt()).assertEqual(12);
                        expect(result.reply.readString()).assertEqual("");
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1170---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1180
             * @tc.name    : test Invoke the rewindRead interface,Set 1-bit offset and read the data after offset
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1180", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1170---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    var reply = rpc.MessageSequence.create();
                    data.writeInt(12);
                    data.writeString("parcel");
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_INT, data, reply, option).then((result) => {
                        expect(result.errCode == 0).assertTrue();
                        expect(result.reply.readInt()).assertEqual(12);
                        result.reply.rewindRead(1);
                        expect(result.reply.readInt()).assertEqual(0);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1180---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1190
             * @tc.name    : test Invoke the rewindWrite interface, Set 0-bit offset and write the data after offset
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1190", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1180---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    var reply = rpc.MessageSequence.create();
                    data.writeInt(4);
                    data.rewindWrite(0);
                    data.writeInt(5);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_INT, data, reply, option).then((result) => {
                        expect(result.errCode == 0).assertTrue();
                        expect(result.reply.readInt()).assertEqual(5);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1190---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1200
             * @tc.name    : test Invoke the rewindWrite interface, Set 1-bit offset and write the data after offset
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1200---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    var reply = rpc.MessageSequence.create();
                    data.writeInt(4);
                    data.rewindWrite(1);
                    data.writeInt(5);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_INT, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readInt() != 5).assertTrue();
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1200---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1210
             * @tc.name    : test setCapacity Sets the storage capacity of the null MessageSequence instance. The getCapacity
                           obtains the current MessageSequence capacity
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1210", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1210---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    var reply = rpc.MessageSequence.create();
                    expect(data.getCapacity()).assertEqual(0);
                    data.setCapacity(100);
                    data.writeString("constant");
                    expect(data.getCapacity()).assertEqual(100);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.getCapacity()).assertEqual("constant".length * 8);
                        expect(result.reply.readString()).assertEqual("constant");
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1210---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1220
             * @tc.name    : test setCapacity Sets the storage capacity of the MessageSequence instance. The getCapacity
                           obtains the current MessageSequence capacity
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1220", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1220---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    var reply = rpc.MessageSequence.create();
                    data.writeString("constant");
                    data.setCapacity(100);
                    expect(data.getCapacity()).assertEqual(100);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readString()).assertEqual("constant");
                        expect(result.reply.getCapacity()).assertEqual("constant".length * 8);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1220---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1230
             * @tc.name    : test Setcapacity test: size limit verification of MessageSequence instance
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1230", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1230---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    expect(data.getCapacity()).assertEqual(0);
                    data.writeString("constant");
                    let getSizedata = data.getSize();
                    data.setCapacity(getSizedata + 1);
                    data.setCapacity(getSizedata);
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    let errCode = `${rpc.ErrorCode.PARCEL_MEMORY_ALLOC_ERROR}`;
                    expect(error.message != null).assertTrue();
                    expect(error.code == errCode).assertTrue();
                } finally {
                    data.reclaim();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1230---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1240
             * @tc.name    : test SetCapacity Tests the storage capacity threshold of the MessageSequence instance
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1240", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1240---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    var reply = rpc.MessageSequence.create();
                    data.writeString("constant");
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        let getSizeresult = result.reply.getSize();
                        expect(result.reply.getCapacity()).assertEqual("constant".length * 8);
                        result.reply.setCapacity(getSizeresult + 1);
                        result.reply.setCapacity(getSizeresult);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    let errCode = `${rpc.ErrorCode.PARCEL_MEMORY_ALLOC_ERROR}`;
                    expect(error.message != null).assertTrue();
                    expect(error.code == errCode).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1240---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1250
             * @tc.name    : test Setcapacity test storage capacity boundary value verification of MessageSequence instance
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1250", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1250---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    expect(data.getSize()).assertEqual(0);
                    data.setCapacity(M);
                    expect(data.getCapacity()).assertEqual(M);
                    data.setCapacity(2 * G);
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    let errCode = `${rpc.ErrorCode.PARCEL_MEMORY_ALLOC_ERROR}`;
                    expect(error.message != null).assertTrue();
                    expect(error.code == errCode).assertTrue();
                } finally {
                    data.reclaim();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1250---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1260
             * @tc.name    : test setSize Sets the size of the data contained in the MessageSequence instance. The getSize command
                            reads the data
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1260", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1260---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    var reply = rpc.MessageSequence.create();
                    expect(data.getSize()).assertEqual(0);
                    data.setSize(0);
                    data.writeString("constant");
                    expect(data.getSize()).assertEqual(("constant".length * 2) + 8);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.getSize()).assertEqual(("constant".length * 2) + 8);
                        expect(result.reply.readString()).assertEqual("constant");
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1260---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1270
             * @tc.name    : test SetSize: Increases the value of the data contained in the MessageSequence instance by 1,
                            Write setSize
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1270", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1270---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    var reply = rpc.MessageSequence.create();
                    data.writeString("constant");
                    expect(data.getSize()).assertEqual(("constant".length * 2) + 8);
                    data.setSize(0);
                    expect(data.getSize()).assertEqual(0);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.getSize()).assertEqual(8);
                        expect(result.reply.readString()).assertEqual("");
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1270---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1280
             * @tc.name    : test Verify the MessageSequence instance SetSize setting and the instance capacitydata qualification verification
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1280", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1280---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    expect(data.getSize()).assertEqual(0);
                    data.writeString("constant");
                    expect(data.getSize()).assertEqual(("constant".length * 2) + 8);
                    let getCapacitydata = data.getCapacity();
                    expect(getCapacitydata).assertEqual(64);
                    data.setSize(getCapacitydata);
                    expect(data.getSize()).assertEqual(getCapacitydata);
                    data.setSize(getCapacitydata + 1);
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1280---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1290
             * @tc.name    : test setSize Sets the storage capacity of the MessageSequence instance to decrease by one.
                           The getSize obtains the current MessageSequence capacity
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1290", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1290---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    var reply = rpc.MessageSequence.create();
                    data.writeString("constant");
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readString()).assertEqual("constant");
                        expect(result.reply.getSize()).assertEqual(("constant".length * 2) + 8);
                        let getCapacityresult = result.reply.getCapacity();
                        result.reply.setSize(getCapacityresult);
                        expect(result.reply.getSize()).assertEqual(getCapacityresult);
                        result.reply.setSize(getCapacityresult + 1);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1290---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1300
             * @tc.name    : test Validate the setSize boundary value in the MessageSequence instance
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1300---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    expect(data.getCapacity()).assertEqual(0);
                    data.setSize(4 * G);
                    expect(data.getSize()).assertEqual(0);
                    data.setSize(4 * G - 1);
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1300---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1310
             * @tc.name    : test Verify that setSize is out of bounds in a MessageSequence instance
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1310", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1310---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    data.setSize(0);
                    expect(data.getSize()).assertEqual(0);
                    data.setSize(2 * 4 * G);
                    expect(data.getSize()).assertEqual(0);
                    data.setSize(2 * G);
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1310---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1320
             * @tc.name    : test Obtains the write and read positions of the MessageSequence
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1320", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1320---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    var reply = rpc.MessageSequence.create();
                    expect(data.getWritePosition()).assertEqual(0);
                    data.writeInt(10);
                    expect(data.getWritePosition()).assertEqual(4);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_INT, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.getReadPosition()).assertEqual(0);
                        expect(result.reply.readInt()).assertEqual(10);
                        expect(result.reply.getReadPosition()).assertEqual(4);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1320---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1330
             * @tc.name    : test Obtaining the Writable and Readable Byte Spaces of MessageSequence
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1330", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1330---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    var reply = rpc.MessageSequence.create();
                    expect(data.getWritableBytes()).assertEqual(0);
                    data.writeInt(10);
                    expect(data.getWritableBytes()).assertEqual(60);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_INT, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readInt()).assertEqual(10);
                        expect(result.reply.getReadableBytes()).assertEqual(0);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1330---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1340
             * @tc.name    : test Obtains the writeable and readable byte space and read position of the MessageSequence
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1340", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1340---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    var reply = rpc.MessageSequence.create();
                    data.writeInt(10);
                    expect(data.getWritePosition()).assertEqual(4);
                    expect(data.getWritableBytes()).assertEqual(60);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_INT, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.getReadableBytes()).assertEqual(4);
                        expect(result.reply.getReadPosition()).assertEqual(0);
                        expect(result.reply.readInt()).assertEqual(10);
                        expect(result.reply.getReadableBytes()).assertEqual(0);
                        expect(result.reply.getReadPosition()).assertEqual(4);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1340---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1350
             * @tc.name    : test Get the space size of MessageSequence to pass rawdata data
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1350", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1350---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    var reply = rpc.MessageSequence.create();
                    data.writeInt(10);
                    expect(data.getWritePosition()).assertEqual(4);
                    expect(data.getWritableBytes()).assertEqual(60);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_INT, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.getReadPosition()).assertEqual(0);
                        expect(result.reply.getReadableBytes()).assertEqual(4);
                        expect(result.reply.readInt()).assertEqual(10);
                        expect(result.reply.getReadPosition()).assertEqual(4);
                        expect(result.reply.getReadableBytes()).assertEqual(0);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1350---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1360
             * @tc.name    : test Test fixed MessageSequence space size to pass rawData data
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1360", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1360---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    expect(data.getRawDataCapacity()).assertEqual(128 * M);
                    let rawdata = [1, 2, 3];
                    let option = new rpc.MessageOption();
                    var reply = rpc.MessageSequence.create();
                    data.writeInt(rawdata.length);
                    data.writeRawData(rawdata, rawdata.length);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_RAWDATA, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        let size = result.reply.readInt();
                        expect(result.reply.readRawData(size) != rawdata).assertTrue();
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1360---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1370
             * @tc.name    : test Test MessageSequence delivery file descriptor object
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1370", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function () {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1370---------------------------");
                try {
                    let testab = new TestProxy(gIRemoteObject).asObject();
                    expect(testab != null).assertTrue();
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1370---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1380
             * @tc.name    : test Test that the asObject interface is called by a RemoteObject and returns itself
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1380", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1380---------------------------");
                try {
                    let testRemoteObject = new TestRemoteObject("testObject");
                    expect(testRemoteObject.asObject() != null).assertTrue();
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1380---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1390
             * @tc.name    : test MessageSequence sendMessageRequest API test
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1390", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1390---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    let rawdata = [1, 2, 3];
                    let option = new rpc.MessageOption();
                    var reply = rpc.MessageSequence.create();
                    data.getRawDataCapacity();
                    data.writeInt(rawdata.length);
                    data.writeRawData(rawdata, rawdata.length);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_RAWDATA, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readInt()).assertEqual(rawdata.length);
                        expect(result.reply.readRawData(rawdata.length) != rawdata).assertTrue();
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1390---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1400
             * @tc.name    : test Invoke the writestring interface to write data to the MessageSequence instance. sendMessageRequest asynchronously
             *               verifies the priority processing levels of onRemoteMessageRequest and onRemoteRequest
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1400---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    let token = "onRemoteRequest or onRemoteMessageRequest invoking";
                    data.writeString(token);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_ONREMOTEMESSAGE_OR_ONREMOTE, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readString()).assertEqual("onRemoteMessageRequest invoking");
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1400---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1410
             * @tc.name    : test writeRemoteObject is proxy or remote object is invalid Error message verification
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1410", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1410---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    let token = {};
                    data.writeRemoteObject(token);
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error.code == 1900008).assertTrue();
                    expect(error.message != null).assertTrue();
                } finally {
                    data.reclaim();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1410---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1420
             * @tc.name    : test readParcelable is Call JS callback function failedv Error message verification
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1420", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1420---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    let sequenceable = new MySequenceable(1, "aaa");
                    data.writeParcelable(sequenceable);
                    data.setCapacity(0);
                    data.setSize(0);
                    let ret = new MySequenceable(1, "");
                    data.readParcelable(ret);
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    let errCode = `${rpc.ErrorCode.CALL_JS_METHOD_ERROR}`;
                    expect(error.message != null).assertTrue();
                    expect(error.code != errCode).assertTrue();
                } finally {
                    data.reclaim();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1420---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1430
             * @tc.name    : test Call the writeinterfacetoken interface, write the interface descriptor, and read interfacetoken
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1430", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, function () {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1430---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    let token = "hello ruan zong xian";
                    data.writeInterfaceToken(token);
                    data.setCapacity(0);
                    data.setSize(0);
                    data.readInterfaceToken();
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    let errCode = `${rpc.ErrorCode.READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR}`;
                    expect(error.message != null).assertTrue();
                    expect(error.code != errCode).assertTrue();
                } finally {
                    data.reclaim();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1430---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1440
             * @tc.name    : test writeString check param error Error message verification
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1440", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1440---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    let token = '';
                    for (let i = 0; i < 40 * K; i++) {
                        token += 'a';
                    };
                    data.writeString(token);
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    let errCode = `${rpc.ErrorCode.CHECK_PARAM_ERROR}`;
                    expect(error.code == errCode).assertTrue();
                    expect(error.message != null).assertTrue();
                } finally {
                    data.reclaim();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1440---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1450
             * @tc.name    : test writeInterfaceToken Sequence memory alloc failed Error message verification
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1450", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1450---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    data.setSize(0);
                    data.setCapacity(0);
                    let token = "hello ruan zong xian";
                    data.writeInterfaceToken(token);
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    let errCode = `${rpc.ErrorCode.PARCEL_MEMORY_ALLOC_ERROR}`;
                    expect(error.code == errCode).assertTrue();
                    expect(error.message != null).assertTrue();
                } finally {
                    data.reclaim();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1450---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1460
             * @tc.name    : test writeInterfaceToken Write data to message sequence failed Error message verification
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1460", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1460---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    data.setSize(true);
                    data.setCapacity(true);
                    let token = "hello ruan zong xian";
                    data.writeInterfaceToken(token);
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    let errCode = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
                    expect(error.code != errCode).assertTrue();
                    expect(error.message != null).assertTrue();
                } finally {
                    data.reclaim();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1460---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1470
             * @tc.name    : test readParcelable Sequence memory alloc failed Error message verification
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1470", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1470---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    let sequenceable = new MySequenceable(1, "aaa");
                    data.writeParcelable(sequenceable);
                    let ret = new MySequenceable(0, "");
                    data.setCapacity(0);
                    data.readParcelable(ret);
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    let errCode = `${rpc.ErrorCode.PARCEL_MEMORY_ALLOC_ERROR}`;
                    expect(error.code == errCode).assertTrue();
                    expect(error.message != null).assertTrue();
                } finally {
                    data.reclaim();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1470---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1480
             * @tc.name    : test Test messageparcel delivery file descriptor object
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1480", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1480---------------------------");
                let context = FA.getContext();
                await context.getFilesDir()
                    .then(async function (path) {
                        expect(path != null).assertTrue();
                        let basePath = path;
                        let filePath = basePath + "/test1.txt";
                        let fd = fileio.openSync(filePath, 0o2 | 0o100 | 0o2000, 0o666);
                        expect(fd >= 0).assertTrue();
                        let str = "HELLO RPC";
                        let bytesWr = fileio.writeSync(fd, str);
                        let option = new rpc.MessageOption();
                        var data = rpc.MessageSequence.create();
                        var reply = rpc.MessageSequence.create();
                        data.containFileDescriptors();
                        data.writeInt(bytesWr);
                        data.writeFileDescriptor(fd);
                        data.containFileDescriptors();
                        data.containFileDescriptors();
                        await gIRemoteObject.sendMessageRequest(CODE_FILESDIR, data, reply, option)
                            .then(function (result) {
                                expect(result.errCode).assertEqual(0);
                                let buf = new ArrayBuffer(str.length * 2);
                                let bytesRd = fileio.readSync(fd, buf, { position: 0, });
                                expect(bytesRd == (bytesWr + bytesWr)).assertTrue();
                                let fdResult = result.reply.readFileDescriptor();
                                expect(fdResult >= fd).assertTrue();
                                let content = String.fromCharCode.apply(null, new Uint8Array(buf));
                                expect(content).assertEqual(str + str);
                                let dupFd = rpc.MessageSequence.dupFileDescriptor(fd);
                                expect(dupFd >= fd).assertTrue();
                                let buf2 = new ArrayBuffer(str.length * 2);
                                let byteRd2 = fileio.readSync(dupFd, buf2, { position: 0, });
                                expect(byteRd2 == (bytesWr + bytesWr)).assertTrue();
                                let content2 = String.fromCharCode.apply(null, new Uint8Array(buf2));
                                expect(content2).assertEqual(str + str);
                                rpc.MessageSequence.closeFileDescriptor(fd);
                                rpc.MessageSequence.closeFileDescriptor(dupFd);
                            })
                        try {
                            console.info("after close fd, write again");
                            fileio.writeSync(fd, str);
                            expect(0).assertEqual(1);
                        } catch (e) {
                            console.error("got exception: " + e);
                        } finally {
                            data.reclaim();
                            reply.reclaim();
                            done();
                        }
                    })
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1480---------------------------");
            });
    
                    /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1480
             * @tc.name    : test Test messageparcel delivery file descriptor object
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1480", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1480---------------------------");
                let context = FA.getContext();
                await context.getFilesDir()
                    .then(async function (path) {
                        expect(path != null).assertTrue();
                        let basePath = path;
                        let filePath = basePath + "/test1.txt";
                        let fd = fileio.openSync(filePath, 0o2 | 0o100 | 0o2000, 0o666);
                        expect(fd >= 0).assertTrue();
                        let str = "HELLO RPC";
                        let bytesWr = fileio.writeSync(fd, str);
                        let option = new rpc.MessageOption();
                        var data = rpc.MessageSequence.create();
                        var reply = rpc.MessageSequence.create();
                        data.containFileDescriptors();
                        data.writeInt(bytesWr);
                        data.writeFileDescriptor(fd);
                        data.containFileDescriptors();
                        data.containFileDescriptors();
                        await gIRemoteObject.sendMessageRequest(CODE_FILESDIR, data, reply, option)
                            .then(function (result) {
                                expect(result.errCode).assertEqual(0);
                                let buf = new ArrayBuffer(str.length * 2);
                                let bytesRd = fileio.readSync(fd, buf, { position: 0, });
                                expect(bytesRd == (bytesWr + bytesWr)).assertTrue();
                                let fdResult = result.reply.readFileDescriptor();
                                expect(fdResult >= fd).assertTrue();
                                let content = String.fromCharCode.apply(null, new Uint8Array(buf));
                                expect(content).assertEqual(str + str);
                                let dupFd = rpc.MessageSequence.dupFileDescriptor(fd);
                                expect(dupFd >= fd).assertTrue();
                                let buf2 = new ArrayBuffer(str.length * 2);
                                let byteRd2 = fileio.readSync(dupFd, buf2, { position: 0, });
                                expect(byteRd2 == (bytesWr + bytesWr)).assertTrue();
                                let content2 = String.fromCharCode.apply(null, new Uint8Array(buf2));
                                expect(content2).assertEqual(str + str);
                                rpc.MessageSequence.closeFileDescriptor(fd);
                                rpc.MessageSequence.closeFileDescriptor(dupFd);
                            })
                        try {
                            console.info("after close fd, write again");
                            fileio.writeSync(fd, str);
                            expect(0).assertEqual(1);
                        } catch (e) {
                            console.error("got exception: " + e);
                        } finally {
                            data.reclaim();
                            reply.reclaim();
                            done();
                        }
                    })
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1480---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1490
             * @tc.name    : test Test MessageSequence write and read ArrayBuffer int8array
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1490", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1490---------------------------");
                var data = rpc.MessageSequence.create();
                let buffer = new ArrayBuffer(5);
                let int8View = new Int8Array(buffer);
                for (let i = 0; i < int8View.length; i++) {
                    int8View[i] = i + 1;
                };
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_1490 int8View is:" + int8View);
                try {
                    data.writeArrayBuffer(buffer, rpc.TypeCode.INT8_ARRAY);
                    let arrayBuffer = data.readArrayBuffer(rpc.TypeCode.INT8_ARRAY);
                    let int8Array = new Int8Array(arrayBuffer);
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_1490 int8Array is:" + int8Array);
                     assertArrayElementEqual(int8View,int8Array);
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_1490 error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1490---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1500
             * @tc.name    : test Test MessageSequence write and read ArrayBuffer uint8array
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1500---------------------------");
                var data = rpc.MessageSequence.create();
                let buffer = new ArrayBuffer(12);
                let uInt8View = new Uint8Array(buffer);
                for (let i = 0; i < uInt8View.length; i++) {
                    uInt8View[i] = i + 10;
                };
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_1500 uInt8View is:" + uInt8View);
                try {
                    data.writeArrayBuffer(buffer, rpc.TypeCode.UINT8_ARRAY);
                    let arrayBuffer = data.readArrayBuffer(rpc.TypeCode.UINT8_ARRAY);
                    let uInt8Array = new Uint8Array(arrayBuffer);
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_1500 uInt8Array is:" + uInt8Array);
                     assertArrayElementEqual(uInt8View,uInt8Array);
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_1500 error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1500---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1510
             * @tc.name    : test Test MessageSequence write and read ArrayBuffer int16array
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1510", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1510---------------------------");
                var data = rpc.MessageSequence.create();
                let buffer = new ArrayBuffer(10);
                let int16View = new Int16Array(buffer);
                for (let i = 0; i < int16View.length; i++) {
                    int16View[i] = i + 20;
                };
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_1510 int16View is:" + int16View);
                try {
                    data.writeArrayBuffer(buffer, rpc.TypeCode.INT16_ARRAY);
                    let arrayBuffer = data.readArrayBuffer(rpc.TypeCode.INT16_ARRAY);
                    let int16Array = new Int16Array(arrayBuffer);
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_1510 int16Array is:" + int16Array);
                    assertArrayElementEqual(int16View,int16Array);
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_1510 error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1510---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1520
             * @tc.name    : test Test MessageSequence write and read ArrayBuffer uint16array
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1520", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1520---------------------------");
                var data = rpc.MessageSequence.create();
                let buffer = new ArrayBuffer(12);
                let uInt16View = new Uint16Array(buffer);
                for (let i = 0; i < uInt16View.length; i++) {
                    uInt16View[i] = i + 20;
                };
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_1520 uInt16View is:" + uInt16View);
                try {
                    data.writeArrayBuffer(buffer, rpc.TypeCode.UINT16_ARRAY);
                    let arrayBuffer = data.readArrayBuffer(rpc.TypeCode.UINT16_ARRAY);
                    let uInt16Array = new Uint16Array(arrayBuffer);
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_1520 uInt16Array is:" + uInt16Array);
                    assertArrayElementEqual(uInt16View,uInt16Array);
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_1520 error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1520---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1530
             * @tc.name    : test Test MessageSequence write and read ArrayBuffer int32array
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1530", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1530---------------------------");
                var data = rpc.MessageSequence.create();
                let buffer = new ArrayBuffer(20);
                let int32View = new Int32Array(buffer);
                for (let i = 0; i < int32View.length; i++) {
                    int32View[i] = 2 * i + 1;
                };
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_1530 int32View is:" + int32View);
                try {
                    data.writeArrayBuffer(buffer, rpc.TypeCode.INT32_ARRAY);
                    let arrayBuffer = data.readArrayBuffer(rpc.TypeCode.INT32_ARRAY);
                    let int32Array = new Int32Array(arrayBuffer);
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_1530 Int32Array is:" + int32Array);
                    assertArrayElementEqual(int32View,int32Array);
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_1530 error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1530---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1540
             * @tc.name    : test Test MessageSequence write and read ArrayBuffer uint32array
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1540", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1540---------------------------");
                var data = rpc.MessageSequence.create();
                let buffer = new ArrayBuffer(12);
                let uInt32View = new Uint32Array(buffer);
                for (let i = 0; i < uInt32View.length; i++) {
                    uInt32View[i] = i + 30;
                };
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_1540 Uint32Array is:" + uInt32View);
                try {
                    data.writeArrayBuffer(buffer, rpc.TypeCode.UINT32_ARRAY);
                    let arrayBuffer = data.readArrayBuffer(rpc.TypeCode.UINT32_ARRAY);
                    let uInt32Array = new Uint32Array(arrayBuffer);
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_1540 Uint32Array is:" + uInt32Array);
                    assertArrayElementEqual(uInt32View,uInt32Array);
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_1540 error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1540---------------------------");
            });
    
            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1550
             * @tc.name    : test Test MessageSequence write and read ArrayBuffer float32array
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_1550", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1550---------------------------");
                var data = rpc.MessageSequence.create();
                let buffer = new ArrayBuffer(12);
                let float32View = new Float32Array(buffer);
                for (let i = 0; i < float32View.length; i++) {
                    float32View[i] = i + 100;
                };
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_1550 float32View is:" + float32View);
                try {
                    data.writeArrayBuffer(buffer, rpc.TypeCode.FLOAT32_ARRAY);
                    let arrayBuffer = data.readArrayBuffer(rpc.TypeCode.FLOAT32_ARRAY);
                    let float32Array = new Float32Array(arrayBuffer);
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_1550 float32Array is:" + float32Array);
                    assertArrayElementEqual(float32View,float32Array);
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_1550 error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1550---------------------------");
            });

    console.info("-----------------------SUB_DSoftbus_IPC_API_Stage_MessageSequence_Test is end-----------------------");
  })
}