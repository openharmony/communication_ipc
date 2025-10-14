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
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1560
    * @tc.name    : test Test MessageSequence write and read ArrayBuffer float64array
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageSequence_1560", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1560---------------------------");
        var data = rpc.MessageSequence.create();
        let buffer = new ArrayBuffer(24);
        let float64View = new Float64Array(buffer);
        for (let i = 0; i < float64View.length; i++) {
            float64View[i] = i + 200;
        };
        console.info("SUB_DSoftbus_IPC_API_MessageSequence_1560 float64View is:" + float64View);
        try {
            data.writeArrayBuffer(buffer, rpc.TypeCode.FLOAT64_ARRAY);
            let arrayBuffer = data.readArrayBuffer(rpc.TypeCode.FLOAT64_ARRAY);
            let float64Array = new Float64Array(arrayBuffer);
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_1560 float64Array is:" + float64Array);
            assertArrayElementEqual(float64View,float64Array);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_1560 error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1560---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1570
    * @tc.name    : test Test MessageSequence write and read ArrayBuffer bigint64array
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageSequence_1570", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
    console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1570---------------------------");
    var data = rpc.MessageSequence.create();
    let buffer = new ArrayBuffer(24);
    let int64View = new BigInt64Array(buffer);
    for (let i = 0; i < int64View.length; i++) {
        int64View[i] = BigInt(1110 + i);
    };
    console.info("SUB_DSoftbus_IPC_API_MessageSequence_1570 int64View is:" + int64View);
    try {
        data.writeArrayBuffer(buffer, rpc.TypeCode.BIGINT64_ARRAY);
        let arrayBuffer = data.readArrayBuffer(rpc.TypeCode.BIGINT64_ARRAY);
        let int64Array = new BigInt64Array(arrayBuffer);
        console.info("SUB_DSoftbus_IPC_API_MessageSequence_1570 int64Array is:" + int64Array);
        assertArrayElementEqual(int64View, int64Array);
    } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_MessageSequence_1570 error is:" + error);
        expect(error == null).assertTrue();
    } finally {
        data.reclaim();
        done();
    }
    console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1570---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1580
    * @tc.name    : test Test MessageSequence write and read ArrayBuffer bigUint64array
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageSequence_1580", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1580---------------------------");
        var data = rpc.MessageSequence.create();
        let buffer = new ArrayBuffer(24);
        let uInt64View = new BigUint64Array(buffer);
        for (let i = 0; i < uInt64View.length; i++) {
            uInt64View[i] = BigInt(i + 40);
        };
        console.info("SUB_DSoftbus_IPC_API_MessageSequence_1580 uInt64View is:" + uInt64View);
        try {
            data.writeArrayBuffer(buffer, rpc.TypeCode.BIGUINT64_ARRAY);
            let arrayBuffer = data.readArrayBuffer(rpc.TypeCode.BIGUINT64_ARRAY);
            let uInt64Array = new BigUint64Array(arrayBuffer);
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_1580 uInt64Array is:" + uInt64Array);
            assertArrayElementEqual(uInt64View, uInt64Array);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_1580 error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1580---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1590
    * @tc.name    : test Test MessageSequence writeArrayBuffer Beyond the maximum
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageSequence_1590", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1590---------------------------");
        var data = rpc.MessageSequence.create();
        let buffer = new ArrayBuffer(24);
        let uInt64View = new BigUint64Array(buffer);
        for (let i = 0; i < uInt64View.length; i++) {
            uInt64View[i] = BigInt(i + 400);
        };
        console.info("SUB_DSoftbus_IPC_API_MessageSequence_1590 uInt64View is:" + uInt64View);
        try {
            data.writeArrayBuffer(buffer, 12);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_1590 error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1590---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1600
    * @tc.name    : test Test MessageSequence writeArrayBuffer Less than the minimum
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageSequence_1600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1600---------------------------");
        var data = rpc.MessageSequence.create();
        let buffer = new ArrayBuffer(24);
        let uInt64View = new BigUint64Array(buffer);
        for (let i = 0; i < uInt64View.length; i++) {
            uInt64View[i] = BigInt(i + 40);
        };
        console.info("SUB_DSoftbus_IPC_API_MessageSequence_1600 uInt64View is:" + uInt64View);
        try {
            data.writeArrayBuffer(buffer, -2);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_1600 error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1600---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1610
    * @tc.name    : test Test MessageSequence readArrayBuffer Beyond the maximum
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageSequence_1610", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1610---------------------------");
        var data = rpc.MessageSequence.create();
        let buffer = new ArrayBuffer(10);
        let int16View = new Int16Array(buffer);
        for (let i = 0; i < int16View.length; i++) {
            int16View[i] = i + 20;
        };
        console.info("SUB_DSoftbus_IPC_API_MessageSequence_1610 int16View is:" + int16View);
        try {
            data.writeArrayBuffer(buffer, rpc.TypeCode.INT16_ARRAY);
            data.readArrayBuffer(13);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_1610 error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1610---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1620
    * @tc.name    : test Test MessageSequence readArrayBuffer Less than the minimum
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageSequence_1620", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1620---------------------------");
        var data = rpc.MessageSequence.create();
        let buffer = new ArrayBuffer(10);
        let int16View = new Int16Array(buffer);
        for (let i = 0; i < int16View.length; i++) {
            int16View[i] = i + 20;
        };
        console.info("SUB_DSoftbus_IPC_API_MessageSequence_1620 int16View is:" + int16View);
        try {
            data.writeArrayBuffer(buffer, rpc.TypeCode.INT16_ARRAY);
            data.readArrayBuffer(-5);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_1620 error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1620---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1630
    * @tc.name    : test Test MessageSequence writeArrayBuffer after reclaim
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageSequence_1630", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1630---------------------------");
        var data = rpc.MessageSequence.create();
        let buffer = new ArrayBuffer(10);
        let int16View = new Int16Array(buffer);
        for (let i = 0; i < int16View.length; i++) {
            int16View[i] = i + 20;
        };
        console.info("SUB_DSoftbus_IPC_API_MessageSequence_1630 int16View is:" + int16View);
        try {
            data.reclaim();
            data.writeArrayBuffer(buffer, rpc.TypeCode.INT16_ARRAY);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_1630 error is:" + error);
            expect(error.code == 1900009).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            done();
            }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1630---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1640
    * @tc.name    : test Test MessageSequence readArrayBuffer after reclaim
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageSequence_1640", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1640---------------------------");
        var data = rpc.MessageSequence.create();
        let buffer = new ArrayBuffer(200);
        let int16View = new Int16Array(buffer);
        for (let i = 0; i < int16View.length; i++) {
            int16View[i] = i + 20;
        };
        console.info("SUB_DSoftbus_IPC_API_MessageSequence_1640 int16View is:" + int16View);
        try {
            data.writeArrayBuffer(buffer, rpc.TypeCode.INT16_ARRAY);
            let arrayBuffer = data.readArrayBuffer(rpc.TypeCode.INT16_ARRAY);
            let int16Array = new Int16Array(arrayBuffer);
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_1640 int16Array is:" + int16Array);
            assertArrayElementEqual(int16View,int16Array);
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_1640 readArrayBuffer second time");
            data.rewindRead(0);
            data.reclaim();
            data.readArrayBuffer(rpc.TypeCode.INT16_ARRAY);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_1640 error is:" + error);
            expect(error.code == 1900010).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            done();
            }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1640---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1650
    * @tc.name    : test Test MessageSequence readArrayBuffer after reclaim
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageSequence_1650", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1650---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            var option = rpc.MessageOption();
            let buffer1 = new ArrayBuffer(200);
            let int16View = new Int16Array(buffer1);
            for (let i = 0; i < int16View.length; i++) {
                int16View[i] = i + 20;
            };
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_1650 int16View is:" + int16View);
            let buffer2 = new ArrayBuffer(200);
            let int8View = new Int8Array(buffer2);
            for (let i = 0; i < int8View.length; i++) {
                int8View[i] = i * 2;
            };
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_1650 int8View is:" + int8View);

            data.writeArrayBuffer(buffer1, rpc.TypeCode.INT16_ARRAY);
            data.writeArrayBuffer(buffer2, rpc.TypeCode.INT8_ARRAY);
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_ARRAYBUFFER, data, reply, option).then((result) => {
                let reply1 = result.reply.readArrayBuffer(rpc.TypeCode.INT8_ARRAY);
                let reply2 = result.reply.readArrayBuffer(rpc.TypeCode.INT16_ARRAY);
                expect(result.errCode).assertEqual(0);
                assertArrayElementEqual(new Int8Array(reply1),int8View);
                assertArrayElementEqual(new Int16Array(reply2),int16View);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_1650 error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
            }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1650---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1660
    * @tc.name    : test Call the writeRemoteObjectArray interface, write the array to the MessageSequence instance,
    *               and call readRemoteObjectArray (datain: string []) to read the data
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageSequence_1660", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1660---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            var option = rpc.MessageOption();
            let listeners = [new TestRemoteObject("rpcListener"), 
                new TestRemoteObject("rpcListener2"), new TestRemoteObject("rpcListener3")];
            data.writeRemoteObjectArray(listeners);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_REMOTEOBJECTARRAY_3, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                let rlisteners = new Array(3);
                result.reply.readRemoteObjectArray(rlisteners);
                for(let index = 0; index < rlisteners.length; index++){
                    expect(rlisteners[index] != null).assertTrue();
                    console.info(" readRemoteObjectArray is success");
                }
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_1660 error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
            }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1660---------------------------");
    });

    
    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1670
    * @tc.name    : test The readRemoteObjectArray interface directly reads parameters
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageSequence_1670", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1670---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            let listeners = [new TestRemoteObject("rpcListener"),
            new TestRemoteObject("rpcListener2"),
            new TestRemoteObject("rpcListener3")];
            data.writeRemoteObjectArray(listeners);
            let rlisteners = data.readRemoteObjectArray();
            expect(rlisteners != null).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_1670 error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1670---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1680
    * @tc.name    : test The readRemoteObjectArray interface reads parameters to an empty array
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageSequence_1680", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1680---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            let listeners = [new TestRemoteObject("rpcListener"),
            new TestRemoteObject("rpcListener2"),
            new TestRemoteObject("rpcListener3")];
            data.writeRemoteObjectArray(listeners);
            let rlisteners = new Array(3);
            data.readRemoteObjectArray(rlisteners);
            expect(rlisteners != null).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_1680 error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1680---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0010
    * @tc.name    : test Call the writeinterfacetoken interface, write the interface descriptor, and read interfacetoken
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0010", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0010---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let token = "hello ruan zong xian";
            let result = data.writeInterfaceToken(token);
            expect(result).assertTrue();
            let resultToken = data.readInterfaceToken();
            expect(resultToken).assertEqual(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel_testcase error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0010---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0020
    * @tc.name    : test Call the writeinterfacetoken interface, write the interface descriptor, and read interfacetoken
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0020", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0020---------------------------");
        try {
            for (let i = 0; i < 5; i++) {
                var data = rpc.MessageParcel.create();
                let token = "hello ruan zong xian";
                let result = data.writeInterfaceToken(token);
                expect(result).assertTrue();
                let resultToken = data.readInterfaceToken();
                expect(resultToken).assertEqual(token);
            }
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0020---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0030
    * @tc.name    : test Call the writeinterfacetoken interface to write a non string interface descriptor 
    *             and read interfacetoken
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0030", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0030---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let token = "";
            for (let i = 0; i < (40 * K - 1); i++) {
                token += 'a';
            };
            let result = data.writeInterfaceToken(token);
            expect(result).assertTrue();
            let resultToken = data.readInterfaceToken();
            expect(resultToken).assertEqual(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0030---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0040
    * @tc.name    : test The WriteInterfaceToken interface is called, the exceeding-length interface descriptor is written,
    *               and the InterfaceToken is read
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0040", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0040---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let token = "";
            for (let i = 0; i < 40 * K; i++) {
                token += 'a';
            };
            let result = data.writeInterfaceToken(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0040---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0050
    * @tc.name    : test Call the writeinterfacetoken interface to write a non string interface descriptor 
    *               and read interfacetoken
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0050", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0050---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let token = 123;
            let result = data.writeInterfaceToken(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0050---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0060
    * @tc.name    : test The data size of the messageparcel obtained by calling the getSize interface
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0060", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0060---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let size = data.getSize();
            expect(size).assertEqual(0);
            let addData = 1;
            let result = data.writeInt(addData);
            expect(result).assertTrue();
            size = data.getSize();
            expect(size).assertEqual(4);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0060---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0070
    * @tc.name    : test The capacity of the messageparcel obtained by calling the getcapacity interface
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0070", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0070---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let size = data.getCapacity();
            expect(size).assertEqual(0);
            let addData = 1;
            let result = data.writeInt(addData);
            expect(result).assertTrue();
            size = data.getCapacity();
            expect(size).assertEqual(64);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0070---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0080
    * @tc.name    : test Call the SetSize interface to set the data size of messageparcel
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0080", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0080---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let addData = 1;
            let result = data.writeInt(addData);
            expect(result).assertTrue();
            let size = 6;
            let setResult = data.setSize(size);
            expect(setResult).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0080---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0090
    * @tc.name    : test Call the SetSize interface to set the data size of messageparcel
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0090", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0090---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let addData = 1;
            let result = data.writeInt(addData);
            expect(result).assertTrue();
            let size = 4 * G;
            let setResult = data.setSize(size);
            expect(setResult).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0090---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0100
    * @tc.name    : test Call the SetSize interface to set the data size of messageparcel
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0100---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let addData = 1;
            let result = data.writeInt(addData);
            expect(result).assertTrue();
            let size = 4 * G - 4;
            let setResult = data.setSize(size);
            expect(setResult).assertEqual(false);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0100---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0110
    * @tc.name    : test Call the SetSize interface to set the data size of messageparcel. The write data size 
    *             does not match the set value
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0110", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0110---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let capacity = 64;
            let setResult = data.setCapacity(capacity);
            expect(setResult).assertTrue();
            let size = 4;
            setResult = data.setSize(size);
            expect(setResult).assertTrue();
            let addData = 2;
            let result = data.writeLong(addData);
            expect(result).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0110---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0120
    * @tc.name    : test Call the setcapacity interface to set the capacity of messageparcel
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0120", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0120---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let size = 64;
            let setResult = data.setCapacity(size);
            expect(setResult).assertTrue();
            let addData = 1;
            let result = data.writeInt(addData);
            expect(result).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0120---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0130
    * @tc.name    : test Call the setcapacity interface to set the capacity of messageparcel
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0130", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0130---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let size = M;
            let setResult = data.setCapacity(size);
            expect(setResult).assertTrue();
            let addData = 1;
            let result = data.writeInt(addData);
            expect(result).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0130---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0140
    * @tc.name    : test Call the setcapacity interface to set the capacity of messageparcel
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0140", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0140---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let size = 4 * G;
            let setResult = data.setCapacity(size);
            expect(setResult).assertEqual(false);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0140---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0150
    * @tc.name    : test Call the setcapacity interface to set the capacity of messageparcel.
    *             The write data capacity is inconsistent with the set value
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0150", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0150---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let size = 4;
            let setResult = data.setCapacity(size);
            expect(setResult).assertTrue();
            let addData = [1, 2, 3, 4, 5, 6, 7, 8];
            let result = data.writeIntArray(addData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0150---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0160
    * @tc.name    : test Empty object to obtain the readable byte space, read location,
    *             writable byte space and write location information of messageparcel
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0160", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0160---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let result1 = data.getWritableBytes();
            expect(result1).assertEqual(0);
            let result2 = data.getReadableBytes();
            expect(result2).assertEqual(0);
            let result3 = data.getReadPosition();
            expect(result3).assertEqual(0);
            let result4 = data.getWritePosition();
            expect(result4).assertEqual(0);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0160---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0170
    * @tc.name    : test Create an object and write data to obtain the readable byte space, read location,
    *             writable byte space and write location information of messageparcel
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0170", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0170---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let dataInt = 1;
            let resultInt = data.writeInt(dataInt);
            expect(resultInt).assertTrue();
            let dataLong = 2;
            let resultLong = data.writeLong(dataLong);
            expect(resultLong).assertTrue();
            let result1 = data.getWritableBytes();
            expect(result1).assertEqual(52);
            let result2 = data.getReadableBytes();
            expect(result2).assertEqual(12);
            let result3 = data.getReadPosition();
            expect(result3).assertEqual(0);
            let result4 = data.getWritePosition();
            expect(result4).assertEqual(12);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0170---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0180
    * @tc.name    : test Call rewindread interface to offset the read position to the specified position
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0180", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0180---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            expect(data.getWritableBytes()).assertEqual(0);
            expect(data.getReadableBytes()).assertEqual(0);
            expect(data.getReadPosition()).assertEqual(0);
            expect(data.getWritePosition()).assertEqual(0);
            let dataInt = 1;
            let resultInt = data.writeInt(dataInt);
            let dataLong = 2;
            let resultLong = data.writeLong(dataLong);
            expect(resultLong).assertTrue();
            expect(data.getWritableBytes()).assertEqual(52);
            expect(data.getReadableBytes()).assertEqual(12);
            expect(data.getReadPosition()).assertEqual(0);
            expect(data.getWritePosition()).assertEqual(12);
            let readIntData = data.readInt();
            expect(readIntData).assertEqual(dataInt);
            let writePosition = 0;
            let writeResult = data.rewindWrite(writePosition);
            expect(writeResult).assertTrue();
            expect(data.getWritePosition()).assertEqual(0);
            dataInt = 3;
            resultInt = data.writeInt(dataInt);
            let readPosition = 0;
            let readResult = data.rewindRead(readPosition);
            expect(readResult).assertTrue();
            readIntData = data.readInt();
            expect(readIntData).assertEqual(dataInt);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0180---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0190
    * @tc.name    : test The rewindread interface is called to re offset the read position to the specified position.
    *               The specified position is out of range
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0190", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0190---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let result1 = data.getWritableBytes();
            expect(result1 == 0).assertTrue();
            let result2 = data.getReadableBytes();
            expect(result2 == 0).assertTrue();
            let result3 = data.getReadPosition();
            expect(result3 == 0).assertTrue();
            let result4 = data.getWritePosition();
            expect(result4 == 0).assertTrue();
            let dataInt = 1;
            let resultInt = data.writeInt(dataInt);
            expect(resultInt).assertTrue();
            let dataLong = 2;
            let resultLong = data.writeLong(dataLong);
            expect(resultLong).assertTrue();
            result1 = data.getWritableBytes();
            expect(result1 == 52).assertTrue();
            result2 = data.getReadableBytes();
            expect(result2 == 12).assertTrue();
            result3 = data.getReadPosition();
            expect(result3 == 0).assertTrue();
            result4 = data.getWritePosition();
            expect(result4 == 12).assertTrue();
            let readPosition = 100;
            let readResult = data.rewindRead(readPosition);
            expect(readResult == false).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0190---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0200
    * @tc.name    : test Call rewindwrite and the interface offsets the write position to the specified position
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0200---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let dataInt = 1;
            let resultInt = data.writeInt(dataInt);
            expect(resultInt).assertTrue();
            let readIntData = data.readInt();
            expect(readIntData).assertEqual(dataInt);
            let writePosition = 0;
            let rewindWriteResult = data.rewindWrite(writePosition);
            expect(rewindWriteResult).assertTrue();
            dataInt = 3;
            resultInt = data.writeInt(dataInt);
            expect(resultInt).assertTrue();
            let readPosition = 0;
            let rewindReadResult = data.rewindRead(readPosition);
            expect(rewindReadResult);
            readIntData = data.readInt();
            expect(readIntData).assertEqual(dataInt);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0200---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0210
    * @tc.name    : test Call rewindwrite and the interface offsets the write position to the specified position.
    *               The specified position is out of range
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0210", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0210---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let dataInt = 1;
            let resultInt = data.writeInt(dataInt);
            expect(resultInt).assertTrue();
            let readIntData = data.readInt();
            expect(readIntData == dataInt).assertTrue();
            let writePosition = 99;
            let rewindWriteResult = data.rewindWrite(writePosition);
            expect(rewindWriteResult).assertEqual(false);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0210---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0220
    * @tc.name    : test Call the writeshortarray interface, write the array to the messageparcel instance,
    *             and call readshortarray to read the data
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0220", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0220---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let wShortArryData = [3, 5, 9];
            let writeShortArrayResult = data.writeShortArray(wShortArryData);
            expect(writeShortArrayResult).assertTrue();
            let rShortArryData = data.readShortArray();
            assertArrayElementEqual(rShortArryData,wShortArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0220---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0230
    * @tc.name    : test Call the writeshortarray interface, write the short integer array to the messageparcel instance,
    *             and call readshortarray (datain: number []) to read the data
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0230", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0230---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let wShortArryData = [];
            for (let i = 0; i < (50 * K - 1); i++) {
                wShortArryData[i] = 1;
            };
            let writeShortArrayResult = data.writeShortArray(wShortArryData);
            expect(writeShortArrayResult).assertTrue();
            let rShortArryData = [];
            data.readShortArray(rShortArryData);
                assertArrayElementEqual(rShortArryData,wShortArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0230---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0240
    * @tc.name    : test Writeshortarray interface, boundary value verification
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0240", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0240---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let wShortArryData = [-32768, 0, 1, 2, 32767];
            let writeShortArrayResult = data.writeShortArray(wShortArryData);
            expect(writeShortArrayResult).assertTrue();
            let rShortArryData = [];
            data.readShortArray(rShortArryData);
            assertArrayElementEqual(rShortArryData,wShortArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0240---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0250
    * @tc.name    : test Writeshortarray interface, illegal value validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0250", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0250---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let wShortArryData = [-32769, 0, 1, 2];
            let writeShortArrayResult = data.writeShortArray(wShortArryData);
            expect(writeShortArrayResult).assertTrue();
            let rShotrArrayData = data.readShortArray();
            expect(32767).assertEqual(rShotrArrayData[0]);
            expect(wShortArryData[1]).assertEqual(rShotrArrayData[1]);
            expect(wShortArryData[2]).assertEqual(rShotrArrayData[2]);
            expect(wShortArryData[3]).assertEqual(rShotrArrayData[3]);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0250---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0260
    * @tc.name    : test Writeshortarray interface, illegal value validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0260", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0260---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let wShortArryData = [0, 1, 2, 32768];
            let writeShortArrayResult = data.writeShortArray(wShortArryData);
            expect(writeShortArrayResult).assertTrue();
            let rShotrArrayData = data.readShortArray();
            expect(wShortArryData[0]).assertEqual(rShotrArrayData[0]);
            expect(wShortArryData[1]).assertEqual(rShotrArrayData[1]);
            expect(wShortArryData[2]).assertEqual(rShotrArrayData[2]);
            expect(-32768).assertEqual(rShotrArrayData[3]);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0260---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0270
    * @tc.name    : test Writeshortarray interface, illegal value validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0270", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0270---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let wShortArryData = [];
            for (let i = 0; i < 50 * K; i++) {
                wShortArryData[i] = 11111;
            };
            let writeShortArrayResult = data.writeShortArray(wShortArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0270---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0280
    * @tc.name    : test Call the writelongarray interface, write the long integer array to the messageparcel instance,
    *             and call readlongarray to read the data
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0280", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0280---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let LongArryData = [];
            for (let i = 0; i < (25 * K - 1); i++) {
                LongArryData[i] = 11;
            };
            let WriteLongArray = data.writeLongArray(LongArryData);
            expect(WriteLongArray).assertTrue();
            let rLongArryData = data.readLongArray();
            assertArrayElementEqual(rLongArryData,LongArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0280---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0290
    * @tc.name    : test Writelongarray interface, boundary value verification
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0290", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0290---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let wLongArryData = [-2147483648, 0, 1, 2, 2147483647];
            let writeLongArrayResult = data.writeLongArray(wLongArryData);
            expect(writeLongArrayResult).assertTrue();
            let rLongArryData = data.readLongArray();
            assertArrayElementEqual(rLongArryData,wLongArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0290---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0300
    * @tc.name    : test Writelongarray interface, illegal value validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0300---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let errorLongArryData = [-2147483649, 0, 1, 2, 3];
            let erWriteLongArray = data.writeLongArray(errorLongArryData);
            expect(erWriteLongArray).assertTrue();
            let erLongArryData = data.readLongArray();
            assertArrayElementEqual(erLongArryData,errorLongArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0300---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0310
    * @tc.name    : test Writelongarray interface, illegal value validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0310", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0310---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let errorLongArryData = [0, 1, 2, 3, 2147483648];
            let erWriteLongArray = data.writeLongArray(errorLongArryData);
            expect(erWriteLongArray).assertTrue();
            let erLongArryData = data.readLongArray();
            assertArrayElementEqual(erLongArryData,errorLongArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0310---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0320
    * @tc.name    : test Writelongarray interface, illegal value validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0320", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0320---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let errorLongArryData = [];
            for (let i = 0; i < 25 * K; i++) {
                errorLongArryData[i] = 11;
            };
            let erWriteLongArray = data.writeLongArray(errorLongArryData);
            expect(erWriteLongArray).assertEqual(false);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0320---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0330
    * @tc.name    : test Call the writedoublearray interface, write the array to the messageparcel instance,
    *             and call readdoublearra to read the data
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0330", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0330---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let wDoubleArryData = [1.2, 235.67, 99.76];
            let writeDoubleArrayResult = data.writeDoubleArray(wDoubleArryData);
            expect(writeDoubleArrayResult).assertTrue();
            let rDoubleArryData = data.readDoubleArray();
            assertArrayElementEqual(rDoubleArryData,wDoubleArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0330---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0340
    * @tc.name    : test Call the writedoublearray interface, write the array to the messageparcel instance,
    *             and call readdoublearra (datain: number []) to read the data
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0340", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0340---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let wDoubleArryData = [];
            for (let i = 0; i < (25 * K - 1); i++) {
                wDoubleArryData[i] = 11.1;
            };
            let writeDoubleArrayResult = data.writeDoubleArray(wDoubleArryData);
            expect(writeDoubleArrayResult).assertTrue();
            let rDoubleArryData = [];
            data.readDoubleArray(rDoubleArryData);
            assertArrayElementEqual(rDoubleArryData,wDoubleArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0340---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0350
    * @tc.name    : test Writedoublearray interface, boundary value verification
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0350", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0350---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let wDoubleArryData = [-1235453.2, 235.67, 9987659.76];
            let writeDoubleArrayResult = data.writeDoubleArray(wDoubleArryData);
            expect(writeDoubleArrayResult).assertTrue();
            let rDoubleArryData = data.readDoubleArray();
            assertArrayElementEqual(rDoubleArryData,wDoubleArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0350---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0360
    * @tc.name    : test Writedoublearray interface, illegal value validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0360", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0360---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let DoubleArryData = [-12354883737337373873853.2, 235.67, 99999999999999993737373773987659.76];
            let WriteDoubleArrayResult = data.writeDoubleArray(DoubleArryData);
            expect(WriteDoubleArrayResult).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0360---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0370
    * @tc.name    : test Writedoublearray interface, illegal value validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0370", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0370---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let errorDoubleArryData = [];
            for (let i = 0; i < 25 * K; i++) {
                errorDoubleArryData[i] = 11.1;
            };
            data.writeDoubleArray(errorDoubleArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0370---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0380
    * @tc.name    : test Call the writeboolean array interface, write the array to the messageparcel instance,
    *             and call readboolean array to read the data
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0380", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0380---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let wBooleanArryData = [true, false, false];
            let writeBooleanArrayResult = data.writeBooleanArray(wBooleanArryData);
            expect(writeBooleanArrayResult).assertTrue();
            let rBooleanArryData = data.readBooleanArray();
            assertArrayElementEqual(rBooleanArryData,wBooleanArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0380---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0390
    * @tc.name    : test Call the writeboolean array interface, write the array to the messageparcel instance,
    *             and call readboolean array (datain: number []) to read the data
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0390", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0390---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let wBooleanArryData = [];
            for (let i = 0; i < (50 * K - 1); i++) {
                if (i % 2 == 0) {
                    wBooleanArryData[i] = false;
                } else {
                    wBooleanArryData[i] = true;
                };
            };
            let writeBooleanArrayResult = data.writeBooleanArray(wBooleanArryData);
            expect(writeBooleanArrayResult).assertTrue();
            let rBooleanArryData = [];
            data.readBooleanArray(rBooleanArryData);
            assertArrayElementEqual(wBooleanArryData,rBooleanArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0390---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0400
    * @tc.name    : test Writeboolean array interface, illegal value validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0400---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let BooleanArryData = [true, 'abc', false];
            let WriteBooleanArrayResult = data.writeBooleanArray(BooleanArryData);
            expect(WriteBooleanArrayResult).assertTrue();
            let rBooleanArryData = data.readBooleanArray();
            let newboolean = [true, false, false];
            assertArrayElementEqual(rBooleanArryData,newboolean);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0400---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0410
    * @tc.name    : test Writeboolean array interface, illegal value validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0410", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0410---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let errorBooleanArryData = [];
            for (let i = 0; i < 50 * K; i++) {
                if (i % 2 == 0) {
                    errorBooleanArryData[i] = false;
                } else {
                    errorBooleanArryData[i] = true;
                };
            }
            data.writeBooleanArray(errorBooleanArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0410---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0420
    * @tc.name    : test Call the writechararray interface, write the array to the messageparcel instance,
    *             and call readchararray to read the data
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0420", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0420---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let wCharArryData = [];
            for (let i = 0; i < (50 * K - 1); i++) {
                wCharArryData[i] = 96;
            }
            let writeCharArrayResult = data.writeCharArray(wCharArryData);
            expect(writeCharArrayResult).assertTrue();
            let rCharArryData = data.readCharArray();
            assertArrayElementEqual(wCharArryData,rCharArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0420---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0430
    * @tc.name    : test Call the writechararray interface, write the array to the messageparcel instance,
    *             and call readchararray (datain: number []) to read the data
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0430", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0430---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let wCharArryData = [];
            for (let i = 0; i < (50 * K - 1); i++) {
                wCharArryData[i] = 96;
            }
            let writeCharArrayResult = data.writeCharArray(wCharArryData);
            expect(writeCharArrayResult).assertTrue();
            let rCharArryData = [];
            data.readCharArray(rCharArryData);
            assertArrayElementEqual(wCharArryData,rCharArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0430---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0440
    * @tc.name    : test Writechararray interface, illegal value validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0440", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0440---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let errorCharArryData = [10, 'asfgdgdtu', 20];
            let WriteCharArrayResult = data.writeCharArray(errorCharArryData);
            expect(WriteCharArrayResult).assertTrue();
            let rCharArryData = data.readCharArray();
            let xresult = [10, 0, 20];
            assertArrayElementEqual(rCharArryData,xresult);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0440---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0450
    * @tc.name    : test Call the writestringarray interface, write the array to the messageparcel instance,
    *             and call readstringarray (datain: number []) to read the data
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0450", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0450---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let wStringArryData = ['abc', 'hello', 'beauty'];
            let writeStringArrayResult = data.writeStringArray(wStringArryData);
            expect(writeStringArrayResult).assertTrue();
            let rStringArryData = data.readStringArray();
            assertArrayElementEqual(rStringArryData,wStringArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0450---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0460
    * @tc.name    : test Call the writestringarray interface, write the array to the messageparcel instance,
    *             and call readstringarray() to read the data
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0460", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0460---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let wStringArryData = ['abc', 'hello', 'beauty'];
            let writeStringArrayResult = data.writeStringArray(wStringArryData);
            expect(writeStringArrayResult).assertTrue();
            let rStringArryData = [];
            data.readStringArray(rStringArryData);
                assertArrayElementEqual(rStringArryData,wStringArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0460---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_0470
    * @tc.name    : test Writestringarray interface, illegal value validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_0470", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_0470---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let errorStringArryData = ['abc', 123, 'beauty'];
            data.writeStringArray(errorStringArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_0470---------------------------");
    });

    console.info("-----------------------SUB_DSoftbus_IPC_API_Stage_MessageSequence_Test is end-----------------------");
  })
}