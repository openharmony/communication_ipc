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
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_2120
    * @tc.name    : test Test MessageSequence write and read ArrayBuffer float64array
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2120", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_2120--------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try{
        let buffer = new ArrayBuffer(24);
        let float64View = new Float64Array(buffer);
        for (let i = 0; i < float64View.length; i++) {
          float64View[i] = i + 200;
        };
        data.writeArrayBuffer(buffer, rpc.TypeCode.FLOAT64_ARRAY);
        let arrayBuffer = data.readArrayBuffer(rpc.TypeCode.FLOAT64_ARRAY);
        let float64Array = new Float64Array(arrayBuffer);
        let assertE = isEqualArrayBuffer(float64View,float64Array);
        expect(assertE).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error == null).assertTrue();
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_2120--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_2130
    * @tc.name    : test Test MessageSequence write and read ArrayBuffer bigint64array
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2130", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_2130--------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try{
        let buffer = new ArrayBuffer(24);
        let int64View = new BigInt64Array(buffer);
        for (let i = 0; i < int64View.length; i++) {
          int64View[i] = BigInt(1110 + i);
        };
        data.writeArrayBuffer(buffer, rpc.TypeCode.BIGINT64_ARRAY);
        let arrayBuffer = data.readArrayBuffer(rpc.TypeCode.BIGINT64_ARRAY);
        let int64Array = new BigInt64Array(arrayBuffer);
        expect(int64View[0]).assertEqual(int64Array[0]);
        expect(int64View[1]).assertEqual(int64Array[1]);
        expect(int64View[2]).assertEqual(int64Array[2]);
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error == null).assertTrue();
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_2130--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_2140
    * @tc.name    : test Test MessageSequence write and read ArrayBuffer bigUint64array
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2140", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_2140--------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try{
        let buffer = new ArrayBuffer(24);
        let uInt64View = new BigUint64Array(buffer);
        for (let i = 0; i < uInt64View.length; i++) {
          uInt64View[i] = BigInt(i + 40);
        };
        data.writeArrayBuffer(buffer, rpc.TypeCode.BIGUINT64_ARRAY);
        let arrayBuffer = data.readArrayBuffer(rpc.TypeCode.BIGUINT64_ARRAY);
        let Iunt64Array = new BigUint64Array(arrayBuffer);
        expect(uInt64View[0]).assertEqual(Iunt64Array[0]);
        expect(uInt64View[1]).assertEqual(Iunt64Array[1]);
        expect(uInt64View[2]).assertEqual(Iunt64Array[2]);
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error == null).assertTrue();
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_2140--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_2150
    * @tc.name    : test Test MessageSequence writeArrayBuffer Beyond the maximum
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2150", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_2150--------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try{
        let buffer = new ArrayBuffer(24);
        let uInt64View = new BigUint64Array(buffer);
        for (let i = 0; i < uInt64View.length; i++) {
          uInt64View[i] = BigInt(i + 400);
        };
        data.writeArrayBuffer(buffer, 12);
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.CHECK_PARAM_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_2150--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_2160
    * @tc.name    : test Test MessageSequence writeArrayBuffer Beyond the maximum
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2160", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_2160--------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try{
        let buffer = new ArrayBuffer(24);
        let uInt64View = new BigUint64Array(buffer);
        for (let i = 0; i < uInt64View.length; i++) {
          uInt64View[i] = BigInt(i + 40);
        };
        data.writeArrayBuffer(buffer, -2);
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.CHECK_PARAM_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_2160--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_2170
    * @tc.name    : test Test MessageSequence readArrayBuffer Beyond the maximum
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2170", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_2170--------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try{
        let buffer = new ArrayBuffer(10);
        let int16View = new Int16Array(buffer);
        for (let i = 0; i < int16View.length; i++) {
          int16View[i] = i + 20;
        };
        data.writeArrayBuffer(buffer, rpc.TypeCode.INT16_ARRAY);
        data.readArrayBuffer(13);
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.CHECK_PARAM_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_2170--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_2180
    * @tc.name    : test Test MessageSequence readArrayBuffer Less than the minimum
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2180", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_2180--------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try{
        let buffer = new ArrayBuffer(10);
        let int16View = new Int16Array(buffer);
        for (let i = 0; i < int16View.length; i++) {
          int16View[i] = i + 20;
        };
        data.writeArrayBuffer(buffer, rpc.TypeCode.INT16_ARRAY);
        data.readArrayBuffer(-5);
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.CHECK_PARAM_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_2180--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_2190
    * @tc.name    : test Test MessageSequence writeArrayBuffer after reclaim
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2190", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_2190--------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try{
        let buffer = new ArrayBuffer(10);
        let int16View = new Int16Array(buffer);
        for (let i = 0; i < int16View.length; i++) {
          int16View[i] = i + 20;
        };
        data.reclaim();
        data.writeArrayBuffer(buffer, rpc.TypeCode.INT16_ARRAY);
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      }finally{
        console.info(logTag + "reclaim done");
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_2190--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_2200
    * @tc.name    : test Test MessageSequence readArrayBuffer after reclaim
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_2200--------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try{
        let buffer = new ArrayBuffer(200);
        let int16View = new Int16Array(buffer);
        for (let i = 0; i < int16View.length; i++) {
          int16View[i] = i + 20;
        };
        data.writeArrayBuffer(buffer, rpc.TypeCode.INT16_ARRAY);
        let arrayBuffer = data.readArrayBuffer(rpc.TypeCode.INT16_ARRAY);
        let int16Array = new Int16Array(arrayBuffer);
        let assertE = isEqualArrayBuffer(int16View,int16Array);
        expect(assertE).assertTrue();
        data.rewindRead(0);
        data.reclaim();
        data.readArrayBuffer(rpc.TypeCode.INT16_ARRAY);
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      }finally{
        console.info(logTag + "reclaim done");
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_2200--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_2210
    * @tc.name    : test Test MessageSequence readArrayBuffer after reclaim
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2210", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_2210--------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try{
        let buffer1 = new ArrayBuffer(200);
        let int16View = new Int16Array(buffer1);
        for (let i = 0; i < int16View.length; i++) {
          int16View[i] = i + 20;
        };
        let buffer2 = new ArrayBuffer(200);
        let int8View = new Int8Array(buffer2);
        for (let i = 0; i < int8View.length; i++) {
          int8View[i] = i * 2;
        };
        data.writeArrayBuffer(buffer1, rpc.TypeCode.INT16_ARRAY);
        data.writeArrayBuffer(buffer2, rpc.TypeCode.INT8_ARRAY);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_ARRAYBUFFER, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let reply1 = result.reply.readArrayBuffer(rpc.TypeCode.INT8_ARRAY);
          let int8Array = new Int8Array(reply1);
          let reply2 = result.reply.readArrayBuffer(rpc.TypeCode.INT16_ARRAY);
          let int16Array = new Int16Array(reply2);
          let assertE1 = isEqualArrayBuffer(int8View,int8Array);
          expect(assertE1).assertTrue();
          let assertE2 = isEqualArrayBuffer(int16View,int16Array);
          expect(assertE2).assertTrue();
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error == null).assertTrue();
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_2210--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_2220
    * @tc.name    : test Test MessageSequence delivery file descriptor object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2220", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_2220--------------------");
      try{
        let testab = new TestProxy(gIRemoteObject).asObject();
        expect(testab != null).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error == null).assertTrue();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_2220--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_2230
    * @tc.name    : test Test that the asObject interface is called by a RemoteObject and returns itself
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2230", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_2230--------------------");
      try{
        let testAbilityStub = new TestRemoteObject("testObject");
        expect(testAbilityStub.asObject() != null).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error == null).assertTrue();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_2230--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0010
    * @tc.name    : test getLocalInterface searches for objects based on descriptors
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改RPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0010", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0010---------------------------");
      try {
        let res = gIRemoteObject.getLocalInterface("rpcTestAbility");
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0010 getLocalInterface: " + res);
        expect(res != null).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_RemoteProxy_testcase error: " + error);
        let errCode = `${rpc.ErrorCode.ONLY_REMOTE_OBJECT_PERMITTED_ERROR}`;
        expect(error.code == errCode).assertTrue();
        expect(error.message != null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0010---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0020
    * @tc.name    : test getLocalInterface 1900005 searches for objects based on descriptors
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改RPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0020", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0020---------------------------");
      try {
        gIRemoteObject.getLocalInterface(null);
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_RemoteProxy_testcase error: " + error);
        let errCode = `${rpc.ErrorCode.ONLY_REMOTE_OBJECT_PERMITTED_ERROR}`;
        expect(error.code == errCode).assertTrue();
        expect(error.message != null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0020---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0030
    * @tc.name    : test Call isobjectdead to check whether the object is dead
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改RPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0030", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0030---------------------------");
      try {
        let recipient = new MyregisterDeathRecipient();
        let isDead = gIRemoteObject.isObjectDead();
        expect(isDead == false).assertTrue();
        gIRemoteObject.registerDeathRecipient(recipient, 0);
        let isDead1 = gIRemoteObject.isObjectDead();
        expect(isDead1 == false).assertTrue();
        gIRemoteObject.unregisterDeathRecipient(recipient, 0);
        gIRemoteObject.registerDeathRecipient(recipient, 0);
        gIRemoteObject.unregisterDeathRecipient(recipient, 0);
        gIRemoteObject.unregisterDeathRecipient(recipient, 0);
        let isDead2 = gIRemoteObject.isObjectDead();
        expect(isDead2 == false).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_RemoteProxy_testcase error: " + error);
        expect(error == null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0030---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0040
    * @tc.name    : test Call registerDeathRecipient to register the death notification
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改RPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0040", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0040---------------------------");
      try {
        let recipient = new MyregisterDeathRecipient();
        gIRemoteObject.registerDeathRecipient(recipient, 0);
        gIRemoteObject.registerDeathRecipient(recipient, 0);
        gIRemoteObject.unregisterDeathRecipient(recipient, 0);
        gIRemoteObject.unregisterDeathRecipient(recipient, 0);
        gIRemoteObject.unregisterDeathRecipient(recipient, 0);
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0040: unregisterDeathRecipient2 is success");
        expect(recipient != null).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_RemoteProxy_testcase error: " + error);
        expect(error == null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0040---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0050
    * @tc.name    : test registerDeathRecipient Validates the interface flags input parameter boundary value
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改RPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0050", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0050---------------------------");
      try {
        let recipient = new MyregisterDeathRecipient();
        gIRemoteObject.registerDeathRecipient(recipient, -(2 * G));
        gIRemoteObject.unregisterDeathRecipient(recipient, -(2 * G));
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0050: unregisterDeathRecipient2 is success");
        expect(recipient != null).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_RemoteProxy_testcase error: " + error);
        expect(error == null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0050---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0060
    * @tc.name    : test registerDeathRecipient Validates the interface flags input parameter boundary value
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改RPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0060", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0060---------------------------");
      try {
        let recipient = new MyregisterDeathRecipient();
        gIRemoteObject.registerDeathRecipient(recipient, (2 * G - 1));
        gIRemoteObject.unregisterDeathRecipient(recipient, (2 * G - 1));
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0060: unregisterDeathRecipient2 is success");
        expect(recipient != null).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_RemoteProxy_testcase error: " + error);
        expect(error == null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0060---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0070
    * @tc.name    : test registerDeathRecipient Validates the interface flags input parameter boundary value
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改RPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0070", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0070---------------------------");
      try {
        let recipient = new MyregisterDeathRecipient();
        gIRemoteObject.registerDeathRecipient(recipient, 2 * G);
        gIRemoteObject.unregisterDeathRecipient(recipient, 2 * G);
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0070: unregisterDeathRecipient2 is success");
        expect(recipient != null).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_RemoteProxy_testcase error: " + error);
        expect(error == null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0070---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0080
    * @tc.name    : test registerDeathRecipient Validates the interface flags input parameter boundary value
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改RPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0080", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0080---------------------------");
      try {
        let recipient = new MyregisterDeathRecipient();
        gIRemoteObject.registerDeathRecipient(recipient, -(2 * G + 1));
        gIRemoteObject.unregisterDeathRecipient(recipient, -(2 * G + 1));
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0080: unregisterDeathRecipient is success");
        expect(recipient != null).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_RemoteProxy_testcase error: " + error);
        expect(error == null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0080---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0090
    * @tc.name    : test getDescriptor to get the object interface description
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改RPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0090", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0090---------------------------");
      try {
        let result = gIRemoteObject.getDescriptor();
        expect(result).assertEqual("rpcTestAbility");
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_RemoteProxy_testcase error: " + error);
        expect(error == null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_RemoteProxy_0090---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageOption_0010
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageOption_0010", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageOption_0010---------------------------");
      let option : rpc.MessageOption = new rpc.MessageOption();
      let tftime : number = rpc.MessageOption.TF_WAIT_TIME;
      try {
        let time = option.getWaitTime();
        expect(time).assertEqual(tftime);
        option.setWaitTime(16);
        let time2 = option.getWaitTime();
        expect(time2).assertEqual(16);
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_MessageOption error is:" + error);
        expect(error == null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageOption_0010---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageOption_0020
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageOption_0020", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageOption_0020---------------------------");
      let option : rpc.MessageOption = new rpc.MessageOption();
      let tftime : number = rpc.MessageOption.TF_WAIT_TIME;
      try {
        let time = option.getWaitTime();
        expect(time).assertEqual(tftime);
        option.setWaitTime(0);
        let time2 = option.getWaitTime();
        expect(time2).assertEqual(tftime);
        option.setWaitTime(60);
        let time3 = option.getWaitTime();
        expect(time3).assertEqual(60);
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_MessageOption error is:" + error);
        expect(error == null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageOption_0020---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageOption_0030
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageOption_0030", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageOption_0030---------------------------");
      let option : rpc.MessageOption = new rpc.MessageOption();
      let tftime : number = rpc.MessageOption.TF_WAIT_TIME;
      try {
        let option = new rpc.MessageOption();
        let time = option.getWaitTime();
        expect(time).assertEqual(tftime);
        option.setWaitTime(-1);
        let time2 = option.getWaitTime();
        expect(time2).assertEqual(tftime);
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_MessageOption error is:" + error);
        expect(error == null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageOption_0030---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageOption_0040
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageOption_0040", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageOption_0040---------------------------");
      let option : rpc.MessageOption = new rpc.MessageOption();
      let tftime : number = rpc.MessageOption.TF_WAIT_TIME;
      try {
        let time = option.getWaitTime();
        expect(time).assertEqual(tftime);
        option.setWaitTime(61);
        let time2 = option.getWaitTime();
        expect(time2).assertEqual(61);
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_MessageOption error is:" + error);
        expect(error == null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageOption_0040---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageOption_0050
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageOption_0050", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageOption_0050---------------------------");
      let option : rpc.MessageOption = new rpc.MessageOption();
      let tfsync : number = rpc.MessageOption.TF_SYNC;
      let tfasync : number = rpc.MessageOption.TF_ASYNC;
      try {
        let flog = option.getFlags();
        expect(flog).assertEqual(tfsync);
        option.setFlags(1);
        let flog2 = option.getFlags();
        expect(flog2).assertEqual(tfasync);
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_MessageOption error is:" + error);
        expect(error == null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageOption_0050---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageOption_0060
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageOption_0060", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageOption_0060---------------------------");
      let option : rpc.MessageOption = new rpc.MessageOption();
      let tfsync : number = rpc.MessageOption.TF_SYNC;
      let tfasync : number = rpc.MessageOption.TF_ASYNC;
      try {
        let flog = option.getFlags();
        expect(flog).assertEqual(tfsync);
        option.setFlags(1);
        let flog2 = option.getFlags();
        expect(flog2).assertEqual(tfasync);
        option.setFlags(0);
        let flog3 = option.getFlags();
        expect(flog3).assertEqual(tfasync);
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_MessageOption error is:" + error);
        expect(error == null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageOption_0060---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageOption_0070
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageOption_0070", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageOption_0070---------------------------");
      let option : rpc.MessageOption = new rpc.MessageOption();
      let tfsync : number = rpc.MessageOption.TF_SYNC;
      try {
        let flog = option.getFlags();
        expect(flog).assertEqual(tfsync);
        option.setFlags(-1);
        let flog2 = option.getFlags();
        expect(flog2).assertEqual(-1);
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_MessageOption error is:" + error);
        expect(error == null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageOption_0070---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageOption_0080
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageOption_0080", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageOption_0080---------------------------");
      let option : rpc.MessageOption = new rpc.MessageOption();
      let tfsync : number = rpc.MessageOption.TF_SYNC;
      try {
        let flog = option.getFlags();
        expect(flog).assertEqual(tfsync);
        option.setFlags(3);
        let flog2 = option.getFlags();
        expect(flog2).assertEqual(3);
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_MessageOption error is:" + error);
        expect(error == null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageOption_0080---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageOption_0090
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageOption_0090", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageOption_0090---------------------------");
      try {
        expect(rpc.MessageOption.TF_SYNC).assertEqual(0);
        expect(rpc.MessageOption.TF_ASYNC).assertEqual(1);
        expect(rpc.MessageOption.TF_WAIT_TIME).assertEqual(8);
        expect(rpc.MessageOption.TF_ACCEPT_FDS).assertEqual(0x10);
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_MessageOption error is:" + error);
        expect(error == null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageOption_0090---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageOption_0100
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageOption_0100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageOption_0100---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        option.setWaitTime(20);
        option.setFlags(0);
        let token = "option";
        data.writeString(token);
        expect(option.getFlags()).assertEqual(0);
        expect(option.getWaitTime()).assertEqual(20);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
          let replyReadResult = result.reply.readString();
          expect(replyReadResult).assertEqual(token);
          expect(option.getFlags()).assertEqual(0);
          expect(option.getWaitTime()).assertEqual(20);
        });
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_MessageOption error is:" + error);
        expect(error == null).assertTrue();
      } finally {
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageOption_0100---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageOption_0110
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageOption_0110", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageOption_0110---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        option.setFlags(1);
        let token = "option";
        data.writeString(token);
        expect(option.getFlags()).assertEqual(1);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
          let replyReadResult = result.reply.readString();
          expect(replyReadResult).assertEqual("");
          expect(option.getFlags()).assertEqual(1);
        });
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_MessageOption error is:" + error);
        expect(error == null).assertTrue();
      } finally {
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageOption_0110---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageOption_0120
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageOption_0120", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageOption_0120---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        option.setFlags(3);
        let token = "option";
        data.writeString(token);
        expect(option.getFlags()).assertEqual(3);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
          let replyReadResult = result.reply.readString();
          expect(replyReadResult).assertEqual("");
          expect(option.getFlags()).assertEqual(3);
        });
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_MessageOption error is:" + error);
        expect(error == null).assertTrue();
      } finally {
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageOption_0120---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageOption_0130
    * @tc.name    : test MessageOption sendMessageRequest test
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageOption_0130", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageOption_0130---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        option.setFlags(1);
        let token = "option";
        data.writeString(token);
        expect(option.getFlags()).assertEqual(1);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
          let replyReadResult = result.reply.readString();
          expect(replyReadResult).assertEqual("");
          expect(option.getFlags()).assertEqual(1);
        });
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_MessageOption error is:" + error);
        expect(error == null).assertTrue();
      } finally {
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageOption_0130---------------------------");
    })

    /*
     * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageOption_0140
     * @tc.name    : test MessageOption sendMessageRequest test
     * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.level   : Level 1
     * @tc.type    : Compatibility
     * @tc.size    : MediumTest
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageOption_0140", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageOption_0140---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let token = "option";
        data.writeString(token);
        let isAsyncData0 = option.isAsync();
        expect(isAsyncData0).assertEqual(false);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let isAsyncData = option.isAsync();
          expect(isAsyncData).assertEqual(false);
          let replyReadResult = result.reply.readString();
          expect(replyReadResult).assertEqual(token);
        });
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_MessageOption error is:" + error);
        expect(error == null).assertTrue();
      } finally {
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageOption_0140---------------------------");
    })

    /*
     * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageOption_0150
     * @tc.name    : test MessageOption setAsync is true test
     * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.level   : Level 1
     * @tc.type    : Compatibility
     * @tc.size    : MediumTest
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageOption_0150", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageOption_0150---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        option.setAsync(true);
        let token = "option";
        data.writeString(token);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let isAsyncData = option.isAsync();
          expect(isAsyncData).assertTrue();
          let replyReadResult = result.reply.readString();
          expect(replyReadResult).assertEqual("");
        });
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_MessageOption error is:" + error);
        expect(error == null).assertTrue();
      } finally {
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageOption_0150---------------------------");
    })


    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageOption_0160
    * @tc.name    : test setAsync is false sendMessageRequest test
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageOption_0160", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageOption_0160---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        option.setAsync(false);
        let token = "option";
        data.writeString(token);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let isAsyncData = option.isAsync();
          expect(isAsyncData).assertEqual(false);
          let replyReadResult = result.reply.readString();
          expect(replyReadResult).assertEqual(token);
        });
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_MessageOption error is:" + error);
        expect(error == null).assertTrue();
      } finally {
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageOption_0160---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0010
    * @tc.name    : test Call the getashmemsize interface to get the size of the shared memory object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0010", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0010---------------------------");
      try {
        let mapSize = 2 * G - 1;
        let ashmem = rpc.Ashmem.create("JsAshmemTest", mapSize);
        let size = ashmem.getAshmemSize();
        expect(size).assertEqual(mapSize);
        ashmem.unmapAshmem();
        ashmem.closeAshmem();
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem error is:" + error);
        expect(error == null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0010---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0020
    * @tc.name    : test Call the getashmemsize interface to get the size of the shared memory object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0020", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0020---------------------------");
      try {
        let mapSize = 2 * G;
        let ashmem = rpc.Ashmem.create("JsAshmemTest ", mapSize);
        ashmem.getAshmemSize();
        ashmem.unmapAshmem();
        ashmem.closeAshmem();
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem error is:" + error);
        expect(error != null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0020---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0030
    * @tc.name    : test Exception parameter validation of the created anonymous shared memory object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0030", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0030---------------------------");
        try {
            let mapSize = K;
            let ashmem = rpc.Ashmem.create("JsAshmemTest", mapSize);
            let ashmem2 = rpc.Ashmem.create(ashmem);
            let size = ashmem2.getAshmemSize();
            console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0030: size " + size);
            expect(size).assertEqual(mapSize);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0030---------------------------");
    })    

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0040
    * @tc.name    : test mapTypedAshmem interface creates shared file mappings
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0040", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0040---------------------------");
      try {
        let ashmem = rpc.Ashmem.create("JsAshmemTest", 4 * K);
        let result = ashmem.mapTypedAshmem(rpc.Ashmem.PROT_READ | rpc.Ashmem.PROT_WRITE);
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0040: run mapTypedAshmem is success" + result);
        ashmem.unmapAshmem();
        ashmem.closeAshmem();
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem error is:" + error);
        expect(error == null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0040---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0050
    * @tc.name    : test mapTypedAshmem exception validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0050", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0050---------------------------");
      try {
        let ashmem = rpc.Ashmem.create("JsAshmemTest", (2 * G - 1))
        ashmem.mapTypedAshmem(999);
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0050: run mapTypedAshmem is success");
        ashmem.unmapAshmem();
        ashmem.closeAshmem();
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem error is:" + error);
        expect(error.code == 401).assertTrue();
        expect(error.message != null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0050---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0060
    * @tc.name    : test mapTypedAshmem exception errorcode validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0060", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0060---------------------------");
      try {
        let ashmem = rpc.Ashmem.create("JsAshmemTest", (2 * G))
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0060: ashmem " + ashmem);
        let result = ashmem.mapTypedAshmem(rpc.Ashmem.PROT_READ | rpc.Ashmem.PROT_WRITE);
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0060: run mapTypedAshmem is success");
        ashmem.unmapAshmem();
        ashmem.closeAshmem();
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem error is:" + error);
        expect(error.message != null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0060---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0070
    * @tc.name    : test mapReadWriteAshmem interface creates a shared file map with the protection level of read-write
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0070", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0070---------------------------");
      try {
        let ashmem = rpc.Ashmem.create("JsAshmemTest", K);
        ashmem.mapReadWriteAshmem();
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0070: run mapReadWriteAshmem is success");
        ashmem.unmapAshmem();
        ashmem.closeAshmem();
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem error is:" + error);
        expect(error == null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0070---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0080
    * @tc.name    : test mapReadWriteAshmem exception validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0080", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0080---------------------------");
      try {
        let ashmem = rpc.Ashmem.create("JsAshmemTest", 4096);
        ashmem.mapTypedAshmem(rpc.Ashmem.PROT_READ);
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0080: run mapTypedAshmem is success");
        ashmem.unmapAshmem();
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0080: run unmapAshmem success");
        ashmem.mapReadWriteAshmem();
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0080: run mapReadWriteAshmem is success");
        ashmem.unmapAshmem();
        ashmem.closeAshmem();
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem error is:" + error);
        expect(error == null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0080---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0090
    * @tc.name    : test Mapreadonlyashmem interface creates a shared file map with the protection level of read-write
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0090", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0090---------------------------");
      try {
        let ashmem = rpc.Ashmem.create("JsAshmemTest", 4096);
        ashmem.mapReadonlyAshmem();
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0090: run mapReadonlyAshmem is success");
        ashmem.unmapAshmem();
        ashmem.closeAshmem();
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem error is:" + error);
        expect(error == null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0090---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0100
    * @tc.name    : test mapReadWriteAshmem exception validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0100---------------------------");
      try {
        let ashmem = rpc.Ashmem.create("JsAshmemTest", K);
        ashmem.setProtectionType(rpc.Ashmem.PROT_WRITE);
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0100: run setProtectionType is success");
        ashmem.setProtectionType(rpc.Ashmem.PROT_READ);
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0100: run setProtectionType is success");
        ashmem.mapReadWriteAshmem();
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0100: run mapReadWriteAshmem success");
        ashmem.setProtectionType(rpc.Ashmem.PROT_NONE);
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0100: run setProtectionType is success");
        ashmem.setProtectionType(rpc.Ashmem.PROT_READ);
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0100: run setProtectionType is success");
        ashmem.unmapAshmem();
        ashmem.closeAshmem();
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem error is:" + error);
        expect(error == null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0100---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0110
    * @tc.name    : test setProtectionType exception input parameter verification
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0110", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0110---------------------------");
      try {
        let ashmem = rpc.Ashmem.create("JsAshmemTest", K);
        ashmem.setProtectionType(3);
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0110: run setProtectionType is success");
        ashmem.unmapAshmem();
        ashmem.closeAshmem();
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem error is:" + error);
        expect(error == null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0110---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0120
    * @tc.name    : test Create a non shared memory object and call setProtectionType to write the messageparcel object
    *               object into the messageparcel object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0120", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0120---------------------------");
      try {
        let ashmem = rpc.Ashmem.create("JsAshmemTest", K);
        ashmem.setProtectionType(rpc.Ashmem.PROT_EXEC);
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0120: run setProtectioniswrite is success");
        ashmem.unmapAshmem();
        ashmem.closeAshmem();
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem error is:" + error);
        expect(error == null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0120---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0130
    * @tc.name    : test Mapreadonlyashmem exception validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0130", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0130---------------------------");
      try {
        let ashmem = rpc.Ashmem.create("JsAshmemTest", K);
        ashmem.mapTypedAshmem(rpc.Ashmem.PROT_WRITE);
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0130: run mapTypedAshmem is success");
        ashmem.unmapAshmem();
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0130: run unmapAshmem success");
        ashmem.closeAshmem();
        ashmem.mapReadonlyAshmem();
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0130: run mapReadonlyAshmem is success");
        ashmem.unmapAshmem();
        ashmem.closeAshmem();
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem error is:" + error);
        expect(error == null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0130---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0140
    * @tc.name    : test create is errorcode 401 exception validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0140", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0140---------------------------");
      try {
        let ashmem = rpc.Ashmem.create("ashmem", (2 * G + 1));
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0140: ashmem " + ashmem);
        ashmem.unmapAshmem();
        ashmem.closeAshmem();
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem error is:" + error);
        let errCode = `${rpc.ErrorCode.CHECK_PARAM_ERROR}`;
        expect(error.code == errCode).assertTrue();
        expect(error.message != null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0140---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0150
    * @tc.name    : test mapReadWriteAshmem exception validation 1900001
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0150", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0150---------------------------");
      try {
        let ashmem = rpc.Ashmem.create("ashmem", (4 * G - 1));
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0150: ashmem " + ashmem);
        ashmem.mapReadWriteAshmem();
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0150: run mapReadWriteAshmem is success");
        ashmem.unmapAshmem();
        ashmem.closeAshmem();
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem error is:" + error);
        let errCode = `${rpc.ErrorCode.OS_MMAP_ERROR}`;
        expect(error.code != errCode).assertTrue();
        expect(error.message != null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0150---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0160
    * @tc.name    : test create 401  exception validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0160", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0160---------------------------");
      try {
        let ashmem = rpc.Ashmem.create("ashmem", 0);
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0160: ashmem " + ashmem);
        ashmem.unmapAshmem();
        ashmem.closeAshmem();
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem error is:" + error);
        let errCode = `${rpc.ErrorCode.CHECK_PARAM_ERROR}`;
        expect(error.code == errCode).assertTrue();
        expect(error.message != null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0160---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0170
    * @tc.name    : test setProtectionType exception validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0170", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0170---------------------------");
      try {
        let ashmem = rpc.Ashmem.create("ashmem", 1024 * 1024);
        ashmem.setProtectionType(0);
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0170: run setProtectionType is success");
        ashmem.unmapAshmem();
        ashmem.closeAshmem();
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem error is:" + error);
        expect(error == null).assertTrue();
        expect(error).assertEqual(null);
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0170---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0180
    * @tc.name    : test setProtectionType is 1900002 exception validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0180", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0180---------------------------");
      try {
        let ashmem = rpc.Ashmem.create("ashmem", 1024 * 1024);
        ashmem.setProtectionType(null);
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0180: run setProtectionType is success");
        ashmem.unmapAshmem();
        ashmem.closeAshmem();
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem error is:" + error);
        let errCode = `${rpc.ErrorCode.OS_IOCTL_ERROR}`;
        expect(error.code != errCode).assertTrue();
        expect(error.message != null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0180---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0190
    * @tc.name    : test Call the getashmemsize interface to get the size of the shared memory object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3 
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0190", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0190---------------------------");
      try {
        let mapSize = 2 * G;
        let ashmem = rpc.Ashmem.create("JsAshmemTest ", mapSize);
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0190: run  create success " + ashmem);
        let size = ashmem.getAshmemSize();
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0190: run getAshmemSize success, size is " + size);
        expect(size).assertEqual(mapSize);
        ashmem.unmapAshmem();
        ashmem.closeAshmem();
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem error is:" + error);
        let errCode = `${rpc.ErrorCode.CHECK_PARAM_ERROR}`;
        expect(error.code == errCode).assertTrue();
        expect(error != null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0190---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0200
    * @tc.name    : test mapTypedAshmem errorcode 401 exception validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0200---------------------------");
      try {
        let ashmem = rpc.Ashmem.create("JsAshmemTest", (2 * G - 1));
        let result = ashmem.mapTypedAshmem(999);
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0200: run mapAshmemis is " + result);
        expect(result).assertEqual(false);
        ashmem.unmapAshmem();
        ashmem.closeAshmem();
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem error is:" + error);
        let errCode = `${rpc.ErrorCode.CHECK_PARAM_ERROR}`;
        expect(error.code == errCode).assertTrue();
        expect(error != null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0200---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0210
    * @tc.name    : test mapTypedAshmem exception validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3 
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0210", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0210---------------------------");
      try {
        let ashmem = rpc.Ashmem.create("JsAshmemTest", (2 * G - 1));
        let result = ashmem.mapTypedAshmem(999);
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0210: run mapTypedAshmem is success");
        ashmem.unmapAshmem();
        ashmem.closeAshmem();
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem error is:" + error);
        let errCode = `${rpc.ErrorCode.OS_MMAP_ERROR}`;
        expect(error.code != errCode).assertTrue();
        expect(error != null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0210---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0220
    * @tc.name    : test mapTypedAshmem exception errorcode validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0220", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0220---------------------------");
      try {
        let ashmem = rpc.Ashmem.create("JsAshmemTest", (2 * G - 1));
        let result = ashmem.mapTypedAshmem(rpc.Ashmem.PROT_READ | rpc.Ashmem.PROT_WRITE);
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0220: run mapTypedAshmem is success");
        ashmem.unmapAshmem();
        ashmem.closeAshmem();
      } catch (error) {
        console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem error is:" + error);
        let errCode = `${rpc.ErrorCode.CHECK_PARAM_ERROR}`;
        expect(error.code != errCode).assertTrue();
        expect(error != null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0220---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0230
    * @tc.name    : test writeDataToAshmem input parameter is a normal data less than 32KB 
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0230", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0230---------------------------");
        let TEST_LEN_32 = 32;
        let data = new rpc.MessageSequence();
        let ashmem = rpc.Ashmem.create('ashmem', TEST_LEN_32);
        try {
            ashmem.mapReadWriteAshmem();
            let buffer = new ArrayBuffer(TEST_LEN_32);
            let size = buffer.byteLength;
            let ashnenInt32Arr = new Int32Array(buffer);
            ashnenInt32Arr.fill(1);
            ashmem.writeDataToAshmem(buffer, size, 0);
            data.writeAshmem(ashmem);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0230 error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0230---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0240
    * @tc.name    : test writeDataToAshmem input parameter is a normal data greater than 32KB 
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0240", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0240---------------------------");
        let TEST_LEN_M = 1024 * 1024;
        let data = new rpc.MessageSequence();
        let ashmem = rpc.Ashmem.create('ashmem', TEST_LEN_M);
        try {
            ashmem.mapReadWriteAshmem();
            let buffer = new ArrayBuffer(TEST_LEN_M);
            let size = buffer.byteLength;
            let ashnenInt32Arr = new Int32Array(buffer);
            ashmem.writeDataToAshmem(buffer, size, 0);
            data.writeAshmem(ashmem);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0240 error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0240---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0250
    * @tc.name    : test writeDataToAshmem input parameter is a normal data size = 0
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0250", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0250---------------------------");
        let TEST_LEN_128M = 128 * 1024 * 1024;
        let TEST_LEN_M = 1024 * 1024;
        let data = new rpc.MessageSequence();
        let ashmem = rpc.Ashmem.create('ashmem', TEST_LEN_128M);
        try {
            ashmem.mapReadWriteAshmem();
            let buffer = new ArrayBuffer(TEST_LEN_M);
            let size = buffer.byteLength;
            let ashnenInt32Arr = new Int32Array(buffer);
            ashmem.writeDataToAshmem(buffer, 0, 0);
            data.writeAshmem(ashmem);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0250 error is:" + error);
            expect(error.code == 1900003).assertTrue();
        } finally {
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0250---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0260
    * @tc.name    : test writeDataToAshmem input parameter is a normal  size less than 0
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0260", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0260---------------------------");
        let TEST_LEN_128M = 128 * 1024 * 1024;
        let TEST_LEN_M = 1024 * 1024;
        let data = new rpc.MessageSequence();
        let ashmem = rpc.Ashmem.create('ashmem', TEST_LEN_128M);
        try {
            ashmem.mapReadWriteAshmem();
            let buffer = new ArrayBuffer(TEST_LEN_M);
            let size = buffer.byteLength;
            let ashnenInt32Arr = new Int32Array(buffer);
            ashmem.writeDataToAshmem(buffer, -1, 0);
            data.writeAshmem(ashmem);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0260 error is:" + error);
            expect(error.code == 1900003).assertTrue();
        } finally {
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0260---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0270
    * @tc.name    : test writeDataToAshmem input parameter is a normal  offset less than 0
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0270", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0270---------------------------");
        let TEST_LEN_128M = 128 * 1024 * 1024;
        let data = new rpc.MessageSequence();
        let ashmem = rpc.Ashmem.create('ashmem', TEST_LEN_128M);
        try {
            ashmem.mapReadWriteAshmem();
            let buffer = new ArrayBuffer(TEST_LEN_128M);
            let size = buffer.byteLength;
            let ashnenInt32Arr = new Int32Array(buffer);
            ashmem.writeDataToAshmem(buffer, size, -1);
            data.writeAshmem(ashmem);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0270 error is:" + error);
            expect(error.code == 1900003).assertTrue();
        } finally {
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0270---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0280
    * @tc.name    : test writeDataToAshmem input parameter is a normal  lenth and offset greater than create
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0280", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0280---------------------------");
        let TEST_LEN_32 = 32;
        let data = new rpc.MessageSequence();
        let ashmem = rpc.Ashmem.create('ashmem', TEST_LEN_32);
        try {
            ashmem.mapReadWriteAshmem();
            let buffer = new ArrayBuffer(TEST_LEN_32);
            let size = buffer.byteLength;
            let ashnenInt32Arr = new Int32Array(buffer);
            ashmem.writeDataToAshmem(buffer, TEST_LEN_32, 1);
            data.writeAshmem(ashmem);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0280 error is:" + error);
            expect(error.code == 1900003).assertTrue();
        } finally {
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0280---------------------------");
    });

    console.info("-----------------------SUB_DSoftbus_IPC_API_Stage_MessageSequence_Test is end-----------------------");
  })
}