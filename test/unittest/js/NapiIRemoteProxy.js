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
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_2110
    * @tc.name    : test Test MessageSequence write and read ArrayBuffer float32array
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2110", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_2110--------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try{
        let buffer = new ArrayBuffer(12);
        let float32View = new Float32Array(buffer);
        for (let i = 0; i < float32View.length; i++) {
          float32View[i] = i + 100;
        };
        data.writeArrayBuffer(buffer, rpc.TypeCode.FLOAT32_ARRAY);
        let arrayBuffer = data.readArrayBuffer(rpc.TypeCode.FLOAT32_ARRAY);
        let float32Array = new Float32Array(arrayBuffer);
        let assertE = isEqualArrayBuffer(float32View,float32Array);
        expect(assertE).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error == null).assertTrue();
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_2110--------------------");
    });

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
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0010
      * @tc.name    : test Call the writeinterfacetoken interface, write the interface descriptor, and read interfacetoken
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 1
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0010", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0010---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let token = "hello softbus";
            data.writeInterfaceToken(token);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_INTERFACETOKEN, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                expect(result.reply.readInterfaceToken()).assertEqual(token);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0010---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0020
      * @tc.name    : test The writeInterfaceToken interface is looping, the interface descriptor is written, and the
                    InterfaceToken is read
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 1
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0020", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0020---------------------------");
        try {
            for (let i = 0; i < 5; i++) {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let token = "hello softbus";
                data.writeInterfaceToken(token);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_INTERFACETOKEN, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    expect(result.reply.readInterfaceToken()).assertEqual(token);
                });
            };
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0020---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0030
      * @tc.name    : test Call the WriteInterfaceToken interface, write the maximum length interface descriptor, and read
                    the InterfaceToken
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 1
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0030", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0030---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let token = "";
            for (let i = 0; i < (40 * K - 1); i++) {
                token += 'a';
            };
            data.writeInterfaceToken(token);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_INTERFACETOKEN, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                expect(result.reply.readInterfaceToken()).assertEqual(token);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0030---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0040
      * @tc.name    : test The WriteInterfaceToken interface is called, the exceeding-length interface descriptor is written,
                    and the InterfaceToken is read
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 3
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0040", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0040---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            let token = "";
            for (let i = 0; i < 40 * K; i++) {
                token += 'a';
            };
            data.writeInterfaceToken(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            let errCode = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
            expect(error.code != errCode).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0040---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0050
      * @tc.name    : test Call the writeinterfacetoken interface to write a non string interface descriptor
                    and read interfacetoken
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 3
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0050", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0050---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            let token = 123;
            data.writeInterfaceToken(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            let errCode = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
            expect(error.code != errCode).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0050---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0060
      * @tc.name    : test Call the writeshortarray interface, write the array to the MessageSequence instance,
      *             and call readshortarray to read the data
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 1
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0060", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0060---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let wShortArryData = [-1, 0, 1];
            data.writeShortArray(wShortArryData);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_SHORTARRAY, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                assertArrayElementEqual(result.reply.readShortArray(), wShortArryData)
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0060---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0070
      * @tc.name    : test Call the writeshortarray interface, write the short integer array to the MessageSequence instance,
      *             and call readshortarray (datain: number []) to read the data
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 1
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0070", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0070---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let wShortArryData = [];
            for (let i = 0; i < (50 * 1024 - 1); i++) {
                wShortArryData[i] = 1;
            };
            data.writeShortArray(wShortArryData);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_SHORTARRAY, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                let rShortArryData = [];
                result.reply.readShortArray(rShortArryData);
                assertArrayElementEqual(rShortArryData, wShortArryData)
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0070---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0080
      * @tc.name    : test Writeshortarray interface, boundary value verification
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 3
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0080", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0080---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let wShortArryData = [-32768, 0, 1, 2, 32767];
            data.writeShortArray(wShortArryData);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_SHORTARRAY, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                assertArrayElementEqual(result.reply.readShortArray(), wShortArryData);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0080---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0090
      * @tc.name    : test Writeshortarray interface, illegal value validation
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 3
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0090", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0090---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let eShortArryData = [-32769, 32768];
            data.writeShortArray(eShortArryData);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_SHORTARRAY, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                let erShortArryData = [32767, -32768];
                assertArrayElementEqual(result.reply.readShortArray(), erShortArryData);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0090---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0100
      * @tc.name    : test Writeshortarray interface, transmission length verification
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 3
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0100---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            let eShortArryData = [];
            for (let i = 0; i < 50 * K; i++) {
                eShortArryData[i] = 1;
            };
            data.writeShortArray(eShortArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            let errCode = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
            expect(error.code != errCode).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0100---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0110
      * @tc.name    : test Call the writelongarray interface, write the long integer array to the MessageSequence instance,
      *             and call readlongarray to read the data
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 1
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0110", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0110---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let wLongArryData = [3276826, 123456, 9999999];
            data.writeLongArray(wLongArryData);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_LONGARRAY, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                assertArrayElementEqual(result.reply.readLongArray(), wLongArryData);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0110---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0120
      * @tc.name    : test Call the writelongarray interface, write the long integer array to the MessageSequence instance,
      *             and call readlongarray (datain: number []) to read the data
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 1
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0120", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0120---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let wLongArryData = [];
            for (let i = 0; i < (25 * K - 1); i++) {
                wLongArryData[i] = 11;
            };
            data.writeLongArray(wLongArryData);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_LONGARRAY, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                let rLongArryData = [];
                result.reply.readLongArray(rLongArryData);
                assertArrayElementEqual(rLongArryData, wLongArryData);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0120---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0130
      * @tc.name    : test Writelongarray interface, boundary value verification
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 3
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0130", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0130---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let wLongArryData = [-9007199254740992, 0, 1, 2, 9007199254740991];
            data.writeLongArray(wLongArryData);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_LONGARRAY, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                let rLongArryData = [];
                result.reply.readLongArray(rLongArryData);
                assertArrayElementEqual(rLongArryData, wLongArryData);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0130---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0140
      * @tc.name    : test Writelongarray interface, long type precision verification
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 3
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0140", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0140---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let wLongArryData = [-9999999999999999, 9999999999999999];
            data.writeLongArray(wLongArryData);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_LONGARRAY, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                let rLongArryData = result.reply.readLongArray();
                let newlongdata = [-10000000000000000, 10000000000000000];
                expect(rLongArryData[0]).assertEqual(newlongdata[0]);
                expect(rLongArryData[1]).assertEqual(newlongdata[1]);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0140---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0150
      * @tc.name    : test Writelongarray Indicates an interface for verifying the input length
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 3
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0150", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0150---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            let wLongArryData = [];
            for (let i = 0; i < 25 * K; i++) {
                wLongArryData[i] = 11;
            };
            data.writeLongArray(wLongArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            let errCode = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
            expect(error.code != errCode).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0150---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0160
      * @tc.name    : test Call the writedoublearray interface, write the array to the MessageSequence instance,
      *             and call readdoublearra to read the data
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 1
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0160", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0160---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let wDoubleArryData = [1.2, 235.67, 99.76];
            data.writeDoubleArray(wDoubleArryData);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_DOUBLEARRAY, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                assertArrayElementEqual(result.reply.readDoubleArray(), wDoubleArryData);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0160---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0170
      * @tc.name    : test Call the writedoublearray interface, write the array to the MessageSequence instance,
      *             and call readdoublearra (datain: number []) to read the data
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 1
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0170", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0170---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let wDoubleArryData = [];
            for (let i = 0; i < (25 * K - 1); i++) {
                wDoubleArryData[i] = 11.1;
            };
            data.writeDoubleArray(wDoubleArryData);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_DOUBLEARRAY, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                let rDoubleArryData = [];
                result.reply.readDoubleArray(rDoubleArryData);
                assertArrayElementEqual(rDoubleArryData, wDoubleArryData);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0170---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0180
      * @tc.name    : test Writedoublearray interface, boundary value verification
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 3
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0180", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0180---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let wDoubleArryData = [4.9E-324, 235.67, 1.79E+308];
            data.writeDoubleArray(wDoubleArryData);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_DOUBLEARRAY, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                assertArrayElementEqual(result.reply.readDoubleArray(), wDoubleArryData);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0180---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0190
      * @tc.name    : test Writedoublearray interface, illegal value validation
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 3
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0190", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0190---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let eDoubleArryData = [(4.9E-324) - 1, (1.79E+308) + 1];
            data.writeDoubleArray(eDoubleArryData);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_DOUBLEARRAY, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                let rDoubleArryData = result.reply.readDoubleArray();
                expect(rDoubleArryData[0]).assertEqual(-1);
                expect(rDoubleArryData[1]).assertEqual(1.79e+308);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0190---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0200
      * @tc.name    : test Writedoublearray interface, Out-of-bounds value verification
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 3
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0200---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            let eDoubleArryData = [];
            for (let i = 0; i < 25 * K; i++) {
                eDoubleArryData[i] = 11.1;
            };
            data.writeDoubleArray(eDoubleArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            let errCode = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
            expect(error.code != errCode).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0200---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0210
      * @tc.name    : test Call the writebooleanarray interface, write the array to the MessageSequence instance,
      *             and call readbooleanarray to read the data
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 1
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0210", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0210---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let wBooleanArryData = [true, false, false];
            data.writeBooleanArray(wBooleanArryData);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_BOOLEANARRAY, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                assertArrayElementEqual(result.reply.readBooleanArray(), wBooleanArryData);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0210---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0220
      * @tc.name    : test Call the writebooleanarray interface, write the array to the MessageSequence instance,
      *             and call readbooleanarray (datain: number []) to read the data
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 1
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0220", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0220---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let wBooleanArryData = [];
            for (let i = 0; i < (50 * K - 1); i++) {
                if (i % 2 == 0) {
                    wBooleanArryData[i] = false;
                } else {
                    wBooleanArryData[i] = true;
                };
            };
            data.writeBooleanArray(wBooleanArryData);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_BOOLEANARRAY, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                let rBooleanArryData = [];
                result.reply.readBooleanArray(rBooleanArryData);
                assertArrayElementEqual(rBooleanArryData, wBooleanArryData);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0220---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0230
      * @tc.name    : test Writebooleanarray interface, illegal value validation
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 3
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0230", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0230---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let errorBooleanArryData = [true, 9, false];
            data.writeBooleanArray(errorBooleanArryData);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_BOOLEANARRAY, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                let eCharArrayData = [true, false, false];
                assertArrayElementEqual(result.reply.readBooleanArray(), eCharArrayData);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0230---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0240
      * @tc.name    : test Writebooleanarray Interface for length verification of input parameters
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 3
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0240", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0240---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            let wBooleanArryData = [];
            for (let i = 0; i < 50 * K; i++) {
                if (i % 2 == 0) {
                    wBooleanArryData[i] = false;
                } else {
                    wBooleanArryData[i] = true;
                };
            };
            data.writeBooleanArray(wBooleanArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            let errCode = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
            expect(error.code != errCode).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0240---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0250
      * @tc.name    : test Call the writechararray interface, write the array to the MessageSequence instance,
      *             and call readchararray to read the data
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 1
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0250", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0250---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let wCharArryData = [0, 97, 255];
            data.writeCharArray(wCharArryData);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_CHARARRAY, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                assertArrayElementEqual(result.reply.readCharArray(), wCharArryData);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0250---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0260
      * @tc.name    : test Call the writechararray interface, write the array to the MessageSequence instance,
      *             and call readchararray (datain: number []) to read the data
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 1
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0260", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0260---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let wCharArryData = [];
            for (let i = 0; i < (50 * K - 1); i++) {
                wCharArryData[i] = 96;
            };
            data.writeCharArray(wCharArryData);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_CHARARRAY, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                let rCharArryData = [];
                result.reply.readCharArray(rCharArryData);
                assertArrayElementEqual(rCharArryData, wCharArryData);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0260---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0270
      * @tc.name    : test Writechararray interface, illegal value validation
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 3
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0270", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0270---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let errorCharArryData = [96, 'asfgdgdtu', 97];
            data.writeCharArray(errorCharArryData);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_CHARARRAY, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                let eCharArrayData = [96, 0, 97];
                let readchardata = result.reply.readCharArray();
                assertArrayElementEqual(readchardata, eCharArrayData);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0270---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0280
      * @tc.name    : test Writechararray Indicates the length of an interface input parameter
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 3
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0280", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0280---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            let errorCharArryData = [];
            for (let i = 0; i < 50 * K; i++) {
                errorCharArryData[i] = 96;
            };
            data.writeCharArray(errorCharArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            let errCode = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
            expect(error.code != errCode).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0280---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0290
      * @tc.name    : test Call the writestringarray interface, write the array to the MessageSequence instance,
      *             and call readstringarray (datain: number []) to read the data
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 1
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0290", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0290---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let wStringArryData = ['abc', 'hello', 'beauty'];
            data.writeStringArray(wStringArryData);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRINGARRAY, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                assertArrayElementEqual(result.reply.readStringArray(), wStringArryData);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0290---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0300
      * @tc.name    : test Call the writestringarray interface, write the array to the MessageSequence instance,
      *             and call readstringarray() to read the data
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 1
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0300---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let wStringArryData = [];
            for (let i = 0; i < (10 * K - 1); i++) {
                wStringArryData[i] = "softbus";
            };
            data.writeStringArray(wStringArryData);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRINGARRAY, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                let rStringArryData = [];
                result.reply.readStringArray(rStringArryData);
                assertArrayElementEqual(rStringArryData, wStringArryData);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0300---------------------------");
    });

    /*
      * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0310
      * @tc.name    : test Writestringarray interface, illegal value validation
      * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
      * @tc.level   : Level 3
      * @tc.type    : Compatibility
      * @tc.size    : MediumTest
      */
    it("SUB_DSoftbus_IPC_API_MessageSequence_0310", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0310---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            let errorStringArryData = ['abc', 123, 'beauty'];
            data.writeStringArray(errorStringArryData);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            let errCode = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
            expect(error.code != errCode).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0310---------------------------");
    });
	  /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0320
         * @tc.name    : test writeStringArray Interface for length verification of input parameters
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0320", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0320---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                let wStringArryData = [];
                for (let i = 0; i < 10 * K; i++) {
                    wStringArryData[i] = "heddSDF";
                };
                data.writeStringArray(wStringArryData);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0320---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0330
         * @tc.name    : test Call the writebytearray interface, write the array to the MessageSequence instance,
         *             and call readbytearray to read the data
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 1
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0330", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0330---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let ByteArraylet = [1, 2, 3, 4, 5];
                data.writeByteArray(ByteArraylet);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_BYTEARRAY, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    assertArrayElementEqual(result.reply.readByteArray(), ByteArraylet);
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0330---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0340
         * @tc.name    : test Call the writebytearray interface, write the array to the MessageSequence instance,
         *             and call readbytearray (datain: number []) to read the data
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0340", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0340---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let ByteArraylet = [-128, 0, 1, 2, 127];
                data.writeByteArray(ByteArraylet);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_BYTEARRAY, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    let newArr = new Array(5);
                    result.reply.readByteArray(newArr);
                    assertArrayElementEqual(newArr, ByteArraylet);
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0340---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0350
         * @tc.name    : test Writebytearray interface, boundary value verification
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0350", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0350---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let ByteArraylet = [];
                for (let i = 0; i < (40 * K - 1); i++) {
                    ByteArraylet[i] = 1;
                };
                data.writeByteArray(ByteArraylet);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_BYTEARRAY, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    let newArr = new Array(5)
                    result.reply.readByteArray(newArr);
                    assertArrayElementEqual(newArr, ByteArraylet);
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0350---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0360
         * @tc.name    : test Writebytearray interface, illegal value validation
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0360", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0360---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let ByteArraylet = [-129, 0, 1, 2, 128];
                data.writeByteArray(ByteArraylet);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_BYTEARRAY, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    let shortArryDataReply = result.reply.readByteArray();
                    expect(shortArryDataReply[0] == 127).assertTrue();
                    expect(shortArryDataReply[1] == ByteArraylet[1]).assertTrue();
                    expect(shortArryDataReply[2] == ByteArraylet[2]).assertTrue();
                    expect(shortArryDataReply[3] == ByteArraylet[3]).assertTrue();
                    expect(shortArryDataReply[4] == -128).assertTrue();
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0360---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0370
         * @tc.name    : test Writebytearray Interface，input parameter length verification
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0370", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0370---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                let ByteArraylet = [];
                for (let i = 0; i < 40 * K; i++) {
                    ByteArraylet[i] = 1;
                };
                data.writeByteArray(ByteArraylet);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                let errCode = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
                expect(error.code != errCode).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0370---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0380
         * @tc.name    : test Call the writeintarray interface, write the array to the MessageSequence instance,
         *             and call readintarray to read the data
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 1
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0380", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0380---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let intArryData = [100, 111, 112];
                data.writeIntArray(intArryData);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_INTARRAY, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    assertArrayElementEqual(result.reply.readIntArray(), intArryData);
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0380---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0390
         * @tc.name    : test Call the writeintarray interface, write the array to the MessageSequence instance,
         *             and call readintarray (datain: number []) to read the data
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 1
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0390", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0390---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let intArryData = [];
                for (let i = 0; i < (50 * K - 1); i++) {
                    intArryData[i] = 1;
                };
                data.writeIntArray(intArryData);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_INTARRAY, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    let newArr = new Array(3);
                    result.reply.readIntArray(newArr);
                    assertArrayElementEqual(newArr, intArryData);
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0390---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0400
         * @tc.name    : test Writeintarray interface, boundary value verification
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0400---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let intArryData = [-2147483648, 0, 1, 2, 2147483647];
                data.writeIntArray(intArryData);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_INTARRAY, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    assertArrayElementEqual(result.reply.readIntArray(), intArryData);
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0400---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0410
         * @tc.name    : test Writeintarray interface, illegal value verification
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0410", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0410---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let intArryData = [-2147483649, 0, 1, 2, 2147483648];
                data.writeIntArray(intArryData);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_INTARRAY, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    let shortArryDataReply = result.reply.readIntArray();
                    expect(shortArryDataReply[0] == 2147483647).assertTrue();
                    expect(shortArryDataReply[1] == intArryData[1]).assertTrue();
                    expect(shortArryDataReply[2] == intArryData[2]).assertTrue();
                    expect(shortArryDataReply[3] == intArryData[3]).assertTrue();
                    expect(shortArryDataReply[4] == -2147483648).assertTrue();
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0410---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0420
         * @tc.name    : test Writeintarray interface, input parameter length verification
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0420", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0420---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                let intArryData = [];
                for (let i = 0; i < 50 * K; i++) {
                    intArryData[i] = 1;
                };
                data.writeIntArray(intArryData);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                let errCode = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
                expect(error.code != errCode).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0420---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0430
         * @tc.name    : test Call the writefloatarray interface, write the array to the MessageSequence instance,
         *             and call readfloatarray to read the data
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 1
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0430", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0430---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let floatArryData = [1.2, 1.3, 1.4];
                data.writeFloatArray(floatArryData);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_FLOATARRAY, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    assertArrayElementEqual(result.reply.readFloatArray(), floatArryData)
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0430---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0440
         * @tc.name    : test Call the writefloatarray interface, write the array to the MessageSequence instance,
         *             and call readfloatarray (datain: number []) to read the data
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 1
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0440", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0440---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let floatArryData = [1.4E-45, 1.3, 3.4028235E38];
                data.writeFloatArray(floatArryData);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_FLOATARRAY, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    let newArr = new Array(3);
                    result.reply.readFloatArray(newArr);
                    assertArrayElementEqual(newArr, floatArryData);
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0440---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0450
         * @tc.name    : test Writefloatarray interface, boundary value verification
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0450", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0450---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let floatArryData = [(1.4E-45) - 1, 1.3, (3.4028235E38) + 1];
                data.writeFloatArray(floatArryData);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_FLOATARRAY, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    let newArr = result.reply.readFloatArray();
                    expect(newArr[0]).assertEqual(-1);
                    expect(newArr[1]).assertEqual(1.3);
                    expect(newArr[2]).assertEqual(3.4028235e+38);
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0450---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0460
         * @tc.name    : test Writefloatarray interface, boundary value verification
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0460", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0460---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let floatArryData = [];
                for (let i = 0; i < (25 * K - 1); i++) {
                    floatArryData[i] = 1.1;
                };
                data.writeFloatArray(floatArryData);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_FLOATARRAY, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    assertArrayElementEqual(result.reply.readFloatArray(), floatArryData);
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0460---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0470
         * @tc.name    : test Writefloatarray interface, Longest array verification
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0470", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0470---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                let floatArryData = [];
                for (let i = 0; i < (25 * K); i++) {
                    floatArryData[i] = 1.1;
                };
                data.writeFloatArray(floatArryData);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                let errCode = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
                expect(error.code != errCode).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0470---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0480
         * @tc.name    : test Call the writeShort interface to write the short integer data to the MessageSequence instance,
         *             and call readshort to read the data
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0480", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0480---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let short = 8;
                data.writeShort(short);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_SHORT, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    assertArrayElementEqual(result.reply.readShort(), short);
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0480---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0490
         * @tc.name    : test WriteShort interface, boundary value verification
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0490", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0490---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                data.writeShort(-32768);
                data.writeShort(0);
                data.writeShort(1);
                data.writeShort(2);
                data.writeShort(32767);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_SHORT_MULTI, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    expect(result.reply.readShort() == -32768).assertTrue();
                    expect(result.reply.readShort() == 0).assertTrue();
                    expect(result.reply.readShort() == 1).assertTrue();
                    expect(result.reply.readShort() == 2).assertTrue();
                    expect(result.reply.readShort() == 32767).assertTrue();
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0490---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0500
         * @tc.name    : test WriteShort interface, Boundary value minimum value out of bounds verification
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0500---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                data.writeShort(-32769);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_SHORT_MULTI, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    expect(result.reply.readShort() == 32767).assertTrue();
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0500---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0510
         * @tc.name    : test WriteShort interface, Boundary value maximum value out of bounds verification
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0510", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0510---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                data.writeShort(32768);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_SHORT_MULTI, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    expect(result.reply.readShort() == -32768).assertTrue();
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0510---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0520
         * @tc.name    : test Call writelong interface to write long integer data to MessageSequence instance
         *             and call readlong to read data
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0520", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0520---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let long = 9007199254740991;
                data.writeLong(long);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_LONG, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    expect(result.reply.readLong()).assertEqual(long);
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0520---------------------------");
        });


        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0530
         * @tc.name    : test Writelong interface, Verification of maximum accuracy value
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0530", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0530---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let long = -9007199254740992;
                data.writeLong(long);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_LONG, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    expect(result.reply.readLong() == long).assertTrue();
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0530---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0540
         * @tc.name    : test Writelong interface, Minimum loss accuracy verification
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0540", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0540---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let long = -9223372036854775300;
                data.writeLong(long);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_LONG, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    expect(result.reply.readLong()).assertEqual(-9223372036854776000);
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0540---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0550
         * @tc.name    : test Writelong interface, Maximum loss accuracy verification
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0550", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0550---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let short = 9223372036854775300;
                data.writeLong(short);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_LONG, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    let readlong = result.reply.readLong();
                    expect(readlong != 0).assertTrue();
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0550---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0560
         * @tc.name    : test Call the parallel interface to read and write data to the double instance
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 1
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0560", TestType.FUNCTION | Size.MEDIUMST | Level.LEVEL1, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0560---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let token = 4.9E-324;
                data.writeDouble(token);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_DOUBLE, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    expect(result.reply.readDouble()).assertEqual(token);
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0560---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0570
         * @tc.name    : test Writedouble interface, boundary value verification
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         *tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0570", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0570---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let token = 1.79E+308;
                data.writeDouble(token);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_DOUBLE, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    expect(result.reply.readDouble()).assertEqual(token);
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0570---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0580
         * @tc.name    : test Writedouble interface, Minimum boundary value out of bounds verification
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0580", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0580---------------------------");
            try {
              var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let token = (4.9E-324) - 1;
                data.writeDouble(token);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_DOUBLE, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    expect(result.reply.readDouble()).assertEqual(-1);
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0580---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0590
         * @tc.name    : test Writedouble interface, illegal value validation
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0590", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
            nsole.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0590---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                let token = "1.79E+465312156";
                data.writeDouble(token);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                let errCode = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
                expect(error.code != errCode).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0590---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0600
         * @tc.name    : test Call the writeboolean interface to write the data to the MessageSequence instance,
         *             and call readboolean to read the data
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 1
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0600-------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let token = true;
                data.writeBoolean(token);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_BOOLEAN, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    expect(result.reply.readBoolean()).assertEqual(token);
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0600---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0610
         * @tc.name    : test Call the writeboolean interface to write the data to the MessageSequence instance,
         *             and call readboolean to read the data
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 1
         * @tc.type    : Compatibility
         * @tc.siz   : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0610", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0610---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let token = false;
                data.writeBoolean(token);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_BOOLEAN, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    expect(result.reply.readBoolean()).assertEqual(token);
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0610---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0620
         * @tc.name    : test Writeboolean interface, illegal value number type verification
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0620", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0620---------------------------");
            try {
                var data = rpc.MesseSequence.create();
                data.writeBoolean(9);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                let errCode = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
                expect(error.code != errCode).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0620---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0630
         * @tc.name    : test Writeboolean interface, illegal value string type verification
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it(UB_DSoftbus_IPC_API_MessageSequence_0630", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0630---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                let token = "true";
                data.writeBoolean(token);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                let errCode = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
                expect(error.code != errCode).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0630---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0640
         * @tc.name    : test Call the writechar interface to write the minimum data to the MessageSequence instance,
         *               and call readchar to read the data
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 1
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0640", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEV1, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0640---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let token = 0;
                data.writeChar(token);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_CHAR, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    expect(result.reply.readChar()).assertEqual(token);
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0640---------------------------");
        });
    console.info("-----------------------SUB_DSoftbus_IPC_API_Stage_MessageSequence_Test is end-----------------------");
  })
}
