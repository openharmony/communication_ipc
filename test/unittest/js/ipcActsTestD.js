/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1230
     * @tc.name       : test Writeintarray interface, illegal value verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1230", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1230---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let intArryData: number[] = [-2147483649, 0, 1, 2, 2147483648];
        data.writeIntArray(intArryData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_INTARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let shortArryDataReply: number[] = result.reply.readIntArray();
          expect(shortArryDataReply[0] == 2147483647).assertTrue();
          expect(shortArryDataReply[1] == intArryData[1]).assertTrue();
          expect(shortArryDataReply[2] == intArryData[2]).assertTrue();
          expect(shortArryDataReply[3] == intArryData[3]).assertTrue();
          expect(shortArryDataReply[4] == -2147483648).assertTrue();
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1230---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1240
     * @tc.name       : test Writeintarray interface, input parameter length verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1240", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1240---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let intArryData: number[] = [];
        for (let i: number = 0; i < 50 * K; i++) {
          intArryData[i] = 1;
        }
        data.writeIntArray(intArryData);
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
        expect('e.code' != errCode).assertTrue();
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1240---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1250
     * @tc.name       : test WriteIntArray is write data to message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1250", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1250---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let ByteArrayVar: number[] = [1, 2, 3, 4, 5];
        data.reclaim();
        data.writeIntArray(ByteArrayVar);
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1250---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1260
     * @tc.name       : test ReadIntArray is read data from message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1260", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1260---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let ByteArrayVar: number[] = [1, 2, 3, 4, 5];
        data.writeIntArray(ByteArrayVar);
        data.reclaim();
        data.readIntArray();
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1260---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1270
     * @tc.name       : test Writelongarray interface, boundary value verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1270", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1270---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let wLongArryData: number[] = [-9007199254740992, 0, 1, 2, 9007199254740991];
        data.writeLongArray(wLongArryData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_LONGARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let rLongArryData: number[] = [];
          result.reply.readLongArray(rLongArryData);
          expect(rLongArryData).assertDeepEquals(wLongArryData);
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1270---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1280
     * @tc.name       : test Call the writelongarray interface, write the long integer array to the MessageSequence instance,
     *                  and call readlongarray (datain: number []) to read the data
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1280", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1280---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let wLongArryData: number[] = [];
        for (let i: number = 0; i < (25 * K - 1); i++) {
          wLongArryData[i] = 11;
        };
        data.writeLongArray(wLongArryData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_LONGARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let rLongArryData: number[] = [];
          result.reply.readLongArray(rLongArryData);
          let assertE = isEqualArray(wLongArryData,rLongArryData);
          expect(assertE).assertTrue();
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1280---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1290
     * @tc.name       : test Writelongarray interface, long type precision verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1290", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1290---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let wLongArryData: number[] = [-9999999999999999, 9999999999999999];
        data.writeLongArray(wLongArryData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_LONGARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let rLongArryData: number[] = result.reply.readLongArray();
          let newlongdata: number[] = [-10000000000000000, 10000000000000000];
          expect(rLongArryData[0]).assertEqual(newlongdata[0]);
          expect(rLongArryData[1]).assertEqual(newlongdata[1]);
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1290---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1300
     * @tc.name       : test Writelongarray Indicates an interface for verifying the input length
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1300---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let wLongArryData: number[] = [];
        for (let i: number = 0; i < 25 * K; i++) {
          wLongArryData[i] = 11;
        };
        data.writeLongArray(wLongArryData);
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
        expect('e.code' != errCode).assertTrue();
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1300---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1310
     * @tc.name       : test WriteLongArray is write data to message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1310", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1310---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let ByteArrayVar: number[] = [1, 2, 3, 4, 5];
        data.reclaim();
        data.writeLongArray(ByteArrayVar);
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1310---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1320
     * @tc.name       : test ReadLongArray is read data from message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1320", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1320---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let ByteArrayVar: number[] = [1, 2, 3, 4, 5];
        data.writeLongArray(ByteArrayVar);
        data.reclaim();
        data.readLongArray();
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1320---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1330
     * @tc.name       : test Call the writefloatarray interface, write the array to the MessageSequence instance, and
     *                  call readfloatarray (datain: number []) to read the data
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1330", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1330---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let wfloatArryData: number[] = [1.4E-45, 1.3, 3.4028235E38];
        data.writeFloatArray(wfloatArryData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_FLOATARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let newArr: number[] = new Array(3);
          result.reply.readFloatArray(newArr);
          expect(newArr).assertDeepEquals(wfloatArryData);
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1330---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1340
     * @tc.name       : test Writefloatarray interface, parameter boundary value verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1340", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1340---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let wfloatArryData: number[] = [(1.4E-45) - 1, 1.3, (3.4028235E38) + 1];
        data.writeFloatArray(wfloatArryData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_FLOATARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let newArr = result.reply.readFloatArray();
          expect(newArr[0]).assertEqual(-1);
          expect(newArr[1]).assertEqual(1.3);
          expect(newArr[2]).assertEqual(3.4028235e+38);
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1340---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1350
     * @tc.name       : test Writefloatarray interface, boundary value verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1350", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1350---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let wfloatArryData: number[] = [];
        for (let i: number = 0; i < (25 * K - 1); i++) {
          wfloatArryData[i] = 1.1;
        };
        data.writeFloatArray(wfloatArryData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_FLOATARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let rFloatArrayData: number[] = [];
          result.reply.readFloatArray(rFloatArrayData);
          let assertE = isEqualArray(wfloatArryData,rFloatArrayData);
          expect(assertE).assertTrue();
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1350---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1360
     * @tc.name       : test Writefloatarray interface, Longest array verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1360", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1300---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let wfloatArryData: number[] = [];
        for (let i: number = 0; i < (25 * K); i++) {
          wfloatArryData[i] = 1.1;
        };
        data.writeFloatArray(wfloatArryData);
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
        expect('e.code' != errCode).assertTrue();
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1360---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1370
     * @tc.name       : test WriteFloatArray is write data to message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1370", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1370---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let wFloatArray = [1.1, 2.2, 3.3];
        data.reclaim();
        data.writeFloatArray(wFloatArray);
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1370---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1380
     * @tc.name       : test ReadFloatArray is read data from message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1380", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1380---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let wFloatArray = [1.1, 2.2, 3.3];
        data.writeFloatArray(wFloatArray);
        data.reclaim();
        data.readFloatArray();
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1380---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1390
     * @tc.name       : test Writedoublearray interface, boundary value verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1390", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1390---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let wDoubleArryData: number[] = [4.9E-324, 235.67, 1.79E+308];
        data.writeDoubleArray(wDoubleArryData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_DOUBLEARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          expect(result.reply.readDoubleArray()).assertDeepEquals(wDoubleArryData);
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1390---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1400
     * @tc.name       : test Call the writedoublearray interface, write the array to the MessageSequence instance,
     *                  and call readdoublearra (datain: number []) to read the data
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1400---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let wDoubleArryData: number[] = [];
        for (let i: number = 0; i < (25 * K - 1); i++) {
          wDoubleArryData[i] = 11.1;
        };
        data.writeDoubleArray(wDoubleArryData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_DOUBLEARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let rDoubleArryData: number[] = [];
          result.reply.readDoubleArray(rDoubleArryData);
          let assertE = isEqualArray(wDoubleArryData,rDoubleArryData);
          expect(assertE).assertTrue();
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1400---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1410
     * @tc.name       : test Writedoublearray interface, illegal value validation
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1410", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1410---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let eDoubleArryData: number[] = [(4.9E-324) - 1, (1.79E+308) + 1];
        data.writeDoubleArray(eDoubleArryData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_DOUBLEARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let rDoubleArryData = result.reply.readDoubleArray();
          expect(rDoubleArryData[0]).assertEqual(-1);
          expect(rDoubleArryData[1]).assertEqual(1.79e+308);
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1410---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1420
     * @tc.name       : test Writedoublearray interface, Out-of-bounds value verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1420", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1420---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let eDoubleArryData: number[] = [];
        for (let i = 0; i < 25 * K; i++) {
          eDoubleArryData[i] = 11.1;
        }
        data.writeDoubleArray(eDoubleArryData);
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
        expect('e.code' != errCode).assertTrue();
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1420---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1430
     * @tc.name       : test WriteDoubleArray is write data to message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1430", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1430---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let ByteArrayVar = [11.1, 22.2, 33.3];
        data.reclaim();
        data.writeDoubleArray(ByteArrayVar);
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1430---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1440
     * @tc.name       : test ReadDoubleArray is read data from message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1440", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1440---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let ByteArrayVar = [11.1, 22.2, 33.3];
        data.writeDoubleArray(ByteArrayVar);
        data.reclaim();
        data.readDoubleArray();
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1440---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1450
     * @tc.name       : test Call the writebooleanarray interface, write the array to the MessageSequence instance,
     *                  and call readbooleanarray to read the data
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1450", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1450---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let wBooleanArryData: boolean[] = [true, false, false];
        data.writeBooleanArray(wBooleanArryData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_BOOLEANARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          expect(result.reply.readBooleanArray()).assertDeepEquals(wBooleanArryData);
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1450---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1460
     * @tc.name       : test Call the writebooleanarray interface, write the array to the MessageSequence instance,
     *                  and call readbooleanarray (datain: boolean []) to read the data
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1460", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1460---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let wBooleanArryData: boolean[] = [];
        for (let i: number = 0; i < (50 * K - 1); i++) {
          if (i % 2 == 0) {
            wBooleanArryData[i] = false;
          } else {
            wBooleanArryData[i] = true;
          }
        }
        data.writeBooleanArray(wBooleanArryData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_BOOLEANARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let rBooleanArryData: boolean[] = [];
          result.reply.readBooleanArray(rBooleanArryData);
          let assertE = isEqualArray(wBooleanArryData,rBooleanArryData);
          expect(assertE).assertTrue();
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1460---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1470
     * @tc.name       : test Writebooleanarray Interface for length verification of input parameters
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1470", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1470---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let wBooleanArryData: boolean[] = [];
        for (let i: number = 0; i < 50 * K; i++) {
          if (i % 2 == 0) {
            wBooleanArryData[i] = false;
          } else {
            wBooleanArryData[i] = true;
          };
        }
        data.writeBooleanArray(wBooleanArryData);
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
        expect('e.code' != errCode).assertTrue();
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1470---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1480
     * @tc.name       : test WriteBooleanArray is write data to message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1480", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1480---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let wBooleanArryData = [false, true, false];
        data.reclaim();
        data.writeBooleanArray(wBooleanArryData);
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1480---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1490
     * @tc.name       : test ReadBooleanArray is read data from message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1490", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1490---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let wBooleanArryData = [false, true, false];
        data.writeBooleanArray(wBooleanArryData);
        data.reclaim();
        data.readBooleanArray();
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1490---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1500
     * @tc.name       : test Call the writechararray interface, write the array to the MessageSequence instance,
     *                  and call readchararray to read the data
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1500---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let wCharArryData: number[] = [0, 97, 255];
        data.writeCharArray(wCharArryData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_CHARARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          expect(result.reply.readCharArray()).assertDeepEquals(wCharArryData);
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1500---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1510
     * @tc.name       : test Call the writechararray interface, write the array to the MessageSequence instance,
     *                  and call readchararray (datain: number []) to read the data
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1510", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1510---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let wCharArryData: number[] = [];
        for (let i: number = 0; i < (50 * K - 1); i++) {
          wCharArryData[i] = 96;
        };
        data.writeCharArray(wCharArryData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_CHARARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let rCharArryData: number[] = [];
          result.reply.readCharArray(rCharArryData);
          let assertE = isEqualArray(wCharArryData,rCharArryData);
          expect(assertE).assertTrue();
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1510---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1520
     * @tc.name       : test Writechararray Indicates the length of an interface input parameter
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1520", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1520---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let errorCharArryData: number[] = [];
        for (let i = 0; i < 50 * K; i++) {
          errorCharArryData[i] = 96;
        };
        data.writeCharArray(errorCharArryData);
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
        expect('e.code' != errCode).assertTrue();
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1520---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1530
     * @tc.name       : test WriteCharArray is write data to message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1530", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1530---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let ByteArrayVar: number[] = [97, 98, 88];
        data.reclaim();
        data.writeCharArray(ByteArrayVar);
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1530---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1540
     * @tc.name       : test ReadCharArray is read data from message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1540", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1540---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let ByteArrayVar: number[] = [97, 98, 88];
        data.writeCharArray(ByteArrayVar);
        data.reclaim();
        data.readCharArray();
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1540---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1550
     * @tc.name       : test Call the writestringarray interface, write the array to the MessageSequence instance,
     *                  and call readstringarray (datain: string []) to read the data
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1550", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1550---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let wStringArryData: string[] = ["abc", "hello", "beauty"];
        data.writeStringArray(wStringArryData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRINGARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          expect(result.reply.readStringArray()).assertDeepEquals(wStringArryData);
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1550---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1560
     * @tc.name       : test Call the writestringarray interface, write the array to the MessageSequence instance,
     *                  and call readstringarray() to read the data
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1560", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1560---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let wStringArryData: string[] = [];
        for (let i = 0; i < (10 * K - 1); i++) {
          wStringArryData[i] = "heddSDF";
        };
        data.writeStringArray(wStringArryData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRINGARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let rStringArryData: string[] = [];
          result.reply.readStringArray(rStringArryData);
          let assertE = isEqualArray(wStringArryData,rStringArryData);
          expect(assertE).assertTrue();
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1560---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1570
     * @tc.name       : test writeStringArray Interface for length verification of input parameters
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1570", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1570---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let wStringArryData: string[] = [];
        for (let i = 0; i < 10 * K; i++) {
          wStringArryData[i] = "heddSDF";
        }
        data.writeStringArray(wStringArryData);
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
        expect('e.code' != errCode).assertTrue();
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1570---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1580
     * @tc.name       : test WriteStringArray is write data to message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1580", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1580---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let ByteArrayVar = ["abc", "def"];
        data.reclaim();
        data.writeStringArray(ByteArrayVar);
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1580---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1590
     * @tc.name       : test ReadStringArray is read data from message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1590", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1590---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let ByteArrayVar: string[] = ["abc", "def"];
        data.writeStringArray(ByteArrayVar);
        data.reclaim();
        data.readStringArray();
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1590---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1600
     * @tc.name       : test After the server finishes processing, write noexception first before writing the result,
     *                  and the client calls readexception to judge whether the server is abnormal
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1600---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        data.writeNoException();
        data.writeInt(6);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_NOEXCEPTION, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          result.reply.readException();
          expect(result.reply.readInt()).assertEqual(6);
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1600---------------------------");
    });

    console.info("-----------------------SUB_DSoftbus_IPC_API_Stage_MessageSequence_Test is end-----------------------");
  })
}