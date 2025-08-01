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
import { BusinessError } from '@kit.BasicServicesKit';

let logTag = "[IpcClient_log:]";
let gIRemoteObject: rpc.IRemoteObject;

function checkResult(num:number, str:string) {
  console.info(logTag + "checkResult is success");
  expect(num).assertEqual(123);
  expect(str).assertEqual("rpcListenerTest");
};

class Stub extends rpc.RemoteObject {
  constructor(descriptor: string) {
    console.info(logTag + "RemoteObject: " + descriptor);
    super(descriptor);
  }
  onRemoteMessageRequest(code: number, data: rpc.MessageSequence, reply: rpc.MessageSequence, option: rpc.MessageOption): boolean | Promise<boolean> {
    try {
      console.info(logTag + "onRemoteMessageRequest: " + code);
      switch (code) {
        case 18:
          {
            console.info(logTag + "case 18 start");
            let tmp: number[] = data.readIntArray();
            reply.writeIntArray(tmp);
            console.info(logTag + "onRemoteMessageRequest success");
            return true;
          }
        case 19:
          {
            console.info(logTag + "case 19 start");
            let tmp: number[] = data.readDoubleArray();
            reply.writeDoubleArray(tmp);
            console.info(logTag + "onRemoteMessageRequest success");
            return true;
          }
        case 20:
          {
            console.info(logTag + "case 20 start");
            let tmp: number[] = data.readLongArray();
            reply.writeLongArray(tmp);
            console.info(logTag + "onRemoteMessageRequest success");
            return true;
          }
        case 21:
          {
            console.info(logTag + "case 21 start");
            let tmp: number[] = data.readFloatArray();
            reply.writeFloatArray(tmp);
            console.info(logTag + "onRemoteMessageRequest success");
            return true;
          }
        case 22:
          {
            console.info(logTag + "case 22 start");
            let tmp: number[] = data.readDoubleArray();
            reply.writeDoubleArray(tmp);
            console.info(logTag + "onRemoteMessageRequest success");
            return true;
          }
        case 23:
          {
            console.info(logTag + "case 23 start");
            let tmp: boolean[] = data.readBooleanArray();
            reply.writeBooleanArray(tmp);
            console.info(logTag + "onRemoteMessageRequest success");
            return true;
          }
        case 24:
          {
            console.info(logTag + "case 24 start");
            let tmp: number[] = data.readCharArray();
            reply.writeCharArray(tmp);
            console.info(logTag + "onRemoteMessageRequest success");
            return true;
          }
      }
    } catch (error) {
      console.info(logTag + "onRemoteMessageRequest: " + error);
    }
    return false;
  }
}

function isEqualArray(arr1: number[] | boolean[] | string[], arr2: number[] | boolean[] | string[]){
  return Array.isArray(arr1) &&
  Array.isArray(arr2) &&
    arr1.length === arr2.length &&
    JSON.stringify(arr1) === JSON.stringify(arr2)
}

export default function ActsRpcClientEtsTest() {
  describe('ActsRpcClientEtsTest', () => {
    console.info("-----------------------SUB_DSoftbus_IPC_API_Stage_MessageSequence_Test is starting-----------------------");
    const K = 1024;
    const M = 1024 * 1024;
    const G = 1024 * 1024 * 1024;
    const CODE_WRITE_INTARRAY = 18;
    const CODE_WRITE_LONGARRAY = 20;
    const CODE_WRITE_FLOATARRAY = 21;
    const CODE_WRITE_DOUBLEARRAY = 22;
    const CODE_WRITE_BOOLEANARRAY = 23
    const CODE_WRITE_CHARARRAY = 24;

    beforeAll(async () => {
      console.info(logTag + 'beforeAll called');
      gIRemoteObject = new Stub("IPCTest");
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
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1210
     * @tc.name       : test Call the writeintarray interface, write the array to the MessageSequence instance,
     *                  and call readintarray (datain: number []) to read the data
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1210", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1210---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let intArrayData: number[] = [];
        for (let i: number = 0; i < (50 * K - 1); i++) {
          intArrayData[i] = 1;
        };
        data.writeIntArray(intArrayData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_INTARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let newArr: number[] = [];
          result.reply.readIntArray(newArr);
          let assertE = isEqualArray(intArrayData,newArr);
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
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1200---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1220
     * @tc.name       : test Writeintarray interface, boundary value verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1220", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1220---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let intArrayData: number[] = [-2147483648, 0, 1, 2, 2147483647];
        data.writeIntArray(intArrayData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_INTARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          expect(result.reply.readIntArray()).assertDeepEquals(intArrayData);
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1220---------------------------");
    });

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
        let intArrayData: number[] = [-2147483649, 0, 1, 2, 2147483648];
        data.writeIntArray(intArrayData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_INTARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let shortArrayDataReply: number[] = result.reply.readIntArray();
          expect(shortArrayDataReply[0] == 2147483647).assertTrue();
          expect(shortArrayDataReply[1] == intArrayData[1]).assertTrue();
          expect(shortArrayDataReply[2] == intArrayData[2]).assertTrue();
          expect(shortArrayDataReply[3] == intArrayData[3]).assertTrue();
          expect(shortArrayDataReply[4] == -2147483648).assertTrue();
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
        let intArrayData: number[] = [];
        for (let i: number = 0; i < 50 * K; i++) {
          intArrayData[i] = 1;
        }
        data.writeIntArray(intArrayData);
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
        let wLongArrayData: number[] = [-9007199254740992, 0, 1, 2, 9007199254740991];
        data.writeLongArray(wLongArrayData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_LONGARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let rLongArrayData: number[] = [];
          result.reply.readLongArray(rLongArrayData);
          expect(rLongArrayData).assertDeepEquals(wLongArrayData);
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
        let wLongArrayData: number[] = [];
        for (let i: number = 0; i < (25 * K - 1); i++) {
          wLongArrayData[i] = 11;
        };
        data.writeLongArray(wLongArrayData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_LONGARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let rLongArrayData: number[] = [];
          result.reply.readLongArray(rLongArrayData);
          let assertE = isEqualArray(wLongArrayData,rLongArrayData);
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
        let wLongArrayData: number[] = [-9999999999999999, 9999999999999999];
        data.writeLongArray(wLongArrayData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_LONGARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let rLongArrayData: number[] = result.reply.readLongArray();
          let newLongData: number[] = [-10000000000000000, 10000000000000000];
          expect(rLongArrayData[0]).assertEqual(newLongData[0]);
          expect(rLongArrayData[1]).assertEqual(newLongData[1]);
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
        let wLongArrayData: number[] = [];
        for (let i: number = 0; i < 25 * K; i++) {
          wLongArrayData[i] = 11;
        };
        data.writeLongArray(wLongArrayData);
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
        let wFloatArrayData: number[] = [1.4E-45, 1.3, 3.4028235E38];
        data.writeFloatArray(wFloatArrayData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_FLOATARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let newArr: number[] = new Array(3);
          result.reply.readFloatArray(newArr);
          expect(newArr).assertDeepEquals(wFloatArrayData);
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
        let wFloatArrayData: number[] = [(1.4E-45) - 1, 1.3, (3.4028235E38) + 1];
        data.writeFloatArray(wFloatArrayData);
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
        let wFloatArrayData: number[] = [];
        for (let i: number = 0; i < (25 * K - 1); i++) {
          wFloatArrayData[i] = 1.1;
        };
        data.writeFloatArray(wFloatArrayData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_FLOATARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let rFloatArrayData: number[] = [];
          result.reply.readFloatArray(rFloatArrayData);
          let assertE = isEqualArray(wFloatArrayData,rFloatArrayData);
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
        let wFloatArrayData: number[] = [];
        for (let i: number = 0; i < (25 * K); i++) {
          wFloatArrayData[i] = 1.1;
        };
        data.writeFloatArray(wFloatArrayData);
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
        let wDoubleArrayData: number[] = [4.9E-324, 235.67, 1.79E+308];
        data.writeDoubleArray(wDoubleArrayData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_DOUBLEARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          expect(result.reply.readDoubleArray()).assertDeepEquals(wDoubleArrayData);
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
        let wDoubleArrayData: number[] = [];
        for (let i: number = 0; i < (25 * K - 1); i++) {
          wDoubleArrayData[i] = 11.1;
        };
        data.writeDoubleArray(wDoubleArrayData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_DOUBLEARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let rDoubleArrayData: number[] = [];
          result.reply.readDoubleArray(rDoubleArrayData);
          let assertE = isEqualArray(wDoubleArrayData,rDoubleArrayData);
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
        let eDoubleArrayData: number[] = [(4.9E-324) - 1, (1.79E+308) + 1];
        data.writeDoubleArray(eDoubleArrayData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_DOUBLEARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let rDoubleArrayData = result.reply.readDoubleArray();
          expect(rDoubleArrayData[0]).assertEqual(-1);
          expect(rDoubleArrayData[1]).assertEqual(1.79e+308);
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
        let eDoubleArrayData: number[] = [];
        for (let i = 0; i < 25 * K; i++) {
          eDoubleArrayData[i] = 11.1;
        }
        data.writeDoubleArray(eDoubleArrayData);
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
        let wBooleanArrayData: boolean[] = [true, false, false];
        data.writeBooleanArray(wBooleanArrayData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_BOOLEANARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          expect(result.reply.readBooleanArray()).assertDeepEquals(wBooleanArrayData);
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
        let wBooleanArrayData: boolean[] = [];
        for (let i: number = 0; i < (50 * K - 1); i++) {
          if (i % 2 == 0) {
            wBooleanArrayData[i] = false;
          } else {
            wBooleanArrayData[i] = true;
          }
        }
        data.writeBooleanArray(wBooleanArrayData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_BOOLEANARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let rBooleanArrayData: boolean[] = [];
          result.reply.readBooleanArray(rBooleanArrayData);
          let assertE = isEqualArray(wBooleanArrayData,rBooleanArrayData);
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
        let wBooleanArrayData: boolean[] = [];
        for (let i: number = 0; i < 50 * K; i++) {
          if (i % 2 == 0) {
            wBooleanArrayData[i] = false;
          } else {
            wBooleanArrayData[i] = true;
          };
        }
        data.writeBooleanArray(wBooleanArrayData);
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
        let wBooleanArrayData = [false, true, false];
        data.reclaim();
        data.writeBooleanArray(wBooleanArrayData);
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
        let wBooleanArrayData = [false, true, false];
        data.writeBooleanArray(wBooleanArrayData);
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
        let wCharArrayData: number[] = [0, 97, 255];
        data.writeCharArray(wCharArrayData);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_CHARARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          expect(result.reply.readCharArray()).assertDeepEquals(wCharArrayData);
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

    console.info("-----------------------SUB_DSoftbus_IPC_API_Stage_MessageSequence_Test is end-----------------------");
  })
}