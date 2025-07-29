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

import rpc from '@ohos.rpc';
import featureAbility from '@ohos.ability.featureAbility';
import process from '@ohos.process';
import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index';

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
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0010
     * @tc.name       : test Call the writeremoteobject interface to serialize the remote object
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0010", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0010---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let testRemoteObject = new TestRemoteObject("testObject");
        data.writeRemoteObject(testRemoteObject);
        expect(data.readRemoteObject() != null).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error == null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0010---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0020
     * @tc.name       : test Call the writeremoteobject interface to serialize the remote object and pass in the empty
     *                  object The object parameter is empty
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0020", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0020---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let testRemoteObject = new TestRemoteObject("");
        data.writeRemoteObject(testRemoteObject);
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_0020 is:" + data.readRemoteObject());
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode = `${rpc.ErrorCode.CHECK_PARAM_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0020---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0030
     * @tc.name       : test Call the writeremoteobject interface to serialize the remote object and pass in the empty object
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0030", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0030---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        data.writeRemoteObject(undefined);
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode = `${rpc.ErrorCode.CHECK_PARAM_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0030---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0040
     * @tc.name       : test ReadRemoteObject is read data from message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0040", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0040---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let testRemoteObject = new TestRemoteObject("testObject");
        data.writeRemoteObject(testRemoteObject);
        data.reclaim();
        data.readRemoteObject();
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
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0040---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0050
     * @tc.name       : test WriteRemoteObject is write data to message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0050", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0050---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let testRemoteObject = new TestRemoteObject("testObject");
        data.reclaim();
        data.writeRemoteObject(testRemoteObject);
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
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0050---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0060
     * @tc.name       : test Call the writeinterfacetoken interface, write the interface descriptor, and read interfacetoken
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0060", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0060---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let token = "hello ruan zong xian";
        data.writeInterfaceToken(token);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_INTERFACETOKEN, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          expect(result.reply.readInterfaceToken()).assertEqual(token);
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error == null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0060---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0070
     * @tc.name       : test Call the WriteInterfaceToken interface, write the maximum length interface descriptor, and read the InterfaceToken
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0070", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0070---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let token = "";
        for (let i = 0; i < (40 * K - 1); i++) {
          token += "a";
        }
        data.writeInterfaceToken(token);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_INTERFACETOKEN, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          expect(result.reply.readInterfaceToken()).assertEqual(token);
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error == null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0070---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0080
     * @tc.name       : test The WriteInterfaceToken interface is called, the exceeding-length interface descriptor is
     *                  written, and the InterfaceToken is read
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0080", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0080---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let token = "";
        for (let i = 0; i < 40 * K; i++) {
          token += "a";
        }
        data.writeInterfaceToken(token);
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.CHECK_PARAM_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0080---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0090
     * @tc.name       : test Call the writeinterfacetoken interface to write null data
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0090", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0090---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        data.writeInterfaceToken(null);
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.CHECK_PARAM_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0090---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0100
     * @tc.name       : test WriteInterfaceToken is write data to message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0100---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        data.reclaim();
        data.writeInterfaceToken("rpctest");
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
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0100---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0110
     * @tc.name       : test ReadInterfaceToken is read data from message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0110", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0110---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        data.writeInterfaceToken("rpctest");
        data.reclaim();
        data.readInterfaceToken();
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
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0110---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0120
     * @tc.name       : test setSize Sets the size of the data contained in the MessageSequence instance. The getSize command reads the data
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0120", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0120---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
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
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error: " + error);
        expect(error == null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0120---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0130
     * @tc.name       : test Set the size of the data contained in the MessageSequence instance to 0
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0130", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0130---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
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
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error: " + error);
        expect(error == null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0130---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0140
     * @tc.name       : test Verify the MessageSequence instance SetSize setting and the instance capacitydata qualification verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0140", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0140---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        expect(data.getSize()).assertEqual(0);
        data.writeString("constant");
        expect(data.getSize()).assertEqual(("constant".length * 2) + 8);
        let getCapacitydata = data.getCapacity();
        expect(getCapacitydata).assertEqual(64);
        data.setSize(getCapacitydata);
        expect(data.getSize()).assertEqual(getCapacitydata);
        data.setSize(getCapacitydata - 1);
        expect(data.getSize()).assertEqual(getCapacitydata-1);
        console.info(logTag + "getSize or getCapacityresult");
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error: " + error);
        expect(error == null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0140---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0150
     * @tc.name       : test setSize Sets the storage capacity of the MessageSequence instance to decrease by one.The
     *                  getSize obtains the current MessageSequence capacity
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0150", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0150---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        data.writeString("constant");
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          expect(result.reply.readString()).assertEqual("constant");
          expect(result.reply.getSize()).assertEqual(("constant".length * 2) + 8);
          let getCapacityresult = result.reply.getCapacity();
          result.reply.setSize(getCapacityresult);
          expect(result.reply.getSize()).assertEqual(getCapacityresult);
          result.reply.setSize(getCapacityresult - 1);
          expect(result.reply.getSize()).assertEqual(getCapacityresult-1);
          console.info(logTag + "getSize or getCapacityresult");
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error: " + error);
        expect(error == null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0150---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0160
     * @tc.name       : test Validate the setSize boundary value in the MessageSequence instance
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0160", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0160---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        expect(data.getCapacity()).assertEqual(0);
        data.setSize(4 * G);
        expect(data.getSize()).assertEqual(0);
        data.setSize(4 * G - 1);
        expect(data.getSize()).assertEqual(0);
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0160---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0170
     * @tc.name       : test Verify that setSize is out of bounds in a MessageSequence instance
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0170", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0170---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        data.setSize(0);
        expect(data.getSize()).assertEqual(0);
        data.setSize(2 * 4 * G);
        expect(data.getSize()).assertEqual(0);
        data.setSize(2 * G + 1);
        expect(data.getSize()).assertEqual(0);
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0170---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0180
     * @tc.name       : test setCapacity Sets the storage capacity of the null MessageSequence instance. The
     *                  getCapacity obtains the current MessageSequence capacity
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0180", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0180---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        expect(data.getCapacity()).assertEqual(0);
        data.setCapacity(100);
        data.writeString("constant");
        expect(data.getCapacity()).assertEqual(100);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          expect(result.reply.getCapacity()).assertEqual(("constant".length * 2) + 8);
          expect(result.reply.readString()).assertEqual("constant");
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error: " + error);
        expect(error == null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0180---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0190
     * @tc.name       : test setCapacity Sets the storage capacity of the MessageSequence instance. After getting the
     *                  MessageSequence instance, get the current MessageSequence capacity
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0190", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0190---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        expect(data.getCapacity()).assertEqual(0);
        data.setCapacity(100);
        data.writeString("constant");
        expect(data.getCapacity()).assertEqual(100);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          expect(result.reply.getCapacity()).assertEqual(("constant".length * 2) + 8);
          expect(result.reply.readString()).assertEqual("constant");
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error: " + error);
        expect(error == null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0190---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0200
     * @tc.name       : test Setcapacity test: size limit verification of MessageSequence instance
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0200---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        expect(data.getCapacity()).assertEqual(0);
        data.writeString("constant");
        let getSizedata = data.getSize();
        data.setCapacity(getSizedata + 1);
        console.info(logTag + "setCapacity is getSizeresult+1 success");
        data.setCapacity(getSizedata);
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.PARCEL_MEMORY_ALLOC_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0200---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0210
     * @tc.name       : test SetCapacity Tests the storage capacity threshold of the MessageSequence instance
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0210", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0210---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        data.writeString("constant");
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let getSizeresult: number = result.reply.getSize();
          let dataLength = ("constant".length * 2) + 8;
          expect(result.reply.getCapacity()).assertEqual(dataLength);
          result.reply.setCapacity(getSizeresult - 1);
          console.info(logTag + "setCapacity is getSizeresult success");
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode = `${rpc.ErrorCode.PARCEL_MEMORY_ALLOC_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0210---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0220
     * @tc.name       : test Setcapacity test storage capacity boundary value verification of MessageSequence instance
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0220", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0220---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        expect(data.getSize()).assertEqual(0);
        data.setCapacity(M);
        expect(data.getCapacity()).assertEqual(M);
        data.setCapacity(2 * G);
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.PARCEL_MEMORY_ALLOC_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0220---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0230
     * @tc.name       : test readParcelable is Call JS callback function failedv Error message verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0230", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0230---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let sequenceable = new MySequenceable(1, "aaa");
        data.writeParcelable(sequenceable);
        data.setCapacity(0);
        data.setSize(0);
        let ret = new MySequenceable(1, "");
        data.readParcelable(ret);
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.CALL_JS_METHOD_ERROR}`;
        expect("e.code" != errCode).assertTrue();
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0230---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0200
     * @tc.name       : test Invoke the writeinterfacetoken interface, write the interface descriptor, and verify the
     *                  error code that fails to be read from the interfacetoken interface
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0240", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0240---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let token = "hello ruan zong xian";
        data.writeInterfaceToken(token);
        data.setCapacity(0);
        data.setSize(0);
        data.readInterfaceToken();
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.PARCEL_MEMORY_ALLOC_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0240---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0250
     * @tc.name       : test writeInterfaceToken Sequence memory alloc failed Error message verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0250", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0250---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        data.setSize(0);
        data.setCapacity(0);
        let token = "hello ruan zong xian";
        data.writeInterfaceToken(token);
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.PARCEL_MEMORY_ALLOC_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0250---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0260
     * @tc.name       : test writeInterfaceToken Write data to message sequence failed Error message verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0260", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0260---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        data.setSize(null);
        data.setCapacity(null);
        let token = "hello ruan zong xian";
        data.writeInterfaceToken(token);
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.CHECK_PARAM_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0260---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0270
     * @tc.name       : test setSize is write data to message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0270", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0270---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        data.reclaim();
        data.setSize(0);
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
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0270---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0280
     * @tc.name       : test readParcelable Sequence memory alloc failed Error message verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0280", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0280---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let sequenceable = new MySequenceable(1, "aaa");
        data.writeParcelable(sequenceable);
        let ret = new MySequenceable(0, "");
        data.setCapacity(0);
        data.readParcelable(ret);
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.PARCEL_MEMORY_ALLOC_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0280---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0290
     * @tc.name       : test Obtaining the Writable and Readable Byte Spaces of MessageSequence
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0290", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0290---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
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
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error == null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0290---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_0300
     * @tc.name       : test Obtains the writeable and readable byte space and read position of the MessageSequence
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_0300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_0300---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
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
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error == null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_0300---------------------------");
    });
    console.info("-----------------------SUB_DSoftbus_IPC_API_Stage_MessageSequence_Test is end-----------------------");
})