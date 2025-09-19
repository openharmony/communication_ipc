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
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1610
     * @tc.name       : test If the data on the server is abnormal, the client calls readexception
     *                  to judge whether the server is abnormal
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1610", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1610---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        data.writeNoException();
        data.writeInt(1232222223444);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_NOEXCEPTION, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          result.reply.readException();
          expect(result.reply.readInt() != 1232222223444).assertTrue();
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1610---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1620
     * @tc.name       : test WriteNoException is write data to message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1620", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1620---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        data.reclaim();
        data.writeNoException();
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
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1620---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1630
     * @tc.name       : test ReadException is read data from message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1630", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1630---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        data.reclaim();
        data.readException();
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
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1630---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1640
     * @tc.name       : test Call the writeParcelablearray interface to write the custom serialized object array (1, 2, 3) to
     *                  the MessageSequence instance, and call readParcelablearray to read the data
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1640", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1640---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let sequenceable = [new MySequenceable(1, "aaa"),
          new MySequenceable(2, "bbb"), new MySequenceable(3, "ccc")];
        data.writeParcelableArray(sequenceable);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_SEQUENCEABLEARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let s = [new MySequenceable(0, ""), new MySequenceable(0, ""),
            new MySequenceable(0, "")];
          result.reply.readParcelableArray(s);
          for (let i = 0; i < s.length; i++) {
            expect(s[i].str).assertEqual(sequenceable[i].str);
            expect(s[i].num).assertEqual(sequenceable[i].num);
          }
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1640---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1650
     * @tc.name       : test Call the writeParcelablearray interface to write the custom serialized object to the
     *                  MessageSequence instance, and call readParcelablearray to read the data
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1650", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1650---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let sequenceable = [new MySequenceable(4, "abc"),
          new MySequenceable(5, "bcd"), new MySequenceable(6, "cef")];
        data.writeParcelableArray(sequenceable);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_SEQUENCEABLEARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let s = [new MySequenceable(0, ""),
            new MySequenceable(0, ""), new MySequenceable(0, "")];
          result.reply.readParcelableArray(s);
          for (let i = 0; i < s.length; i++) {
            expect(s[i].str).assertEqual(sequenceable[i].str);
            expect(s[i].num).assertEqual(sequenceable[i].num);
          };
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1650---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1660
     * @tc.name       : test WriteParcelableArray is write data to message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1660", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1660---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let a = [new MySequenceable(1, "aaa"), new MySequenceable(2, "bbb"),
          new MySequenceable(3, "ccc")];
        data.reclaim();
        data.writeParcelableArray(a);
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
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1660---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1670
     * @tc.name       : test ReadParcelableArray is read data from message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1670", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1670---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let a = [new MySequenceable(1, "aaa"), new MySequenceable(2, "bbb"),
          new MySequenceable(3, "ccc")];
        let b = [new MySequenceable(0, ""), new MySequenceable(0, ""), new MySequenceable(0, "")];
        data.writeParcelableArray(a);
        data.reclaim();
        data.readParcelableArray(b);
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
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1670---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1680
     * @tc.name       : test Test MessageSequence to deliver the reply message received in promise across processes
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 0
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1680", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL0, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1680---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
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
          expect(result.reply.readChar()).assertEqual(97);
          expect(result.reply.readString()).assertEqual("HelloWorld");
          let s = new MySequenceable(0,"");
          result.reply.readParcelable(s);
          expect(s.num).assertEqual(1);
          expect(s.str).assertEqual("aaa");
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1680---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1700
     * @tc.name       : test Test the cross process transmission of MessageSequence.After receiving the reply message
     *                  in promise, read letious types of arrays in order
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1700", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1700---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        data.writeByteArray([1, 2, 3]);
        data.writeShortArray([4, 5, 6]);
        data.writeIntArray([7, 8, 9]);
        data.writeLongArray([10, 11, 12]);
        data.writeFloatArray([1.1, 1.2, 1.3]);
        data.writeDoubleArray([2.1, 2.2, 2.3]);
        data.writeBooleanArray([true, true, false]);
        data.writeCharArray([65, 97, 122]);
        data.writeStringArray(["abc", "seggg"]);
        let a = [new MySequenceable(1, "aaa"), new MySequenceable(2, "bbb"),
          new MySequenceable(3, "ccc")]
        data.writeParcelableArray(a);
        await gIRemoteObject.sendMessageRequest(CODE_ALL_ARRAY_TYPE, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          expect(result.reply.readByteArray()).assertDeepEquals([1, 2, 3]);
          expect(result.reply.readShortArray()).assertDeepEquals([4, 5, 6]);
          expect(result.reply.readIntArray()).assertDeepEquals([7, 8, 9]);
          expect(result.reply.readLongArray()).assertDeepEquals([10, 11, 12]);
          expect(result.reply.readFloatArray()).assertDeepEquals([1.1, 1.2, 1.3]);
          expect(result.reply.readDoubleArray()).assertDeepEquals([2.1, 2.2, 2.3]);
          expect(result.reply.readBooleanArray()).assertDeepEquals([true, true, false]);
          expect(result.reply.readCharArray()).assertDeepEquals([65, 97, 122]);
          expect(result.reply.readStringArray()).assertDeepEquals(["abc", "seggg"]);
          let b = [new MySequenceable(0, ""), new MySequenceable(0, ""),
            new MySequenceable(0, "")];
          result.reply.readParcelableArray(b);
          for (let i = 0; i < b.length; i++) {
            expect(b[i].str).assertEqual(a[i].str);
            expect(b[i].num).assertEqual(a[i].num);
          }
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1700---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1710
     * @tc.name       : test Test MessageSequence cross process delivery. After receiving the reply message in promise,
     *                  the client constructs an empty array in sequence and reads the data from the reply message
     *                  into the corresponding array
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1710", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1710---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        data.writeByteArray([1, 2, 3]);
        data.writeShortArray([4, 5, 6]);
        data.writeIntArray([7, 8, 9]);
        data.writeLongArray([10, 11, 12]);
        data.writeFloatArray([1.1, 1.2, 1.3]);
        data.writeDoubleArray([2.1, 2.2, 2.3]);
        data.writeBooleanArray([true, true, false]);
        data.writeCharArray([65, 97, 122]);
        data.writeStringArray(["abc", "seggg"]);
        let a = [new MySequenceable(1, "aaa"), new MySequenceable(2, "bbb"),
          new MySequenceable(3, "ccc")]
        data.writeParcelableArray(a);
        await gIRemoteObject.sendMessageRequest(CODE_ALL_ARRAY_TYPE, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let ByteArray: number[] = new Array();
          result.reply.readByteArray(ByteArray);
          expect(ByteArray).assertDeepEquals([1, 2, 3]);
          let ShortArray: number[] = new Array();
          result.reply.readShortArray(ShortArray);
          expect(ShortArray).assertDeepEquals([4, 5, 6]);
          let IntArray: number[] = new Array();
          result.reply.readIntArray(IntArray);
          expect(IntArray).assertDeepEquals([7, 8, 9]);
          let LongArray: number[] = new Array();
          result.reply.readLongArray(LongArray);
          expect(LongArray).assertDeepEquals([10, 11, 12]);
          let FloatArray: number[] = new Array();
          result.reply.readFloatArray(FloatArray);
          expect(FloatArray).assertDeepEquals([1.1, 1.2, 1.3]);
          let DoubleArray: number[] = new Array();
          result.reply.readDoubleArray(DoubleArray);
          expect(DoubleArray).assertDeepEquals([2.1, 2.2, 2.3]);
          let BooleanArray: boolean[] = new Array();
          result.reply.readBooleanArray(BooleanArray);
          expect(BooleanArray).assertDeepEquals([true, true, false]);
          let CharArray: number[] = new Array();
          result.reply.readCharArray(CharArray);
          expect(CharArray).assertDeepEquals([65, 97, 122]);
          let StringArray: string[] = new Array();
          result.reply.readStringArray(StringArray);
          expect(StringArray).assertDeepEquals(["abc", "seggg"]);
          let b = [new MySequenceable(0, ""), new MySequenceable(0, ""),
            new MySequenceable(0, "")];
          result.reply.readParcelableArray(b);
          for (let i = 0; i < b.length; i++) {
            expect(b[i].str).assertEqual(a[i].str);
            expect(b[i].num).assertEqual(a[i].num);
          }
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1710---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1720
     * @tc.name       : test Call the writeRemoteObjectArray interface, write the array to the MessageSequence instance,
     *                  and call readRemoteObjectArray (datain: string []) to read the data
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1720", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1720---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let listeners = [new TestRemoteObject("rpcListener"), new TestRemoteObject("rpcListener2"), new TestRemoteObject("rpcListener3")];
        data.writeRemoteObjectArray(listeners);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_REMOTEOBJECTARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let rlisteners: Array<rpc.IRemoteObject> = new Array(3);
          result.reply.readRemoteObjectArray(rlisteners);
          for (let index = 0; index < rlisteners.length; index++) {
            expect(rlisteners[index] != null).assertTrue();
            console.info(logTag + " readRemoteObjectArray is success:");
          }
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1720---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1730
     * @tc.name       : test Call the writeremoteobjectarray interface to write the object array to the MessageSequence instance,
     *                  and call readremoteobjectarray to read the data
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1730", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1730---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let listeners = [new TestListener("rpcListener", checkResult),new TestListener("rpcListener2", checkResult),
          new TestListener("rpcListener3", checkResult)];
        data.writeRemoteObjectArray(listeners);
        data.writeInt(123);
        data.writeString("rpcListenerTest");
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_REMOTEOBJECTARRAY_1, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          expect(result.code).assertEqual(CODE_WRITE_REMOTEOBJECTARRAY_1);
          expect(result.data).assertEqual(data);
          expect(result.reply).assertEqual(reply);
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1730---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1740
     * @tc.name       : test Test MessageSequence to pass the array of iremoteobject objects across processes. The server
     *                  constructs an empty array in onremoterequest and reads it from MessageSequence
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1740", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1740---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try {
        let listeners = [new TestListener("rpcListener", checkResult),new TestListener("rpcListener2", checkResult),
          new TestListener("rpcListener3", checkResult)];
        data.writeRemoteObjectArray(listeners);
        data.writeInt(123);
        data.writeString("rpcListenerTest");
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_REMOTEOBJECTARRAY_2, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          result.reply.readException();
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1740---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1750
     * @tc.name       : test WriteRemoteObjectArray is write data to message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1750", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1750---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let listeners = [new TestRemoteObject("rpcListener"), new TestRemoteObject("rpcListener2"), new TestRemoteObject("rpcListener3")];
        data.reclaim();
        data.writeRemoteObjectArray(listeners);
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
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1750---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1760
     * @tc.name       : test ReadRemoteObjectArray is read data from message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1760", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1760---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let listeners = [new TestRemoteObject("rpcListener"), new TestRemoteObject("rpcListener2"), new TestRemoteObject("rpcListener3")];
        data.writeRemoteObjectArray(listeners);
        data.reclaim();
        data.readRemoteObjectArray();
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
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1760---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1770
     * @tc.name       : test the basic function of closeFileDescriptor
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1770", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1770---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let context = AppStorage.get<common.UIAbilityContext>("TestAbilityContext") as common.UIAbilityContext;
      let pathDir = context.filesDir;
      try {
        let filePath = pathDir + "/test1.txt";
        let file = fileIo.openSync(filePath, fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.CREATE);
        expect(data.containFileDescriptors()).assertFalse();
        rpc.MessageSequence.closeFileDescriptor(file.fd);
        expect(data.containFileDescriptors()).assertFalse();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1770---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1780
     * @tc.name       : test the function of the closeFileDescriptor interface
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1780", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1780---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let context = AppStorage.get<common.UIAbilityContext>("TestAbilityContext") as common.UIAbilityContext;
      let pathDir = context.filesDir;
      try {
        let filePath = pathDir + "/test1.txt";
        let file = fileIo.openSync(filePath, fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.CREATE);
        expect(data.containFileDescriptors()).assertFalse();
        data.writeFileDescriptor(file.fd);
        expect(data.containFileDescriptors()).assertTrue();
        rpc.MessageSequence.closeFileDescriptor(file.fd);
        expect(data.containFileDescriptors()).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1780---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1790
     * @tc.name       : test the basic function of dupFileDescriptor
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1790", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1790---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let context = AppStorage.get<common.UIAbilityContext>("TestAbilityContext") as common.UIAbilityContext;
      let pathDir = context.filesDir;
      try {
        let filePath = pathDir + "/test1.txt";
        let file = fileIo.openSync(filePath, fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.CREATE);
        let newdescriptor = rpc.MessageSequence.dupFileDescriptor(file.fd);
        expect(newdescriptor != 0).assertTrue();
        expect(data.containFileDescriptors()).assertFalse();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1790---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1800
     * @tc.name       : test the function of the dupFileDescriptor interface
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1800", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1800---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let context = AppStorage.get<common.UIAbilityContext>("TestAbilityContext") as common.UIAbilityContext;
      let pathDir = context.filesDir;
      try {
        let filePath = pathDir + "/test1.txt";
        let file = fileIo.openSync(filePath, fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.CREATE);
        data.writeFileDescriptor(file.fd);
        expect(data.containFileDescriptors()).assertTrue();
        let newdescriptor = rpc.MessageSequence.dupFileDescriptor(file.fd);
        expect(newdescriptor != 0).assertTrue();
        expect(data.containFileDescriptors()).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1800---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1810
     * @tc.name       : test the basic function of writeFileDescriptor and readFileDescriptor
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1810", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1810---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let context = AppStorage.get<common.UIAbilityContext>("TestAbilityContext") as common.UIAbilityContext;
      let pathDir = context.filesDir;
      try {
        let filePath = pathDir + "/test1.txt";
        let file = fileIo.openSync(filePath, fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.CREATE);
        data.writeFileDescriptor(file.fd);
        expect(data.containFileDescriptors()).assertTrue();
        let rdescrt = data.readFileDescriptor();
        expect(rdescrt != 0).assertTrue();
        expect(data.containFileDescriptors()).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1810---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1820
     * @tc.name       : test the function of the readFileDescriptor interface
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1820", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1820---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let context = AppStorage.get<common.UIAbilityContext>("TestAbilityContext") as common.UIAbilityContext;
      let pathDir = context.filesDir;
      try {
        let filePath = pathDir + "/test1.txt";
        let file = fileIo.openSync(filePath, fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.CREATE);
        data.writeFileDescriptor(file.fd);
        let newdescriptor = rpc.MessageSequence.dupFileDescriptor(file.fd);
        expect(newdescriptor != 0).assertTrue();
        expect(data.containFileDescriptors()).assertTrue();
        let rdescrt = data.readFileDescriptor();
        expect(rdescrt != 0).assertTrue();
        expect(data.containFileDescriptors()).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1820---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1830
     * @tc.name       : test readFileDescriptor reads the null interface descriptor
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1830", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1830---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try {
        let rdescrt = data.readFileDescriptor();
        expect(rdescrt != 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1830---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1840
     * @tc.name       : test readFileDescriptor repeatedly reads the interface descriptor
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1840", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1840---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let context = AppStorage.get<common.UIAbilityContext>("TestAbilityContext") as common.UIAbilityContext;
      let pathDir = context.filesDir;
      try {
        let filePath = pathDir + "/test1.txt";
        let file = fileIo.openSync(filePath, fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.CREATE);
        data.writeFileDescriptor(file.fd);
        expect(data.containFileDescriptors()).assertTrue();
        let rdescrt = data.readFileDescriptor();
        expect(rdescrt != 0).assertTrue();
        let newdescriptor = rpc.MessageSequence.dupFileDescriptor(file.fd);
        expect(newdescriptor != 0).assertTrue();
        let newrdescrt = data.readFileDescriptor();
        expect(newrdescrt != 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1840---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1850
     * @tc.name       : test writeFileDescriptor is write data to message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1850", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1850---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let context = AppStorage.get<common.UIAbilityContext>("TestAbilityContext") as common.UIAbilityContext;
      let pathDir = context.filesDir;
      try {
        let filePath = pathDir + "/test1.txt";
        let file = fileIo.openSync(filePath, fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.CREATE);
        data.reclaim();
        data.writeFileDescriptor(file.fd);
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1850---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1860
     * @tc.name       : test readFileDescriptor is read data from message sequence failed Error verification
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1860", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1860---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let context = AppStorage.get<common.UIAbilityContext>("TestAbilityContext") as common.UIAbilityContext;
      let pathDir = context.filesDir;
      try {
        let filePath = pathDir + "/test1.txt";
        let file = fileIo.openSync(filePath, fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.CREATE);
        data.writeFileDescriptor(file.fd);
        expect(data.containFileDescriptors()).assertTrue();
        data.reclaim();
        let rdescrt = data.readFileDescriptor();
        expect(rdescrt != 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      } finally {
        console.info(logTag + "reclaim done");
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1860---------------------------");
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1870
     * @tc.name       : test the basic function of readFileDescriptor
     * @tc.desc       : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.size       : MediumTest
     * @tc.type       : Compatibility
     * @tc.level      : Level 3
     */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1870", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1870---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      let context = AppStorage.get<common.UIAbilityContext>("TestAbilityContext") as common.UIAbilityContext;
      let pathDir = context.filesDir;
      try {
        let filePath = pathDir + "/test1.txt";
        let file = fileIo.openSync(filePath, fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.CREATE);
        data.writeFileDescriptor(file.fd);
        expect(data.containFileDescriptors()).assertTrue();
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_FILESDIR, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          let rdescrt = result.reply.readFileDescriptor();
          expect(rdescrt != 0).assertTrue();
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      } finally {
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1870---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1880
    * @tc.name    : test Writes the specified anonymous shared object to this MessageSequence
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1880", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1880--------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try{
        let ashmem = rpc.Ashmem.create("ashmem", K);
        data.writeAshmem(ashmem);
        ashmem.unmapAshmem();
        ashmem.closeAshmem();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error == null).assertTrue();
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1880--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1890
    * @tc.name    : test Test the function of serializing the readAshmem interface in MessageSequence mode
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1890", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1890--------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try{
        let ashmem = rpc.Ashmem.create("ashmem", K);
        data.writeAshmem(ashmem);
        let ashmemdata = data.readAshmem();
        expect(ashmemdata != null).assertTrue();
        ashmem.unmapAshmem();
        ashmem.closeAshmem();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1890--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1900
    * @tc.name    : test To test the function of handling the exception of the writeAshmem interface in MessageSequence mode
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1900", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1900--------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try{
        data.writeAshmem(null);
        expect(data.getSize() == 0).assertTrue();
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
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1900--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1910
    * @tc.name    : test WriteAshmem is write data to message sequence failed Error verification
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1910", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1910---------------------------");
      let data = rpc.MessageSequence.create();
      try{
        let ashmem = rpc.Ashmem.create("JsAshmemTest", K);
        data.reclaim();
        data.writeAshmem(ashmem);
        ashmem.unmapAshmem();
        ashmem.closeAshmem();
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1910 ---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1920
    * @tc.name    : test readAshmem is read data from message sequence failed Error verification
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1920", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1920---------------------------");
      let data = rpc.MessageSequence.create();
      try{
        let ashmem = rpc.Ashmem.create("JsAshmemTest", K);
        data.writeAshmem(ashmem);
        data.reclaim();
        data.readAshmem();
        ashmem.unmapAshmem();
        ashmem.closeAshmem();
        expect(data.getSize() == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1920 ---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1930
    * @tc.name    : test Call the getRawDataCapacity interface to get the maximum amount of raw data that a MessageSequence
    *               can hold
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改RPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1930", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1930---------------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      let reply: rpc.MessageSequence = rpc.MessageSequence.create();
      let option: rpc.MessageOption = new rpc.MessageOption();
      try{
        expect(data.getRawDataCapacity()).assertEqual(128 * M);
        data.writeIntArray([1, 2, 3, 4, 5]);
        expect(data.getRawDataCapacity()).assertEqual(128 * M);
        expect(gIRemoteObject != undefined).assertTrue();
        await gIRemoteObject.sendMessageRequest(CODE_WRITE_INTARRAY, data, reply, option).then((result) => {
          expect(result.errCode).assertEqual(0);
          expect(result.reply.getRawDataCapacity()).assertEqual(128 * M);
          expect(result.reply.readIntArray()).assertDeepEquals([1, 2, 3, 4, 5]);
          expect(result.reply.getRawDataCapacity()).assertEqual(128 * M);
        });
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error == null).assertTrue();
      } finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
        reply.reclaim();
      }
      console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1930---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1940
    * @tc.name    : test writeRawDataBuffer input parameter is a normal data less than 32KB
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1940", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1940--------------------");
      let data: rpc.MessageSequence = new rpc.MessageSequence();
      try{
        let TEST_LEN_32K = 32 * K;
        let buffer = new ArrayBuffer(TEST_LEN_32K);
        let size = buffer.byteLength;
        let int32View = new Int32Array(buffer);
        int32View.fill(1);
        data.writeRawDataBuffer(buffer, size);
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1940--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1950
    * @tc.name    : test writeRawDataBuffer input parameter is a normal data greater than 32KB and less than 128MB
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1950", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1950--------------------");
      let data: rpc.MessageSequence = new rpc.MessageSequence();
      try{
        let TEST_LEN_128M = 128 * M;
        let buffer = new ArrayBuffer(TEST_LEN_128M);
        let size = buffer.byteLength;
        let int32View = new Int32Array(buffer);
        int32View.fill(1);
        data.writeRawDataBuffer(buffer, size);
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1950--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1960
    * @tc.name    : test writeRawDataBuffer input parameter is a normal size = 0
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1960", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1960--------------------");
      let data: rpc.MessageSequence = new rpc.MessageSequence();
      try{
        let TEST_LEN_32K = 32 * K;
        let buffer = new ArrayBuffer(TEST_LEN_32K);
        let int32View = new Int32Array(buffer);
        int32View.fill(1);
        let errSize = 0;
        data.writeRawDataBuffer(buffer, errSize);
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
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1960--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1970
    * @tc.name    : test writeRawDataBuffer input parameter is a normal size less than 0
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1970", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1970--------------------");
      let data: rpc.MessageSequence = new rpc.MessageSequence();
      try{
        let TEST_LEN_32K = 32 * K;
        let buffer = new ArrayBuffer(TEST_LEN_32K);
        let int32View = new Int32Array(buffer);
        int32View.fill(1);
        let errSize = -1;
        data.writeRawDataBuffer(buffer, errSize);
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
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1970--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1980
    * @tc.name    : test writeRawDataBuffer input parameter is a normal data greater than 128MB
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1980", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1980--------------------");
      let data: rpc.MessageSequence = new rpc.MessageSequence();
      try{
        let TEST_LEN_128M = 128 * M;
        let buffer = new ArrayBuffer(TEST_LEN_128M + 4);
        let size = buffer.byteLength;
        let int32View = new Int32Array(buffer);
        int32View.fill(1);
        data.writeRawDataBuffer(buffer, size);
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1980--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_1990
    * @tc.name    : test readRawDataBuffer input parameter is a normal data less than 32KB
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_1990", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_1990--------------------");
      let data: rpc.MessageSequence = new rpc.MessageSequence();
      try{
        let TEST_LEN_32K = 32 * K;
        let buffer = new ArrayBuffer(TEST_LEN_32K);
        let size = buffer.byteLength;
        let int32View = new Int32Array(buffer);
        int32View.fill(1);
        data.writeRawDataBuffer(buffer, size);
        let readBuffer = data.readRawDataBuffer(size);
        let readInt32Arr = new Int32Array(readBuffer);
        let assertE = isEqualArrayBuffer(readInt32Arr,int32View);
        expect(assertE).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1990--------------------");
    });

    console.info("-----------------------SUB_DSoftbus_IPC_API_Stage_MessageSequence_Test is end-----------------------");
  })
}