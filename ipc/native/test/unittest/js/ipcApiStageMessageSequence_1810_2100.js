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
        expect(readInt32Arr.length == int32View.length).assertTrue();
        for (let i = 0; i < readInt32Arr.length; i++) {
          expect(readInt32Arr[i]).assertEqual(int32View[i]);
        }
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_1990--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_2000
    * @tc.name    : test readRawDataBuffer input parameter is a normal data less than 128MB
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2000", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_2000--------------------");
      let data: rpc.MessageSequence = new rpc.MessageSequence();
      try{
        let TEST_LEN_64K = 64 * K;
        let buffer = new ArrayBuffer(TEST_LEN_64K + 4);
        let size = buffer.byteLength;
        let int32View = new Int32Array(buffer);
        int32View.fill(1);
        data.writeRawDataBuffer(buffer, size);
        let readBuffer = data.readRawDataBuffer(size);
        let readInt32Arr = new Int32Array(readBuffer);
        let assertE: boolean =  JSON.stringify(readInt32Arr) === JSON.stringify(int32View) &&
          readInt32Arr.length === int32View.length;
        expect(assertE).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_2000--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_2010
    * @tc.name    : test readRawDataBuffer input parameter is a normal data greater than 128MB
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2010", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_2010--------------------");
      let data: rpc.MessageSequence = new rpc.MessageSequence();
      try{
        let TEST_LEN_128M = 128 * M;
        let buffer = new ArrayBuffer(TEST_LEN_128M);
        let size = buffer.byteLength;
        let int32View = new Int32Array(buffer);
        int32View.fill(1);
        data.writeRawDataBuffer(buffer, size);
        data.readRawDataBuffer(TEST_LEN_128M + 1);
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_2010--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_2020
    * @tc.name    : test readRawDataBuffer input parameter is a normal size = 0
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2020", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_2020--------------------");
      let data: rpc.MessageSequence = new rpc.MessageSequence();
      try{
        let TEST_LEN_32K = 32 * K;
        let buffer = new ArrayBuffer(TEST_LEN_32K);
        let size = buffer.byteLength;
        let int32View = new Int32Array(buffer);
        int32View.fill(1);
        data.writeRawDataBuffer(buffer, size);
        let readBuffer = data.readRawDataBuffer(0);
        let readInt32Arr = new Int32Array(readBuffer);
        expect(readInt32Arr.length == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_2020--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_2030
    * @tc.name    : test readRawDataBuffer input parameter is a normal size less than 0
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2030", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_2030--------------------");
      let data: rpc.MessageSequence = new rpc.MessageSequence();
      try{
        let TEST_LEN_32K = 32 * K;
        let buffer = new ArrayBuffer(TEST_LEN_32K);
        let size = buffer.byteLength;
        let int32View = new Int32Array(buffer);
        int32View.fill(1);
        data.writeRawDataBuffer(buffer, size);
        let readBuffer = data.readRawDataBuffer(-1);
        let readInt32Arr = new Int32Array(readBuffer);
        expect(readInt32Arr.length == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error).assertEqual(null);
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_2030--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_2040
    * @tc.name    : test readRawDataBuffer input parameter is a normal size not match write
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2040", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_2040--------------------");
      let data: rpc.MessageSequence = new rpc.MessageSequence();
      try{
        let TEST_LEN_32K = 32 * K;
        let buffer = new ArrayBuffer(TEST_LEN_32K);
        let size = buffer.byteLength;
        let int32View = new Int32Array(buffer);
        int32View.fill(1);
        data.writeRawDataBuffer(buffer, size);
        let readBuffer = data.readRawDataBuffer(TEST_LEN_32K - 1);
        let readInt32Arr = new Int32Array(readBuffer);
        expect(readInt32Arr.length == 0).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        let e: BusinessError = error as BusinessError;
        let errCode: string = `${rpc.ErrorCode.READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR}`;
        expect(e.code).assertEqual(errCode);
        expect(e.message != null).assertTrue();
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_2040--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_2050
    * @tc.name    : test Test MessageSequence write and read ArrayBuffer int8array
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2050", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_2050--------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try{
        let buffer = new ArrayBuffer(5);
        let int8View = new Int8Array(buffer);
        for (let i = 0; i < int8View.length; i++) {
          int8View[i] = i + 1;
        };
        console.info("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2050 int8View is:" + int8View);
        data.writeArrayBuffer(buffer, rpc.TypeCode.INT8_ARRAY);
        let arrayBuffer = data.readArrayBuffer(rpc.TypeCode.INT8_ARRAY);
        let int8Array = new Int8Array(arrayBuffer);
        console.info("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2050 int8Array is:" + int8Array);

      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error == null).assertTrue();
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_2050--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_2060
    * @tc.name    : test Test MessageSequence write and read ArrayBuffer uint8array
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2060", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_2060--------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try{
        let buffer = new ArrayBuffer(12);
        let uInt8View = new Uint8Array(buffer);
        for (let i = 0; i < uInt8View.length; i++) {
          uInt8View[i] = i + 10;
        };
        data.writeArrayBuffer(buffer, rpc.TypeCode.UINT8_ARRAY);
        let arrayBuffer = data.readArrayBuffer(rpc.TypeCode.UINT8_ARRAY);
        let uInt8Array = new Uint8Array(arrayBuffer);
        let assertE: boolean = uInt8View.length === uInt8Array.length && JSON.stringify(uInt8View) === JSON.stringify(uInt8Array);
        expect(assertE).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error == null).assertTrue();
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_2060--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_2070
    * @tc.name    : test Test MessageSequence write and read ArrayBuffer uint8array
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2070", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_2070--------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try{
        let buffer = new ArrayBuffer(10);
        let int16View = new Int16Array(buffer);
        for (let i = 0; i < int16View.length; i++) {
          int16View[i] = i + 20;
        };
        data.writeArrayBuffer(buffer, rpc.TypeCode.INT16_ARRAY);
        let arrayBuffer = data.readArrayBuffer(rpc.TypeCode.INT16_ARRAY);
        let int16Array = new Int16Array(arrayBuffer);
        let assertE: boolean = int16View.length === int16Array.length && JSON.stringify(int16View) === JSON.stringify(int16Array);
        expect(assertE).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error == null).assertTrue();
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_2070--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_2080
    * @tc.name    : test Test MessageSequence write and read ArrayBuffer uint16array
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2080", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_2080--------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try{
        let buffer = new ArrayBuffer(12);
        let uInt16View = new Uint16Array(buffer);
        for (let i = 0; i < uInt16View.length; i++) {
          uInt16View[i] = i + 20;
        };
        data.writeArrayBuffer(buffer, rpc.TypeCode.UINT16_ARRAY);
        let arrayBuffer = data.readArrayBuffer(rpc.TypeCode.UINT16_ARRAY);
        let uInt16Array = new Uint16Array(arrayBuffer);
        let assertE: boolean = uInt16View.length === uInt16Array.length && JSON.stringify(uInt16View) === JSON.stringify(uInt16Array);
        expect(assertE).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error == null).assertTrue();
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_2080--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_2090
    * @tc.name    : test Test MessageSequence write and read ArrayBuffer int32array
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2090", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_2090--------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try{
        let buffer = new ArrayBuffer(20);
        let int32View = new Int32Array(buffer);
        for (let i = 0; i < int32View.length; i++) {
          int32View[i] = 2 * i + 1;
        };
        data.writeArrayBuffer(buffer, rpc.TypeCode.INT32_ARRAY);
        let arrayBuffer = data.readArrayBuffer(rpc.TypeCode.INT32_ARRAY);
        let int32Array = new Int32Array(arrayBuffer);
        let assertE: boolean = int32View.length === int32Array.length && JSON.stringify(int32View) === JSON.stringify(int32Array);
        expect(assertE).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error == null).assertTrue();
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_2090--------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_MessageSequence_2100
    * @tc.name    : test Test MessageSequence write and read ArrayBuffer uint32array
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_MessageSequence_2100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
      console.info("--------------------start SUB_DSoftbus_IPC_API_Stage_MessageSequence_2100--------------------");
      let data: rpc.MessageSequence = rpc.MessageSequence.create();
      try{
        let buffer = new ArrayBuffer(12);
        let uInt32View = new Uint32Array(buffer);
        for (let i = 0; i < uInt32View.length; i++) {
          uInt32View[i] = i + 30;
        };
        data.writeArrayBuffer(buffer, rpc.TypeCode.UINT32_ARRAY);
        let arrayBuffer = data.readArrayBuffer(rpc.TypeCode.UINT32_ARRAY);
        let uInt32Array = new Uint32Array(arrayBuffer);
        let assertE: boolean = uInt32View.length === uInt32Array.length && JSON.stringify(uInt32View) === JSON.stringify(uInt32Array);
        expect(assertE).assertTrue();
      } catch (error) {
        console.info(logTag + "SUB_DSoftbus_IPC_API_Stage_MessageSequence_testcase error is:" + error);
        expect(error == null).assertTrue();
      }finally{
        console.info(logTag + "reclaim done");
        data.reclaim();
      }
      console.info("--------------------end SUB_DSoftbus_IPC_API_Stage_MessageSequence_2100--------------------");
    });
    console.info("-----------------------SUB_DSoftbus_IPC_API_Stage_MessageSequence_Test 1810 to 2100 is end-----------------------");
})
}