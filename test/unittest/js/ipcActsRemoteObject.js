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
  onRemoteMessageRequest(code: number, data: rpc.MessageSequence,
    reply: rpc.MessageSequence, option: rpc.MessageOption): boolean | Promise<boolean> {
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

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0290
    * @tc.name    : test writeDataToAshmem input parameter is a normal lenth is normal offset greater than create
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0290", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0290---------------------------");
        let TEST_LEN_32 = 32;
        let data = new rpc.MessageSequence();
        let ashmem = rpc.Ashmem.create('ashmem', TEST_LEN_32);
        try {
            ashmem.mapReadWriteAshmem();
            let buffer = new ArrayBuffer(TEST_LEN_32);
            let size = buffer.byteLength;
            let ashnenInt32Arr = new Int32Array(buffer);
            ashmem.writeDataToAshmem(buffer, TEST_LEN_32 + 1, 0);
            data.writeAshmem(ashmem);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0290 error is:" + error);
            expect(error.code == 1900003).assertTrue();
        } finally {
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0290---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0300
    * @tc.name    : test writeDataToAshmem input parameter is a normal lenth greater than create offset is normal
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0300---------------------------");
        let TEST_LEN_32 = 32;
        let data = new rpc.MessageSequence();
        let ashmem = rpc.Ashmem.create('ashmem', TEST_LEN_32);
        try {
            ashmem.mapReadWriteAshmem();
            let buffer = new ArrayBuffer(TEST_LEN_32);
            let size = buffer.byteLength;
            let ashnenInt32Arr = new Int32Array(buffer);
            ashmem.writeDataToAshmem(buffer, size, TEST_LEN_32 + 1);
            data.writeAshmem(ashmem);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0300 error is:" + error);
            expect(error.code == 1900003).assertTrue();
        } finally {
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0300---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0310
    * @tc.name    : test readDataFromAshmem input parameter is a normal lenth greater than create offset is normal
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0310", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0310---------------------------");
        let TEST_LEN_32 = 32;
        let data = new rpc.MessageSequence();
        let ashmem = rpc.Ashmem.create('ashmem', 1024 * 1024);
        try {
            ashmem.mapReadWriteAshmem();
            let buffer = new ArrayBuffer(TEST_LEN_32);
            let size = buffer.byteLength;
            let ashnenInt32Arr = new Int32Array(buffer);
            ashnenInt32Arr.fill(1);
            ashmem.writeDataToAshmem(buffer, size, 0);
            data.writeAshmem(ashmem);
            let readBuffuer = ashmem.readDataFromAshmem(size, 0);
            let readInt32Arr = new Int32Array(readBuffuer);
            expect(readInt32Arr.length == ashnenInt32Arr.length).assertTrue();
            let assertE = isEqualArrayBuffer(readInt32Arr,ashnenInt32Arr);
            expect(assertE).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0310 error is:" + error);
            expect(error== null).assertTrue();
        } finally {
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0310---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0320
    * @tc.name    : test readDataFromAshmem input parameter is a normal lenth is normal create offset is normal
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0320", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0320---------------------------");
        let TEST_LEN_64K = 64 * 1024;
        let data = new rpc.MessageSequence();
        let ashmem = rpc.Ashmem.create('ashmem', TEST_LEN_64K);
        try {
            ashmem.mapReadWriteAshmem();
            let buffer = new ArrayBuffer(TEST_LEN_64K);
            let size = buffer.byteLength;
            let ashnenInt32Arr = new Int32Array(buffer);
            ashnenInt32Arr.fill(1);
            ashmem.writeDataToAshmem(buffer, size, 0);
            data.writeAshmem(ashmem);
            let readBuffuer = ashmem.readDataFromAshmem(size, 0);
            let readInt32Arr = new Int32Array(readBuffuer);
            let assertE = isEqualArrayBuffer(readInt32Arr,ashnenInt32Arr);
            expect(assertE).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0320 error is:" + error);
            expect(error== null).assertTrue();
        } finally {
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0320---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0330
    * @tc.name    : test readDataFromAshmem input parameter is a normal lenth is 0 create offset is normal
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0330", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0330---------------------------");
        let TEST_LEN_64K = 64 * 1024;
        let data = new rpc.MessageSequence();
        let ashmem = rpc.Ashmem.create('ashmem', TEST_LEN_64K);
        try {
            ashmem.mapReadWriteAshmem();
            let buffer = new ArrayBuffer(TEST_LEN_64K);
            let size = buffer.byteLength;
            let ashnenInt32Arr = new Int32Array(buffer);
            ashnenInt32Arr.fill(1);
            ashmem.writeDataToAshmem(buffer, size, 0);
            data.writeAshmem(ashmem);
            let readBuffuer = ashmem.readDataFromAshmem(0, 0);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0330 error is:" + error);
            expect(error.code == 1900004).assertTrue();
        } finally {
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0330---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0340
    * @tc.name    : test readDataFromAshmem input parameter is a normal lenth less than 0 create offset is normal
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0340", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0340---------------------------");
        let TEST_LEN_64K = 64 * 1024;
        let data = new rpc.MessageSequence();
        let ashmem = rpc.Ashmem.create('ashmem', TEST_LEN_64K);
        try {
            ashmem.mapReadWriteAshmem();
            let buffer = new ArrayBuffer(TEST_LEN_64K);
            let size = buffer.byteLength;
            let ashnenInt32Arr = new Int32Array(buffer);
            ashnenInt32Arr.fill(1);
            ashmem.writeDataToAshmem(buffer, size, 0);
            data.writeAshmem(ashmem);
            let readBuffuer = ashmem.readDataFromAshmem(-1, 0);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0340 error is:" + error);
            expect(error.code == 1900004).assertTrue();
        } finally {
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0340---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0350
    * @tc.name    : test readDataFromAshmem input parameter is a normal lenth is normal offset less than 0
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0350", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0350---------------------------");
        let TEST_LEN_64K = 64 * 1024;
        let data = new rpc.MessageSequence();
        let ashmem = rpc.Ashmem.create('ashmem', TEST_LEN_64K);
        try {
            ashmem.mapReadWriteAshmem();
            let buffer = new ArrayBuffer(TEST_LEN_64K);
            let size = buffer.byteLength;
            let ashnenInt32Arr = new Int32Array(buffer);
            ashnenInt32Arr.fill(1);
            ashmem.writeDataToAshmem(buffer, size, 0);
            data.writeAshmem(ashmem);
            let readBuffuer = ashmem.readDataFromAshmem(size, -1);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0350 error is:" + error);
            expect(error.code == 1900004).assertTrue();
        } finally {
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0350---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0360
    * @tc.name    : test readDataFromAshmem input parameter is a normal lenth is normal offset greater than create
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0360", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0360---------------------------");
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
            let readBuffuer = ashmem.readDataFromAshmem(size, TEST_LEN_32 + 1);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0360 error is:" + error);
            expect(error.code == 1900004).assertTrue();
        } finally {
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0360---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0370
    * @tc.name    : test readDataFromAshmem input parameter is a normal lenth greater than create offset is normal
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0370", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0370---------------------------");
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
            let readBuffuer = ashmem.readDataFromAshmem(TEST_LEN_32 + 1, 0)
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0370 error is:" + error);
            expect(error.code == 1900004).assertTrue();
        } finally {
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0370---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Stage_Ashmem_0380
    * @tc.name    : test readDataFromAshmem input parameter is a normal lenth and offset greater than create
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Stage_Ashmem_0380", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async () => {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Stage_Ashmem_0380---------------------------");
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
            let readBuffuer = ashmem.readDataFromAshmem(TEST_LEN_32 + 1, 1);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Stage_Ashmem_0380 error is:" + error);
            expect(error.code == 1900004).assertTrue();
        } finally {
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Stage_Ashmem_0380---------------------------");
    });
    console.info("-----------------------SUB_DSoftbus_IPC_API_Stage_MessageSequence_Test is end-----------------------");
  })
}
