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
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1540
    * @tc.name    : test MessageParcel sendMessageRequest API test
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1540", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1540---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            let Capacity = data.getRawDataCapacity()
            let rawdata = [1, 2, 3];
            let option = new rpc.MessageOption();
            var reply = rpc.MessageSequence.create();
            data.writeInt(rawdata.length);
            data.writeRawData(rawdata, rawdata.length);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_RAWDATA, data, reply, option).then((result) => {
                expect(result.errCode == 0).assertTrue();
                let size = result.reply.readInt();
                let newReadResult = result.reply.readRawData(size);
                expect(newReadResult != rawdata).assertTrue();
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1540---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1550
    * @tc.name    : test Invoke the writestring interface to write data to the messageparcel instance SendRequest Asynchronous
    *               Authentication onRemoteMessageRequest Server Processing
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1550", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1550---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            var reply = rpc.MessageParcel.create();
            let option = new rpc.MessageOption();
            let token = 'onRemoteMessageRequest invoking';
            let result = data.writeString(token);
            expect(result == true).assertTrue();
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
                var replyReadResult = result.reply.readString();
                expect(replyReadResult).assertEqual(token);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1550---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1560
    * @tc.name    : test Invoke the writestring interface to write data to the messageparcel instance sendMessageRequest Asynchronous
    *               Authentication onRemoteMessageRequest Server Processing
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1560", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1560---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let token = 'onRemoteMessageRequest invoking';
            data.writeString(token);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                var replyReadResult = result.reply.readString();
                expect(replyReadResult).assertEqual(token);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1560---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1570
    * @tc.name    : test Invoke the writestring interface to write data to the messageparcel instance. SendRequest asynchronously
    *               verifies the priority processing levels of onRemoteMessageRequest and onRemoteRequest
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1570", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1570---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            var reply = rpc.MessageParcel.create();
            let option = new rpc.MessageOption();
            let token = "onRemoteRequest or onRemoteMessageRequest invoking";
            let result = data.writeString(token);
            expect(result == true).assertTrue();
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendRequest(CODE_ONREMOTEMESSAGE_OR_ONREMOTE, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                var replyReadResult = result.reply.readString();
                expect(replyReadResult).assertEqual("onRemoteMessageRequest invoking");
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1570---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1580
    * @tc.name   Invoke the writestring interface to write data to the messageparcel instance. sendMessageRequest asynchronously verifies
    *               the priority processing levels of onRemoteMessageRequest and onRemoteRequest
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1580", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1580---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            let token = 'onRemoteRequest or onRemoteMessageRequest invoking';
            data.writeString(token);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_ONREMOTEMESSAGE_OR_ONREMOTE, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                var replyReadResult = result.reply.readString();
                expect(replyReadResult).assertEqual("onRemoteMessageRequest invoking");
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1580---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1590
    * @tc.name    : test Call the 401 interface to set the writeString of MessageSequence
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1590", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1590---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            let token = '';
            for (let i = 0; i < 40 * K; i++) {
                token += 'a';
            };
            let result = data.writeString(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            let errCode = `${rpc.ErrorCode.CHECK_PARAM_ERROR}`;
            expect(error.code == errCode).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1590---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1600
    * @tc.name    : test Call the 1900011 interface, write the interface descriptor, and read interfacetoken
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1600---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            data.setSize(0);
            data.setCapacity(0);
            let token = "hello ruan zong xian";
            data.writeInterfaceToken(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error.code == 1900011).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1600---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1610
    * @tc.name    : test Call the 1900009 interface, write the interface descriptor, and read interfacetoken
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1610", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1610---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            data.setSize(true);
            data.setCapacity(true);
            let token = "hello ruan zong xian";
            data.writeInterfaceToken(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            let errCode = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
            expect(error.code != errCode).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1610---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1620
    * @tc.name    : test Call the setcapacity interface to set the capacity of messageparcel
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1620", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1620---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            let sequenceable = new MySequenceable(1, "aaa");
            data.writeParcelable(sequenceable);
            let ret = new MySequenceable(0, "");
            data.setCapacity(0);
            data.readParcelable(ret);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            let errCode = `${rpc.ErrorCode.PARCEL_MEMORY_ALLOC_ERROR}`;
            expect(error.code == errCode).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1620---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1630
    * @tc.name    : test Call the 1900008 interface to serialize the remote object and pass in the empty object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3   
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1630", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1630---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            console.info("SUB_DSoftbus_IPC_API_MessageParcel_1630: create object successfully.");
            let token = {}
            data.writeRemoteObject(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error.code == 1900008).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1630---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1640
    * @tc.name    : test Call the writeparcelable 1900012 interface to write the custom serialized
    *             object to the MessageSequence instance
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1640", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1640---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            let sequenceable = new MySequenceable(1, "aaa");
            data.writeParcelable(sequenceable);
            data.setCapacity(0);
            data.setSize(0);
            let ret = new MySequenceable(1, "");
            data.readParcelable(ret);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            let errCode = `${rpc.ErrorCode.CALL_JS_METHOD_ERROR}`;
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1640---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1650
    * @tc.name    : test Call the writeinterfacetoken interface, write the interface descriptor, and read interfacetoken
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1650", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1650---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            let token = "hello ruan zong xian";
            data.writeInterfaceToken(token);
            data.setCapacity(0);
            data.setSize(0);
            data.readInterfaceToken();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            let errCode = `${rpc.ErrorCode.READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR}`;
            expect(error.message != null).assertTrue();
            expect(error.code != errCode).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1650---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1660
    * @tc.name    : test Test 1900013 messageparcel delivery file descriptor object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1660", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1660---------------------------");
        try {
            let filePath = "path/to/file";
            let fd = fileio.openSync(filePath, null);
            rpc.MessageSequence.dupFileDescriptor(fd);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            let errCode = `${rpc.ErrorCode.OS_DUP_ERROR}`;
            expect(error.code != errCode).assertTrue();
            expect(error.message != null).assertTrue();
        }
        done();
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1660---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1670
    * @tc.name    : test The readRemoteObjectArray interface directly reads parameters
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1670", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1670---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let listeners = [new TestRemoteObject("rpcListener"),
            new TestRemoteObject("rpcListener2"),
            new TestRemoteObject("rpcListener3")];
            let result = data.writeRemoteObjectArray(listeners);
            expect(result == true).assertTrue();
            let rlisteners = data.readRemoteObjectArray();
            expect(rlisteners != null).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1670---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1680
    * @tc.name    : test The readRemoteObjectArray interface reads parameters to an empty array
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1680", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1680---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let listeners = [new TestRemoteObject("rpcListener"),
            new TestRemoteObject("rpcListener2"),
            new TestRemoteObject("rpcListener3")];
            let result = data.writeRemoteObjectArray(listeners);
            expect(result == true).assertTrue();
            let rlisteners = new Array(3);
            data.readRemoteObjectArray(rlisteners);
            expect(rlisteners != null).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1680---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1670
    * @tc.name    : test The readRemoteObjectArray interface directly reads parameters
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1670", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1670---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let listeners = [new TestRemoteObject("rpcListener"),
            new TestRemoteObject("rpcListener2"),
            new TestRemoteObject("rpcListener3")];
            let result = data.writeRemoteObjectArray(listeners);
            expect(result == true).assertTrue();
            let rlisteners = data.readRemoteObjectArray();
            expect(rlisteners != null).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1670---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageParcel_1680
    * @tc.name    : test The readRemoteObjectArray interface reads parameters to an empty array
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageParcel_1680", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageParcel_1680---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            let listeners = [new TestRemoteObject("rpcListener"),
            new TestRemoteObject("rpcListener2"),
            new TestRemoteObject("rpcListener3")];
            let result = data.writeRemoteObjectArray(listeners);
            expect(result == true).assertTrue();
            let rlisteners = new Array(3);
            data.readRemoteObjectArray(rlisteners);
            expect(rlisteners != null).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageParcel error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageParcel_1680---------------------------");
    });        

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0010
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0010", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0010---------------------------");
        try {
            let option = new rpc.MessageOption();
            let time = option.getWaitTime();
            expect(time).assertEqual(rpc.MessageOption.TF_WAIT_TIME);
            option.setWaitTime(16);
            let time2 = option.getWaitTime();
            expect(time2).assertEqual(16);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0010---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0020
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0020", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0020---------------------------");
        try {
            let option = new rpc.MessageOption();
            let time = option.getWaitTime();
            expect(time).assertEqual(rpc.MessageOption.TF_WAIT_TIME);
            option.setWaitTime(0);
            let time2 = option.getWaitTime();
            expect(time2).assertEqual(rpc.MessageOption.TF_WAIT_TIME);
            option.setWaitTime(60);
            let time3 = option.getWaitTime();
            expect(time3).assertEqual(60);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0020---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0030
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0030", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0030---------------------------");
        try {
            let option = new rpc.MessageOption();
            let time = option.getWaitTime();
            expect(time).assertEqual(rpc.MessageOption.TF_WAIT_TIME);
            option.setWaitTime(-1);
            let time2 = option.getWaitTime();
            expect(time2).assertEqual(rpc.MessageOption.TF_WAIT_TIME);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0030---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0040
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0040", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0040---------------------------");
        try {
            let option = new rpc.MessageOption();
            let time = option.getWaitTime();
            expect(time).assertEqual(rpc.MessageOption.TF_WAIT_TIME);
            option.setWaitTime(61);
            let time2 = option.getWaitTime();
            expect(time2).assertEqual(61);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0040---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0050
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0050", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0050---------------------------");
        try {
            let option = new rpc.MessageOption();
            let flog = option.getFlags();
            expect(flog).assertEqual(rpc.MessageOption.TF_SYNC);
            option.setFlags(1);
            let flog2 = option.getFlags();
            expect(flog2).assertEqual(rpc.MessageOption.TF_ASYNC);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0050---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0060
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0060", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0060---------------------------");
        try {
            let option = new rpc.MessageOption();
            let flog = option.getFlags();
            expect(flog).assertEqual(rpc.MessageOption.TF_SYNC);
            option.setFlags(1);
            let flog2 = option.getFlags();
            expect(flog2).assertEqual(rpc.MessageOption.TF_ASYNC);
            option.setFlags(0);
            let flog3 = option.getFlags();
            expect(flog3).assertEqual(rpc.MessageOption.TF_ASYNC);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0060---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0070
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0070", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0070---------------------------");
        try {
            let option = new rpc.MessageOption();
            let flog = option.getFlags();
            expect(flog).assertEqual(rpc.MessageOption.TF_SYNC);
            option.setFlags(-1);
            let flog2 = option.getFlags();
            expect(flog2).assertEqual(-1);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0070---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0080
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0080", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0080---------------------------");
        try {
            let option = new rpc.MessageOption();
            let flog = option.getFlags();
            expect(flog).assertEqual(rpc.MessageOption.TF_SYNC);
            option.setFlags(3);
            let flog2 = option.getFlags();
            expect(flog2).assertEqual(3);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0080---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0090
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0090", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0090---------------------------");
        try {
            expect(rpc.MessageOption.TF_SYNC).assertEqual(0);
            expect(rpc.MessageOption.TF_ASYNC).assertEqual(1);
            expect(rpc.MessageOption.TF_WAIT_TIME).assertEqual(8);
            expect(rpc.MessageOption.TF_ACCEPT_FDS).assertEqual(0x10);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0090---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0100
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0100---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            var reply = rpc.MessageParcel.create();
            let option = new rpc.MessageOption();
            option.setWaitTime(20);
            option.setFlags(0);
            let token = "option";
            let result = data.writeString(token);
            expect(result).assertTrue();
            expect(option.getFlags()).assertEqual(0);
            expect(option.getWaitTime()).assertEqual(20);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
                let replyReadResult = result.reply.readString();
                expect(replyReadResult).assertEqual(token);
                expect(option.getFlags()).assertEqual(0);
                expect(option.getWaitTime()).assertEqual(20);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0100---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0110
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0110", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0110---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            var reply = rpc.MessageParcel.create();
            let option = new rpc.MessageOption();
            option.setFlags(1);
            let token = "option";
            let result = data.writeString(token);
            expect(result).assertTrue();
            expect(option.getFlags()).assertEqual(1);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
                let replyReadResult = result.reply.readString();
                expect(replyReadResult).assertEqual("option");
                expect(option.getFlags()).assertEqual(1);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0110---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0120
    * @tc.name    : test Basic method of testing messageoption
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0120", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0120---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            var reply = rpc.MessageParcel.create();
            let option = new rpc.MessageOption();
            option.setFlags(3);
            let token = "option";
            let result = data.writeString(token);
            expect(result).assertTrue();
            expect(option.getFlags()).assertEqual(3);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
                let replyReadResult = result.reply.readString();
                expect(replyReadResult).assertEqual("option");
                expect(option.getFlags()).assertEqual(3);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0120---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0130
    * @tc.name    : test MessageOption sendMessageRequest test
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0130", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0130---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            option.setFlags(1);
            let token = "option";
            data.writeString(token);
            expect(option.getFlags()).assertEqual(1);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
                let replyReadResult = result.reply.readString();
                expect(replyReadResult).assertEqual("option");
                expect(option.getFlags()).assertEqual(1);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0130---------------------------");
    })

    /*
        * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0140
        * @tc.name    : test MessageOption sendMessageRequest test
        * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level   : Level 1
        * @tc.type    : Compatibility
        * @tc.size    : MediumTest
        */
    it("SUB_DSoftbus_IPC_API_MessageOption_0140", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0140---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
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
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0140---------------------------");
    })

    /*
        * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0150
        * @tc.name    : test MessageOption setAsync is true test
        * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level   : Level 1
        * @tc.type    : Compatibility
        * @tc.size    : MediumTest
        */
    it("SUB_DSoftbus_IPC_API_MessageOption_0150", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0150---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            option.setAsync(true);
            let token = "option";
            data.writeString(token);
            expect(gIRemoteObject != undefined).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                let isAsyncData = option.isAsync();
                expect(isAsyncData).assertTrue();
                let replyReadResult = result.reply.readString();
                expect(replyReadResult).assertEqual("option");
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0150---------------------------");
    })


    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0160
    * @tc.name    : test setAsync is false sendMessageRequest test
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0160", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0160---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
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
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0160---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_MessageOption_0170
    * @tc.name    : test setAsync sendMessageRequest test
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_MessageOption_0170", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_MessageOption_0170---------------------------");
        try {
            let option = new rpc.MessageOption();
            option.setAsync(3);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageOption error is:" + error);
            expect(error != null).assertTrue();
        } finally {
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_MessageOption_0170---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0010
    * @tc.name    : test Exception parameter validation of the created anonymous shared memory object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0010", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0010---------------------------");
        try {
            let ashmem = rpc.Ashmem.createAshmem("JsAshmemTest", -1);
            console.info("SUB_DSoftbus_IPC_API_Ashmem_0010: ashmem " + ashmem);
            let ashmem2 = rpc.Ashmem.createAshmem(null, K);
            console.info("SUB_DSoftbus_IPC_API_Ashmem_0010: ashmem2 " + ashmem2);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0010---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0020
    * @tc.name    : test Call the getashmemsize interface to get the size of the shared memory object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0020", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0020---------------------------");
        try {
            let mapSize = 2 * G - 1;
            let jsash = "";
            for (let i = 0; i < (256 - 1); i++) {
                jsash += "a";
            };
            let ashmem = rpc.Ashmem.createAshmem(jsash, mapSize);
            expect(ashmem != null).assertTrue();
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0020---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0030
    * @tc.name    : test Call the getashmemsize interface to get the size of the shared memory object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0030", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0030---------------------------");
        try {
            let mapSize = 2 * G - 1;
            let jsash = '';
            for (let i = 0; i < 256; i++) {
                jsash += 'a';
            }
            let ashmem = rpc.Ashmem.createAshmem(jsash, mapSize);
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0030---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0040
    * @tc.name    : test Call the getashmemsize interface to get the size of the shared memory object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0040", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0040---------------------------");
        try {
            let mapSize = 2 * G - 1;
            let ashmem = rpc.Ashmem.createAshmem("JsAshmemTest", mapSize);
            let size = ashmem.getAshmemSize();
            expect(size).assertEqual(mapSize);
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0040---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0050
    * @tc.name    : test Call the getashmemsize interface to get the size of the shared memory object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0050", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0050---------------------------");
        try {
            let mapSize = 2 * G;
            let ashmem = rpc.Ashmem.createAshmem("JsAshmemTest ", mapSize);
            ashmem.getAshmemSize();
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0050---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0060
    * @tc.name    : test Writeashmem exception validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0060", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0060---------------------------");
        try {
            let ashmem = rpc.Ashmem.createAshmem("JsAshmemTest", 4096);
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
            var data = rpc.MessageParcel.create();
            let writeAshmem = data.writeAshmem(ashmem);
            expect(writeAshmem).assertEqual(false);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0060---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0070
    * @tc.name    : test Readfromashmem exception validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0070", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0070---------------------------");
        try {
            let ashmem = rpc.Ashmem.createAshmem("JsAshmemTest", 4096);
            ashmem.unmapAshmem();
            let bytes = [1, 2, 3, 4, 5];
            let ret = ashmem.readFromAshmem(bytes.length, 0);
            expect(ret == null).assertTrue();
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0070---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0080
    * @tc.name    : test Mapashmem interface creates shared file mappings
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0080", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0080---------------------------");
        try {
            let ashmem = rpc.Ashmem.createAshmem("JsAshmemTest", 4096);
            let result = ashmem.mapAshmem(rpc.Ashmem.PROT_READ);
            expect(result).assertTrue();
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0080---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0090
    * @tc.name    : test Mapashmem exception validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0090", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0090---------------------------");
        try {
            let ashmem = rpc.Ashmem.createAshmem("JsAshmemTest", (2 * G - 1))
            let result = ashmem.mapAshmem(999);
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0090---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0100
    * @tc.name    : test Mapreadandwriteashmem interface creates a shared file map with the protection level of read-write
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0100---------------------------");
        try {
            let ashmem = rpc.Ashmem.createAshmem("JsAshmemTest", K);
            let result = ashmem.mapReadAndWriteAshmem();
            expect(result).assertTrue();
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0100---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0110
    * @tc.name    : test Mapreadandwriteashmem exception validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0110", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0110---------------------------");
        try {
            let ashmem = rpc.Ashmem.createAshmem("JsAshmemTest", 4096);
            let result = ashmem.mapAshmem(rpc.Ashmem.PROT_READ);
            expect(result).assertTrue();
            ashmem.unmapAshmem();
            let result2 = ashmem.mapReadAndWriteAshmem();
            expect(result2).assertTrue();
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0110---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0120
    * @tc.name    : test Mapreadonlyashmem interface creates a shared file map with the protection level of read-write
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0120", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0120---------------------------");
        try {
            let ashmem = rpc.Ashmem.createAshmem("JsAshmemTest", 4096);
            let result = ashmem.mapReadOnlyAshmem();
            expect(result).assertTrue();
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0120---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0130
    * @tc.name    : test Mapreadonlyashmem exception validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0130", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0130---------------------------");
        try {
            let ashmem = rpc.Ashmem.createAshmem("JsAshmemTest", K);
            let result = ashmem.mapAshmem(rpc.Ashmem.PROT_WRITE);
            expect(result).assertTrue();
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
            let result2 = ashmem.mapReadOnlyAshmem();
            expect(result2).assertEqual(false);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0130---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0140
    * @tc.name    : test Mapreadonlyashmem exception validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0140", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0140---------------------------");
        try {
            let ashmem = rpc.Ashmem.createAshmem("JsAshmemTest", K);
            let resultwrite = ashmem.setProtection(rpc.Ashmem.PROT_WRITE);
            expect(resultwrite).assertTrue();
            let resultread = ashmem.setProtection(rpc.Ashmem.PROT_READ);
            expect(resultread).assertEqual(false);
            let resultreadAndwrite = ashmem.mapReadAndWriteAshmem();
            expect(resultreadAndwrite).assertEqual(false);
            let resultnone = ashmem.setProtection(rpc.Ashmem.PROT_NONE);
            expect(resultnone).assertTrue();
            let resultread2 = ashmem.setProtection(rpc.Ashmem.PROT_READ);
            expect(resultread2).assertEqual(false);
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0140---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0150
    * @tc.name    : test Setprotection exception input parameter verification
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0150", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0150---------------------------");
        try {
            let ashmem = rpc.Ashmem.createAshmem("JsAshmemTest", K);
            let result = ashmem.setProtection(3);
            expect(result).assertTrue();
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0150---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0160
    * @tc.name    : test The writetoashmem interface writes the shared file associated with the object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0160", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0160---------------------------");
        try {
            let mapSize = 4096;
            let ashmem = rpc.Ashmem.createAshmem("JsAshmemTest", mapSize);
            let resultMapRAndW = ashmem.mapReadAndWriteAshmem();
            expect(resultMapRAndW).assertTrue();
            let bytes = [1, 2, 3, 4, 5];
            let result = ashmem.writeToAshmem(bytes, bytes.length, 0);
            expect(result).assertTrue();
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0160---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0170
    * @tc.name    : test The writetoashmem interface writes the shared file associated with the object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0170", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0170---------------------------");
        try {
            let mapSize = 4096;
            let ashmem = rpc.Ashmem.createAshmem("JsAshmemTest", mapSize);
            let resultMapRAndW = ashmem.mapReadAndWriteAshmem();
            expect(resultMapRAndW).assertTrue();
            let bytes = [-2147483648, 2147483647];
            let result = ashmem.writeToAshmem(bytes, bytes.length, 0);
            expect(result).assertTrue();
            let reresult = ashmem.readFromAshmem(bytes.length, 0);
            for (let i = 0; i < reresult.length; i++) {
                expect(reresult[i]).assertEqual(bytes[i]);
            }
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0170---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0180
    * @tc.name    : test The writetoashmem interface writes the shared file associated with the object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0180", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0180---------------------------");
        try {
            let mapSize = 4096;
            let ashmem = rpc.Ashmem.createAshmem("JsAshmemTest", mapSize);
            let resultMapRAndW = ashmem.mapReadAndWriteAshmem();
            expect(resultMapRAndW).assertTrue();
            let bytes = [-2147483649, 2147483647];
            let result = ashmem.writeToAshmem(bytes, bytes.length, 0);
            expect(result).assertTrue();
            let readresult = ashmem.readFromAshmem(bytes.length, 0);
            expect(readresult[0]).assertEqual(2147483647);
            expect(readresult[1]).assertEqual(bytes[1]);
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0180---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0190
    * @tc.name    : test The writetoashmem interface writes the shared file associated with the object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0190", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0190---------------------------");
        try {
            let mapSize = 4096;
            let ashmem = rpc.Ashmem.createAshmem("JsAshmemTest", mapSize);
            let resultMapRAndW = ashmem.mapReadAndWriteAshmem();
            expect(resultMapRAndW).assertTrue();
            let bytes = [-2147483648, 2147483648];
            let result = ashmem.writeToAshmem(bytes, bytes.length, 0);
            expect(result).assertTrue();
            let reresult = ashmem.readFromAshmem(bytes.length, 0);
            expect(reresult[0]).assertEqual(bytes[0]);
            expect(reresult[1]).assertEqual(-2147483648);
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0190---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0200
    * @tc.name    : test The writetoashmem interface writes the shared file associated with the object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0200---------------------------");
        try {
            let mapSize = 2 * M;
            let ashmem = rpc.Ashmem.createAshmem("JsAshmemTest", mapSize);
            let resultMapRAndW = ashmem.mapReadAndWriteAshmem();
            expect(resultMapRAndW).assertTrue();
            let bytes = [0, 1];
            let result = ashmem.writeToAshmem(bytes, bytes.length, 2147483647 / 4);
            expect(result).assertEqual(false);
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0200---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0210
    * @tc.name    : test The writetoashmem interface writes the shared file associated with the object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0210", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0210---------------------------");
        try {
            let mapSize = 2 * M;
            let ashmem = rpc.Ashmem.createAshmem("JsAshmemTest", mapSize);
            let resultMapRAndW = ashmem.mapReadAndWriteAshmem();
            expect(resultMapRAndW).assertTrue();
            let bytes = [0, 1];
            let result = ashmem.writeToAshmem(bytes, bytes.length, 2147483648 / 4);
            expect(result).assertEqual(false);
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0210---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0220
    * @tc.name    : test The writetoashmem interface writes the shared file associated with the object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0220", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0220---------------------------");
        try {
            let ashmem = rpc.Ashmem.createAshmem("JsAshmemTest", 4096);
            let resultMapRAndW = ashmem.mapReadAndWriteAshmem();
            expect(resultMapRAndW).assertTrue();
            let bytes = [1, 2, 3, 4, 5];
            let result = ashmem.writeToAshmem(bytes, bytes.length, 0);
            expect(result).assertTrue();
            let resultread = ashmem.setProtection(rpc.Ashmem.PROT_READ);
            expect(resultread).assertTrue();
            let result2 = ashmem.writeToAshmem(bytes, bytes.length, 0);
            expect(result2).assertEqual(false);
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0220---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0230
    * @tc.name    : test Writetoashmem exception validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0230", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0230---------------------------");
        try {
            let ashmem = rpc.Ashmem.createAshmem("JsAshmemTest", 4096);
            let resultMapRAndW = ashmem.mapReadAndWriteAshmem();
            expect(resultMapRAndW).assertTrue();
            let bytes = [1, 2, 3, 4, 5];
            let size = bytes.length + 10;
            let result = ashmem.writeToAshmem(bytes, 3, 0);
            expect(result).assertTrue();
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0230---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0240
    * @tc.name    : test Read data from the shared file associated with readfromashmem
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0240", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0240---------------------------");
        try {
            let ashmem = rpc.Ashmem.createAshmem("JsAshmemTest", 4096);
            let resultMapRAndW = ashmem.mapReadAndWriteAshmem();
            expect(resultMapRAndW).assertTrue();
            let bytes = [1, 2, 3, 4, 5];
            let result = ashmem.writeToAshmem(bytes, bytes.length, 0);
            expect(result).assertTrue();
            let resultRead = ashmem.readFromAshmem(bytes.length, 0);
            for (let i = 0; i < resultRead.length; i++) {
                expect(resultRead[i]).assertEqual(bytes[i]);
            }
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0240---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0250
    * @tc.name    : test Readfromashmem exception validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0250", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0250---------------------------");
        try {
            let ashmem = rpc.Ashmem.createAshmem("JsAshmemTest", 4096);
            let resultMapRAndW = ashmem.mapReadAndWriteAshmem();
            expect(resultMapRAndW).assertTrue();
            let bytes = [1, 2, 3, 4, 5];
            let result = ashmem.writeToAshmem(bytes, bytes.length, 1);
            expect(result).assertTrue();
            let result2 = ashmem.readFromAshmem(bytes.length, 3);
            expect(bytes[2]).assertEqual(result2[0]);
            expect(bytes[3]).assertEqual(result2[1]);
            expect(bytes[4]).assertEqual(result2[2]);
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0250---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0260
    * @tc.name    : test Createashmemfromexisting copies the ashmem object description and creates a new object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0260", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0260---------------------------");
        try {
            let ashmem = rpc.Ashmem.createAshmem("JsAshmemTest", 4096);
            let resultWriteAndRead = ashmem.mapReadAndWriteAshmem();
            expect(resultWriteAndRead).assertTrue();
            let bytes = [1, 2, 3];
            let result = ashmem.writeToAshmem(bytes, bytes.length, 1);
            expect(result).assertTrue()
            let newashmem = rpc.Ashmem.createAshmemFromExisting(ashmem);
            let resultWriteAndRead2 = newashmem.mapReadAndWriteAshmem();
            expect(resultWriteAndRead2).assertTrue();
            let result2 = newashmem.readFromAshmem(bytes.length, 1);
            expect(result).assertTrue();
            for (let i = 0; i < result2.length; i++) {
                expect(result2[i]).assertEqual(bytes[i]);
            }
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
            newashmem.unmapAshmem();
            newashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0260---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0270
    * @tc.name    : test Create a shared memory object and call writeashmem to write the shared anonymous
    object into the messageparcel object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0270", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0270---------------------------");
        try {
            let ashmem = rpc.Ashmem.createAshmem("JsAshmemTest", K);
            var data = rpc.MessageParcel.create();
            let resultMapRAndW = ashmem.mapReadAndWriteAshmem();
            expect(resultMapRAndW).assertTrue();
            let bytes = [1, 2, 3];
            let result = ashmem.writeToAshmem(bytes, bytes.length, 1);
            expect(result).assertTrue();
            let result2 = data.writeAshmem(ashmem);
            expect(result2).assertTrue();
            let retReadAshmem = data.readAshmem();
            let retBytes = retReadAshmem.readFromAshmem(bytes.length, 1);
            console.info("SUB_DSoftbus_IPC_API_Ashmem_0270: run readFromAshmem result is " + retBytes);
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0270---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_Ashmem_0280
    * @tc.name    : test Create a non shared memory object and call writeashmem to write the messageparcel object
    object into the messageparcel object
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Ashmem_0280", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_Ashmem_0280---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            var data2 = rpc.MessageParcel.create();
            data.writeAshmem(data2);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_Ashmem error is:" + error);
            expect(error != null).assertTrue();
        } finally {
            data.reclaim();
            data2.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Ashmem_0280---------------------------");
    })

    console.info("-----------------------SUB_DSoftbus_IPC_API_Stage_MessageSequence_Test is end-----------------------");
  })
}