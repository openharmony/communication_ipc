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
    * @tc.number  : SUB_DSoftbus_IPC_API_IRemoteObject_0090
    * @tc.name    : test IRemoteObject sendMessageRequest API Test
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 0
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_IRemoteObject_0090", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL0, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_IRemoteObject_0090---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            data.writeByte(1);
            data.writeShort(2);
            data.writeInt(3);
            data.writeLong(10000);
            data.writeFloat(1.2);
            data.writeDouble(10.2);
            data.writeBoolean(true);
            data.writeChar(96);
            data.writeString("HelloWorld");
            data.writeParcelable(new MySequenceable(1, "aaa"));
            await gIRemoteObject.sendMessageRequest(CODE_ALL_TYPE, data, reply, option).then((result) => {
                console.info("SUB_DSoftbus_IPC_API_IRemoteObject_0090 errorcode: " + result.errCode);
                expect(result.errCode).assertEqual(0);
                expect(result.reply.readByte()).assertEqual(1);
                expect(result.reply.readShort()).assertEqual(2);
                expect(result.reply.readInt()).assertEqual(3);
                expect(result.reply.readLong()).assertEqual(10000);
                expect(result.reply.readFloat()).assertEqual(1.2);
                expect(result.reply.readDouble()).assertEqual(10.2);
                expect(result.reply.readBoolean()).assertTrue();
                expect(result.reply.readChar()).assertEqual(96);
                expect(result.reply.readString()).assertEqual("HelloWorld");
                let s = new MySequenceable(0, '');
                expect(result.reply.readParcelable(s)).assertTrue();
                expect(s.num).assertEqual(1);
                expect(s.str).assertEqual("aaa");
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_IRemoteObject error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_IRemoteObject_0090---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_IRemoteObject_0100
    * @tc.name    : test getDescriptor to get the interface description
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_IRemoteObject_0100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_IRemoteObject_0100---------------------------");
        try {
            let object = new TestAbilityMessageStub("Test1223");
            let result = object.isObjectDead();
            expect(result == false).assertTrue();
            let callingPid = object.getCallingPid();
            expect(callingPid != null).assertTrue();
            let callingUid = object.getCallingUid();
            expect(callingUid != null).assertTrue();
            object.modifyLocalInterface(object, "test1");
            let result2 = object.getDescriptor();
            expect(result2 != null).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_IRemoteObject error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_IRemoteObject_0100---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_IRemoteObject_0110
    * @tc.name    : test Test that MessageSequence passes through the same process, and the client
    *             receives the reply message in the callback function
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_IRemoteObject_0110", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_IRemoteObject_0110---------------------------");
        try {
            let object = new TestAbilityMessageStub("TestAbilityMessageStub");
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            data.writeInterfaceToken("TestAbilityMessageStub");
            data.writeByte(2);
            data.writeShort(3);
            data.writeInt(4);
            data.writeLong(5);
            data.writeFloat(1.2);
            data.writeDouble(10.2);
            data.writeBoolean(true);
            data.writeChar(5);
            data.writeString("HelloWorld");
            data.writeParcelable(new MySequenceable(1, "aaa"));
            console.info("data is success");
            function sendRequestCallback(result) {
                try {
                    console.info("sendRequest Callback");
                    console.info("sendRequest done, error code: " + result.errCode);
                    expect(result.errCode).assertEqual(0);
                    result.reply.readException();
                    expect(result.reply.readByte()).assertEqual(2);
                    expect(result.reply.readShort()).assertEqual(3);
                    expect(result.reply.readInt()).assertEqual(4);
                    expect(result.reply.readLong()).assertEqual(5);
                    expect(result.reply.readFloat()).assertEqual(1.2);
                    expect(result.reply.readDouble()).assertEqual(10.2);
                    expect(result.reply.readBoolean()).assertTrue();
                    expect(result.reply.readChar()).assertEqual(5);
                    expect(result.reply.readString()).assertEqual("HelloWorld");
                    let s = new MySequenceable(null, null);
                    expect(result.reply.readParcelable(s)).assertTrue();
                    expect(s.num).assertEqual(1);
                    expect(s.str).assertEqual("aaa");
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    console.info("test done");
                    done();
                };
            };
            console.info("start send request");
            object.sendMessageRequest(CODE_SAME_PROCESS, data, reply, option, sendRequestCallback);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_IRemoteObject error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_IRemoteObject_0110---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_IRemoteObject_0120
    * @tc.name    : test Iremoteobject, register death notification verification
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_IRemoteObject_0120", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_IRemoteObject_0120---------------------------");
        try {
            let recipient = new MyregisterDeathRecipient(gIRemoteObject, null);
            gIRemoteObject.registerDeathRecipient(recipient, 0)
            console.info("SUB_DSoftbus_IPC_API_IRemoteObject_0120:run registerDeathRecipient is done");
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_IRemoteObject error is:" + error);
            expect(error != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_IRemoteObject_0120---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_IRemoteObject_0130
    * @tc.name    : test Iremoteobject, register death notification verification
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_IRemoteObject_0130", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_IRemoteObject_0130---------------------------");
        try {
            let recipient = new MyregisterDeathRecipient(gIRemoteObject, null);
            gIRemoteObject.registerDeathRecipient(recipient, 0);
            console.info("SUB_DSoftbus_IPC_API_IRemoteObject_0130:run registerDeathRecipient is done");
            gIRemoteObject.unregisterDeathRecipient(recipient, 0);
            console.info("SUB_DSoftbus_IPC_API_IRemoteObject_0130:run unregisterDeathRecipient is done");
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_IRemoteObject error is:" + error);
            expect(error != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_IRemoteObject_0130---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RemoteProxy_0100
    * @tc.name    : test Call adddeathrecipient to register the death notification
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RemoteProxy_0100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RemoteProxy_0100---------------------------");
        try {
            let recipient = new MyDeathRecipient(gIRemoteObject, null);
            let resultAdd1 = gIRemoteObject.addDeathRecipient(recipient, 0);
            expect(resultAdd1 == false).assertTrue();
            let resultAdd2 = gIRemoteObject.addDeathRecipient(recipient, 0);
            expect(resultAdd2 == false).assertTrue();
            let resultRemove1 = gIRemoteObject.removeDeathRecipient(recipient, 0);
            expect(resultRemove1 == false).assertTrue();
            let resultRemove2 = gIRemoteObject.removeDeathRecipient(recipient, 0);
            expect(resultRemove2 == false).assertTrue();
            let resultRemove3 = gIRemoteObject.removeDeathRecipient(recipient, 0);
            expect(resultRemove3 == false).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RemoteProxy_0100---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RemoteProxy_0200
    * @tc.name    : test AddDeathRecipient Validates the interface flags input parameter boundary value
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RemoteProxy_0200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RemoteProxy_0200---------------------------");
        try {
            let recipient = new MyDeathRecipient(gIRemoteObject, null);
            let resultAdd = gIRemoteObject.addDeathRecipient(recipient, -(2 * G));
            expect(resultAdd == false).assertTrue();
            let resultRemove = gIRemoteObject.removeDeathRecipient(recipient, -(2 * G));
            expect(resultRemove == false).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RemoteProxy_0200---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RemoteProxy_0300
    * @tc.name    : test AddDeathRecipient Validates the interface flags input parameter boundary value
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RemoteProxy_0300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RemoteProxy_0300---------------------------");
        try {
            let recipient = new MyDeathRecipient(gIRemoteObject, null);
            let resultAdd = gIRemoteObject.addDeathRecipient(recipient, (2 * G - 1));
            expect(resultAdd == false).assertTrue();
            let resultRemove = gIRemoteObject.removeDeathRecipient(recipient, (2 * G - 1));
            expect(resultRemove == false).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RemoteProxy_0300---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RemoteProxy_0400
    * @tc.name    : test AddDeathRecipient Validates the interface flags input parameter boundary value
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RemoteProxy_0400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RemoteProxy_0400---------------------------");
        try {
            let recipient = new MyDeathRecipient(gIRemoteObject, null);
            let resultAdd = gIRemoteObject.addDeathRecipient(recipient, 2 * G);
            expect(resultAdd == false).assertTrue();
            let resultRemove = gIRemoteObject.removeDeathRecipient(recipient, 2 * G);
            expect(resultRemove == false).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RemoteProxy_0400---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RemoteProxy_0500
    * @tc.name    : test AddDeathRecipient Validates the interface flags input parameter boundary value
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RemoteProxy_0500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RemoteProxy_0500---------------------------");
        try {
            let recipient = new MyDeathRecipient(gIRemoteObject, null);
            let resultAdd = gIRemoteObject.addDeathRecipient(recipient, -(2 * G + 1));
            expect(resultAdd == false).assertTrue();
            let resultRemove = gIRemoteObject.removeDeathRecipient(recipient, -(2 * G + 1));
            expect(resultRemove == false).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RemoteProxy_0500---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RemoteProxy_0600
    * @tc.name    : test Call isobjectdead to check whether the object is dead
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RemoteProxy_0600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RemoteProxy_0600---------------------------");
        try {
            let recipient = new MyDeathRecipient(gIRemoteObject, null);
            let isDead = gIRemoteObject.isObjectDead();
            expect(isDead == false).assertTrue();
            let resultAdd1 = gIRemoteObject.addDeathRecipient(recipient, 0);
            expect(resultAdd1 == false).assertTrue();
            let isDead1 = gIRemoteObject.isObjectDead();
            expect(isDead1 == false).assertTrue();
            let resultRemove1 = gIRemoteObject.removeDeathRecipient(recipient, 0);
            expect(resultRemove1 == false).assertTrue();
            let resultAdd2 = gIRemoteObject.addDeathRecipient(recipient, 0);
            expect(resultAdd2 == false).assertTrue();
            let resultRemove2 = gIRemoteObject.removeDeathRecipient(recipient, 0);
            expect(resultRemove2 == false).assertTrue();
            let resultRemove3 = gIRemoteObject.removeDeathRecipient(recipient, 0);
            expect(resultRemove3 == false).assertTrue();
            let isDead2 = gIRemoteObject.isObjectDead();
            expect(isDead2 == false).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RemoteProxy_0600---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RemoteProxy_0700
    * @tc.name    : test Getinterfacedescriptor to get the object interface description
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RemoteProxy_0700", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RemoteProxy_0700---------------------------");
        try {
            let object = new TestAbilityStub("Test030");
            let result = object.getInterfaceDescriptor();
            expect(result).assertEqual("Test030");
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RemoteProxy_0700---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RemoteProxy_0800
    * @tc.name    : test Querylocalinterface searches for objects based on descriptors
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RemoteProxy_0800", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RemoteProxy_0800---------------------------");
        try {
            let object = new TestAbilityStub("Test040");
            let result = object.isObjectDead();
            expect(result).assertEqual(false);
            object.attachLocalInterface(object, "Test2");
            let res2 = object.queryLocalInterface('Test2');
            expect(res2 != null).assertTrue();
            let resultDescrip = object.getInterfaceDescriptor();
            expect(resultDescrip != null).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RemoteProxy_0800---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RemoteProxy_0900
    * @tc.name    : test Transaction constant validation
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RemoteProxy_0900", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------SUB_DSoftbus_IPC_API_RemoteProxy_0900 is starting-----------------");
        try {
            expect(rpc.RemoteProxy.PING_TRANSACTION).assertEqual(1599098439);
            expect(rpc.RemoteProxy.DUMP_TRANSACTION).assertEqual(1598311760);
            expect(rpc.RemoteProxy.INTERFACE_TRANSACTION).assertEqual(1598968902);
            expect(rpc.RemoteProxy.MIN_TRANSACTION_ID).assertEqual(0x1);
            expect(rpc.RemoteProxy.MAX_TRANSACTION_ID).assertEqual(0x00FFFFFF);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RemoteProxy_0090---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RemoteProxy_1000
    * @tc.name    : test Call isobjectdead to check whether the object is dead
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RemoteProxy_1000", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RemoteProxy_1000---------------------------");
        try {
            let recipient = new MyregisterDeathRecipient(gIRemoteObject, null);
            let isDead = gIRemoteObject.isObjectDead();
            expect(isDead == false).assertTrue();
            gIRemoteObject.registerDeathRecipient(recipient, 0);
            let isDead1 = gIRemoteObject.isObjectDead();
            expect(isDead1 == false).assertTrue();
            gIRemoteObject.unregisterDeathRecipient(recipient, 0);
            gIRemoteObject.registerDeathRecipient(recipient, 0);
            gIRemoteObject.unregisterDeathRecipient(recipient, 0);
            gIRemoteObject.unregisterDeathRecipient(recipient, 0);
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy_1000: unregisterDeathRecipient is success");
            let isDead2 = gIRemoteObject.isObjectDead();
            expect(isDead2 == false).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy error is:" + error);
            expect(error != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RemoteProxy_1000---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RemoteProxy_1100
    * @tc.name    : test getDescriptor to get the object interface description
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RemoteProxy_1100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RemoteProxy_1100---------------------------");
        try {
            let object = new TestAbilityStub("Test0300");
            let result = object.getDescriptor();
            expect(result).assertEqual("Test0300");
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RemoteProxy_1100---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RemoteProxy_1200
    * @tc.name    : test getLocalInterface searches for objects based on descriptors
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RemoteProxy_1200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RemoteProxy_1200---------------------------");
        try {
            let object = new TestAbilityStub("Test0400");
            let result = object.isObjectDead();
            expect(result).assertEqual(false);
            object.modifyLocalInterface(object, "Test2");
            let res2 = object.getLocalInterface('Test2');
            expect(res2 != null).assertTrue();
            let resultDescrip = object.getDescriptor();
            expect(resultDescrip != null).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RemoteProxy_1200---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RemoteProxy_1300
    * @tc.name    : test Call registerDeathRecipient to register the death notification
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RemoteProxy_1300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RemoteProxy_1300---------------------------");
        try {
            let recipient = new MyregisterDeathRecipient(gIRemoteObject, null);
            gIRemoteObject.registerDeathRecipient(recipient, 0);
            gIRemoteObject.registerDeathRecipient(recipient, 0);
            gIRemoteObject.unregisterDeathRecipient(recipient, 0);
            gIRemoteObject.unregisterDeathRecipient(recipient, 0);
            gIRemoteObject.unregisterDeathRecipient(recipient, 0);
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy_1300: unregisterDeathRecipient is success");
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy error is:" + error);
            expect(error != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RemoteProxy_1300---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RemoteProxy_1400
    * @tc.name    : test registerDeathRecipient Validates the interface flags input parameter boundary value
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RemoteProxy_1400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RemoteProxy_1400---------------------------");
        try {
            let recipient = new MyregisterDeathRecipient(gIRemoteObject, null);
            gIRemoteObject.registerDeathRecipient(recipient, -(2 * G));
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy_1400: registerDeathRecipient is success");
            gIRemoteObject.unregisterDeathRecipient(recipient, -(2 * G));
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy_1400: unregisterDeathRecipient is success");
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy error is:" + error);
            expect(error != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RemoteProxy_1400---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RemoteProxy_1500
    * @tc.name    : test registerDeathRecipient Validates the interface flags input parameter boundary value
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RemoteProxy_1500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RemoteProxy_1500---------------------------");
        try {
            let recipient = new MyregisterDeathRecipient(gIRemoteObject, null);
            gIRemoteObject.registerDeathRecipient(recipient, (2 * G - 1));
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy_1500: registerDeathRecipient is success");
            gIRemoteObject.unregisterDeathRecipient(recipient, (2 * G - 1));
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy_1500: unregisterDeathRecipient is success");
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy error is:" + error);
            expect(error != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RemoteProxy_1500---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RemoteProxy_1600
    * @tc.name    : test registerDeathRecipient Validates the interface flags input parameter boundary value
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RemoteProxy_1600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RemoteProxy_1600---------------------------");
        try {
            let recipient = new MyregisterDeathRecipient(gIRemoteObject, null);
            gIRemoteObject.registerDeathRecipient(recipient, 2 * G);
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy_1600: registerDeathRecipient is success");
            gIRemoteObject.unregisterDeathRecipient(recipient, 2 * G);
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy_1600: unregisterDeathRecipient is success");
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy error is:" + error);
            expect(error != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RemoteProxy_1600---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RemoteProxy_1700
    * @tc.name    : test registerDeathRecipient Validates the interface flags input parameter boundary value
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RemoteProxy_1700", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RemoteProxy_1700---------------------------");
        try {
            let recipient = new MyregisterDeathRecipient(gIRemoteObject, null);
            gIRemoteObject.registerDeathRecipient(recipient, -(2 * G + 1));
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy_1700: registerDeathRecipient is success");
            gIRemoteObject.unregisterDeathRecipient(recipient, -(2 * G + 1));
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy_1700: unregisterDeathRecipient is success");
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy error is:" + error);
            expect(error != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RemoteProxy_1700---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RemoteProxy_1800
    * @tc.name    : test getLocalInterface 1900005 searches for objects based on descriptors
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RemoteProxy_1800", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RemoteProxy_1800---------------------------");
        try {
            let object = new TestAbilityStub("Test040");
            let result = object.isObjectDead();
            expect(result).assertEqual(false);
            object.modifyLocalInterface(object, "Test2");
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy_1800: run modifyLocalInterface success");
            object.getLocalInterface(null);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy error is:" + error);
            let errCode = `${rpc.ErrorCode.ONLY_PROXY_OBJECT_PERMITTED_ERROR}`;
            expect(error.code != errCode).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RemoteProxy_1800---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RemoteProxy_1900
    * @tc.name    : test Querylocalinterface searches for objects based on descriptors
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RemoteProxy_1900", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RemoteProxy_1900---------------------------");
        try {
            let res = gIRemoteObject.queryLocalInterface("testRpc");
            expect(res == null).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RemoteProxy_1900---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RemoteProxy_2000
    * @tc.name    : test getLocalInterface searches for objects based on descriptors
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RemoteProxy_2000", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RemoteProxy_2000---------------------------");
        try {
            let res = gIRemoteObject.getLocalInterface("testRpc");
            expect(res == null).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RemoteProxy_2000---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RemoteProxy_2100
    * @tc.name    : test Getinterfacedescriptor to get the object interface description
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RemoteProxy_2100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RemoteProxy_2100---------------------------");
        try {
            let result = gIRemoteObject.getInterfaceDescriptor();
            expect(result).assertEqual("rpcTestAbility");
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RemoteProxy_2100---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RemoteProxy_2200
    * @tc.name    : test getDescriptor to get the object interface description
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RemoteProxy_2200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RemoteProxy_2200---------------------------");
        try {
            let result = gIRemoteObject.getDescriptor();
            expect(result).assertEqual("rpcTestAbility");
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RemoteProxy_2200---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RemoteProxy_2300
    * @tc.name    : test sendRequest to get the object interface description
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RemoteProxy_2300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RemoteProxy_2300---------------------------");
        try {
            var data = rpc.MessageParcel.create();
            var reply = rpc.MessageParcel.create();
            let option = new rpc.MessageOption();
            let result = data.writeString('sendRequest');
            expect(result == true).assertTrue();
            expect(gIRemoteObject != undefined).assertTrue();
            let resultSendRequest = gIRemoteObject.sendRequest(CODE_WRITE_STRING, data, reply, option);
            expect(resultSendRequest != null).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RemoteProxy error is:" + error);
            expect(error == null).assertTrue();
        } finally{
            data.reclaim();
            reply.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RemoteProxy_2300---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_IPCSkeleton_0010
    * @tc.name    : test Create an empty object and verify the function of the flushcommands interface
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_IPCSkeleton_0010", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_IPCSkeleton_0010---------------------------");
        try {
            let remoteObject = new TestRemoteObject("aaa");
            let ret = rpc.IPCSkeleton.flushCommands(remoteObject);
            expect(ret != null).assertTrue();
        }
        catch (error) {
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_IPCSkeleton_0010---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_IPCSkeleton_0020
    * @tc.name    : test Create an empty object and verify the function of the flushcommands interface
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_IPCSkeleton_0020", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_IPCSkeleton_0020---------------------------");
        try {
            let remoteObject = {};
            let ret = rpc.IPCSkeleton.flushCommands(remoteObject);
            expect(ret != null).assertTrue();
        }
        catch (error) {
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_IPCSkeleton_0020---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_IPCSkeleton_0030
    * @tc.name    : test Create an empty object and verify the function of the flushcommands interface
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_IPCSkeleton_0030", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_IPCSkeleton_0030---------------------------");
        try {
            let samgr = rpc.IPCSkeleton.getContextObject();
            expect(samgr != null).assertTrue();
        }
        catch (error) {
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_IPCSkeleton_0030---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_IPCSkeleton_0040
    * @tc.name    : test Create an empty object and verify the function of the flushcommands interface
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_IPCSkeleton_0040", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_IPCSkeleton_0040---------------------------");
        try {
            let getCallingPid = rpc.IPCSkeleton.getCallingPid();
            expect(getCallingPid != null).assertTrue();
            let getCallingUid = rpc.IPCSkeleton.getCallingUid();
            expect(getCallingUid != null).assertTrue();
        }
        catch (error) {
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_IPCSkeleton_0040---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_IPCSkeleton_0050
    * @tc.name    : test Create an empty object and verify the function of the flushcommands interface
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_IPCSkeleton_0050", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_IPCSkeleton_0050---------------------------");
        try {
            let getCallingPid = rpc.IPCSkeleton.getLocalDeviceID();
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton_0050 getCallingPid result: " + getCallingPid);
            expect(getCallingPid != null).assertTrue();
            let getCallingUid = rpc.IPCSkeleton.getCallingDeviceID();
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton_0050 getCallingUid result: " + getCallingUid);
            expect(getCallingUid != null).assertTrue();
        }
        catch (error) {
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_IPCSkeleton_0050---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_IPCSkeleton_0060
    * @tc.name    : test Do not get the server agent, do not create a remoteobject instance, and directly getcallingpid,
    *             getcallingpid, getcallingdeviceid, getlocaldeviceid
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_IPCSkeleton_0060", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_IPCSkeleton_0060---------------------------");
        try {
            let getCallingPid = rpc.IPCSkeleton.getCallingPid();
            expect(getCallingPid != null).assertTrue();
            let getCallingUid = rpc.IPCSkeleton.getCallingUid();
            expect(getCallingUid != null).assertTrue();
            let getCallingToKenId = rpc.IPCSkeleton.getCallingTokenId();
            expect(getCallingToKenId != null).assertTrue();
            let getLocalDeviceID = rpc.IPCSkeleton.getLocalDeviceID();
            expect(getLocalDeviceID != null).assertTrue();
            let getCallingDeviceID = rpc.IPCSkeleton.getCallingDeviceID();
            expect(getCallingDeviceID != null).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_IPCSkeleton_0060---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_IPCSkeleton_0070
    * @tc.name    : test Basic method of testing ipcskeleton
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_IPCSkeleton_0070", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_IPCSkeleton_0070---------------------------");
        try {
            let callingPid = rpc.IPCSkeleton.getCallingPid();
            let callingUid = rpc.IPCSkeleton.getCallingUid();
            let option = new rpc.MessageOption();
            var data = rpc.MessageParcel.create();
            var reply = rpc.MessageParcel.create();
            expect(data.writeInterfaceToken("rpcTestAbility")).assertTrue();
            expect(callingUid != null).assertTrue();
            expect(callingPid != null).assertTrue();
            await gIRemoteObject.sendRequest(CODE_IPCSKELETON, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                result.reply.readException();
                let rescallingPid = result.reply.readInt();
                let rescallingUid = result.reply.readInt();
                expect(rescallingPid).assertEqual(callingPid);
                expect(rescallingUid).assertEqual(callingUid);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_IPCSkeleton_0070---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_IPCSkeleton_0080
    * @tc.name    : test Basic method of testing ipcskeleton
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_IPCSkeleton_0080", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_IPCSkeleton_0080---------------------------");
        try {
            let callingPid = rpc.IPCSkeleton.getCallingPid();
            let callingUid = rpc.IPCSkeleton.getCallingUid();
            let option = new rpc.MessageOption();
            var data = rpc.MessageParcel.create();
            var reply = rpc.MessageParcel.create();
            expect(data.writeInterfaceToken("rpcTestAbility")).assertTrue();
            expect(callingUid != null).assertTrue();
            expect(callingPid != null).assertTrue();
            await gIRemoteObject.sendRequest(CODE_IPCSKELETON_INT, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                result.reply.readException();
                let rescallingPid = result.reply.readInt();
                let rescallingUid = result.reply.readInt();
                let restcallingPid = result.reply.readInt();
                let restcallingUid = result.reply.readInt();
                let resicallingPid = result.reply.readInt();
                let resicallingUid = result.reply.readInt();
                let resflushCommands = result.reply.readInt();
                expect(rescallingPid).assertEqual(callingPid);
                expect(rescallingUid).assertEqual(callingUid);
                expect(restcallingPid).assertEqual(callingPid);
                expect(restcallingUid).assertEqual(callingUid);
                expect(resicallingPid).assertEqual(callingPid);
                expect(resicallingUid).assertEqual(callingUid);
                expect(resflushCommands).assertEqual(101);
            })
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_IPCSkeleton_0080---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_IPCSkeleton_0090
    * @tc.name    : test SetCallingIdentity Interface flags input parameter boundary value verification
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_IPCSkeleton_0090", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_IPCSkeleton_0090---------------------------");
        try {
            let id = "";
            let ret = rpc.IPCSkeleton.setCallingIdentity(id);
            expect(ret).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_IPCSkeleton_0090---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_IPCSkeleton_0100
    * @tc.name    : test SetCallingIdentity Interface flags input parameter boundary value verification
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_IPCSkeleton_0100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_IPCSkeleton_0100---------------------------");
        try {
            let id = 0;
            let ret = rpc.IPCSkeleton.setCallingIdentity(id);
            expect(ret).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_IPCSkeleton_0100---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_IPCSkeleton_0110
    * @tc.name    : test SetCallingIdentity Interface flags input parameter boundary value verification
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_IPCSkeleton_0110", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_IPCSkeleton_0110---------------------------");
        try {
            let id = "";
            for (let i = 0; i < (40 * K - 1); i++) {
                id += "a";
            };
            let ret = rpc.IPCSkeleton.setCallingIdentity(id);
            expect(ret).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_IPCSkeleton_0110---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_IPCSkeleton_0120
    * @tc.name    : test Basic method of testing ipcskeleton
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_IPCSkeleton_0120", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_IPCSkeleton_0120---------------------------");
        try {
            let object = rpc.IPCSkeleton.getContextObject();
            let callingPid = rpc.IPCSkeleton.getCallingPid();
            let callingUid = rpc.IPCSkeleton.getCallingUid();
            let callingDeviceID = rpc.IPCSkeleton.getCallingDeviceID();
            let localDeviceID = rpc.IPCSkeleton.getLocalDeviceID();
            let isLocalCalling = rpc.IPCSkeleton.isLocalCalling();
            let id = rpc.IPCSkeleton.resetCallingIdentity();
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton_0120：" + id);
            let ret = rpc.IPCSkeleton.setCallingIdentity(id);
            expect(callingDeviceID).assertEqual("");
            expect(localDeviceID).assertEqual("");
            expect(isLocalCalling).assertTrue();
            expect(id).assertEqual("");
            expect(ret).assertTrue();
            expect(rpc.IPCSkeleton.flushCommands(gIRemoteObject)).assertEqual(101);
            let option = new rpc.MessageOption();
            var data = rpc.MessageParcel.create();
            var reply = rpc.MessageParcel.create();
            expect(data.writeInterfaceToken("rpcTestAbility")).assertTrue();
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton_0120： start send request");
            await gIRemoteObject.sendRequest(CODE_IPCSKELETON, data, reply, option).then(function (result) {
                expect(result.errCode).assertEqual(0);
                result.reply.readException();
                expect(result.reply.readInt()).assertEqual(callingPid);
                expect(result.reply.readInt()).assertEqual(callingUid);
                expect(result.reply.readString()).assertEqual("");
                expect(result.reply.readString()).assertEqual("");
                expect(result.reply.readBoolean()).assertTrue();
                expect(result.reply.readInt()).assertEqual(callingPid);
                expect(result.reply.readInt()).assertEqual(callingUid);
                expect(result.reply.readInt()).assertEqual(callingPid);
                expect(result.reply.readInt()).assertEqual(callingUid);
                expect(result.reply.readInt()).assertEqual(101);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_IPCSkeleton_0120---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_IPCSkeleton_0130
    * @tc.name    : test IPCSkeleton sendMessageRequest API test
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_IPCSkeleton_0130", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
        console.info("---------------------start SUB_DSoftbus_IPC_API_IPCSkeleton_0130---------------------------");
        try {
            let callingPid = rpc.IPCSkeleton.getCallingPid();
            let callingUid = rpc.IPCSkeleton.getCallingUid();
            let option = new rpc.MessageOption();
            var data = rpc.MessageSequence.create();
            var reply = rpc.MessageSequence.create();
            data.writeInterfaceToken("rpcTestAbility");
            expect(callingUid != null).assertTrue();
            expect(callingPid != null).assertTrue();
            await gIRemoteObject.sendMessageRequest(CODE_IPCSKELETON, data, reply, option).then((result) => {
                expect(result.errCode).assertEqual(0);
                result.reply.readException();
                let rescallingPid = result.reply.readInt();
                let rescallingUid = result.reply.readInt();
                expect(rescallingPid).assertEqual(callingPid);
                expect(rescallingUid).assertEqual(callingUid);
            });
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
            reply.reclaim();
            done();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_IPCSkeleton_0130---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_IPCSkeleton_0140
    * @tc.name    : test Create an empty object and verify the function of the flushCmdBuffer interface
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 1
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_IPCSkeleton_0140", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_IPCSkeleton_0140---------------------------");
        try {
            let remoteObject = new TestRemoteObject("aaa");
            rpc.IPCSkeleton.flushCmdBuffer(remoteObject);
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton_0140 RpcServer: flushCmdBuffer is success");
        }
        catch (error) {
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_IPCSkeleton_0140---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_IPCSkeleton_0150
    * @tc.name    : test Create an empty object and verify the function of the flushCmdBuffer interface
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_IPCSkeleton_0150", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_IPCSkeleton_0150---------------------------");
        try {
            let remoteObject = {};
            rpc.IPCSkeleton.flushCmdBuffer(remoteObject);
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton_0150 RpcServer: flushCmdBuffer is success");
        }
        catch (error) {
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_IPCSkeleton_0150---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_IPCSkeleton_0160
    * @tc.name    : test Basic method of testing ipcskeleton 1900007
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_IPCSkeleton_0160", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_IPCSkeleton_0160---------------------------");
        try {
            let object = rpc.IPCSkeleton.getContextObject();
            object.getDescriptor();
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton_0160: is success");
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton error is:" + error);
            let errCode = `${rpc.ErrorCode.COMMUNICATION_ERROR}`;
            expect(error.message != null).assertTrue();
            expect(error.code == errCode).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_IPCSkeleton_0160---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_IPCSkeleton_0170
    * @tc.name    : test Create an empty object and verify the function of the flushCmdBuffer interface 1900006
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_IPCSkeleton_0170", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_IPCSkeleton_0170---------------------------");
        try {
            let remoteObject = null;
            rpc.IPCSkeleton.flushCmdBuffer(remoteObject);
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton_0170 RpcServer: flushCmdBuffer is success");
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton error is:" + error);
            let errCode = `${rpc.ErrorCode.ONLY_REMOTE_OBJECT_PERMITTED_ERROR}`;
            expect(error.message != null).assertTrue();
            expect(error.code != errCode).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_IPCSkeleton_0170---------------------------");
    })

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_IPCSkeleton_0180
    * @tc.name    : test restoreCallingIdentity Interface flags input parameter boundary value verification
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_IPCSkeleton_0180", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_IPCSkeleton_0180---------------------------");
        try {
            let id = "";
            rpc.IPCSkeleton.restoreCallingIdentity(id);
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton_0180 restoreCallingIdentity is success");
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_IPCSkeleton_0180---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_IPCSkeleton_0190
    * @tc.name    : test restoreCallingIdentity Interface flags input parameter 0 value verification
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_IPCSkeleton_0190", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_IPCSkeleton_0190---------------------------");
        try {
            let id = 0;
            rpc.IPCSkeleton.restoreCallingIdentity(id);
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton_0190 restoreCallingIdentity is success");
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_IPCSkeleton_0190---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_IPCSkeleton_0200
    * @tc.name    : test restoreCallingIdentity Interface flags input parameter null value verification
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_IPCSkeleton_0200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_IPCSkeleton_0200---------------------------");
        try {
            let id = "";
            for (let i = 0; i < (40 * K - 1); i++) {
                id += "a";
            };
            rpc.IPCSkeleton.restoreCallingIdentity(id);
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton_0200 restoreCallingIdentity is success");
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_IPCSkeleton error is:" + error);
            expect(error == null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_IPCSkeleton_0200---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RawDataBuffer_0100
    * @tc.name    : test writeRawDataBuffer input parameter is a normal data less than 32KB 
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RawDataBuffer_0100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RawDataBuffer_0100---------------------------");
        let TEST_LEN_32K = 32 * 1024;
        let data = new rpc.MessageSequence();
        try {
            let buffer = new ArrayBuffer(TEST_LEN_32K);
            let size = buffer.byteLength;
            let int32View = new Int32Array(buffer);
            int32View.fill(1);
            data.writeRawDataBuffer(buffer, size);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RawDataBuffer_0100 error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RawDataBuffer_0100---------------------------");
    });

    /*
        * @tc.number  : SUB_DSoftbus_IPC_API_RawDataBuffer_0200
        * @tc.name    : test writeRawDataBuffer input parameter is a normal data greater than 32KB and less than 128MB 
        * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level   : Level 3
        * @tc.type    : Compatibility
        * @tc.size    : MediumTest
        */
    it("SUB_DSoftbus_IPC_API_RawDataBuffer_0200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RawDataBuffer_0200---------------------------");
        let TEST_LEN_128M = 128 * 1024 * 1024;
        let data = new rpc.MessageSequence();
        try {
            let buffer = new ArrayBuffer(TEST_LEN_128M);
            let size = buffer.byteLength;
            let int32View = new Int32Array(buffer);
            int32View.fill(1);
            data.writeRawDataBuffer(buffer, size);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RawDataBuffer_0200 error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RawDataBuffer_0200---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RawDataBuffer_0300
    * @tc.name    : test writeRawDataBuffer input parameter is a normal size = 0
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RawDataBuffer_0300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RawDataBuffer_0300---------------------------");
        let TEST_LEN_32K = 32 * 1024;
        let data = new rpc.MessageSequence();
        try {
            let buffer = new ArrayBuffer(TEST_LEN_32K);
            let size = buffer.byteLength;
            let int32View = new Int32Array(buffer);
            int32View.fill(1);
            let errSize = 0;
            data.writeRawDataBuffer(buffer, 0);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RawDataBuffer_0300 error is:" + error);
            expect(error.code == 401).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RawDataBuffer_0300---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RawDataBuffer_0400
    * @tc.name    : test writeRawDataBuffer input parameter is a normal size less than 0
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RawDataBuffer_0400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RawDataBuffer_0400---------------------------");
        let TEST_LEN_32K = 32 * 1024;
        let data = new rpc.MessageSequence();
        try {
            let buffer = new ArrayBuffer(TEST_LEN_32K);
            let size = buffer.byteLength;
            let int32View = new Int32Array(buffer);
            int32View.fill(1);
            let errSize = -1;
            data.writeRawDataBuffer(buffer, errSize);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RawDataBuffer_0400 error is:" + error);
            expect(error.code == 401).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RawDataBuffer_0400---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RawDataBuffer_0500
    * @tc.name    : test writeRawDataBuffer input parameter is a normal data greater than 128MB
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RawDataBuffer_0500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RawDataBuffer_0500---------------------------");
        let TEST_LEN_128M = 128 * 1024 * 1024;
        let data = new rpc.MessageSequence();
        try {
            let buffer = new ArrayBuffer(TEST_LEN_128M + 4);
            let size = buffer.byteLength;
            let int32View = new Int32Array(buffer);
            int32View.fill(1);
            data.writeRawDataBuffer(buffer, size);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RawDataBuffer_0500 error is:" + error);
            expect(error.code == 1900009).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RawDataBuffer_0500---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RawDataBuffer_0600
    * @tc.name    : test readRawDataBuffer input parameter is a normal data less than 32KB
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RawDataBuffer_0600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RawDataBuffer_0600---------------------------");
        let TEST_LEN_32K = 32 * 1024;
        let data = new rpc.MessageSequence();
        try {
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
            console.info("SUB_DSoftbus_IPC_API_RawDataBuffer_0600 error is:" + error);
            expect(error== null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RawDataBuffer_0600---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RawDataBuffer_0700
    * @tc.name    : test readRawDataBuffer input parameter is a normal data less than 128MB
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RawDataBuffer_0700", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RawDataBuffer_0700---------------------------");
        let TEST_LEN_64K = 64 * 1024;
        let data = new rpc.MessageSequence();
        try {
            let buffer = new ArrayBuffer(TEST_LEN_64K + 4);
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
            console.info("SUB_DSoftbus_IPC_API_RawDataBuffer_0700 error is:" + error);
            expect(error== null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RawDataBuffer_0700---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RawDataBuffer_0800
    * @tc.name    : test readRawDataBuffer input parameter is a normal data greater than 128MB
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RawDataBuffer_0800", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RawDataBuffer_0800---------------------------");
        let TEST_LEN_128M = 128 * 1024 * 1024;
        let data = new rpc.MessageSequence();
        try {
            let buffer = new ArrayBuffer(TEST_LEN_128M);
            let size = buffer.byteLength;
            let int32View = new Int32Array(buffer);
            int32View.fill(1);
            data.writeRawDataBuffer(buffer, size);
            let readBuffer = data.readRawDataBuffer(TEST_LEN_128M + 1);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RawDataBuffer_0800 error is:" + error);
            expect(error.code == 1900010).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RawDataBuffer_0800---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RawDataBuffer_0900
    * @tc.name    : test readRawDataBuffer input parameter is a normal size = 0
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RawDataBuffer_0900", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RawDataBuffer_0900---------------------------");
        let TEST_LEN_32K = 32 * 1024;
        let data = new rpc.MessageSequence();
        try {
            let buffer = new ArrayBuffer(TEST_LEN_32K);
            let size = buffer.byteLength;
            let int32View = new Int32Array(buffer);
            int32View.fill(1);
            data.writeRawDataBuffer(buffer, size);
            let readBuffer = data.readRawDataBuffer(0);
            let readInt32Arr = new Int32Array(readBuffer);
            expect(readInt32Arr.length == 0).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RawDataBuffer_0900 error is:" + error);
            expect(error== null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RawDataBuffer_0900---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RawDataBuffer_1000
    * @tc.name    : test readRawDataBuffer input parameter is a normal size less than 0
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RawDataBuffer_1000", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RawDataBuffer_1000---------------------------");
        let TEST_LEN_32K = 32 * 1024;
        let data = new rpc.MessageSequence();
        try {
            let buffer = new ArrayBuffer(TEST_LEN_32K);
            let size = buffer.byteLength;
            let int32View = new Int32Array(buffer);
            int32View.fill(1);
            data.writeRawDataBuffer(buffer, size);
            let readBuffer = data.readRawDataBuffer(-1);
            let readInt32Arr = new Int32Array(readBuffer);
            expect(readInt32Arr.length == 0).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RawDataBuffer_1000 error is:" + error);
            expect(error== null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RawDataBuffer_1000---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_RawDataBuffer_1100
    * @tc.name    : test readRawDataBuffer input parameter is a normal size not match write
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_RawDataBuffer_1100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_RawDataBuffer_1100---------------------------");
        let TEST_LEN_32K = 32 * 1024;
        let data = new rpc.MessageSequence();
        try {
            let buffer = new ArrayBuffer(TEST_LEN_32K);
            let size = buffer.byteLength;
            let int32View = new Int32Array(buffer);
            int32View.fill(1);
            data.writeRawDataBuffer(buffer, size);
            let readBuffer = data.readRawDataBuffer(TEST_LEN_32K - 1);
            let readInt32Arr = new Int32Array(readBuffer);
            expect(readInt32Arr.length == 0).assertTrue();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_RawDataBuffer_1100 error is:" + error);
            expect(error.code == 1900010).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_RawDataBuffer_1100---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_NewAshmen_0100
    * @tc.name    : test writeDataToAshmem input parameter is a normal data less than 32KB 
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_NewAshmen_0100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_NewAshmen_0100---------------------------");
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
            console.info("SUB_DSoftbus_IPC_API_NewAshmen_0100 error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_NewAshmen_0100---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_NewAshmen_0200
    * @tc.name    : test writeDataToAshmem input parameter is a normal data greater than 32KB 
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_NewAshmen_0200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_NewAshmen_0200---------------------------");
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
            console.info("SUB_DSoftbus_IPC_API_NewAshmen_0200 error is:" + error);
            expect(error == null).assertTrue();
        } finally {
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_NewAshmen_0200---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_NewAshmen_0300
    * @tc.name    : test writeDataToAshmem input parameter is a normal data size = 0
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_NewAshmen_0300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_NewAshmen_0300---------------------------");
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
            console.info("SUB_DSoftbus_IPC_API_NewAshmen_0300 error is:" + error);
            expect(error.code == 1900003).assertTrue();
        } finally {
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_NewAshmen_0300---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_NewAshmen_0400
    * @tc.name    : test writeDataToAshmem input parameter is a normal  size less than 0
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_NewAshmen_0400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_NewAshmen_0400---------------------------");
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
            console.info("SUB_DSoftbus_IPC_API_NewAshmen_0400 error is:" + error);
            expect(error.code == 1900003).assertTrue();
        } finally {
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_NewAshmen_0400---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_NewAshmen_0500
    * @tc.name    : test writeDataToAshmem input parameter is a normal  offset less than 0
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_NewAshmen_0500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_NewAshmen_0500---------------------------");
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
            console.info("SUB_DSoftbus_IPC_API_NewAshmen_0500 error is:" + error);
            expect(error.code == 1900003).assertTrue();
        } finally {
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_NewAshmen_0500---------------------------");
    });

    /*
    * @tc.number  : SUB_DSoftbus_IPC_API_NewAshmen_0600
    * @tc.name    : test writeDataToAshmem input parameter is a normal  lenth and offset greater than create
    * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level   : Level 3
    * @tc.type    : Compatibility
    * @tc.size    : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_NewAshmen_0600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
        console.info("---------------------start SUB_DSoftbus_IPC_API_NewAshmen_0600---------------------------");
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
            console.info("SUB_DSoftbus_IPC_API_NewAshmen_0600 error is:" + error);
            expect(error.code == 1900003).assertTrue();
        } finally {
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_NewAshmen_0600---------------------------");
    });

    console.info("-----------------------SUB_DSoftbus_IPC_API_Stage_MessageSequence_Test is end-----------------------");
  })
}