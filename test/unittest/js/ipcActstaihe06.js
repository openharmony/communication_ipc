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
            it("SUB_DSoftbus_IPC_API_MessageSequence_0560", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
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
             * @tc.type    : Compatibility
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
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0590---------------------------");
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
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0600---------------------------");
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
             * @tc.size    : MediumTest
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
                    var data = rpc.MessageSequence.create();
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
            it("SUB_DSoftbus_IPC_API_MessageSequence_0630", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
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
            it("SUB_DSoftbus_IPC_API_MessageSequence_0640", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
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

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0650
             * @tc.name    : test Call the writechar interface to write the maximum data to the MessageSequence instance,
             *              and call readchar to read the data
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0650", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0650---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    let token = 255;
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
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0650---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0660
             * @tc.name    : test Call the writechar interface to write the minimum out of range data to the MessageSequence instance,
             *              and call readchar to read the data
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0660", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0660---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    let token = -1;
                    data.writeChar(token);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_CHAR, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readChar()).assertEqual(255);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0660---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0670
             * @tc.name    : test Call the writechar interface to write the maximum out of range data to the MessageSequence instance,
             *              and call readchar to read the data
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0670", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0670---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    let token = 256;
                    data.writeChar(token);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_CHAR, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readChar()).assertEqual(0);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0670---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0680
             * @tc.name    : test Writechar interface, illegal value verification
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0680", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0680---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    let token = 'ades';
                    data.writeChar(token);
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    let errCode = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
                    expect(error.code != errCode).assertTrue();
                    expect(error.message != null).assertTrue();
                } finally {
                    data.reclaim();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0680---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0690
             * @tc.name    : test Call the writestring interface to write the data to the MessageSequence instance,
             *             and call readstring() to read the data
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0690", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0690---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    let token = '';
                    for (let i = 0; i < (40 * K - 1); i++) {
                        token += 'a';
                    }
                    data.writeString(token);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_STRING, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readString()).assertEqual(token);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0690---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0700
             * @tc.name    : test Writestring interface Maximum data out of range verification
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0700", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0700---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    let token = '';
                    for (let i = 0; i < 40 * K; i++) {
                        token += 'a';
                    }
                    data.writeString(token);
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    let errCode = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
                    expect(error.code != errCode).assertTrue();
                    expect(error.message != null).assertTrue();
                } finally {
                    data.reclaim();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0700---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0710
             * @tc.name    : test Writestring interface, illegal value verification
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0710", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0710---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    let token = 123;
                    data.writeString(token);
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    let errCode = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
                    expect(error.code != errCode).assertTrue();
                    expect(error.message != null).assertTrue();
                } finally {
                    data.reclaim();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0710---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0720
             * @tc.name    : test Call the writebyte interface to write data to the MessageSequence instance,
             *             and call readbyte to read data
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0720", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0720---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    let token = 2;
                    data.writeByte(token);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_BYTE, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readByte()).assertEqual(token);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0720---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0730
             * @tc.name    : test Writebyte interface, boundary value verification
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0730", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0730---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    data.writeByte(128);
                    data.writeByte(0);
                    data.writeByte(1);
                    data.writeByte(2);
                    data.writeByte(127);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_BYTE_MULTI, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(reply.readByte()).assertEqual(-128);
                        expect(reply.readByte()).assertEqual(0);
                        expect(reply.readByte()).assertEqual(1);
                        expect(reply.readByte()).assertEqual(2);
                        expect(reply.readByte()).assertEqual(127);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0730---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0740
             * @tc.name    : test Writebyte interface, Maximum boundary value verification
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0740", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0740---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    data.writeByte(-129);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_BYTE, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readByte()).assertEqual(127);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0740---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0750
             * @tc.name    : test Writebyte interface, Minimum boundary value verification
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0750", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0750---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    data.writeByte(128);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_BYTE, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readByte()).assertEqual(-128);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0750---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0760
             * @tc.name    : test Writebyte interface, illegal value verification
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0760", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0760---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    data.writeByte("error");
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    let errCode = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
                    expect(error.code != errCode).assertTrue();
                    expect(error.message != null).assertTrue();
                } finally {
                    data.reclaim();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0760---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0770
             * @tc.name    : test Call the writeint interface to write the data to the MessageSequence instance,
             *             and call readint to read the data
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0770", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0770---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    let token = 2;
                    data.writeInt(token);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_INT, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readInt()).assertEqual(token);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0770---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0780
             * @tc.name    : test Writeint interface, boundary value verification
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0780", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0780---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    data.writeInt(-2147483648);
                    data.writeInt(0);
                    data.writeInt(1);
                    data.writeInt(2);
                    data.writeInt(2147483647);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_INT_MULTI, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readInt()).assertEqual(-2147483648);
                        expect(result.reply.readInt()).assertEqual(0);
                        expect(result.reply.readInt()).assertEqual(1);
                        expect(result.reply.readInt()).assertEqual(2);
                        expect(result.reply.readInt()).assertEqual(2147483647);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0780---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0790
             * @tc.name    : test Writeint interface, Verification of minimum boundary overrun value
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0790", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0790---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    data.writeInt(-2147483649);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_INT_MULTI, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readInt()).assertEqual(2147483647);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0790---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0800
             * @tc.name    : test Writeint interface, Verification of maximum boundary overrun value
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0800", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0800---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    data.writeInt(2147483648);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_INT_MULTI, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readInt()).assertEqual(-2147483648);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0800---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0810
             * @tc.name    : test Writeint interface, illegal value verification
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0810", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0810---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    data.writeInt("error");
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    let errCode = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
                    expect(error.code != errCode).assertTrue();
                    expect(error.message != null).assertTrue();
                } finally {
                    data.reclaim();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0810---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0820
             * @tc.name    : test Call the writefloat interface to write data to the MessageSequence instance,
             *             and call readfloat to read data
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0820", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0820---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    let token = 2.2;
                    data.writeFloat(token);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_FLOAT, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readFloat()).assertEqual(token);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0820---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0830
             * @tc.name    : test Writefloat interface, Minimum boundary value verification
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0830", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0830---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    let token = 1.4E-45;
                    data.writeFloat(token);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_FLOAT, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readFloat()).assertEqual(token);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0830---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0840
             * @tc.name    : test Writefloat interface, Maximum boundary value verification
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0840", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0840---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    let token = 3.4028235E38;
                    data.writeFloat(token);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_FLOAT, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readFloat()).assertEqual(token);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0840---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0850
             * @tc.name    : test Writefloat interface, Verification of maximum boundary overrun value
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0850", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0850---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    let token = (3.4028235E38) + 1;
                    data.writeFloat(token);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_FLOAT, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readFloat()).assertEqual(3.4028235e+38);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0850---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0860
             * @tc.name    : test Writefloat interface, Verification of minimum boundary overrun value
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0860", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0860---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    var reply = rpc.MessageSequence.create();
                    let option = new rpc.MessageOption();
                    let token = (1.4E-45) - 1;
                    data.writeFloat(token);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_FLOAT, data, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readFloat()).assertEqual(-1);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    data.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0860---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0870
             * @tc.name    : test Writefloat interface, illegal value validation
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0870", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0870---------------------------");
                try {
                    var data = rpc.MessageSequence.create();
                    let token = 'a';
                    data.writeFloat(token);
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    let errCode = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
                    expect(error.code != errCode).assertTrue();
                    expect(error.message != null).assertTrue();
                } finally {
                    data.reclaim();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0870---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0880
             * @tc.name    : test Call the getRawDataCapacity interface to get the maximum amount of raw data that a MessageSequence
                             can hold
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0880", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0880---------------------------");
                try {
                    var parcel = new rpc.MessageSequence();
                    var reply = new rpc.MessageSequence();
                    let option = new rpc.MessageOption();
                    expect(parcel.getRawDataCapacity()).assertEqual(128 * M);
                    let arr = [1, 2, 3, 4, 5];
                    parcel.writeIntArray(arr);
                    expect(parcel.getRawDataCapacity()).assertEqual(128 * M);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_INTARRAY, parcel, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.getRawDataCapacity()).assertEqual(128 * M);
                        let newReadResult = result.reply.readIntArray();
                        expect(newReadResult[0]).assertEqual(arr[0]);
                        expect(newReadResult[1]).assertEqual(arr[1]);
                        expect(newReadResult[2]).assertEqual(arr[2]);
                        expect(newReadResult[3]).assertEqual(arr[3]);
                        expect(newReadResult[4]).assertEqual(arr[4]);
                        expect(result.reply.getRawDataCapacity()).assertEqual(128 * M);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    parcel.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0880---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0890
             * @tc.name    : test Test MessageSequence to deliver rawdata data
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0890", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0890---------------------------");
                try {
                    var parcel = new rpc.MessageSequence();
                    var reply = new rpc.MessageSequence();
                    let option = new rpc.MessageOption();
                    let arr = [1, 2, 3, 4, 5];
                    parcel.writeInt(arr.length);
                    parcel.writeRawData(arr, arr.length);
                    expect(parcel.getRawDataCapacity()).assertEqual(128 * M);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_RAWDATA, parcel, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        let size = result.reply.readInt();
                        expect(size).assertEqual(arr.length);
                        expect(result.reply.getRawDataCapacity()).assertEqual(128 * M);
                        let newReadResult = result.reply.readRawData(size);
                        expect(newReadResult[0]).assertEqual(arr[0]);
                        expect(newReadResult[1]).assertEqual(arr[1]);
                        expect(newReadResult[2]).assertEqual(arr[2]);
                        expect(newReadResult[3]).assertEqual(arr[3]);
                        expect(newReadResult[4]).assertEqual(arr[4]);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    parcel.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0890---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0900
             * @tc.name    : test Test MessageSequence to pass abnormal rawdata data, and expand the capacity for verification
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0900", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0900---------------------------");
                try {
                    var parcel = new rpc.MessageSequence();
                    var reply = new rpc.MessageSequence();
                    let option = new rpc.MessageOption();
                    let arr = [1, 2, 3, 4, 5];
                    parcel.writeInt(arr.length + 1);
                    parcel.writeRawData(arr, (arr.length + 1));
                    expect(parcel.getRawDataCapacity()).assertEqual(128 * M);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_RAWDATA, parcel, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        let size = result.reply.readInt();
                        expect(size).assertEqual(arr.length + 1);
                        expect(result.reply.getRawDataCapacity()).assertEqual(128 * M);
                        let newReadResult = result.reply.readRawData(size);
                        expect(newReadResult[0]).assertEqual(arr[0]);
                        expect(newReadResult[1]).assertEqual(arr[1]);
                        expect(newReadResult[2]).assertEqual(arr[2]);
                        expect(newReadResult[3]).assertEqual(arr[3]);
                        expect(newReadResult[4]).assertEqual(arr[4]);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    parcel.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0900---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0910
             * @tc.name    : test Test MessageSequence to pass exception rawdata data data interception verification
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 1
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0910", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0910---------------------------");
                try {
                    var parcel = new rpc.MessageSequence();
                    var reply = new rpc.MessageSequence();
                    let option = new rpc.MessageOption();
                    let arr = [1, 2, 3, 4, 5];
                    parcel.writeInt(arr.length - 1);
                    parcel.writeRawData(arr, (arr.length - 1));
                    expect(parcel.getRawDataCapacity()).assertEqual(128 * M);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_RAWDATA, parcel, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        let size = result.reply.readInt();
                        expect(size).assertEqual(arr.length - 1);
                        expect(result.reply.getRawDataCapacity()).assertEqual(128 * M);
                        let newReadResult = result.reply.readRawData(size);
                        expect(newReadResult[0]).assertEqual(arr[0]);
                        expect(newReadResult[1]).assertEqual(arr[1]);
                        expect(newReadResult[2]).assertEqual(arr[2]);
                        expect(newReadResult[3]).assertEqual(arr[3]);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    parcel.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0910---------------------------");
            });

            /*
             * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0920
             * @tc.name    : test Test MessageSequence to deliver out-of-bounds RawData data
             * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
             * @tc.level   : Level 3
             * @tc.type    : Compatibility
             * @tc.size    : MediumTest
             */
            it("SUB_DSoftbus_IPC_API_MessageSequence_0920", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
                console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0920---------------------------");
                try {
                    var parcel = new rpc.MessageSequence();
                    var reply = new rpc.MessageSequence();
                    let option = new rpc.MessageOption();
                    let arr = [-129, 2, 3, 4, 128];
                    parcel.writeInt(arr.length);
                    parcel.writeRawData(arr, arr.length);
                    expect(parcel.getRawDataCapacity()).assertEqual(128 * M);
                    expect(gIRemoteObject != undefined).assertTrue();
                    await gIRemoteObject.sendMessageRequest(CODE_WRITE_RAWDATA, parcel, reply, option).then((result) => {
                        expect(result.errCode).assertEqual(0);
                        let size = result.reply.readInt();
                        expect(size).assertEqual(arr.length);
                        expect(result.reply.getRawDataCapacity()).assertEqual(128 * M);
                        let newReadResult = result.reply.readRawData(size);
                        expect(newReadResult[0]).assertEqual(arr[0]);
                        expect(newReadResult[1]).assertEqual(arr[1]);
                        expect(newReadResult[2]).assertEqual(arr[2]);
                        expect(newReadResult[3]).assertEqual(arr[3]);
                        expect(newReadResult[4]).assertEqual(arr[4]);
                    });
                } catch (error) {
                    console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                    expect(error == null).assertTrue();
                } finally {
                    parcel.reclaim();
                    reply.reclaim();
                    done();
                }
                console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0920---------------------------");
            });

    console.info("-----------------------SUB_DSoftbus_IPC_API_Stage_MessageSequence_Test is end-----------------------");
  })
}