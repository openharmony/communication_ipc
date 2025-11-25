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

    /**
         * @tc.number   SUB_IPC_IPCSkeleton_getCallingTokenId_0100
         * @tc.name     SUB_IPC_IPCSkeleton_getCallingTokenId_0100
         * @tc.desc     test IPCSkeleton getCallingTokenId
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_IPCSkeleton_getCallingTokenId_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_IPCSkeleton_getCallingTokenId_0100 --------------------')

            try {
                let callerTokenId = rpc.IPCSkeleton.getCallingTokenId();
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_IPCSkeleton_getCallingTokenId_0100 callerTokenId is: ' + callerTokenId)
            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_IPCSkeleton_getCallingTokenId_0100 error is: ' + error)
                expect(error == null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_IPCSkeleton_getCallingTokenId_0100 finally done')
            }

            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_IPCSkeleton_getCallingTokenId_0100 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_MessageSequence_writeRemoteObject_0100
         * @tc.name     SUB_IPC_MessageSequence_writeRemoteObject_0100
         * @tc.desc     test MessageSequence writeRemoteObject
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_writeRemoteObject_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_writeRemoteObject_0100 --------------------')

            let data =  rpc.MessageSequence.create();
            try {
                let testRemoteObject = new TestRemoteObject("testObject");
                data.writeRemoteObject(testRemoteObject);
            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeRemoteObject_0100 error is: ' + error)
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeRemoteObject_0100 reclaim done')
            }

            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeRemoteObject_0100 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_MessageSequence_writeRemoteObject_readRemoteObject_0100
         * @tc.name     SUB_IPC_MessageSequence_writeRemoteObject_readRemoteObject_0100
         * @tc.desc     test MessageSequence writeRemoteObject and readRemoteObject
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_writeRemoteObject_readRemoteObject_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_writeRemoteObject_readRemoteObject_0100 --------------------')

            let data =  rpc.MessageSequence.create();
            try {
                let testRemoteObject = new TestRemoteObject("testObject");
                data.writeRemoteObject(testRemoteObject);
                let res = data.readRemoteObject();
            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeRemoteObject_readRemoteObject_0100 error is: ' + error)
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeRemoteObject_readRemoteObject_0100 reclaim done')
            }

            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeRemoteObject_readRemoteObject_0100 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_RemoteObject_sendMessageRequest_0100
         * @tc.name     SUB_IPC_RemoteObject_sendMessageRequest_0100
         * @tc.desc     test RemoteObject sendMessageRequest
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_RemoteObject_sendMessageRequest_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_RemoteObject_sendMessageRequest_0100 --------------------')

            let data = rpc.MessageSequence.create();
            let reply = rpc.MessageSequence.create();
            try {
                let testRemoteObject = new TestRemoteObject("testObject");
                let option = new rpc.MessageOption();
                data.writeInt(666);
                testRemoteObject.sendMessageRequest(1, data, reply, option);
                await Utils.msSleep(1000)
                let res = reply.readInt();
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_sendMessageRequest_0100 res is: ' + res)
                expect(res == 999).assertTrue();
            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_sendMessageRequest_0100 error is: ' + error)
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_sendMessageRequest_0100 reclaim done')
            }

            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_RemoteObject_sendMessageRequest_0100 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_RemoteObject_sendMessageRequest_0200
         * @tc.name     SUB_IPC_RemoteObject_sendMessageRequest_0200
         * @tc.desc     test RemoteObject sendMessageRequest SYNC
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_RemoteObject_sendMessageRequest_0200", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_RemoteObject_sendMessageRequest_0200 --------------------')

            let data = rpc.MessageSequence.create();
            let reply = rpc.MessageSequence.create();
            try {
                let testRemoteObject = new TestRemoteObject("testObject");
                let option = new rpc.MessageOption();
                option.setAsync(false);
                data.writeInt(666);
                testRemoteObject.sendMessageRequest(1, data, reply, option);
                await Utils.msSleep(1000)
                let res = reply.readInt();
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_sendMessageRequest_0200 res is: ' + res)
                expect(res == 999).assertTrue();
            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_sendMessageRequest_0200 error is: ' + error)
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_sendMessageRequest_0200 reclaim done')
            }

            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_RemoteObject_sendMessageRequest_0200 --------------------')
        });

        /**
        * @tc.number   SUB_IPC_RemoteObject_sendMessageRequest_0300
        * @tc.name     SUB_IPC_RemoteObject_sendMessageRequest_0300
        * @tc.desc     test RemoteObject sendMessageRequest ASYNC
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
       */
        it("SUB_IPC_RemoteObject_sendMessageRequest_0300", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_RemoteObject_sendMessageRequest_0300 --------------------')

            let data = rpc.MessageSequence.create();
            let reply = rpc.MessageSequence.create();
            try {
                let testRemoteObject = new TestRemoteObject("testObject");
                let option = new rpc.MessageOption();
                option.setAsync(true);
                data.writeInt(666);
                testRemoteObject.sendMessageRequest(1, data, reply, option);
                await Utils.msSleep(1000)
                let res = reply.readInt();
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_sendMessageRequest_0300 res is: ' + res)
                expect(res == 999).assertTrue();
            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_sendMessageRequest_0300 error is: ' + error)
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_sendMessageRequest_0300 reclaim done')
            }

            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_RemoteObject_sendMessageRequest_0300 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_RemoteObject_sendMessageRequest_0400
         * @tc.name     SUB_IPC_RemoteObject_sendMessageRequest_0400
         * @tc.desc     test RemoteObject sendMessageRequest SYNC
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_RemoteObject_sendMessageRequest_0400", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_RemoteObject_sendMessageRequest_0400 --------------------')

            let data = rpc.MessageSequence.create();
            let reply = rpc.MessageSequence.create();
            try {
                let testRemoteObject = new TestRemoteObject("testObject");
                let option = new rpc.MessageOption();
                option.setAsync(false);
                data.writeInt(666);
                await testRemoteObject.sendMessageRequest(1, data, reply, option)
                    .then((ret: rpc.RequestResult) => {
                        hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_sendMessageRequest_0400 .then.data is: ' + JSON.stringify(ret.data) );
                        hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_sendMessageRequest_0400 .then.reply is: ' + JSON.stringify(ret.reply) );
                        let res = reply.readInt();
                        hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_sendMessageRequest_0400 res is: ' + res)
                        expect(res == 999).assertTrue();
                    }).catch((err) => {
                    hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_sendMessageRequest_0400 err in catch is: ' + err);
                });

            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_sendMessageRequest_0400 error is: ' + error)
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_sendMessageRequest_0400 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_RemoteObject_sendMessageRequest_0400 --------------------')
        });

       /**
        * @tc.number   SUB_IPC_RemoteObject_sendMessageRequest_Callback_0100
        * @tc.name     SUB_IPC_RemoteObject_sendMessageRequest_Callback_0100
        * @tc.desc     test RemoteObject sendMessageRequest
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
        */
        it("SUB_IPC_RemoteObject_sendMessageRequest_Callback_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_RemoteObject_sendMessageRequest_Callback_0100 --------------------')

            let data = rpc.MessageSequence.create();
            let reply = rpc.MessageSequence.create();
            try {
                let testRemoteObject = new TestRemoteObject("testObject");
                let option = new rpc.MessageOption();
                data.writeInt(666);
                testRemoteObject.sendMessageRequest(1, data, reply, option, sendMessageRequestCallback);
                await Utils.msSleep(1000)

            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_sendMessageRequest_Callback_0100 error is: ' + error)
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_sendMessageRequest_Callback_0100 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_RemoteObject_sendMessageRequest_Callback_0100 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_RemoteObject_getDescriptor_0100
         * @tc.name     SUB_IPC_RemoteObject_getDescriptor_0100
         * @tc.desc     test RemoteObject getDescriptor
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_RemoteObject_getDescriptor_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_RemoteObject_getDescriptor_0100 --------------------')

            let data = rpc.MessageSequence.create();
            let reply = rpc.MessageSequence.create();
            try {
                let testRemoteObject = new TestRemoteObject("testObject");
                let res = testRemoteObject.getDescriptor();
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_getDescriptor_0100 res is: ' + res)
                expect(res == "testObject").assertTrue();
            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_getDescriptor_0100 error is: ' + error)
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_getDescriptor_0100 reclaim done')
            }

            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_RemoteObject_getDescriptor_0100 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_RemoteObject_getCallingPid_0100
         * @tc.name     SUB_IPC_RemoteObject_getCallingPid_0100
         * @tc.desc     test RemoteObject getCallingPid
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_RemoteObject_getCallingPid_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_RemoteObject_getCallingPid_0100 --------------------')

            try {
                let testRemoteObject = new TestRemoteObject("testObject");
                let res = testRemoteObject.getCallingPid();
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_getCallingPid_0100 res is: ' + res);
                expect(res == rpc.IPCSkeleton.getCallingPid()).assertTrue();
            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_getCallingPid_0100 error is: ' + error)
                expect(error == null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_getCallingPid_0100 finally done')
            }

            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_RemoteObject_getCallingPid_0100 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_RemoteObject_getCallingUid_0100
         * @tc.name     SUB_IPC_RemoteObject_getCallingUid_0100
         * @tc.desc     test RemoteObject getCallingUid
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_RemoteObject_getCallingUid_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_RemoteObject_getCallingUid_0100 --------------------')

            try {
                let testRemoteObject = new TestRemoteObject("testObject");
                let res = testRemoteObject.getCallingUid();
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_getCallingUid_0100 res is: ' + res);
                expect(res == rpc.IPCSkeleton.getCallingUid()).assertTrue();
            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_getCallingUid_0100 error is: ' + error)
                expect(error == null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteObject_getCallingUid_0100 finally done')
            }

            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_RemoteObject_getCallingUid_0100 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_registerDeathRecipient_0100
         * @tc.name     SUB_IPC_registerDeathRecipient_0100
         * @tc.desc     test registerDeathRecipient
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_registerDeathRecipient_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_registerDeathRecipient_0100 --------------------')

            try {
                let deathRecipient = new MyDeathRecipient();
                let samgr = rpc.IPCSkeleton.getContextObject();
                samgr.registerDeathRecipient(deathRecipient, 0);
                samgr.unregisterDeathRecipient(deathRecipient, 0);
            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_registerDeathRecipient_0100 error is: ' + error)
                expect(error == null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_registerDeathRecipient_0100 finally done')
            }

            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_registerDeathRecipient_0100 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_RemoteProxy_SendMessageRequest_0100
         * @tc.name     SUB_IPC_RemoteProxy_SendMessageRequest_0100
         * @tc.desc     test RemoteProxy SendMessageRequest
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_RemoteProxy_SendMessageRequest_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_RemoteProxy_SendMessageRequest_0100 --------------------')

            let data = rpc.MessageSequence.create();
            let reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            try {
                // CheckSystemAbility
                data.writeInterfaceToken("ohos.samgr.accessToken");
                data.writeInt(4700);
                data.writeBoolean(true);

                let samgr = rpc.IPCSkeleton.getContextObject();

                await samgr.sendMessageRequest(12, data, reply, option)
                    .then((ret: rpc.RequestResult) => {
                        hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteProxy_SendMessageRequest_0100 .then.errCode is: ' + ret.errCode);
                        hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteProxy_SendMessageRequest_0100 .then.code is: ' + ret.code);
                        hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteProxy_SendMessageRequest_0100 .then.reply is: ' + ret.reply);
                    }).catch((err) => {
                        hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteProxy_SendMessageRequest_0100 err in catch is: ' + err);
                    });
            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteProxy_SendMessageRequest_0100 error is: ' + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteProxy_SendMessageRequest_0100 reclaim done')
            }

            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_RemoteProxy_SendMessageRequest_0100 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_RemoteProxy_SendMessageRequest_WriteAndRead_0100
         * @tc.name     SUB_IPC_RemoteProxy_SendMessageRequest_WriteAndRead_0100
         * @tc.desc     test RemoteProxy SendMessageRequest after write and read Proxy
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_RemoteProxy_SendMessageRequest_WriteAndRead_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_RemoteProxy_SendMessageRequest_WriteAndRead_0100 --------------------')

            let dataM = rpc.MessageSequence.create();

            let data = rpc.MessageSequence.create();
            let reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            try {
                // CheckSystemAbility
                data.writeInterfaceToken("ohos.samgr.accessToken");
                data.writeInt(4700);
                data.writeBoolean(true);

                let samgr = rpc.IPCSkeleton.getContextObject();

                dataM.writeRemoteObject(samgr);
                let res = dataM.readRemoteObject();

                await res.sendMessageRequest(12, data, reply, option)
                    .then((ret: rpc.RequestResult) => {
                        hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteProxy_SendMessageRequest_WriteAndRead_0100 .then.errCode is: ' + ret.errCode);
                        hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteProxy_SendMessageRequest_WriteAndRead_0100 .then.code is: ' + ret.code);
                        hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteProxy_SendMessageRequest_WriteAndRead_0100 .then.data is: ' + JSON.stringify(ret.data) );
                        expect(ret.data != null).assertTrue();
                        hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteProxy_SendMessageRequest_WriteAndRead_0100 .then.reply is: ' + JSON.stringify(ret.reply) );
                    }).catch((err) => {
                        hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteProxy_SendMessageRequest_WriteAndRead_0100 err in catch is: ' + err);
                    });
            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteProxy_SendMessageRequest_WriteAndRead_0100 error is: ' + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteProxy_SendMessageRequest_WriteAndRead_0100 reclaim done')
            }

            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_RemoteProxy_SendMessageRequest_WriteAndRead_0100 --------------------')
        });

        /**
        * @tc.number   SUB_IPC_RemoteProxy_SendMessageRequest_Callback_0100
        * @tc.name     SUB_IPC_RemoteProxy_SendMessageRequest_Callback_0100
        * @tc.desc     test RemoteProxy SendMessageRequest  callback after write and read Proxy
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
        */
        it("SUB_IPC_RemoteProxy_SendMessageRequest_Callback_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_RemoteProxy_SendMessageRequest_Callback_0100 --------------------')

            let dataM = rpc.MessageSequence.create();

            let data = rpc.MessageSequence.create();
            let reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            try {
                // CheckSystemAbility
                data.writeInterfaceToken("ohos.samgr.accessToken");
                data.writeInt(4700);
                data.writeBoolean(true);

                let samgr = rpc.IPCSkeleton.getContextObject();

                dataM.writeRemoteObject(samgr);
                let res = dataM.readRemoteObject();

                res.sendMessageRequest(12, data, reply, option, sendMessageRequestCallback_Proxy);

            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteProxy_SendMessageRequest_Callback_0100 error is: ' + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteProxy_SendMessageRequest_Callback_0100 reclaim done')
            }

            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_RemoteProxy_SendMessageRequest_Callback_0100 --------------------')
        });

        /**
        * @tc.number   SUB_IPC_RemoteProxy_IsObjectDead_0100
        * @tc.name     SUB_IPC_RemoteProxy_IsObjectDead_0100
        * @tc.desc     test RemoteProxy IsObjectDead
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
        */
        it("SUB_IPC_RemoteProxy_IsObjectDead_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_RemoteProxy_IsObjectDead_0100 --------------------')

            let dataM = rpc.MessageSequence.create();

            let data = rpc.MessageSequence.create();
            let reply = rpc.MessageSequence.create();
            let option = new rpc.MessageOption();
            try {
                // CheckSystemAbility
                data.writeInterfaceToken("ohos.samgr.accessToken");
                data.writeInt(4700);
                data.writeBoolean(true);

                let samgr = rpc.IPCSkeleton.getContextObject();

                dataM.writeRemoteObject(samgr);
                let res = dataM.readRemoteObject();

                let result = res.isObjectDead();
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteProxy_IsObjectDead_0100 result is: ' + result);
                expect(result).assertFalse();
            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteProxy_IsObjectDead_0100 error is: ' + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteProxy_IsObjectDead_0100 reclaim done')
            }

            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_RemoteProxy_IsObjectDead_0100 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_RemoteProxy_getDescriptor_0100
         * @tc.name     SUB_IPC_RemoteProxy_getDescriptor_0100
         * @tc.desc     test RemoteProxy getDescriptor
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
         */
        it("SUB_IPC_RemoteProxy_getDescriptor_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
          await Utils.msSleep(200)
          hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_RemoteProxy_getDescriptor_0100 --------------------')

          let dataM = rpc.MessageSequence.create();

          let data = rpc.MessageSequence.create();
          let option = new rpc.MessageOption();
          try {
            // CheckSystemAbility
            data.writeInterfaceToken("ohos.samgr.accessToken");
            data.writeInt(4700);
            data.writeBoolean(true);

            let samgr = rpc.IPCSkeleton.getContextObject();

            dataM.writeRemoteObject(samgr);
            let res = dataM.readRemoteObject();
            let reult = res.getDescriptor();
            expect(reult == "").assertTrue();
          } catch (error) {
            hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteProxy_getDescriptor_0100 error is: ' + error);
            expect(error == null).assertTrue();
          } finally {
            data.reclaim();
            hilog.info(domain, tag, '%{public}s', 'SUB_IPC_RemoteProxy_getDescriptor_0100 reclaim done')
          }
          done()
          hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_RemoteProxy_getDescriptor_0100 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_IRemoteBroker_asObject_0100
         * @tc.name     SUB_IPC_IRemoteBroker_asObject_0100
         * @tc.desc     test asObject
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
         */
        it("SUB_IPC_IRemoteBroker_asObject_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
          await Utils.msSleep(200)
          hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_IRemoteBroker_asObject_0100 --------------------')

          let data = rpc.MessageSequence.create();
          let reply = rpc.MessageSequence.create();
          try {
            let testRemoteObject = new TestStub("testObject");
            let testRemoteObject1 = testRemoteObject.asObject();
            let option = new rpc.MessageOption();
            option.setAsync(false);
            data.writeInt(666);
            await testRemoteObject1.sendMessageRequest(1, data, reply, option)
              .then((ret: rpc.RequestResult) => {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_IRemoteBroker_asObject_0100 .then.data is: ' + JSON.stringify(ret.data) );
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_IRemoteBroker_asObject_0100 .then.reply is: ' + JSON.stringify(ret.reply) );
                let res = reply.readInt();
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_IRemoteBroker_asObject_0100 res is: ' + res)
                expect(res == 123).assertTrue();
              }).catch((err) => {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_IRemoteBroker_asObject_0100 err in catch is: ' + err);
              });
          } catch (error) {
            hilog.info(domain, tag, '%{public}s', 'SUB_IPC_IRemoteBroker_asObject_0100 error is: ' + error);
            expect(error == null).assertTrue();
          } finally {
            data.reclaim();
            hilog.info(domain, tag, '%{public}s', 'SUB_IPC_IRemoteBroker_asObject_0100 reclaim done')
          }
          done()
          hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_IRemoteBroker_asObject_0100 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_MessageSequence_writeRemoteObject_ErrorCode_0100
         * @tc.name     SUB_IPC_MessageSequence_writeRemoteObject_ErrorCode_0100
         * @tc.desc     test writeRemoteObject errCode
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
         */
        it("SUB_IPC_MessageSequence_writeRemoteObject_ErrorCode_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL3, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_writeRemoteObject_ErrorCode_0100 --------------------')
            let data = rpc.MessageSequence.create();
            try {
                let testRemoteObject = new TestRemoteObject("testObject");
                data.reclaim();
                data.writeRemoteObject(testRemoteObject)
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeRemoteObject_ErrorCode_0100 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeRemoteObject_ErrorCode_0100 error code is: ' + err.code);
                expect(err.code == 1900009).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeRemoteObject_ErrorCode_0100 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeRemoteObject_ErrorCode_0100 --------------------')
        });

        /**
        * @tc.number   SUB_IPC_MessageSequence_readRemoteObject_ErrorCode_0100
        * @tc.name     SUB_IPC_MessageSequence_readRemoteObject_ErrorCode_0100
        * @tc.desc     test readRemoteObject errCode
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_readRemoteObject_ErrorCode_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL3, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_readRemoteObject_ErrorCode_0100 --------------------')
            let data = rpc.MessageSequence.create();
            try {
                let testRemoteObject = new TestRemoteObject("testObject");
                data.writeRemoteObject(testRemoteObject);
                data.reclaim();
                data.readRemoteObject();
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readRemoteObject_ErrorCode_0100 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readRemoteObject_ErrorCode_0100 error code is: ' + err.code);
                expect(err.code == 1900010).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readRemoteObject_ErrorCode_0100 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeRemoteObject_ErrorCode_0200 --------------------')
        });

        /**
        * @tc.number   SUB_IPC_MessageSequence_writeInterfaceToken_ErrorCode_0100
        * @tc.name     SUB_IPC_MessageSequence_writeInterfaceToken_ErrorCode_0100
        * @tc.desc     test writeInterfaceToken errCode
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_writeInterfaceToken_ErrorCode_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL3, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_writeInterfaceToken_ErrorCode_0100 --------------------')
            let data = rpc.MessageSequence.create();
            try {
                data.reclaim();
                data.writeInterfaceToken("ipctest");
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeInterfaceToken_ErrorCode_0100 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeInterfaceToken_ErrorCode_0100 error code is: ' + err.code);
                expect(err.code == 1900009).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeInterfaceToken_ErrorCode_0100 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeInterfaceToken_ErrorCode_0100 --------------------')
        });

        /**
        * @tc.number   SUB_IPC_MessageSequence_readInterfaceToken_ErrorCode_0100
        * @tc.name     SUB_IPC_MessageSequence_readInterfaceToken_ErrorCode_0100
        * @tc.desc     test readInterfaceToken errCode
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_readInterfaceToken_ErrorCode_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL3, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_readInterfaceToken_ErrorCode_0100 --------------------')
            let data = rpc.MessageSequence.create();
            try {
                data.writeInterfaceToken("testRemoteObject");
                data.reclaim();
                data.readInterfaceToken();
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readInterfaceToken_ErrorCode_0100 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readInterfaceToken_ErrorCode_0100 error code is: ' + err.code);
                expect(err.code == 1900010).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readInterfaceToken_ErrorCode_0100 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_readInterfaceToken_ErrorCode_0100 --------------------')
        });

        /**
        * @tc.number   SUB_IPC_MessageSequence_setCapacity_ErrorCode_0100
        * @tc.name     SUB_IPC_MessageSequence_setCapacity_ErrorCode_0100
        * @tc.desc     test setCapacity errCode
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_setCapacity_ErrorCode_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL3, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_setCapacity_ErrorCode_0100 --------------------')
            let data = rpc.MessageSequence.create();
            try {
                data.reclaim();
                data.setCapacity(64);
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_setCapacity_ErrorCode_0100 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_setCapacity_ErrorCode_0100 error code is: ' + err.code);
                expect(err.code == 1900009).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_setCapacity_ErrorCode_0100 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_setCapacity_ErrorCode_0100 --------------------')
        });

        /**
        * @tc.number   SUB_IPC_MessageSequence_writeNoException_ErrorCode_0100
        * @tc.name     SUB_IPC_MessageSequence_writeNoException_ErrorCode_0100
        * @tc.desc     test writeNoException errCode
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_writeNoException_ErrorCode_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL3, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_writeNoException_ErrorCode_0100 --------------------')
            let data = rpc.MessageSequence.create();
            try {
                data.reclaim();
                data.writeNoException();
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeNoException_ErrorCode_0100 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeNoException_ErrorCode_0100 error code is: ' + err.code);
                expect(err.code == 1900009).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeNoException_ErrorCode_0100 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeNoException_ErrorCode_0100 --------------------')
        });

        /**
        * @tc.number   SUB_IPC_MessageSequence_readException_ErrorCode_0100
        * @tc.name     SUB_IPC_MessageSequence_readException_ErrorCode_0100
        * @tc.desc     test readException errCode
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_readException_ErrorCode_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL3, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_readException_ErrorCode_0100 --------------------')
            let data = rpc.MessageSequence.create();
            try {
                data.reclaim();
                data.readException();
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readException_ErrorCode_0100 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readException_ErrorCode_0100 error code is: ' + err.code);
                expect(err.code == 1900010).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readException_ErrorCode_0100 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_readException_ErrorCode_0100 --------------------')
        });

        /**
        * @tc.number   SUB_IPC_MessageSequence_writeInt_ErrorCode_0100
        * @tc.name     SUB_IPC_MessageSequence_writeInt_ErrorCode_0100
        * @tc.desc     test writeInt errCode
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_writeInt_ErrorCode_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL3, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_writeInt_ErrorCode_0100 --------------------')
            let data = rpc.MessageSequence.create();
            try {
                data.reclaim();
                data.writeInt(0);
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeInt_ErrorCode_0100 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeInt_ErrorCode_0100 error code is: ' + err.code);
                expect(err.code == 1900009).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeInt_ErrorCode_0100 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeInt_ErrorCode_0100 --------------------')
        });

        /**
        * @tc.number   SUB_IPC_MessageSequence_readInt_ErrorCode_0100
        * @tc.name     SUB_IPC_MessageSequence_readInt_ErrorCode_0100
        * @tc.desc     test readInt errCode
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_readInt_ErrorCode_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL3, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_readInt_ErrorCode_0100 --------------------')
            let data = rpc.MessageSequence.create();
            try {
                data.writeInt(0);
                data.reclaim();
                data.readInt();
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readInt_ErrorCode_0100 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readInt_ErrorCode_0100 error code is: ' + err.code);
                expect(err.code == 1900010).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readInt_ErrorCode_0100 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_readInt_ErrorCode_0100 --------------------')
        });

        /**
        * @tc.number   SUB_IPC_MessageSequence_writeLong_ErrorCode_0100
        * @tc.name     SUB_IPC_MessageSequence_writeLong_ErrorCode_0100
        * @tc.desc     test writeLong errCode
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_writeLong_ErrorCode_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL3, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_writeLong_ErrorCode_0100 --------------------')
            let data = rpc.MessageSequence.create();
            try {
                data.reclaim();
                data.writeLong(0);
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeLong_ErrorCode_0100 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeLong_ErrorCode_0100 error code is: ' + err.code);
                expect(err.code == 1900009).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeLong_ErrorCode_0100 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeLong_ErrorCode_0100 --------------------')
        });

        /**
        * @tc.number   SUB_IPC_MessageSequence_readLong_ErrorCode_0100
        * @tc.name     SUB_IPC_MessageSequence_readLong_ErrorCode_0100
        * @tc.desc     test readLong errCode
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_readLong_ErrorCode_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL3, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_readLong_ErrorCode_0100 --------------------')
            let data = rpc.MessageSequence.create();
            try {
                data.writeLong(0);
                data.reclaim();
                data.readLong();
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readLong_ErrorCode_0100 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readLong_ErrorCode_0100 error code is: ' + err.code);
                expect(err.code == 1900010).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readLong_ErrorCode_0100 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_readLong_ErrorCode_0100 --------------------')
        });

        /**
        * @tc.number   SUB_IPC_MessageSequence_readDoubleArray_ErrorCode_0100
        * @tc.name     SUB_IPC_MessageSequence_readDoubleArray_ErrorCode_0100
        * @tc.desc     test readDoubleArray errCode
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_readDoubleArray_ErrorCode_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL3, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_readDoubleArray_ErrorCode_0100 --------------------')
            let data = rpc.MessageSequence.create();
            try {
                let input: Array<double> = [1.1, 2.1, 3.1, 4.1, 5.1, 6.1, 7.1, 8.1, 9.1];
                data.writeDoubleArray(input);
                let res: Array<double> = new Array<double>(input.length);
                data.reclaim();
                data.readDoubleArray(res);
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readDoubleArray_ErrorCode_0100 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readDoubleArray_ErrorCode_0100 error code is: ' + err.code);
                expect(err.code == 1900010).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readDoubleArray_ErrorCode_0100 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_readDoubleArray_ErrorCode_0100 --------------------')
        });

        /**
        * @tc.number   SUB_IPC_MessageSequence_readDoubleArray_ErrorCode_0200
        * @tc.name     SUB_IPC_MessageSequence_readDoubleArray_ErrorCode_0200
        * @tc.desc     test readDoubleArray errCode
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_readDoubleArray_ErrorCode_0200", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL3, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_readDoubleArray_ErrorCode_0200 --------------------')
            let data = rpc.MessageSequence.create();
            try {
                let input: Array<double> = [1.1, 2.1, 3.1, 4.1, 5.1, 6.1, 7.1, 8.1, 9.1];
                data.writeDoubleArray(input);
                data.reclaim();
                let res = data.readDoubleArray();
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readDoubleArray_ErrorCode_0200 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readDoubleArray_ErrorCode_0200 error code is: ' + err.code);
                expect(err.code == 1900010).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                data.reclaim();
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readDoubleArray_ErrorCode_0200 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_readDoubleArray_ErrorCode_0200 --------------------')
        });

        /**
        * @tc.number   SUB_IPC_MessageSequence_writeBooleanArray_ErrorCode_0100
        * @tc.name     SUB_IPC_MessageSequence_writeBooleanArray_ErrorCode_0100
        * @tc.desc     test writeBooleanArray errCode
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_writeBooleanArray_ErrorCode_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL3, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_writeBooleanArray_ErrorCode_0100 --------------------')
            let data = rpc.MessageSequence.create();
            try {
                let input: Array<Boolean> = [false, true, false, true, false, true, false, true, false, true];
                data.reclaim();
                data.writeBooleanArray(input);
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeBooleanArray_ErrorCode_0100 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeBooleanArray_ErrorCode_0100 error code is: ' + err.code);
                expect(err.code == 1900009).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeBooleanArray_ErrorCode_0100 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeBooleanArray_ErrorCode_0100 --------------------')
        });

        /**
        * @tc.number   SUB_IPC_MessageSequence_readBooleanArray_ErrorCode_0100
        * @tc.name     SUB_IPC_MessageSequence_readBooleanArray_ErrorCode_0100
        * @tc.desc     test readBooleanArray errCode
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_readBooleanArray_ErrorCode_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL3, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_readBooleanArray_ErrorCode_0100 --------------------')
            let data = rpc.MessageSequence.create();
            try {
                let input: Array<Boolean> = [false, true, false, true, false, true, false, true, false, true];
                data.writeBooleanArray(input);
                let res: Array<Boolean> = new Array<Boolean>(input.length);
                data.reclaim();
                data.readBooleanArray(res);
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readBooleanArray_ErrorCode_0100 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readBooleanArray_ErrorCode_0100 error code is: ' + err.code);
                expect(err.code == 1900010).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readBooleanArray_ErrorCode_0100 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_readBooleanArray_ErrorCode_0100 --------------------')
        });

        /**
        * @tc.number   SUB_IPC_MessageSequence_readBooleanArray_ErrorCode_0200
        * @tc.name     SUB_IPC_MessageSequence_readBooleanArray_ErrorCode_0200
        * @tc.desc     test readBooleanArray errCode
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_readBooleanArray_ErrorCode_0200", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL3, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_readBooleanArray_ErrorCode_0200 --------------------')
            let data = rpc.MessageSequence.create();
            try {
                let input: Array<Boolean> = [false, true, false, true, false, true, false, true, false, true];
                data.writeBooleanArray(input);
                data.reclaim();
                let res = data.readBooleanArray();
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readBooleanArray_ErrorCode_0200 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readBooleanArray_ErrorCode_0200 error code is: ' + err.code);
                expect(err.code == 1900010).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                data.reclaim();
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readBooleanArray_ErrorCode_0200 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_readBooleanArray_ErrorCode_0200 --------------------')
        });

        /**
        * @tc.number   SUB_IPC_MessageSequence_writeStringArray_ErrorCode_0100
        * @tc.name     SUB_IPC_MessageSequence_writeStringArray_ErrorCode_0100
        * @tc.desc     test writeStringArray errCode
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_writeStringArray_ErrorCode_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL3, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_writeStringArray_ErrorCode_0100 --------------------')
            let data = rpc.MessageSequence.create();
            try {
                let input: Array<String> = ["this", "is", "a", "test", "stirng", "array"];
                data.reclaim();
                data.writeStringArray(input);
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeStringArray_ErrorCode_0100 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeStringArray_ErrorCode_0100 error code is: ' + err.code);
                expect(err.code == 1900009).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeStringArray_ErrorCode_0100 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeStringArray_ErrorCode_0100 --------------------')
        });

        /**
        * @tc.number   SUB_IPC_MessageSequence_readStringArray_ErrorCode_0100
        * @tc.name     SUB_IPC_MessageSequence_readStringArray_ErrorCode_0100
        * @tc.desc     test readStringArray errCode
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_readStringArray_ErrorCode_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL3, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_readStringArray_ErrorCode_0100 --------------------')
            let data = rpc.MessageSequence.create();
            try {
                let input: Array<String> = ["this", "is", "a", "test", "stirng", "array"];
                data.writeStringArray(input);
                let res: Array<String> = new Array<String>(input.length);
                data.reclaim();
                data.readStringArray(res);
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readStringArray_ErrorCode_0100 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readStringArray_ErrorCode_0100 error code is: ' + err.code);
                expect(err.code == 1900010).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readStringArray_ErrorCode_0100 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_readStringArray_ErrorCode_0100 --------------------')
        });

        /**
        * @tc.number   SUB_IPC_MessageSequence_readStringArray_ErrorCode_0200
        * @tc.name     SUB_IPC_MessageSequence_readStringArray_ErrorCode_0200
        * @tc.desc     test readStringArray errCode
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_readStringArray_ErrorCode_0200", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL3, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_readStringArray_ErrorCode_0200 --------------------')
            let data = rpc.MessageSequence.create();
            try {
                let input: Array<String> = ["this", "is", "a", "test", "stirng", "array"];
                data.writeStringArray(input);
                data.reclaim();
                let res = data.readStringArray();
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readStringArray_ErrorCode_0200 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readStringArray_ErrorCode_0200 error code is: ' + err.code);
                expect(err.code == 1900010).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                data.reclaim();
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readStringArray_ErrorCode_0200 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_readStringArray_ErrorCode_0200 --------------------')
        });

        /**
        * @tc.number   SUB_IPC_MessageSequence_writeParcelableArray_ErrorCode_0100
        * @tc.name     SUB_IPC_MessageSequence_writeParcelableArray_ErrorCode_0100
        * @tc.desc     test writeParcelableArray errCode
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_writeParcelableArray_ErrorCode_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL3, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_writeParcelableArray_ErrorCode_0100 --------------------')
            let data = rpc.MessageSequence.create();
            try {
                let parcelable1 = new MyParcelable(1, "this is a test parcelable 1");
                let parcelable2 = new MyParcelable(2, "this is a test parcelable 2");
                let parcelable3 = new MyParcelable(3, "this is a test parcelable 3");
                let input: Array<rpc.Parcelable> = [parcelable1, parcelable2, parcelable3];
                data.reclaim();
                data.writeParcelableArray(input);
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeParcelableArray_ErrorCode_0100 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeParcelableArray_ErrorCode_0100 error code is: ' + err.code);
                expect(err.code == 1900009).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeParcelableArray_ErrorCode_0100 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeParcelableArray_ErrorCode_0100 --------------------')
        });

        /**
        * @tc.number   SUB_IPC_MessageSequence_readParcelableArray_ErrorCode_0100
        * @tc.name     SUB_IPC_MessageSequence_readParcelableArray_ErrorCode_0100
        * @tc.desc     test readParcelableArray errCode
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_readParcelableArray_ErrorCode_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL3, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_readParcelableArray_ErrorCode_0100 --------------------')
            let data = rpc.MessageSequence.create();
            try {
                let parcelable1 = new MyParcelable(1, "this is a test parcelable 1");
                let parcelable2 = new MyParcelable(2, "this is a test parcelable 2");
                let parcelable3 = new MyParcelable(3, "this is a test parcelable 3");
                let input: Array<rpc.Parcelable> = [parcelable1, parcelable2, parcelable3];
                data.writeParcelableArray(input);
                data.reclaim();
                let res: Array<rpc.Parcelable> = [new MyParcelable(0, ""), new MyParcelable(0, ""), new MyParcelable(0, "")];

                data.readParcelableArray(res);
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readParcelableArray_ErrorCode_0100 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readParcelableArray_ErrorCode_0100 error code is: ' + err.code);
                expect(err.code == 1900010).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readParcelableArray_ErrorCode_0100 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_readParcelableArray_ErrorCode_0100 --------------------')
        });

       /**
        * @tc.number   SUB_IPC_MessageSequence_writeByteArray_ErrorCode_0100
        * @tc.name     SUB_IPC_MessageSequence_writeByteArray_ErrorCode_0100
        * @tc.desc     test writeByteArray errCode
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_writeByteArray_ErrorCode_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL3, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_writeByteArray_ErrorCode_0100 --------------------')
            let data = rpc.MessageSequence.create();
            try {
                let input: Array<int> = [1, 2, 3, 4, 5, 6, 7, 8, 9];
                data.reclaim();
                data.writeByteArray(input);
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeByteArray_ErrorCode_0100 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeByteArray_ErrorCode_0100 error code is: ' + err.code);
                expect(err.code == 1900009).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeByteArray_ErrorCode_0100 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeByteArray_ErrorCode_0100 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_MessageSequence_writeAshmem_ErrorCode_0100
         * @tc.name     SUB_IPC_MessageSequence_writeAshmem_ErrorCode_0100
         * @tc.desc     test MessageSequence writeAshmem Ashmem errCode
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_writeAshmem_ErrorCode_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_writeAshmem_ErrorCode_0100 --------------------')

            let data = rpc.MessageSequence.create();
            try {
                let ashmem = rpc.Ashmem.create("ashmem", 1024 * 1024);
                data.reclaim();
                data.writeAshmem(ashmem);
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeAshmem_ErrorCode_0100 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeAshmem_ErrorCode_0100 error code is: ' + err.code);
                expect(err.code == 1900009).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeAshmem_ErrorCode_0100 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeAshmem_ErrorCode_0100 --------------------')
        });

       /**
        * @tc.number   SUB_IPC_MessageSequence_readAshmem_ErrorCode_0100
        * @tc.name     SUB_IPC_MessageSequence_readAshmem_ErrorCode_0100
        * @tc.desc     test MessageSequence writeAshmem Ashmem errCode
        * @tc.level    LEVEL1
        * @tc.size     MEDIUMTEST
        * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_readAshmem_ErrorCode_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_readAshmem_ErrorCode_0100 --------------------')

            let data = rpc.MessageSequence.create();
            try {
                let ashmem = rpc.Ashmem.create("ashmem", 1024 * 1024);
                data.writeAshmem(ashmem)
                data.reclaim();
                let res = data.readAshmem();
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readAshmem_ErrorCode_0100 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readAshmem_ErrorCode_0100 error code is: ' + err.code);
                expect(err.code == 1900010).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readAshmem_ErrorCode_0100 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_readAshmem_ErrorCode_0100 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_MessageSequence_writeRawDataBuffer_ErrorCode_0100
         * @tc.name     SUB_IPC_MessageSequence_writeRawDataBuffer_ErrorCode_0100
         * @tc.desc     test MessageSequence writeRawDataBuffer errCode
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_writeRawDataBuffer_ErrorCode_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_writeRawDataBuffer_ErrorCode_0100 --------------------')
            let data = rpc.MessageSequence.create();
            let TEST_LEN_128M = 128 * 1024 * 1024;
            try {
                let buffer = new ArrayBuffer(TEST_LEN_128M + 4);
                let size = buffer.byteLength;
                let int32View = new Int32Array(buffer);
                int32View.fill(1)
                data.writeRawDataBuffer(buffer, size);
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeRawDataBuffer_ErrorCode_0100 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeRawDataBuffer_ErrorCode_0100 error code is: ' + err.code);
                expect(err.code == 1900009).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeRawDataBuffer_ErrorCode_0100 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeRawDataBuffer_ErrorCode_0100 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_MessageSequence_readRawDataBuffer_ErrorCode_0100
         * @tc.name     SUB_IPC_MessageSequence_readRawDataBuffer_ErrorCode_0100
         * @tc.desc     test MessageSequence readRawDataBuffer errCode
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
         */
        it("SUB_IPC_MessageSequence_readRawDataBuffer_ErrorCode_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_readRawDataBuffer_ErrorCode_0100 --------------------')
            let data = rpc.MessageSequence.create();
            let TEST_LEN_128M = 128 * 1024 * 1024;
            try {
                let buffer = new ArrayBuffer(TEST_LEN_128M);
                let size = buffer.byteLength;
                let int32View = new Int32Array(buffer);
                int32View.fill(1)
                data.writeRawDataBuffer(buffer, size);
                let readBuffer = data.readRawDataBuffer(TEST_LEN_128M + 1)
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readRawDataBuffer_ErrorCode_0100 error is: ' + err);
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readRawDataBuffer_ErrorCode_0100 error code is: ' + err.code);
                expect(err.code == 1900010).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_readRawDataBuffer_ErrorCode_0100 reclaim done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_readRawDataBuffer_ErrorCode_0100 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_MessageSequence_writeFileDescriptor_ErrorCode_0300
         * @tc.name     SUB_IPC_MessageSequence_writeFileDescriptor_ErrorCode_0300
         * @tc.desc     test MessageSequence writeFileDescriptor errCode
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_writeFileDescriptor_ErrorCode_0300", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_writeFileDescriptor_ErrorCode_0300 --------------------')
            let data =  rpc.MessageSequence.create();
            try {
                data.writeFileDescriptor(-1);
            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeFileDescriptor_ErrorCode_0300 error is: ' + err)
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeFileDescriptor_ErrorCode_0300 error is: ' + err.code)
                expect(err.code == 1900009).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeFileDescriptor_ErrorCode_0300  done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeFileDescriptor_ErrorCode_0300 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_MessageSequence_closeFileDescriptor_ErrorCode_0100
         * @tc.name     SUB_IPC_MessageSequence_closeFileDescriptor_ErrorCode_0100
         * @tc.desc     test MessageSequence closeFileDescriptor errCode
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_closeFileDescriptor_ErrorCode_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_closeFileDescriptor_ErrorCode_0100 --------------------')
            let data =  rpc.MessageSequence.create();
            try {

                rpc.MessageSequence.closeFileDescriptor(-1);

            } catch (err: BusinessError) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_closeFileDescriptor_ErrorCode_0100 error is: ' + err)
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_closeFileDescriptor_ErrorCode_0100 error is: ' + err.code)
                expect(err.code == 401).assertTrue();
                expect(err.message != null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_closeFileDescriptor_ErrorCode_0100  done')
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_closeFileDescriptor_ErrorCode_0100 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_MessageSequence_writeBoolean_readBoolean_0100
         * @tc.name     SUB_IPC_MessageSequence_writeBoolean_readBoolean_0100
         * @tc.desc     test MessageSequence writeBoolean and readBoolean
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_writeBoolean_readBoolean_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_writeBoolean_readBoolean_0100 --------------------')
            let data =  rpc.MessageSequence.create();
            try {
                let input = true;
                data.writeBoolean(input);
                let res = data.readBoolean();
                expect(res).assertTrue();
            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeBoolean_readBoolean_0100 error is: ' + error)
                expect(error == null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeBoolean_readBoolean_0100 reclaim done')
                data.reclaim();
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeBoolean_readBoolean_0100 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_MessageSequence_writeBoolean_readBoolean_0200
         * @tc.name     SUB_IPC_MessageSequence_writeBoolean_readBoolean_0200
         * @tc.desc     test MessageSequence writeBoolean and readBoolean
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_writeBoolean_readBoolean_0200", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_writeBoolean_readBoolean_0200 --------------------')
            let data =  rpc.MessageSequence.create();
            try {
                let input = false;
                data.writeBoolean(input);
                let res = data.readBoolean();
                expect(res).assertFalse();
            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeBoolean_readBoolean_0200 error is: ' + error)
                expect(error == null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeBoolean_readBoolean_0200 reclaim done')
                data.reclaim();
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeBoolean_readBoolean_0200 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_MessageSequence_writeString_readString_0100
         * @tc.name     SUB_IPC_MessageSequence_writeString_readString_0100
         * @tc.desc     test MessageSequence writeString and readString
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_writeString_readString_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
           await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_writeString_readString_0100 --------------------')
            let data =  rpc.MessageSequence.create();
            try {
                let input = "this is test write and read string";
                data.writeString(input);
                let res = data.readString();
                expect(res == input).assertTrue();
            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeString_readString_0100 error is: ' + error)
                expect(error == null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeString_readString_0100 reclaim done')
                data.reclaim();
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeString_readString_0100 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_MessageSequence_writeByteArray_0100
         * @tc.name     SUB_IPC_MessageSequence_writeByteArray_0100
         * @tc.desc     test MessageSequence writeByteArray
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_writeByteArray_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_writeByteArray_0100 --------------------')
            let data =  rpc.MessageSequence.create();
            try {
                let input: Array<int> = [1, 2, 3, 4, 5, 6, 7, 8, 9];
                data.writeByteArray(input);
            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeByteArray_0100 error is: ' + error)
                expect(error == null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeByteArray_0100 reclaim done')
                data.reclaim();
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeByteArray_0100 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_MessageSequence_writeIntArray_readIntArray_0100
         * @tc.name     SUB_IPC_MessageSequence_writeIntArray_readIntArray_0100
         * @tc.desc     test MessageSequence writeIntArray and readIntArray
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_writeIntArray_readIntArray_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_writeIntArray_readIntArray_0100 --------------------')
            let data =  rpc.MessageSequence.create();
            try {
                let input: Array<int> = [1, 2, 3, 4, 5, 6, 7, 8, 9];
                data.writeIntArray(input);
                let res = data.readIntArray();
                expect(res).assertDeepEquals(input);
            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeIntArray_readIntArray_0100 error is: ' + error)
                expect(error == null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeIntArray_readIntArray_0100 reclaim done')
                data.reclaim();
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeIntArray_readIntArray_0100 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_MessageSequence_writeIntArray_readIntArray_0200
         * @tc.name     SUB_IPC_MessageSequence_writeIntArray_readIntArray_0200
         * @tc.desc     test MessageSequence writeIntArray and readIntArray
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_writeIntArray_readIntArray_0200", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_writeIntArray_readIntArray_0200 --------------------')
            let data =  rpc.MessageSequence.create();
            try {
                let input: Array<int> = [1, 2, 3, 4, 5, 6, 7, 8, 9];
                data.writeIntArray(input);
                let res: Array<int> = new Array<int>(input.length);
                data.readIntArray(res);
                expect(res).assertDeepEquals(input);
            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeIntArray_readIntArray_0200 error is: ' + error)
                expect(error == null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeIntArray_readIntArray_0200 reclaim done')
                data.reclaim();
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeIntArray_readIntArray_0200 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_MessageSequence_writeDoubleArray_readDoubleArray_0100
         * @tc.name     SUB_IPC_MessageSequence_writeDoubleArray_readDoubleArray_0100
         * @tc.desc     test MessageSequence writeDoubleArray and readDoubleArray
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_writeDoubleArray_readDoubleArray_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_writeDoubleArray_readDoubleArray_0100 --------------------')
            let data =  rpc.MessageSequence.create();
            try {
                let input: Array<double> = [1.1, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7, 8.8, 9.9];
                data.writeDoubleArray(input);
                let res = data.readDoubleArray();
                expect(res).assertDeepEquals(input);
            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeDoubleArray_readDoubleArray_0100 error is: ' + error)
                expect(error == null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeDoubleArray_readDoubleArray_0100 reclaim done')
                data.reclaim();
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeDoubleArray_readDoubleArray_0100 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_MessageSequence_writeDoubleArray_readDoubleArray_0200
         * @tc.name     SUB_IPC_MessageSequence_writeDoubleArray_readDoubleArray_0200
         * @tc.desc     test MessageSequence writeDoubleArray and readDoubleArray
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_writeDoubleArray_readDoubleArray_0200", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_writeDoubleArray_readDoubleArray_0200 --------------------')
            let data =  rpc.MessageSequence.create();
            try {
                let input: Array<double> = [1.1, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7, 8.8, 9.9];
                data.writeDoubleArray(input);
                let res: Array<double> = new Array<double>(input.length);
                data.readDoubleArray(res);
                expect(res).assertDeepEquals(input);
            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeDoubleArray_readDoubleArray_0200 error is: ' + error)
                expect(error == null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeDoubleArray_readDoubleArray_0200 reclaim done')
                data.reclaim();
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeDoubleArray_readDoubleArray_0200 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_MessageSequence_writeStringArray_readStringArray_0100
         * @tc.name     SUB_IPC_MessageSequence_writeStringArray_readStringArray_0100
         * @tc.desc     test MessageSequence writeStringArray and readStringArray
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_writeStringArray_readStringArray_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_writeStringArray_readStringArray_0100 --------------------')
            let data =  rpc.MessageSequence.create();
            try {
                let input: Array<string> = ["this", "is", "a", "test", "stirng", "array"];
                data.writeStringArray(input);
                let res = data.readStringArray();
                expect(res).assertDeepEquals(input);
            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeStringArray_readStringArray_0100 error is: ' + error)
                expect(error == null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeStringArray_readStringArray_0100 reclaim done')
                data.reclaim();
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeStringArray_readStringArray_0100 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_MessageSequence_writeStringArray_readStringArray_0200
         * @tc.name     SUB_IPC_MessageSequence_writeStringArray_readStringArray_0200
         * @tc.desc     test MessageSequence writeStringArray and readStringArray
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_writeStringArray_readStringArray_0200", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_writeStringArray_readStringArray_0200 --------------------')
            let data =  rpc.MessageSequence.create();
            try {
                let input: Array<string> = ["this", "is", "a", "test", "stirng", "array"];
                data.writeStringArray(input);
                let res: Array<string> = new Array<string>(input.length);
                data.readStringArray(res);
                expect(res).assertDeepEquals(input);
            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeStringArray_readStringArray_0200 error is: ' + error)
                expect(error == null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeStringArray_readStringArray_0200 reclaim done')
                data.reclaim();
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeStringArray_readStringArray_0200 --------------------')
        });

        /**
         * @tc.number   SUB_IPC_MessageSequence_writeBooleanArray_readBooleanArray_0100
         * @tc.name     SUB_IPC_MessageSequence_writeBooleanArray_readBooleanArray_0100
         * @tc.desc     test MessageSequence writeBooleanArray and readBooleanArray
         * @tc.level    LEVEL1
         * @tc.size     MEDIUMTEST
         * @tc.type     FUNCTION
        */
        it("SUB_IPC_MessageSequence_writeBooleanArray_readBooleanArray_0100", TestType.FUNCTION|Size.MEDIUMTEST|Level.LEVEL1, async (done: () => void): Promise<void> => {
            await Utils.msSleep(200)
            hilog.info(domain, tag, '%{public}s', '-------------------- start SUB_IPC_MessageSequence_writeBooleanArray_readBooleanArray_0100 --------------------')
            let data =  rpc.MessageSequence.create();
            try {
                let input: Array<boolean> = [true, false, true, false, true, false, true, false, true, false];
                data.writeBooleanArray(input);
                let res = data.readBooleanArray();
                expect(res).assertDeepEquals(input);
            } catch (error) {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeBooleanArray_readBooleanArray_0100 error is: ' + error)
                expect(error == null).assertTrue();
            } finally {
                hilog.info(domain, tag, '%{public}s', 'SUB_IPC_MessageSequence_writeBooleanArray_readBooleanArray_0100 reclaim done')
                data.reclaim();
            }
            done()
            hilog.info(domain, tag, '%{public}s', '-------------------- end SUB_IPC_MessageSequence_writeBooleanArray_readBooleanArray_0100 --------------------')
        });

    console.info("-----------------------SUB_DSoftbus_IPC_API_Stage_MessageSequence_Test is end-----------------------");
  })
}