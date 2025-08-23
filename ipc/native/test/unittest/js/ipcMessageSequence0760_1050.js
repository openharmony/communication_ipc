/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
import fileio from '@ohos.fileio';
import FA from '@ohos.ability.featureAbility';
import { describe, expect, beforeAll, it, TestType, Size, Level } from '@ohos/hypium';
import assertDeepEquals from './assertDeepEquals'
let gIRemoteObject = null;


function assertArrayElementEqual(actual, expected) {
    let result = assertDeepEquals(actual, expected)
    expect(result).assertTrue();
}



export default function ActsRpcClientJsTest() {
    describe('ActsRpcClientJsTest', function () {
        console.info("-----------------------SUB_DSoftbus_IPC_API_MessageParce_Test is starting-----------------------");
        beforeAll(async function () {
            console.info('beforeAll called');
            gIRemoteObject = new Stub("rpcTestAbility");
            return gIRemoteObject;
        });

        beforeEach(async function () {
            console.info('beforeEach called');
        });

        afterEach(async function () {
            console.info('afterEach called');
        });

        afterAll(async function () {
            console.info('afterAll called');
        });

        const K = 1024;
        const M = 1024 * 1024;
        const G = 1024 * 1024 * 1024;
        const CODE_WRITE_BYTEARRAY = 1;
        const CODE_SAME_PROCESS = 1;
        const CODE_WRITE_INTARRAY = 2;
        const CODE_WRITE_FLOATARRAY = 3;
        const CODE_WRITE_SHORT = 4;
        const CODE_WRITE_LONG = 5;
        const CODE_WRITE_DOUBLE = 6;
        const CODE_WRITE_BOOLEAN = 7;
        const CODE_WRITE_CHAR = 8;
        const CODE_WRITE_STRING = 9;
        const CODE_WRITE_BYTE = 10;
        const CODE_WRITE_INT = 11;
        const CODE_WRITE_FLOAT = 12;
        const CODE_WRITE_RAWDATA = 13;
        const CODE_WRITE_REMOTEOBJECT = 14;
        const CODE_WRITE_SEQUENCEABLE = 15;
        const CODE_WRITE_NOEXCEPTION = 16;
        const CODE_WRITE_SEQUENCEABLEARRAY = 17;
        const CODE_WRITE_REMOTEOBJECTARRAY = 18;
        const CODE_ALL_TYPE = 20;
        const CODE_ALL_ARRAY_TYPE = 21;
        const CODE_IPCSKELETON_INT = 22;
        const CODE_WRITESEQUENCEABLE = 23
        const CODE_WRITE_SHORT_MULTI = 24;
        const CODE_WRITE_BYTE_MULTI = 25;
        const CODE_WRITE_INT_MULTI = 26;
        const CODE_WRITE_REMOTEOBJECTARRAY_3 = 27;
        const CODE_IPCSKELETON = 28;
        const CODE_FILESDIR = 29;
        const CODE_WRITE_REMOTEOBJECTARRAY_1 = 30;
        const CODE_WRITE_REMOTEOBJECTARRAY_2 = 31;
        const CODE_ONREMOTEMESSAGE_OR_ONREMOTE = 32;
        const CODE_ONREMOTEMESSAGEREQUEST = 33;
        const CODE_INTERFACETOKEN = 34;
        const CODE_WRITE_SHORTARRAY = 35;
        const CODE_WRITE_LONGARRAY = 36;
        const CODE_WRITE_DOUBLEARRAY = 37;
        const CODE_WRITE_BOOLEANARRAY = 38;
        const CODE_WRITE_CHARARRAY = 39;
        const CODE_WRITE_STRINGARRAY = 40;
        const CODE_WRITE_ARRAYBUFFER = 41;

        function sleep(numberMillis) {
            let now = new Date();
            let exitTime = now.getTime() + numberMillis;
            while (true) {
                now = new Date();
                if (now.getTime() > exitTime)
                    return;
            }
        }

        class TestRemoteObject extends rpc.RemoteObject {
            constructor(descriptor) {
                super(descriptor);
                this.modifyLocalInterface(this, descriptor);
            }
            asObject() {
                return this;
            }
        }

        class TestProxy {
            remote = rpc.RemoteObject;
            constructor(remote) {
                this.remote = remote;
                console.info("test remote");
            }
            asObject() {
                console.info("server remote");
                return this.remote;
            }
        }

        class MyDeathRecipient {
            constructor(gIRemoteObject, done) {
                this.gIRemoteObject = gIRemoteObject;
                this.done = done;
            }

            onRemoteDied() {
                console.info("server died");
                expect(this.proxy.removeDeathRecipient(this, 0)).assertTrue();
                let _done = this.done;
                _done();
                sleep(1000);
            }
        }

        class MyregisterDeathRecipient {
            constructor(gIRemoteObject, done) {
                this.gIRemoteObject = gIRemoteObject;
                this.done = done;
            }

            onRemoteDied() {
                console.info("server died");
                expect(this.proxy.unregisterDeathRecipient(this, 0)).assertTrue();
                let _done = this.done;
                _done();
                sleep(1000);
            }
        }

        class Stub extends rpc.RemoteObject {
            constructor(descriptor) {
                super(descriptor);
            }
            onRemoteRequest(code, data, reply, option) {
                try {
                    console.info("onRemoteRequest: " + code);
                    if (code === 32) {
                        console.info("case 32 start");
                        let tmp1 = data.readString();
                        let result = reply.writeString("onRemoteRequest invoking");
                        return true;
                    } else if (code === 33) {
                        console.info("case 33 start");
                        let tmp1 = data.readString();
                        let result = reply.writeString(tmp1);
                        return true;
                    } else {
                        console.error("default case " + code);
                        return super.onRemoteRequest(code, data, reply, option);
                    };
                } catch (error) {
                    console.info("onRemoteRequest: " + error);
                }
                return false;
            }
            onRemoteMessageRequest(code, data, reply, option) {
                try {
                    console.info("onRemoteMessageRequest: " + code);
                    switch (code) {
                        case 1:
                            {
                                console.info("case 1 start");
                                let tmp1 = data.readByteArray();
                                let result = reply.writeByteArray(tmp1);
                                return true;
                            }
                        case 2:
                            {
                                console.info("case 2 start");
                                let tmp1 = data.readIntArray();
                                let result = reply.writeIntArray(tmp1);
                                return true;
                            }
                        case 3:
                            {
                                console.info("case 3 start");
                                let tmp1 = data.readFloatArray();
                                let result = reply.writeFloatArray(tmp1);
                                return true;
                            }
                        case 4:
                            {
                                console.info("case 4 start");
                                let tmp1 = data.readShort();
                                let result = reply.writeShort(tmp1);
                                return true;
                            }
                        case 5:
                            {
                                console.info("case 5 start");
                                let tmp1 = data.readLong();
                                let result = reply.writeLong(tmp1);
                                return true;
                            }
                        case 6:
                            {
                                console.info("case 6 start");
                                let tmp1 = data.readDouble();
                                let result = reply.writeDouble(tmp1);
                                return true;
                            }
                        case 7:
                            {
                                console.info("case 7 start");
                                let tmp1 = data.readBoolean();
                                let result = reply.writeBoolean(tmp1);
                                return true;
                            }
                        case 8:
                            {
                                console.info("case 8 start");
                                let tmp1 = data.readChar();
                                let result = reply.writeChar(tmp1);
                                return true;
                            }
                        case 9:
                            {
                                console.info("case 9 start");
                                let tmp1 = data.readString();
                                let result = reply.writeString(tmp1);
                                return true;
                            }
                        case 10:
                            {
                                console.info("case 10 start");
                                let tmp1 = data.readByte();
                                let result = reply.writeByte(tmp1);
                                return true;
                            }
                        case 11:
                            {
                                console.info("case 11 start");
                                let tmp1 = data.readInt();
                                let result = reply.writeInt(tmp1);
                                return true;
                            }
                        case 12:
                            {
                                console.info("case 12 start");
                                let tmp1 = data.readFloat();
                                let result = reply.writeFloat(tmp1);
                                return true;
                            }
                        case 13:
                            {
                                console.info("case 13 start");
                                let size = data.readInt();
                                let tmp = data.readRawData(size);
                                let size1 = reply.writeInt(size);
                                let result = reply.writeRawData(tmp, tmp.length);
                                return true;
                            }
                        case 14:
                            {
                                console.info("case 14 start");
                                let listener = data.readRemoteObject();
                                let num = data.readInt();
                                let str = data.readString();
                                let option2 = new rpc.MessageOption();
                                let data2 = rpc.MessageParcel.create();
                                let reply2 = rpc.MessageParcel.create();
                                data2.writeInt(num);
                                data2.writeString(str);
                                listener.sendRequest(1, data2, reply2, option2)
                                    .then(function (result) {
                                        console.info("14 send request done, error code: " + result.errCode);
                                    })
                                    .catch(function (e) {
                                        console.error("14 send request got exception: " + e);
                                    })
                                    .finally(() => {
                                        data2.reclaim();
                                        reply2.reclaim();
                                        console.info("case 14 test done");
                                    })
                                reply.writeNoException();
                                return true;
                            }
                        case 15:
                            {
                                console.info("case 15 start");
                                let s = new MySequenceable(null, null);
                                let tmp1 = data.readParcelable(s);
                                let result = reply.writeParcelable(s);
                                return true;
                            }
                        case 16:
                            {
                                console.info("case 16 start");
                                data.readException();
                                let tmp = data.readInt();
                                reply.writeNoException();
                                let result = reply.writeInt(tmp);
                                return true;
                            }
                        case 17:
                            {
                                console.info("case 17 start");
                                let s = [new MySequenceable(null, null), new MySequenceable(null, null),
                                new MySequenceable(null, null)];
                                data.readParcelableArray(s);
                                let result = reply.writeParcelableArray(s);
                                return true;
                            }
                        case 18:
                            {
                                console.info("case 18 start");
                                let listeners = data.readRemoteObjectArray();
                                for (let i = 0; i < listeners.length; i++) {
                                    let option2 = new rpc.MessageOption();
                                    let data2 = rpc.MessageParcel.create();
                                    let reply2 = rpc.MessageParcel.create();
                                    listeners[i].sendRequest(1, data2, reply2, option2)
                                        .then(function (result) {
                                            console.info("18 send request done, error code: " + result.errCode + ", index: " + i);
                                        })
                                        .catch(function (e) {
                                            console.error("18 send request got exception: " + e);
                                        })
                                        .finally(() => {
                                            data2.reclaim();
                                            reply2.reclaim();
                                            console.info("case 18 test done");
                                        })
                                }
                                return true;
                            }
                        case 19:
                            {
                                console.info("case 19 start");
                                let tmp1 = data.readDoubleArray();
                                let result = reply.writeDoubleArray(tmp1);
                                return true;
                            }

                        case 20:
                            {
                                console.info("case 20 start");
                                let tmp1 = data.readByte();
                                let tmp2 = data.readShort();
                                let tmp3 = data.readInt();
                                let tmp4 = data.readLong();
                                let tmp5 = data.readFloat();
                                let tmp6 = data.readDouble();
                                let tmp7 = data.readBoolean();
                                let tmp8 = data.readChar();
                                let tmp9 = data.readString();
                                let s = new MySequenceable(null, null);
                                let tmp10 = data.readParcelable(s);
                                let result1 = reply.writeByte(tmp1);
                                let result2 = reply.writeShort(tmp2);
                                let result3 = reply.writeInt(tmp3);
                                let result4 = reply.writeLong(tmp4);
                                let result5 = reply.writeFloat(tmp5);
                                let result6 = reply.writeDouble(tmp6);
                                let result7 = reply.writeBoolean(tmp7);
                                let result8 = reply.writeChar(tmp8);
                                let result9 = reply.writeString(tmp9);
                                let result10 = reply.writeParcelable(s);
                                return true;
                            }
                        case 21:
                            {
                                console.info("case 21 start");
                                let tmp1 = data.readByteArray();
                                let tmp2 = data.readShortArray();
                                let tmp3 = data.readIntArray();
                                let tmp4 = data.readLongArray();
                                let tmp5 = data.readFloatArray();
                                let tmp6 = data.readDoubleArray();
                                let tmp7 = data.readBooleanArray();
                                let tmp8 = data.readCharArray();
                                let tmp9 = data.readStringArray();
                                let s = [new MySequenceable(null, null), new MySequenceable(null, null),
                                new MySequenceable(null, null)];
                                let tmp10 = data.readParcelableArray(s);
                                let result1 = reply.writeByteArray(tmp1);
                                let result2 = reply.writeShortArray(tmp2);
                                let result3 = reply.writeIntArray(tmp3);
                                let result4 = reply.writeLongArray(tmp4);
                                let result5 = reply.writeFloatArray(tmp5);
                                let result6 = reply.writeDoubleArray(tmp6);
                                let result7 = reply.writeBooleanArray(tmp7);
                                let result8 = reply.writeCharArray(tmp8);
                                let result9 = reply.writeStringArray(tmp9);
                                let result10 = reply.writeParcelableArray(s);
                                return true;
                            }
                        case 22:
                            {
                                console.info("case 22 start");
                                let callingPid = rpc.IPCSkeleton.getCallingPid();
                                let callingUid = rpc.IPCSkeleton.getCallingUid();
                                reply.writeNoException();
                                reply.writeInt(callingPid);
                                reply.writeInt(callingUid);
                                reply.writeInt(this.getCallingPid());
                                reply.writeInt(this.getCallingUid());
                                let id = rpc.IPCSkeleton.resetCallingIdentity();
                                rpc.IPCSkeleton.setCallingIdentity(id);
                                reply.writeInt(rpc.IPCSkeleton.getCallingPid());
                                reply.writeInt(rpc.IPCSkeleton.getCallingUid());
                                reply.writeInt(rpc.IPCSkeleton.flushCommands(this));
                                return true;
                            }
                        case 23:
                            {
                                console.info("case 23 start");
                                let s = new MySequenceable(null, null);
                                let tmp1 = data.readParcelable(s);
                                let result = reply.writeParcelable(s);
                                return true;
                            }
                        case 24:
                            {
                                console.info("case 24 start");
                                let tmp1 = data.readShort();
                                let tmp2 = data.readShort();
                                let tmp3 = data.readShort();
                                let tmp4 = data.readShort();
                                let tmp5 = data.readShort();
                                let result1 = reply.writeShort(tmp1);
                                let result2 = reply.writeShort(tmp2);
                                let result3 = reply.writeShort(tmp3);
                                let result4 = reply.writeShort(tmp4);
                                let result5 = reply.writeShort(tmp5);
                                return true;
                            }
                        case 25:
                            {
                                console.info("case 25 start");
                                let tmp1 = data.readByte();
                                let tmp2 = data.readByte();
                                let tmp3 = data.readByte();
                                let tmp4 = data.readByte();
                                let tmp5 = data.readByte();
                                let result1 = reply.writeByte(tmp1);
                                let result2 = reply.writeByte(tmp2);
                                let result3 = reply.writeByte(tmp3);
                                let result4 = reply.writeByte(tmp4);
                                let result5 = reply.writeByte(tmp5);
                                return true;
                            }
                        case 26:
                            {
                                console.info("case 26 start");
                                let tmp1 = data.readInt();
                                let tmp2 = data.readInt();
                                let tmp3 = data.readInt();
                                let tmp4 = data.readInt();
                                let tmp5 = data.readInt();
                                let result1 = reply.writeInt(tmp1);
                                let result2 = reply.writeInt(tmp2);
                                let result3 = reply.writeInt(tmp3);
                                let result4 = reply.writeInt(tmp4);
                                let result5 = reply.writeInt(tmp5);
                                return true;
                            }
                        case 27:
                            {
                              console.info("case 27 starts");
                              let listeners = data.readRemoteObjectArray();
                              reply.writeRemoteObjectArray(listeners);
                              console.info("onRemoteMessageRequest success");
                              return true;
                            }
                        case 28:
                            {
                                console.info("case 28 start");
                                let callingPid = rpc.IPCSkeleton.getCallingPid();
                                let callingUid = rpc.IPCSkeleton.getCallingUid();
                                let callingDeviceID = rpc.IPCSkeleton.getCallingDeviceID();
                                let localDeviceID = rpc.IPCSkeleton.getLocalDeviceID();
                                let isLocalCalling = rpc.IPCSkeleton.isLocalCalling();
                                reply.writeNoException();
                                reply.writeInt(callingPid);
                                reply.writeInt(callingUid);
                                reply.writeString(callingDeviceID);
                                reply.writeString(localDeviceID);
                                reply.writeBoolean(isLocalCalling);
                                reply.writeInt(this.getCallingPid());
                                reply.writeInt(this.getCallingUid());
                                let id = rpc.IPCSkeleton.resetCallingIdentity();
                                rpc.IPCSkeleton.setCallingIdentity(id);
                                reply.writeInt(rpc.IPCSkeleton.getCallingPid());
                                reply.writeInt(rpc.IPCSkeleton.getCallingUid());
                                reply.writeInt(rpc.IPCSkeleton.flushCommands(this));
                                return true;
                            }
                        case 29:
                            {
                                console.info("case 29 starts");
                                let bytesWr = data.readInt();
                                let fd = data.readFileDescriptor();
                                reply.writeFileDescriptor(fd);
                                fileio.writeSync(fd, "HELLO RPC", { position: bytesWr + 1 });
                                reply.writeFileDescriptor(fd);
                                rpc.MessageSequence.closeFileDescriptor(fd)
                                return true;
                            }
                        case 30:
                            {
                                console.info("case 30 start");
                                let listeners = data.readRemoteObjectArray();
                                let num = data.readInt();
                                let str = data.readString();
                                for (let i = 0; i < listeners.length; i++) {
                                    let option2 = new rpc.MessageOption();
                                    let data2 = rpc.MessageParcel.create();
                                    let reply2 = rpc.MessageParcel.create();
                                    data2.writeInt(num);
                                    data2.writeString(str);
                                    listeners[i].sendRequest(1, data2, reply2, option2)
                                        .then(function (result) {
                                            console.info("30 send request done, error code: " + result.errCode + ", index: " + i);
                                        })
                                        .catch(function (e) {
                                            console.error("30 send request got exception: " + e);
                                        })
                                        .finally(() => {
                                            data2.reclaim();
                                            reply2.reclaim();
                                            console.info("case 30 test done");
                                        })
                                }
                                reply.writeNoException();
                                return true;
                            }

                        case 31:
                            {
                                console.info("case 31 start");
                                let listeners = data.readRemoteObjectArray();
                                let num = data.readInt();
                                let str = data.readString();
                                console.info("31 num: " + num);
                                console.info("31 str: " + str);
                                for (let i = 0; i < listeners.length; i++) {
                                    let option2 = new rpc.MessageOption();
                                    let data2 = rpc.MessageParcel.create();
                                    let reply2 = rpc.MessageParcel.create();
                                    data2.writeInt(num);
                                    data2.writeString(str);
                                    listeners[i].sendRequest(1, data2, reply2, option2)
                                        .then(function (result) {
                                            console.info("31 send request done, error code: " + result.errCode + ", index: " + i);
                                        })
                                        .catch(function (e) {
                                            console.error("31 send request got exception: " + e);
                                        })
                                        .finally(() => {
                                            data2.reclaim();
                                            reply2.reclaim();
                                            console.info("case 31 test done");
                                        })
                                }
                                reply.writeNoException();
                                return true;
                            }
                        case 32:
                            {
                                console.info("case 32 start");
                                let tmp1 = data.readString();
                                let result = reply.writeString("onRemoteMessageRequest invoking");
                                return true;
                            }
                        case 34:
                            {
                                console.info("case 34 start");
                                let tmp = data.readInterfaceToken();
                                let result = reply.writeInterfaceToken(tmp);
                                return true;
                            }
                        case 35:
                            {
                                console.info("case 35 start");
                                let tmp1 = data.readShortArray();
                                let result = reply.writeShortArray(tmp1);
                                return true;
                            }
                        case 36:
                            {
                                console.info("case 36 start");
                                let tmp1 = data.readLongArray();
                                let result = reply.writeLongArray(tmp1);
                                return true;
                            }
                        case 37:
                            {
                                console.info("case 37 start");
                                let tmp1 = data.readDoubleArray();
                                let result = reply.writeDoubleArray(tmp1);
                                return true;
                            }
                        case 38:
                            {
                                console.info("case 38 start");
                                let tmp1 = data.readBooleanArray();
                                let result = reply.writeBooleanArray(tmp1);
                                return true;
                            }
                        case 39:
                            {
                                console.info("case 39 start");
                                let tmp1 = data.readCharArray();
                                let result = reply.writeCharArray(tmp1);
                                return true;
                            }
                        case 40:
                            {
                                console.info("case 40 start");
                                let tmp1 = data.readStringArray();
                                let result = reply.writeStringArray(tmp1);
                                return true;
                            }
                        case 41:
                            {
                                console.info("case 41 start");
                                let tmp1 = data.readArrayBuffer(rpc.TypeCode.INT16_ARRAY);
                                let tmp2 = data.readArrayBuffer(rpc.TypeCode.INT8_ARRAY);

                                reply.writeArrayBuffer(tmp2, rpc.TypeCode.INT8_ARRAY);
                                reply.writeArrayBuffer(tmp1, rpc.TypeCode.INT16_ARRAY);
                                return true;
                            }
                        default:
                            this.onRemoteRequest(code, data, reply, option);
                    }
                } catch (error) {
                    console.info("onRemoteMessageRequest: " + error);
                }
                return false;
            }
        }

        class TestAbilityStub extends rpc.RemoteObject {
            constructor(descriptor) {
                super(descriptor);
            }

            onRemoteRequest(code, data, reply, option) {
                console.info("TestAbilityStub: onRemoteRequest called, code: " + code);
                let descriptor = data.readInterfaceToken();
                if (descriptor !== "TestAbilityStub") {
                    console.error("received unknown descriptor: " + descriptor);
                    return false;
                }
                switch (code) {
                    case 1:
                        {
                            let tmp1 = data.readByte();
                            let tmp2 = data.readShort();
                            let tmp3 = data.readInt();
                            let tmp4 = data.readLong();
                            let tmp5 = data.readFloat();
                            let tmp6 = data.readDouble();
                            let tmp7 = data.readBoolean();
                            let tmp8 = data.readChar();
                            let tmp9 = data.readString();
                            let s = new MySequenceable(null, null);
                            data.readSequenceable(s);
                            reply.writeNoException();
                            reply.writeByte(tmp1);
                            reply.writeShort(tmp2);
                            reply.writeInt(tmp3);
                            reply.writeLong(tmp4);
                            reply.writeFloat(tmp5);
                            reply.writeDouble(tmp6);
                            reply.writeBoolean(tmp7);
                            reply.writeChar(tmp8);
                            reply.writeString(tmp9);
                            reply.writeSequenceable(s);
                            return true;
                        }
                    default:
                        {
                            console.error("default case, code: " + code);
                            return false;
                        }
                }
            }
        }

        class TestAbilityMessageStub extends rpc.RemoteObject {
            constructor(descriptor) {
                super(descriptor);
            }
            onRemoteMessageRequest(code, data, reply, option) {
                console.info("TestAbilityMessageStub: onRemoteMessageRequest called, code: " + code);
                let descriptor = data.readInterfaceToken();
                if (descriptor !== "TestAbilityMessageStub") {
                    console.error("received unknown descriptor: " + descriptor);
                    return false;
                }
                switch (code) {
                    case 1:
                        {
                            let tmp1 = data.readByte();
                            let tmp2 = data.readShort();
                            let tmp3 = data.readInt();
                            let tmp4 = data.readLong();
                            let tmp5 = data.readFloat();
                            let tmp6 = data.readDouble();
                            let tmp7 = data.readBoolean();
                            let tmp8 = data.readChar();
                            let tmp9 = data.readString();
                            let s = new MySequenceable(null, null);
                            data.readParcelable(s);
                            reply.writeNoException();
                            reply.writeByte(tmp1);
                            reply.writeShort(tmp2);
                            reply.writeInt(tmp3);
                            reply.writeLong(tmp4);
                            reply.writeFloat(tmp5);
                            reply.writeDouble(tmp6);
                            reply.writeBoolean(tmp7);
                            reply.writeChar(tmp8);
                            reply.writeString(tmp9);
                            reply.writeParcelable(s);
                            return true;
                        }
                    default:
                        {
                            console.error("default case, code: " + code);
                            return false;
                        }
                }
            }
        }

        class TestListener extends rpc.RemoteObject {
            constructor(descriptor, checkResult) {
                super(descriptor);
                this.checkResult = checkResult;
            }
            onRemoteRequest(code, data, reply, option) {
                let result = false;
                if (code == 1) {
                    console.info("onRemoteRequest called, descriptor: " + this.getInterfaceDescriptor());
                    result = true;
                } else {
                    console.info("unknown code: " + code);
                }
                let _checkResult = this.checkResult
                let _num = data.readInt();
                let _str = data.readString();

                _checkResult(_num, _str);
                sleep(2000);
                return result;
            }
        }

        class MySequenceable {
            constructor(num, string) {
                this.num = num;
                this.str = string;
            }
            marshalling(messageParcel) {
                messageParcel.writeInt(this.num);
                messageParcel.writeString(this.str);
                return true;
            }
            unmarshalling(messageParcel) {
                this.num = messageParcel.readInt();
                this.str = messageParcel.readString();
                return true;
            }
        }


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

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0930
         * @tc.name    : test Test MessageSequence to deliver illegal RawData data
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0930", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0930---------------------------");
            try {
                var parcel = new rpc.MessageSequence();
                let arr = ["aaa", 1, 2, 3];
                parcel.writeInt(arr.length);
                parcel.writeRawData(arr, arr.length);
                expect(parcel.getRawDataCapacity()).assertEqual(128 * M);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                parcel.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0930---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0940
         * @tc.name    : test Call the writeremoteobject interface to serialize the remote object
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 1
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0940", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function () {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0940---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                let testRemoteObject = new TestRemoteObject("testObject");
                data.writeRemoteObject(testRemoteObject);
                expect(data.readRemoteObject() != null).assertTrue();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0940---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0950
         * @tc.name    : test Call the writeremoteobject interface to serialize the remote object and pass in the empty object
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0950", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0950---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                let token = new TestRemoteObject(null);
                data.writeRemoteObject(token);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0950---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0960
         * @tc.name    : test Call the writeremoteobject interface to serialize the remote object and pass in the empty object
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3   
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0960", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0960---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                let token = {};
                data.writeRemoteObject(token);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error.code == 1900008).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0960---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0970
         * @tc.name    : test Call the writeParcelable interface to write the custom serialized
         *             object to the MessageSequence instance
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0970", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function () {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0970---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                let sequenceable = new MySequenceable(1, "aaa");
                data.writeParcelable(sequenceable);
                let ret = new MySequenceable(0, "");
                data.readParcelable(ret);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error).assertEqual(null);
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0970---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0980
         * @tc.name    : test Call the writeParcelable interface to write the custom serialized
         *             object to the MessageSequence instance, Migration to read
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 1
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0980", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function () {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0980---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                let sequenceable = new MySequenceable(1, "aaa");
                data.writeParcelable(sequenceable);
                let ret = new MySequenceable(1, "");
                data.readParcelable(ret);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0980---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_0990
         * @tc.name    : test After the server finishes processing, write noexception first before writing the result,
         *             and the client calls readexception to judge whether the server is abnormal
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 1
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_0990", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_0990---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                data.writeNoException();
                data.writeInt(6);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_NOEXCEPTION, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    result.reply.readException();
                    expect(result.reply.readInt()).assertEqual(6);
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_0990---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1000
         * @tc.name    : test If the data on the server is abnormal, the client calls readexception
         *             to judge whether the server is abnormal
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_1000", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1000---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                data.writeNoException();
                data.writeInt(1232222223444);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_NOEXCEPTION, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    result.reply.readException();
                    expect(result.reply.readInt() != 1232222223444).assertTrue();
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1000---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1010
         * @tc.name    : test Serializable object marshaling and unmarshalling test
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_1010", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1010---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let sequenceable = new MySequenceable(1, "aaa");
                data.writeParcelable(sequenceable);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_SEQUENCEABLE, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    let s = new MySequenceable(null, null);
                    result.reply.readParcelable(s);
                    expect(s.str).assertEqual(sequenceable.str);
                    expect(s.num).assertEqual(sequenceable.num);
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1010---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1020
         * @tc.name    : test Non serializable object marshaling test
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 1
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_1020", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1020---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                let sequenceable = new MySequenceable(1, 1);
                data.writeParcelable(sequenceable);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                let errCode = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
                expect(error.code == errCode).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1020---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1030
         * @tc.name    : test The server did not send a serializable object, and the client was ungrouped
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 3
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_1030", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1030---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let sequenceable = 10;
                data.writeInt(sequenceable);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_INT, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    let s = new MySequenceable(0, null);
                    result.reply.readParcelable(s);
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1030---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1040
         * @tc.name    : test Call the writeParcelable interface to write the custom serialized object to the
         *             MessageSequence instance, and call readParcelable to read the data
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 1
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_1040", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1040---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let sequenceable = new MySequenceable(2, "abc");
                data.writeParcelable(sequenceable);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_SEQUENCEABLE, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    let s = new MySequenceable(null, null);
                    result.reply.readParcelable(s);
                    expect(s.str).assertEqual(sequenceable.str);
                    expect(s.num).assertEqual(sequenceable.num);
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1040---------------------------");
        });

        /*
         * @tc.number  : SUB_DSoftbus_IPC_API_MessageSequence_1050
         * @tc.name    : test Call the writeParcelablearray interface to write the custom serialized object array (1, 2, 3) to
         *              the MessageSequence instance, and call readParcelablearray to read the data
         * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
         * @tc.level   : Level 1
         * @tc.type    : Compatibility
         * @tc.size    : MediumTest
         */
        it("SUB_DSoftbus_IPC_API_MessageSequence_1050", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL1, async function (done) {
            console.info("---------------------start SUB_DSoftbus_IPC_API_MessageSequence_1050---------------------------");
            try {
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let sequenceable = [new MySequenceable(1, "aaa"),
                new MySequenceable(2, "bbb"), new MySequenceable(3, "ccc")];
                data.writeParcelableArray(sequenceable);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_WRITE_SEQUENCEABLEARRAY, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    let s = [new MySequenceable(null, null), new MySequenceable(null, null),
                    new MySequenceable(null, null)];
                    result.reply.readParcelableArray(s);
                    for (let i = 0; i < s.length; i++) {
                        expect(s[i].str).assertEqual(sequenceable[i].str);
                        expect(s[i].num).assertEqual(sequenceable[i].num);
                    };
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
                expect(error == null).assertTrue();
            } finally {
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_MessageSequence_1050---------------------------");
        });

    });
}
