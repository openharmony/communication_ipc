/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
import {describe, expect, beforeAll, it, TestType, Size, Level} from '@ohos/hypium';
import fileio from '@ohos.fileio';
import FA from '@ohos.ability.featureAbility';
var gIRemoteObject = null;
export default function ActsRpcRequestJsTest() {
    describe('ActsRpcRequestJsTest', function(){
        console.info("-----------------------SUB_DSoftbus_IPC_API_OnRemoteRequest_Test is starting-----------------------");
        beforeAll(async function () {
            console.info('beforeAll called');
            gIRemoteObject = new Stub("rpcTestAbility");
            return gIRemoteObject;
        });

        beforeEach(async function (){
            console.info('beforeEach called');
        });

        afterEach(async function (){
            console.info('afterEach called');
        });

        afterAll(async function (){
            console.info('afterAll called');
        });

        const CODE_ASYNC_ONREMOTEMESSAGE = 1;
        const CODE_ONREMOTE_ASYNC_ONREMOTEMESSAGE = 2;
        const CODE_ASHMEMDATA = 3;
        
        function sleep(numberMillis)
        {
            var now = new Date();
            var exitTime = now.getTime() + numberMillis;
            while (true) {
                now = new Date();
                if (now.getTime() > exitTime)
                    return;
            }
        }       

        class MyregisterDeathRecipient {
            constructor(gIRemoteObject) {
                this.gIRemoteObject = gIRemoteObject;
            }
            onRemoteDied() {
                console.info("server died");
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

        class TestListener extends rpc.RemoteObject {
            constructor(descriptor, checkResult) {
                super(descriptor);
                this.checkResult = checkResult;
            }
            onRemoteRequest(code, data, reply, option) {
                let result = false;
                if (code  == 1) {
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

        class TestRemoteObject extends rpc.RemoteObject {
            constructor(descriptor) {
                super(descriptor);
                this.modifyLocalInterface(this, descriptor);
            }
            asObject() {
                return this;
            }
        }        

        class Stub extends rpc.RemoteObject {
            constructor(descriptor) {
                super(descriptor);
            }
            onRemoteRequest(code, data, reply, option) {
                try{
                    console.info("onRemoteRequest: " + code);
                    if (code === 2){
                        console.info("case 1 start");
                        let tmp1 = data.readString();
                        let result =  reply.writeString("onRemoteRequest invoking");
                        return true;
                    } else {
                        console.error("onRemoteRequest default case " + code);
                        return super.onRemoteRequest(code, data, reply, option);
                    }
                } catch (error) {
                    console.info("onRemoteRequest error: " + error);
                }
                return false
            }
            async onRemoteMessageRequest(code, data, reply, option) {
                try{
                    if (code === 1){
                        console.info("case 1 start");
                        let tmp1 = data.readString();
                        reply.writeString("async onRemoteMessageRequest invoking");
                    } else if (code === 2){
                        console.info("case 2 start");
                        let tmp1 = data.readString();
                        reply.writeString("async onRemoteMessageRequest invoking");
                    }else if (code === 3){
                        console.info("case 3 start");
                        let tmp1 = data.readAshmem();
                        console.error("async onRemoteMessageRequest default case " + tmp1);
                        reply.writeAshmem(tmp1);
                    }else {
                        console.error("async onRemoteMessageRequest default case " + code);
                        return super.onRemoteMessageRequest(code, data, reply, option);
                    }
                    await new Promise((resolve)=>{
                        console.info("new promise")
                        setTimeout(resolve,100);
                    })
                    return true;
                } catch (error) {
                    console.info("async onRemoteMessageRequest: " + error);
                }
                return false
            }
        }        

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_9900
        * @tc.name   : test readParcelable is Call JS callback function failedv Error message verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_9900", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_9900---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                let ret = new MySequenceable(1, "");
                data.readParcelable(ret);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900012).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_9900 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_10000
        * @tc.name   : test writeByteArray interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_10000", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_10000---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeByteArray("The type does not match");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_10000 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_10100
        * @tc.name   : test readByteArray interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_10100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_10100---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.readByteArray("The type does not match");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_10100 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_10200
        * @tc.name   : test readByteArray interface, requires 1 parameters value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_10200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_10200---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeStringArray(["a","b","c"]);
                data.readByteArray();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_10200 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_10300
        * @tc.name   : readByteArray newArr is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_10300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_10300---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.reclaim();
                let newArr = new Array(5);
                data.readByteArray(newArr);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900010).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_10300---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_10400
        * @tc.name   : test writeShortArray interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_10400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_10400---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeShortArray("The type does not match");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_10400 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_10500
        * @tc.name   : test readShortArray interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_10500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_10500---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.readShortArray("The type does not match");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_10500 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_10600
        * @tc.name   : test readShortArray interface, requires 1 parameters value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_10600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_10600---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeStringArray(["a","b","c"]);
                data.readShortArray();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_10600 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_10700
        * @tc.name   : readShortArray newArr is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_10700", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_10700---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.reclaim();
                let newArr = new Array(5);
                data.readShortArray(newArr);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900010).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_10700---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_10800
        * @tc.name   : test writeIntArray interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_10800", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_10800---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeIntArray("The type does not match");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_10800 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_10900
        * @tc.name   : test readIntArray interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_10900", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_10900---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.readIntArray("The type does not match");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_10900 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_11000
        * @tc.name   : test readIntArray interface, requires 1 parameters value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_11000", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_11000---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeStringArray(["a","b","c"]);
                data.readIntArray();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_11000 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_11100
        * @tc.name   : readIntArray newArr is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_11100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_11100---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.reclaim();
                let newArr = new Array(5);
                data.readIntArray(newArr);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900010).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_11100---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_11200
        * @tc.name   : test writeLongArray interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_11200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_12000---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeLongArray("The type does not match");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_11200 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_11300
        * @tc.name   : test readLongArray interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_11300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_11300---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.readLongArray("The type does not match");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_11300 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_11400
        * @tc.name   : test readLongArray interface, requires 1 parameters value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_11400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_11400---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeStringArray(["a","b","c"]);
                data.readLongArray();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_11400 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_11500
        * @tc.name   : readLongArray newArr is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_11500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_11500---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.reclaim();
                let newArr = new Array(5);
                data.readLongArray(newArr);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900010).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_11500---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_11600
        * @tc.name   : test writeFloatArray interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_11600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_11600---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeFloatArray("The type does not match");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_11600 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_11700
        * @tc.name   : test readFloatArray interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_11700", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_11700---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.readFloatArray("The type does not match");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_11700 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_11800
        * @tc.name   : readFloatArray newArr is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_11800", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_10300---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.reclaim();
                let newArr = new Array(5);
                data.readFloatArray(newArr);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900010).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_11800---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_11900
        * @tc.name   : test writeDoubleArray interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_11900", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_11900---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeDoubleArray("The type does not match");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_11900 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_12000
        * @tc.name   : test readDoubleArray interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_12000", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_12000---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.readDoubleArray("The type does not match");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_12000 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_12000
        * @tc.name   : readDoubleArray newArr is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_12000", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_12000---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.reclaim();
                let newArr = new Array(5);
                data.readDoubleArray(newArr);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900010).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_12000---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_12100
        * @tc.name   : test writeBooleanArray interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_12100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_12100---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeBooleanArray("The type does not match");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_12100 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_12200
        * @tc.name   : test readBooleanArray interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_12200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_12200---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.readBooleanArray("The type does not match");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_12200 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_12300
        * @tc.name   : readBooleanArray newArr is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_12300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_12300---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.reclaim();
                let newArr = new Array(5);
                data.readBooleanArray(newArr);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900010).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_12300---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_12400
        * @tc.name   : test writeCharArray interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_12400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_12400---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeCharArray("The type does not match");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_12400 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_12500
        * @tc.name   : test readCharArray interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_12500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_12500---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.readCharArray("The type does not match");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_12500 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_12600
        * @tc.name   : readCharArray newArr is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_12600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_12600---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.reclaim();
                let newArr = new Array(5);
                data.readCharArray(newArr);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900010).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_12600---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_12700
        * @tc.name   : test writeStringArray interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_12700", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_12700---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeStringArray(3);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_12700 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_12800
        * @tc.name   : test readStringArray interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_12800", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_12800---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.readStringArray(123);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_12800 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_12900
        * @tc.name   : readStringArray newArr is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_12900", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_12900---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.reclaim();
                let newArr = new Array(5);
                data.readStringArray(newArr);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900010).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_12900---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_13000
        * @tc.name   : test writeParcelableArray interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_13000", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_13000---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeParcelableArray(123);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_13000 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_13100
        * @tc.name   : test readParcelableArray interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_13100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_13100---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.readParcelableArray("The type does not match");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_13100 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_13200
        * @tc.name   : test writeRemoteObjectArray interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_13200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_13200---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeRemoteObjectArray(123);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_13200 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_13300
        * @tc.name   : test readRemoteObjectArray interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_13300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_13300---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.readRemoteObjectArray("The type does not match");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_13300 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_13300
        * @tc.name   : readRemoteObjectArray newArr is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_13300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_13300---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.reclaim();
                let newArr = new Array(5);
                data.readRemoteObjectArray(newArr);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900010).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_13300---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_13400
        * @tc.name   : test closeFileDescriptor interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_13400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_13400---------------------------");
            try{
                rpc.MessageSequence.closeFileDescriptor("error");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_13400 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_13500
        * @tc.name   : test dupFileDescriptor interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_13500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_13500---------------------------");
            try{
                rpc.MessageSequence.dupFileDescriptor("error");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_13500 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_13600
        * @tc.name   : test writeFileDescriptor interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_13600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_13600---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeFileDescriptor("The type does not match");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_13600 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_13700
        * @tc.name   : test writeAshmem interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_13700", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_13700---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeAshmem("The type does not match");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_13700 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_13800
        * @tc.name   : test writeRawData interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_13800", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_13800---------------------------");
            try{
                var data = new rpc.MessageSequence();
                let rawdata = [1, 2, 3];
                data.writeRawData(rawdata, "error");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_13800 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_13900
        * @tc.name   : test readRawData interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_13900", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_13900---------------------------");
            try{
                var data = new rpc.MessageSequence();
                data.readRawData("error");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_13900 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_14000
        * @tc.name   : test readRawDataBuffer interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_14000", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_14000---------------------------");
            try{
                var data = new rpc.MessageSequence();
                data.readRawDataBuffer("error");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally {
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_14000 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_14100
        * @tc.name   : test sendMessageRequest interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_14100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_14100---------------------------");
            try{
                gIRemoteObject.sendMessageRequest(1);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } 
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_14100 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_14200
        * @tc.name   : test sendMessageRequestCallback interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_14200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_14200---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption(1);
                let token = "onRemoteRequest or async onRemoteMessageRequest invoking";
                data.writeString(token);
                function sendMessageRequestCallback(result) {
                    try{
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readString()).assertEqual("async onRemoteMessageRequest invoking");
                    } catch(e) {
                        expect(e == null).assertTrue();
                    }
                }
                console.info("start sendMessageRequestCallback");
                gIRemoteObject.sendMessageRequest(CODE_ASYNC_ONREMOTEMESSAGE, option,sendMessageRequestCallback);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally{
                data.reclaim();
                reply.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_14200 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_14300
        * @tc.name   : test getLocalInterface interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_14300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_14300---------------------------");
            try{
                let object = new Stub("Test0400");
                let result = object.isObjectDead();
                expect(result).assertEqual(false);
                object.modifyLocalInterface(object, "Test2");
                let res2 = object.getLocalInterface(123);
                console.info("getLocalInterface success: " + res2);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_14300 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_14400
        * @tc.name   : getLocalInterface is only proxy object permitted Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_14400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_14400---------------------------");
            try{
                let object = rpc.IPCSkeleton.getContextObject();
                object.getLocalInterface("test");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900006).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_14400 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_14500
        * @tc.name   : test registerDeathRecipient interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_14500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_14500---------------------------");
            try{
                let object = rpc.IPCSkeleton.getContextObject();
                object.registerDeathRecipient(0);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_14500 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_14600
        * @tc.name   : test unregisterDeathRecipient interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_14600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_14600---------------------------");
            try{
                let object = rpc.IPCSkeleton.getContextObject();
                object.unregisterDeathRecipient();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } 
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_14600 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_14700
        * @tc.name   : test getDescriptor interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_14700", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_14700---------------------------");
            try{
                let object = rpc.IPCSkeleton.getContextObject();
                object.getDescriptor();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900007).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_14700 ---------------------------");
        });

        /*
        * @tc.number  : SUB_DSoftbus_IPC_API_Errorcode_14800
        * @tc.name    : test flushCmdBuffer interface, illegal value verification
        * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level   : 3
        * @tc.type    : Compatibility
        * @tc.size    : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_14800", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_14800---------------------------");
            try {
                let remoteObject = null;
                rpc.IPCSkeleton.flushCmdBuffer(remoteObject);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_IPCSkeleton error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_14800---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_14900
        * @tc.name   : test sendMessageRequest interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_14900", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_14900---------------------------");
            try{
                let testRemoteObject = new TestRemoteObject("testObject");
                testRemoteObject.sendMessageRequest(1);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } 
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_14900 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_15000
        * @tc.name   : test sendMessageRequestCallback interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_15000", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_15000---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption(1);
                let testRemoteObject = new TestRemoteObject("testObject");
                let token = "onRemoteRequest or async onRemoteMessageRequest invoking";
                data.writeString(token);
                function sendMessageRequestCallback(result) {
                    try{
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readString()).assertEqual("async onRemoteMessageRequest invoking");
                    } catch(e) {
                        expect(e == null).assertTrue();
                    }
                }
                console.info("start sendMessageRequestCallback");
                testRemoteObject.sendMessageRequest(CODE_ASYNC_ONREMOTEMESSAGE, option,sendMessageRequestCallback);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            } finally{
                data.reclaim();
                reply.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_15000 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_15100
        * @tc.name   : test modifyLocalInterface interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_15100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_15100---------------------------");
            try{
                let testRemoteObject = new TestRemoteObject("testObject");
                testRemoteObject.modifyLocalInterface();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_15100 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_15200
        * @tc.name   : Test the function of serializing the writeAshmem interface in MessageSequence mode
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level3
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */   
        it("SUB_DSoftbus_IPC_API_Errorcode_15200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function(){
            console.info("--------------------start SUB_DSoftbus_IPC_API_Errorcode_15200--------------------");
            try{
                let ashmem = rpc.Ashmem.create(1, 1024);
                data.writeAshmem(ashmem);
                ashmem.unmapAshmem();
                ashmem.closeAshmem();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("--------------------end SUB_DSoftbus_IPC_API_Errorcode_15200--------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_15300
        * @tc.name   : Test the function of serializing the writeAshmem interface in MessageSequence mode
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level3
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */   
        it("SUB_DSoftbus_IPC_API_Errorcode_15300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function(){
            console.info("--------------------start SUB_DSoftbus_IPC_API_Errorcode_15300--------------------");
            try{
                let ashmem = rpc.Ashmem.create("ashmem", 1024*1024);
                let ashmem2 = rpc.Ashmem.create(ashmem,1);
                console.info("SUB_DSoftbus_IPC_API_Errorcode_15300 ashmem" + ashmem2);
                ashmem.unmapAshmem();
                ashmem.closeAshmem();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("--------------------end SUB_DSoftbus_IPC_API_Errorcode_15300--------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_15400
        * @tc.name   : test writeDataToAshmem interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_15400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_15400---------------------------");
            try{
                let TEST_LEN_M = 1024 * 1024;
                let ashmem = rpc.Ashmem.create('ashmem', TEST_LEN_M);
                ashmem.mapReadWriteAshmem();
                let buffer = new ArrayBuffer(TEST_LEN_M);
                ashmem.writeDataToAshmem(buffer, 0);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_15400 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_15500
        * @tc.name   : test readDataFromAshmem interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_15500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_15500---------------------------");
            try{
                let TEST_LEN_M = 1024 * 1024;
                let ashmem = rpc.Ashmem.create('ashmem', TEST_LEN_M);
                ashmem.mapReadWriteAshmem();
                let buffer = new ArrayBuffer(TEST_LEN_M);
                ashmem.writeDataToAshmem(buffer, 0);
                ashmem.readDataFromAshmem(0);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_15500 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_15600
        * @tc.name   : test readAshmem interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_15600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_15600---------------------------");
            try{
                let ashmem = rpc.Ashmem.create("ashmem", 1024*1024);
                ashmem.mapReadWriteAshmem();
                let ByteArrayVar = [1, 2, 3, 4, 5];
                ashmem.writeAshmem(ByteArrayVar, 5, 0);
                ashmem.readAshmem(0);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_15600 ---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_15700
        * @tc.name   : test readAshmem interface, illegal value verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3 
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_15700", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_15700---------------------------");
            try{
                let ashmem = rpc.Ashmem.create("ashmem", 1024 * 1024);
                ashmem.setProtectionType(rpc.Ashmem.PROT_WRITE, rpc.Ashmem.PROT_READ);
                console.info("SUB_DSoftbus_IPC_API_Ashmem_0450: run setProtectionType is success");
                ashmem.unmapAshmem();
                ashmem.closeAshmem();
            } catch (error) { 
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_15700 ---------------------------");
        });

        console.info("-----------------------SUB_DSoftbus_IPC_API_OnRemoteRequest_Test is end-----------------------");
    });
}
