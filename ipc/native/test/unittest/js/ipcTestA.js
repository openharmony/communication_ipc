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
        * @tc.number : SUB_DSoftbus_IPC_API_OnRemoteRequest_0100
        * @tc.name   : Verifying the processing of the MessageSequence synchronous callback information of the async_onRemoteMessageRequest interface
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level3
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */       
        it("SUB_DSoftbus_IPC_API_OnRemoteRequest_0100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(done){
            console.info("--------------------start SUB_DSoftbus_IPC_API_OnRemoteRequest_0100--------------------");
            try{
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let token = "async onRemoteMessageRequest invoking";
                data.writeString(token);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_ASYNC_ONREMOTEMESSAGE, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    expect(result.reply.readString()).assertEqual("async onRemoteMessageRequest invoking");
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error == null).assertTrue();
            }finally{
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("--------------------end SUB_DSoftbus_IPC_API_OnRemoteRequest_0100--------------------");
        });       

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_OnRemoteRequest_0200
        * @tc.name   : Verifying the processing of the MessageSequence Asynchronous callback information of the async_onRemoteMessageRequest interface
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level3
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */   
        it("SUB_DSoftbus_IPC_API_OnRemoteRequest_0200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(done){
            console.info("--------------------start SUB_DSoftbus_IPC_API_OnRemoteRequest_0200--------------------");
            try{
                var data = new rpc.MessageSequence();
                var reply = new rpc.MessageSequence();
                var option = new rpc.MessageOption(1);
                let token = "async onRemoteMessageRequest invoking";
                data.writeString(token);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_ASYNC_ONREMOTEMESSAGE, data, reply, option).then(function(result){
                    expect(result.errCode).assertEqual(0);
                    expect(result.reply.readString()).assertEqual("async onRemoteMessageRequest invoking");
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error == null).assertTrue();
            }finally{
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("--------------------end SUB_DSoftbus_IPC_API_OnRemoteRequest_0200--------------------");
        });      

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_OnRemoteRequest_0300
        * @tc.name   : To test the processing priority of the MessageSequence interface for synchronously invoking 
        *               onRemoteRequest and async_onRemoteMessageRequest callback information
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level3
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */   
        it("SUB_DSoftbus_IPC_API_OnRemoteRequest_0300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(done){
            console.info("--------------------start SUB_DSoftbus_IPC_API_OnRemoteRequest_0300--------------------");
            try{
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let token = "onRemoteRequest or async onRemoteMessageRequest invoking";
                data.writeString(token);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_ONREMOTE_ASYNC_ONREMOTEMESSAGE, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    expect(result.reply.readString()).assertEqual("async onRemoteMessageRequest invoking");
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error == null).assertTrue();
            }finally{
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("--------------------end SUB_DSoftbus_IPC_API_OnRemoteRequest_0300--------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_OnRemoteRequest_0400
        * @tc.name   : To test the processing priority of the MessageSequence interface for Asynchronously invoking 
        *               onRemoteRequest and async_onRemoteMessageRequest callback information
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level3
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */   
        it("SUB_DSoftbus_IPC_API_OnRemoteRequest_0400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(done){
            console.info("--------------------start SUB_DSoftbus_IPC_API_OnRemoteRequest_0400--------------------");
            try{
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption(1);
                let token = "onRemoteRequest or async onRemoteMessageRequest invoking";
                data.writeString(token);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendMessageRequest(CODE_ONREMOTE_ASYNC_ONREMOTEMESSAGE, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    expect(result!=null).assertTrue();
                    expect(result.reply.readString()).assertEqual("async onRemoteMessageRequest invoking");
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error == null).assertTrue();
            }finally{
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("--------------------end SUB_DSoftbus_IPC_API_OnRemoteRequest_0400--------------------");
        });
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_OnRemoteRequest_0500
        * @tc.name   : Verifying the processing of the MessageParcel synchronous callback information of the async_onRemoteMessageRequest interface
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level3
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */   
        it("SUB_DSoftbus_IPC_API_OnRemoteRequest_0500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(done){
            console.info("--------------------start SUB_DSoftbus_IPC_API_OnRemoteRequest_0500--------------------");
            try{
                var data = rpc.MessageParcel.create();
                var reply = rpc.MessageParcel.create();
                let option = new rpc.MessageOption();
                let token = "async onRemoteMessageRequest invoking";
                var result = data.writeString(token);
                expect(result == true).assertTrue();
                if (gIRemoteObject == undefined)
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendRequest(CODE_ASYNC_ONREMOTEMESSAGE, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    expect(result.reply.readString()).assertEqual("async onRemoteMessageRequest invoking");
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error).assertEqual(null);
            }finally{
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("--------------------end SUB_DSoftbus_IPC_API_OnRemoteRequest_0500--------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_OnRemoteRequest_0600
        * @tc.name   : Verifying the processing of the MessageParcel Asynchronous callback information of the async_onRemoteMessageRequest interface
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level3
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */   
        it("SUB_DSoftbus_IPC_API_OnRemoteRequest_0600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(done){
            console.info("--------------------start SUB_DSoftbus_IPC_API_OnRemoteRequest_0600--------------------");
            try{
                var data = rpc.MessageParcel.create();
                var reply = rpc.MessageParcel.create();
                let option = new rpc.MessageOption(1);
                let token = 'async onRemoteMessageRequest invoking';
                var result = data.writeString(token);
                expect(result == true).assertTrue();
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendRequest(CODE_ASYNC_ONREMOTEMESSAGE, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    expect(result.reply.readString()).assertEqual("async onRemoteMessageRequest invoking");
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error).assertEqual(null);
            }finally{
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("--------------------end SUB_DSoftbus_IPC_API_OnRemoteRequest_0600--------------------");
        });  
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_OnRemoteRequest_0700
        * @tc.name   : To test the processing priority of the MessageParcel interface for synchronously invoking 
        *               onRemoteRequest and async_onRemoteMessageRequest callback information
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level3
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */   
        it("SUB_DSoftbus_IPC_API_OnRemoteRequest_0700", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(done){
            console.info("--------------------start SUB_DSoftbus_IPC_API_OnRemoteRequest_0700--------------------");
            try{
                var data = rpc.MessageParcel.create();
                var reply = rpc.MessageParcel.create();
                let option = new rpc.MessageOption();
                let token = 'onRemoteRequest or async onRemoteMessageRequest invoking';
                var result = data.writeString(token);
                expect(result == true).assertTrue();
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendRequest(CODE_ONREMOTE_ASYNC_ONREMOTEMESSAGE, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    var replyReadResult = result.reply.readString();
                    expect(replyReadResult).assertEqual("async onRemoteMessageRequest invoking");
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error).assertEqual(null);
            }finally{
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("--------------------end SUB_DSoftbus_IPC_API_OnRemoteRequest_0700--------------------");
        });
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_OnRemoteRequest_0800
        * @tc.name   : To test the processing priority of the MessageParcel interface for Asynchronously invoking 
        *               onRemoteRequest and async_onRemoteMessageRequest callback information
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level3
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */   
        it("SUB_DSoftbus_IPC_API_OnRemoteRequest_0800", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(done){
            console.info("--------------------start SUB_DSoftbus_IPC_API_OnRemoteRequest_0800--------------------");
            try{
                var data = rpc.MessageParcel.create();
                var reply = rpc.MessageParcel.create();
                let option = new rpc.MessageOption(1);
                let token = 'onRemoteRequest or async onRemoteMessageRequest invoking';
                var result = data.writeString(token);
                expect(result == true).assertTrue();
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendRequest(CODE_ONREMOTE_ASYNC_ONREMOTEMESSAGE, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    expect(result.reply.readString()).assertEqual("async onRemoteMessageRequest invoking");
                });
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error).assertEqual(null);
            }finally{
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("--------------------end SUB_DSoftbus_IPC_API_OnRemoteRequest_0800--------------------");
        });
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_OnRemoteRequest_0900
        * @tc.name   : Invoke async_onRemoteMessageRequest to process information in synchronization mode and call back in AsyncCallback mode
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level3
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */   
        it("SUB_DSoftbus_IPC_API_OnRemoteRequest_0900", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function(done){
            console.info("--------------------start SUB_DSoftbus_IPC_API_OnRemoteRequest_0900--------------------");
            try{
                function sendMessageRequestCallback(result) {
                    try{
                        expect(result.errCode).assertEqual(0);
                        expect(result.reply.readString()).assertEqual("async onRemoteMessageRequest invoking");
                    } catch(e) {
                        expect(e == null).assertTrue();
                    }finally{
                        data.reclaim();
                        reply.reclaim();
                        done();
                    }
                }
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let token = "onRemoteRequest or async onRemoteMessageRequest invoking";
                data.writeString(token);
                console.info("start sendMessageRequestCallback");
                gIRemoteObject.sendMessageRequest(CODE_ASYNC_ONREMOTEMESSAGE, data, reply, option, sendMessageRequestCallback);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error == null).assertTrue();
            }
            console.info("--------------------end SUB_DSoftbus_IPC_API_OnRemoteRequest_0900--------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_OnRemoteRequest_1000
        * @tc.name   : Invoke async_onRemoteMessageRequest to process information in asynchronous mode and call back in AsyncCallback mode
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level3
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */   
        it("SUB_DSoftbus_IPC_API_OnRemoteRequest_1000", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function(done){
            console.info("--------------------start SUB_DSoftbus_IPC_API_OnRemoteRequest_1000--------------------");
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
                    }finally{
                        data.reclaim();
                        reply.reclaim();
                        done();
                    }
                }
                console.info("start sendMessageRequestCallback");
                gIRemoteObject.sendMessageRequest(CODE_ASYNC_ONREMOTEMESSAGE, data, reply, option,sendMessageRequestCallback);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error == null).assertTrue();
            }
            console.info("--------------------end SUB_DSoftbus_IPC_API_OnRemoteRequest_1000--------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_OnRemoteRequest_1100
        * @tc.name   : Test the function of serializing the writeAshmem interface in MessageSequence mode
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level3
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */   
        it("SUB_DSoftbus_IPC_API_OnRemoteRequest_1100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function(){
            console.info("--------------------start SUB_DSoftbus_IPC_API_OnRemoteRequest_1100--------------------");
            try{
                var data = rpc.MessageSequence.create();
                let ashmem = rpc.Ashmem.create("ashmem", 1024);
                data.writeAshmem(ashmem);
                let ashmemdata = data.readAshmem();
                expect(ashmemdata != null).assertTrue();
                ashmem.unmapAshmem();
                ashmem.closeAshmem();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error == null).assertTrue();
            }finally{
                data.reclaim();
            }
            console.info("--------------------end SUB_DSoftbus_IPC_API_OnRemoteRequest_1100--------------------");
        }); 
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_OnRemoteRequest_1200
        * @tc.name   : Test the function of serializing the readAshmem interface in MessageSequence mode
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level3
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */   
        it("SUB_DSoftbus_IPC_API_OnRemoteRequest_1200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(done){
            console.info("--------------------start SUB_DSoftbus_IPC_API_OnRemoteRequest_1200--------------------");
            try{
                var data = rpc.MessageSequence.create();
                var reply = rpc.MessageSequence.create();
                let option = new rpc.MessageOption();
                let ashmem = rpc.Ashmem.create("ashmem", 1024);
                data.writeAshmem(ashmem);
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendRequest(CODE_ASHMEMDATA, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    let replyReadResult = result.reply.readAshmem();
                    expect(replyReadResult != null).assertTrue();
                });
                ashmem.unmapAshmem();
                ashmem.closeAshmem();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error).assertEqual(null);
            }finally{
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("--------------------end SUB_DSoftbus_IPC_API_OnRemoteRequest_1200--------------------");
        });  
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_OnRemoteRequest_1300
        * @tc.name   : Test the function of serializing the writeAshmem interface in MessageParcel mode
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level3
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */   
        it("SUB_DSoftbus_IPC_API_OnRemoteRequest_1300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function(){
            console.info("--------------------start SUB_DSoftbus_IPC_API_OnRemoteRequest_1300--------------------");
            try{
                var data = rpc.MessageParcel.create();
                let ashmem = rpc.Ashmem.create("ashmem", 1024);
                let weitedata = data.writeAshmem(ashmem);
                expect(weitedata).assertTrue();
                let ashmemdata = data.readAshmem();
                expect(ashmemdata != null).assertTrue();
                ashmem.unmapAshmem();
                ashmem.closeAshmem();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error == null).assertTrue();
            }finally{
                data.reclaim();
            }
            console.info("--------------------end SUB_DSoftbus_IPC_API_OnRemoteRequest_1300--------------------");
        }); 
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_OnRemoteRequest_1400
        * @tc.name   : Test the function of serializing the readAshmem interface in MessageParcel mode
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level3
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */   
        it("SUB_DSoftbus_IPC_API_OnRemoteRequest_1400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(done){
            console.info("--------------------start SUB_DSoftbus_IPC_API_OnRemoteRequest_1400--------------------");
            try{
                var data = rpc.MessageParcel.create();
                var reply = rpc.MessageParcel.create();
                let option = new rpc.MessageOption();
                let ashmem = rpc.Ashmem.create("ashmem", 1024);
                let weitedata = data.writeAshmem(ashmem);
                expect(weitedata).assertTrue();
                expect(gIRemoteObject != undefined).assertTrue();
                await gIRemoteObject.sendRequest(CODE_ASHMEMDATA, data, reply, option).then((result) => {
                    expect(result.errCode).assertEqual(0);
                    let replyReadResult = result.reply.readAshmem();
                    expect(replyReadResult != null).assertTrue();
                });
                ashmem.unmapAshmem();
                ashmem.closeAshmem();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error).assertEqual(null);
            }finally{
                data.reclaim();
                reply.reclaim();
                done();
            }
            console.info("--------------------end SUB_DSoftbus_IPC_API_OnRemoteRequest_1400--------------------");
        });  
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_OnRemoteRequest_1500
        * @tc.name   : To test the function of handling the exception of the writeAshmem interface in MessageSequence mode
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level3
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */   
        it("SUB_DSoftbus_IPC_API_OnRemoteRequest_1500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function(){
            console.info("--------------------start SUB_DSoftbus_IPC_API_OnRemoteRequest_1500--------------------");
            try{
                var data = rpc.MessageSequence.create();
                let ashmem = "";
                data.writeAshmem(ashmem);
                ashmem.unmapAshmem();
                ashmem.closeAshmem();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 401).assertTrue();
                expect(error.message != null).assertTrue();
            }finally{
                data.reclaim();
            }
            console.info("--------------------end SUB_DSoftbus_IPC_API_OnRemoteRequest_1500--------------------");
        }); 
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_OnRemoteRequest_1600
        * @tc.name   : To test the function of handling the exception of the writeAshmem interface in MessageParcel mode
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level3
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */   
        it("SUB_DSoftbus_IPC_API_OnRemoteRequest_1600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, function(){
            console.info("--------------------start SUB_DSoftbus_IPC_API_OnRemoteRequest_1600--------------------");
            try{
                var data = rpc.MessageParcel.create();
                let weitedata = data.writeAshmem();
                ashmem.unmapAshmem();
                ashmem.closeAshmem();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error != null).assertTrue();
            }finally{
                data.reclaim();
            }
            console.info("--------------------end SUB_DSoftbus_IPC_API_OnRemoteRequest_1600--------------------");
        });
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_0000
        * @tc.name   : test errorcode data verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_0000", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_0000---------------------------");
            try{
                let errCode401 = `${rpc.ErrorCode.CHECK_PARAM_ERROR}`;
                expect(errCode401).assertEqual("401");
                let errCode1900001 = `${rpc.ErrorCode.OS_MMAP_ERROR}`;
                expect(errCode1900001).assertEqual("1900001");
                let errCode1900002 = `${rpc.ErrorCode.OS_IOCTL_ERROR}`;
                expect(errCode1900002).assertEqual("1900002");
                let errCode1900003 = `${rpc.ErrorCode.WRITE_TO_ASHMEM_ERROR}`;
                expect(errCode1900003).assertEqual("1900003");
                let errCode1900004 = `${rpc.ErrorCode.READ_FROM_ASHMEM_ERROR}`;
                expect(errCode1900004).assertEqual("1900004");
                let errCode1900005 = `${rpc.ErrorCode.ONLY_PROXY_OBJECT_PERMITTED_ERROR}`;
                expect(errCode1900005).assertEqual("1900005");
                let errCode1900006 = `${rpc.ErrorCode.ONLY_REMOTE_OBJECT_PERMITTED_ERROR}`;
                expect(errCode1900006).assertEqual("1900006");
                let errCode1900007 = `${rpc.ErrorCode.COMMUNICATION_ERROR}`;
                expect(errCode1900007).assertEqual("1900007");
                let errCode1900008 = `${rpc.ErrorCode.PROXY_OR_REMOTE_OBJECT_INVALID_ERROR}`;
                expect(errCode1900008).assertEqual("1900008");
                let errCode1900009 = `${rpc.ErrorCode.WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR}`;
                expect(errCode1900009).assertEqual("1900009");
                let errCode1900010 = `${rpc.ErrorCode.READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR}`;
                expect(errCode1900010).assertEqual("1900010");
                let errCode1900011 = `${rpc.ErrorCode.PARCEL_MEMORY_ALLOC_ERROR}`;
                expect(errCode1900011).assertEqual("1900011");
                let errCode1900012 = `${rpc.ErrorCode.CALL_JS_METHOD_ERROR}`;
                expect(errCode1900012).assertEqual("1900012");
                let errCode1900013 = `${rpc.ErrorCode.OS_DUP_ERROR}`;
                expect(errCode1900013).assertEqual("1900013");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.message == null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_0000---------------------------");
        });

        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_0100
        * @tc.name   : writeRemoteObject is write data to message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_0100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_0100---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                let testRemoteObject = new TestRemoteObject("testObject");
                data.reclaim();
                data.writeRemoteObject(testRemoteObject);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900009).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_0100---------------------------");
        });        
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_0200
        * @tc.name   : readRemoteObject is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_0200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_0200---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                let testRemoteObject = new TestRemoteObject("testObject");
                data.writeRemoteObject(testRemoteObject);
                data.reclaim();
                data.readRemoteObject();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900010).assertTrue();
                expect(error.message != null).assertTrue();
            } 
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_0200---------------------------");
        });         
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_0300
        * @tc.name   : readRemoteObject is proxy or remote object is invalid Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_0300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_0300---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.readRemoteObject();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900008).assertTrue();
                expect(error.message != null).assertTrue();
            } finally{
                data.reclaim();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_0300---------------------------");
        });
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_0400
        * @tc.name   : writeInterfaceToken is write data to message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_0400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_0400---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.reclaim();
                data.writeInterfaceToken("rpctest");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900009).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_0400---------------------------");
        });
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_0500
        * @tc.name   : readInterfaceToken is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_0500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_0500---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeInterfaceToken("rpctest");
                data.reclaim();
                data.readInterfaceToken();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900010).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_0500---------------------------");
        });
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_0600
        * @tc.name   : setSize is write data to message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_0600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_0600---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.reclaim();
                data.setSize(0);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900009).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_0600---------------------------");
        });
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_0700
        * @tc.name   : setCapacity is write data to message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_0700", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_0700---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.reclaim();
                data.setCapacity(64);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900009).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_0700---------------------------");
        }); 
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_0800
        * @tc.name   : rewindRead is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_0800", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_0800---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.reclaim();
                data.rewindRead(0);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900010).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_0800---------------------------");
        });  
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_0900
        * @tc.name   : rewindWrite is write data to message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_0900", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_0900---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.reclaim();
                data.rewindWrite(0);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900009).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_0900---------------------------");
        });
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_1000
        * @tc.name   : writeByte is write data to message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_1000", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_1000---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.reclaim();
                data.writeByte(2);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900009).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_1000---------------------------");
        });
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_1100
        * @tc.name   : readByte is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_1100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_1100---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.reclaim();
                data.readByte();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900010).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_1100---------------------------");
        });
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_1200
        * @tc.name   : writeShort is write data to message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_1200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_1200---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.reclaim();
                data.writeShort(0);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900009).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_1200---------------------------");
        });
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_1300
        * @tc.name   : readShort is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_1300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_1300---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeShort(0);
                data.reclaim();
                data.readShort();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900010).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_1300---------------------------");
        });
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_1400
        * @tc.name   : writeInt is write data to message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_1400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_1400---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.reclaim();
                data.writeInt(0);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900009).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_1400---------------------------");
        }); 
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_1500
        * @tc.name   : readInt is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_1500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_1500---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeInt(0);
                data.reclaim();
                data.readInt();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900010).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_1500---------------------------");
        });
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_1600
        * @tc.name   : writeLong is write data to message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_1600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_1600---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.reclaim();
                data.writeLong(0);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900009).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_1600---------------------------");
        }); 
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_1700
        * @tc.name   : readLong is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_1700", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_1700---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeLong(0);
                data.reclaim();
                data.readLong();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900010).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_1700---------------------------");
        });
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_1800
        * @tc.name   : writeFloat is write data to message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_1800", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_1800---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.reclaim();
                data.writeFloat(1.0);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900009).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_1800---------------------------");
        }); 
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_1900
        * @tc.name   : readFloat is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_1900", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_1900---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeFloat(1.0);
                data.reclaim();
                data.readFloat();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900010).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_1900---------------------------");
        });
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_2000
        * @tc.name   : writeDouble is write data to message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_2000", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_2000---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.reclaim();
                data.writeDouble(1.0);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900009).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_2000---------------------------");
        }); 
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_2100
        * @tc.name   : readDouble is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_2100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_2100---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeDouble(1.0);
                data.reclaim();
                data.readDouble();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900010).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_2100---------------------------");
        });
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_2200
        * @tc.name   : writeBoolean is write data to message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_2200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_2200---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.reclaim();
                data.writeBoolean(true);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900009).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_2200---------------------------");
        }); 
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_2300
        * @tc.name   : readBoolean is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_2300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_2300---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeBoolean(true);
                data.reclaim();
                data.readBoolean();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900010).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_2300---------------------------");
        });
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_2400
        * @tc.name   : writeChar is write data to message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_2400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_2400---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.reclaim();
                data.writeChar(56);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900009).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_2400---------------------------");
        }); 
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_2500
        * @tc.name   : readChar is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_2500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_2500---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeChar(56);
                data.reclaim();
                data.readChar();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900010).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_2500---------------------------");
        });
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_2600
        * @tc.name   : writeString is write data to message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_2600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_2600---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.reclaim();
                data.writeString("rpc");
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900009).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_2600---------------------------");
        }); 
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_2700
        * @tc.name   : readString is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_2700", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_2700---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                data.writeString("rpc");
                data.reclaim();
                data.readString();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900010).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_2700---------------------------");
        });
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_2800
        * @tc.name   : writeParcelable is write data to message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_2800", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_2800---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                let sequenceable = new MySequenceable(1, "aaa");
                data.reclaim();
                data.writeParcelable(sequenceable);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900009).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_2800---------------------------");
        }); 
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_2900
        * @tc.name   : writeParcelable is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_2900", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_2900---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                let sequenceable = new MySequenceable(1, "aaa");
                data.writeParcelable(sequenceable);
                let ret = new MySequenceable(0, "");
                data.reclaim();
                data.readParcelable(ret);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900010).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_2900---------------------------");
        });
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_3000
        * @tc.name   : writeByteArray is write data to message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_3000", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_3000---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                let ArrayVar = [1, 2, 3, 4, 5];
                data.reclaim();
                data.writeByteArray(ArrayVar);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900009).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_3000---------------------------");
        }); 
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_3100
        * @tc.name   : readByteArray is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_3100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_3100---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                let ArrayVar = [1, 2, 3, 4, 5];
                data.writeByteArray(ArrayVar);
                data.reclaim();
                data.readByteArray();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900010).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_3100---------------------------");
        });
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_3200
        * @tc.name   : writeShortArray is write data to message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_3200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_3200---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                let ArrayVar = [1, 2, 3, 4, 5];
                data.reclaim();
                data.writeShortArray(ArrayVar);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900009).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_3200---------------------------");
        }); 
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_3300
        * @tc.name   : readShortArray is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_3300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_3300---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                let ArrayVar = [1, 2, 3, 4, 5];
                data.writeShortArray(ArrayVar);
                data.reclaim();
                data.readShortArray();
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900010).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_3300---------------------------");
        });
        
        /*
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_3400
        * @tc.name   : writeIntArray is write data to message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
        it("SUB_DSoftbus_IPC_API_Errorcode_3400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
            console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_3400---------------------------");
            try{
                var data = rpc.MessageSequence.create();
                let ArrayVar = [1, 2, 3, 4, 5];
                data.reclaim();
                data.writeIntArray(ArrayVar);
            } catch (error) {
                console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
                expect(error.code == 1900009).assertTrue();
                expect(error.message != null).assertTrue();
            }
            console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_3400---------------------------");
        }); 

        console.info("-----------------------SUB_DSoftbus_IPC_API_OnRemoteRequest_Test is end-----------------------");
    });
}
