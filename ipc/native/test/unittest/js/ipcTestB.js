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
        * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_3500
        * @tc.name   : readIntArray is read data from message sequence failed Error verification
        * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
        * @tc.level  : Level 3  
        * @tc.type   : Compatibility
        * @tc.size   : MediumTest
        */
       it("SUB_DSoftbus_IPC_API_Errorcode_3500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_3500---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let ArrayVar = [1, 2, 3, 4, 5];
            data.writeIntArray(ArrayVar);
            data.reclaim();
            data.readIntArray();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900010).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_3500---------------------------");
    }); 
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_3600
    * @tc.name   : writeLongArray is write data to message sequence failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_3600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_3600---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let ArrayVar = [1, 2, 3, 4, 5];
            data.reclaim();
            data.writeLongArray(ArrayVar);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900009).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_3600---------------------------");
    }); 
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_3700
    * @tc.name   : readLongArray is read data from message sequence failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_3700", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_3700---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let ArrayVar = [1, 2, 3, 4, 5];
            data.writeLongArray(ArrayVar);
            data.reclaim();
            data.readLongArray();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900010).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_3700---------------------------");
    }); 
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_3800
    * @tc.name   : writeFloatArray is write data to message sequence failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_3800", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_3800---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let ArrayVar = [1.1, 2.2, 3.3];
            data.reclaim();
            data.writeFloatArray(ArrayVar);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900009).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_3800---------------------------");
    }); 
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_3900
    * @tc.name   : readFloatArray is read data from message sequence failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_3900", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_3900---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let ArrayVar = [1.1, 2.2, 3.3];
            data.writeFloatArray(ArrayVar);
            data.reclaim();
            data.readFloatArray();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900010).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_3900---------------------------");
    }); 
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_4000
    * @tc.name   : writeDoubleArray is write data to message sequence failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_4000", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_4000---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let ArrayVar = [11.1, 22.2, 33.3];
            data.reclaim();
            data.writeDoubleArray(ArrayVar);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900009).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_4000---------------------------");
    }); 
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_4100
    * @tc.name   : readDoubleArray is read data from message sequence failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_4100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_4100---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let ArrayVar = [11.1, 22.2, 33.3];
            data.writeDoubleArray(ArrayVar);
            data.reclaim();
            data.readDoubleArray();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900010).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_4100---------------------------");
    }); 
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_4200
    * @tc.name   : writeBooleanArray is write data to message sequence failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_4200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_4200---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let ArrayVar = [false, true, false];
            data.reclaim();
            data.writeBooleanArray(ArrayVar);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900009).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_4200---------------------------");
    }); 
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_4300
    * @tc.name   : readBooleanArray is read data from message sequence failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_4300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_4300---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let ArrayVar = [false, true, false];
            data.writeBooleanArray(ArrayVar);
            data.reclaim();
            data.readBooleanArray();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900010).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_4300---------------------------");
    }); 
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_4400
    * @tc.name   : writeCharArray is write data to message sequence failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_4400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_4400---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let ArrayVar = [97, 98, 88];
            data.reclaim();
            data.writeCharArray(ArrayVar);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900009).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_4400---------------------------");
    }); 
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_4500
    * @tc.name   : readCharArray is read data from message sequence failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_4500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_4500---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let ArrayVar = [97, 98, 88];
            data.writeCharArray(ArrayVar);
            data.reclaim();
            data.readCharArray();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900010).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_4500---------------------------");
    }); 
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_4600
    * @tc.name   : writeStringArray is write data to message sequence failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_4600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_4600---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let ArrayVar = ["abc", "def"];
            data.reclaim();
            data.writeStringArray(ArrayVar);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900009).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_4600---------------------------");
    }); 
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_4700
    * @tc.name   : readStringArray is read data from message sequence failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_4700", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_4700---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let ArrayVar = ["abc", "def"];
            data.writeStringArray(ArrayVar);
            data.reclaim();
            data.readStringArray();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900010).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_4700---------------------------");
    }); 
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_4800
    * @tc.name   : writeNoException is write data to message sequence failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_4800", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_4800---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            data.reclaim();
            data.writeNoException();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900009).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_4800---------------------------");
    }); 
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_4900
    * @tc.name   : readException is read data from message sequence failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_4900", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_4900---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            data.reclaim();
            data.readException();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900010).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_4900 ---------------------------");
    });
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_5000
    * @tc.name   : writeParcelableArray is write data to message sequence failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_5000", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_5000---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let a = [new MySequenceable(1, "aaa"), new MySequenceable(2, "bbb"),
            new MySequenceable(3, "ccc")];
            data.reclaim();
            data.writeParcelableArray(a);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900009).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_5000---------------------------");
    }); 
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_5100
    * @tc.name   : readParcelableArray is read data from message sequence failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_5100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_5100---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let a = [new MySequenceable(1, "aaa"), new MySequenceable(2, "bbb"),
            new MySequenceable(3, "ccc")];
            let b = [new MySequenceable(0, ""), new MySequenceable(0, ""), new MySequenceable(0, "")];
            data.writeParcelableArray(a);
            data.reclaim();
            data.readParcelableArray(b);                
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900010).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_5100 ---------------------------");
    });
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_5200
    * @tc.name   : writeRemoteObjectArray is write data to message sequence failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_5200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_5200---------------------------");
        try{
            let count = 0;
            function checkResult(num, str) {
                expect(num).assertEqual(123);
                expect(str).assertEqual("rpcListenerTest");
                count++;
                console.info("check result done, count: " + count);
                if (count == 3) {
                    done();
                }
            }
            var data = rpc.MessageSequence.create();
            let listeners = [new TestListener("rpcListener", checkResult),
                new TestListener("rpcListener2", checkResult),
                new TestListener("rpcListener3", checkResult)];
            data.reclaim();
            data.writeRemoteObjectArray(listeners);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900009).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_5200---------------------------");
    }); 
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_5300
    * @tc.name   : readRemoteObjectArray is read data from message sequence failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_5300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_5300---------------------------");
        try{
            let count = 0;
            function checkResult(num, str) {
                expect(num).assertEqual(123);
                expect(str).assertEqual("rpcListenerTest");
                count++;
                console.info("check result done, count: " + count);
                if (count == 3) {
                    done();
                }
            }
            var data = rpc.MessageSequence.create();
            let listeners = [new TestListener("rpcListener", checkResult),
                new TestListener("rpcListener2", checkResult),
                new TestListener("rpcListener3", checkResult)];
            data.writeRemoteObjectArray(listeners);
            data.reclaim();
            data.readRemoteObjectArray();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900010).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_5300 ---------------------------");
    }); 
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_5400
    * @tc.name   : dupFileDescriptor is call os dup function failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_5400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_5400---------------------------");
        try{
            rpc.MessageSequence.dupFileDescriptor(-1);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900013).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_5400 ---------------------------");
    });         
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_5500
    * @tc.name   : writeFileDescriptor is write data to message sequence failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_5500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_5500---------------------------");
        try{
            let context = FA.getContext();
            await context.getFilesDir().then(async function(path) {
                expect(path != null).assertTrue();
                let basePath = path;
                let filePath = basePath + "/test1.txt";
                let fd = fileio.openSync(filePath, 0o2| 0o100 | 0o2000, 0o666);
                var data = rpc.MessageSequence.create();
                data.reclaim();
                data.writeFileDescriptor(fd);
            })
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900009).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_5500 ---------------------------");
    });
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_5600
    * @tc.name   : readFileDescriptor is read data from message sequence failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_5600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_5600---------------------------");
        try{
            let context = FA.getContext();
            await context.getFilesDir().then(async function(path) {
                expect(path != null).assertTrue();
                let basePath = path;
                let filePath = basePath + "/test1.txt";
                let fd = fileio.openSync(filePath, 0o2| 0o100 | 0o2000, 0o666);
                var data = rpc.MessageSequence.create();
                data.writeFileDescriptor(fd);
                data.reclaim();
                data.readFileDescriptor();
            })
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900010).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_5600 ---------------------------");
    });
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_5700
    * @tc.name   : writeAshmem is write data to message sequence failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_5700", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_5700---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let ashmem = rpc.Ashmem.create("JsAshmemTest", 1024);
            data.reclaim();
            data.writeAshmem(ashmem);
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900009).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_5700 ---------------------------");
    });
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_5800
    * @tc.name   :  readAshmem is read data from message sequence failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_5800", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_5800---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let ashmem = rpc.Ashmem.create("JsAshmemTest", 1024);
            data.writeAshmem(ashmem);
            data.reclaim();
            data.readAshmem();
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900010).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_5800 ---------------------------");
    }); 
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_5900
    * @tc.name   : writeRawData is write data to message sequence failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_5900", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_5900---------------------------");
        try{
            var data = new rpc.MessageSequence();
            let arr = ["aaa", 1, 2, 3];
            data.reclaim();
            data.writeRawData(arr, arr.length);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900009).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_5900 ---------------------------");
    });
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_6000
    * @tc.name   : readRawData is read data from message sequence failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_6000", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_6000---------------------------");
        try{
            var data = new rpc.MessageSequence();
            let rawdata = [1, 2, 3]
            data.writeRawData(rawdata, rawdata.length);
            data.reclaim();
            data.readRawData(rawdata.length);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900010).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_6000 ---------------------------");
    });
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_6100
    * @tc.name   : registerDeathRecipient is only proxy object permitted Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_6100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_6100---------------------------");
        try{
            let recipient = new MyregisterDeathRecipient(gIRemoteObject, null);
            gIRemoteObject.registerDeathRecipient(recipient, 0)
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900005).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_6100 ---------------------------");
    });
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_6200
    * @tc.name   : unregisterDeathRecipient is only proxy object permitted Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_6200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_6200---------------------------");
        try{
            let recipient = new MyregisterDeathRecipient(gIRemoteObject, null);
            gIRemoteObject.unregisterDeathRecipient(recipient, 0);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900005).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_6200 ---------------------------");
    });      
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_6300
    * @tc.name   : writeAshmem is write to ashmem failed Error verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_6300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_6300---------------------------");
        try{
            let ashmem = rpc.Ashmem.create("ashmem", 4);
            ashmem.mapReadWriteAshmem();
            let ArrayVar = [1, 2, 3, 4, 5];
            ashmem.writeAshmem(ArrayVar, 5, 0);
            ashmem.unmapAshmem();
            ashmem.closeAshmem();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 1900003).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_6300 ---------------------------");
    });
    
    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_6400
    * @tc.name   : test The input parameter type of the writeRemoteObject interface is incorrect
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_6400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_6400---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            data.writeRemoteObject(rpc.RemoteObject);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_6400 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_6500
    * @tc.name   : test writeRemoteObject interface, null value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_6500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_6500---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            data.writeRemoteObject();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_6500 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_6600
    * @tc.name   : test writeInterfaceToken interface, illegal value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_6600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_6600---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let token = 123;
            data.writeInterfaceToken(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_6600 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_6700
    * @tc.name   : test writeInterfaceToken interface, null value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_6700", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_6700---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            data.writeInterfaceToken("token","error");
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_6700 ---------------------------");
    });

    /*
     * @tc.number  : SUB_DSoftbus_IPC_API_Errorcode_6800
     * @tc.name    : test writeInterfaceToken interface, string length too large
     * @tc.desc    : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
     * @tc.level   : 3
     * @tc.type    : Compatibility
     * @tc.size    : MediumTest
     */
    it("SUB_DSoftbus_IPC_API_Errorcode_6800", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_6800---------------------------");
        try {
            var data = rpc.MessageSequence.create();
            let token = "";
            for (let i = 0; i < 40 * 1024; i++) {
                token += 'a';
            };
            data.writeInterfaceToken(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_MessageSequence_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_6800---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_6900
    * @tc.name   : test setSize interface, type mismatch for parameter value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_6900", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_6900---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let token = true;
            data.setSize(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_6900 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_7000
    * @tc.name   : test setSize interface, null value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_7000", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_7000---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            data.setSize();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_7000 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_7100
    * @tc.name   : test setCapacity interface, type mismatch for parameter value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_7100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_7100---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let token = true;
            data.setCapacity(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_7100 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_7200
    * @tc.name   : test setCapacity interface, null value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_7200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_7200---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            data.setCapacity();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_7200 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_7300
    * @tc.name   : test rewindRead interface, illegal value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_7300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_7300---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let token = true;
            data.rewindRead(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_7300 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_7400
    * @tc.name   : test rewindRead interface, null value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_7400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_7400---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            data.rewindRead();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_7400 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_7500
    * @tc.name   : test rewindWrite interface, illegal value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_7500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_7500---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let token = true;
            data.rewindWrite(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_7500 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_7600
    * @tc.name   : test rewindWrite interface, null value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_7600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_7600---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            data.rewindWrite();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_7600 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_7700
    * @tc.name   : test writeByte interface, illegal value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_7700", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_7700---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            data.writeByte("The type does not match");
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_7700 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_7800
    * @tc.name   : test writeByte interface, null value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_7800", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_7800---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            data.writeByte();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_7800 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_7900
    * @tc.name   : test writeShort interface, illegal value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_7900", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_7900---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let token = "The type does not match";
            data.writeShort(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_7900 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_8000
    * @tc.name   : test writeShort interface, null value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_8000", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_8000---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            data.writeShort();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_8000 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_8100
    * @tc.name   : test writeInt interface, illegal value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_8100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_8100---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let token = "The type does not match";
            data.writeInt(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_8100 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_8200
    * @tc.name   : test writeInt interface, null value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_8200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_8200---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            data.writeInt();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_8200 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_8300
    * @tc.name   : test writeLong interface, illegal value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_8300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_8300---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let token = "The type does not match";
            data.writeLong(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_8300 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_8400
    * @tc.name   : test writeLong interface, null value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_8400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_8400---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            data.writeLong();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_8400 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_8500
    * @tc.name   : test writeFloat interface, illegal value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_8500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_8500---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let token = "The type does not match";
            data.writeFloat(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_8500 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_8600
    * @tc.name   : test writeFloat interface, null value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_8600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_8600---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            data.writeFloat();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_8600 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_8700
    * @tc.name   : test writeDouble interface, illegal value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_8700", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_8700---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let token = "The type does not match";
            data.writeDouble(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_8700 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_8800
    * @tc.name   : test writeDouble interface, null value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_8800", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_8800---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            data.writeDouble();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_8800 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_8900
    * @tc.name   : test writeBoolean interface, illegal value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_8900", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_8900---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let token = "The type does not match";
            data.writeBoolean(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_8900 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_9000
    * @tc.name   : test writeBoolean interface, null value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_9000", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_9000---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            data.writeBoolean();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_9000 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_9100
    * @tc.name   : test writeChar interface, illegal value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_9100", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_9100---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let token = "The type does not match";
            data.writeChar(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_9100 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_9200
    * @tc.name   : test writeChar interface, null value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_9200", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_9200---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            data.writeChar();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_9200 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_9300
    * @tc.name   : test writeString interface, type mismatch for parameter value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_9300", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_9300---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let token = 123;
            data.writeString(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_9300 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_9400
    * @tc.name   : test writeString interface, null value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_9400", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_9400---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            data.writeString();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_9400 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_9500
    * @tc.name   : test writeString interface, string length too large value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_9500", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_9500---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let token = "";
            for (let i = 0; i < 40 * 1024; i++) {
                token += 'a';
            };
            data.writeString(token);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_9500 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_9600
    * @tc.name   : test writeParcelable interface, null value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_9600", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_9600---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            data.writeParcelable();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_9600 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_9700
    * @tc.name   : test writeParcelable interface, illegal value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_9700", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_9700---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            let sequenceable = new MySequenceable(1, "aaa");
            data.writeParcelable(sequenceable,0);
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_9700 ---------------------------");
    });

    /*
    * @tc.number : SUB_DSoftbus_IPC_API_Errorcode_9800
    * @tc.name   : test readParcelable interface, null value verification
    * @tc.desc   : [G-DISTRIBUTED-0212]禁止修改IPC中定义的数据结构和接口，并提供对应完整实现
    * @tc.level  : Level 3  
    * @tc.type   : Compatibility
    * @tc.size   : MediumTest
    */
    it("SUB_DSoftbus_IPC_API_Errorcode_9800", TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async function(){
        console.info("---------------------start SUB_DSoftbus_IPC_API_Errorcode_9800---------------------------");
        try{
            var data = rpc.MessageSequence.create();
            data.readParcelable();
        } catch (error) {
            console.info("SUB_DSoftbus_IPC_API_OnRemoteRequest_testcase error is:" + error);
            expect(error.code == 401).assertTrue();
            expect(error.message != null).assertTrue();
        } finally {
            data.reclaim();
        }
        console.info("---------------------end SUB_DSoftbus_IPC_API_Errorcode_9800 ---------------------------");
    });

        console.info("-----------------------SUB_DSoftbus_IPC_API_OnRemoteRequest_Test is end-----------------------");
    });
}
