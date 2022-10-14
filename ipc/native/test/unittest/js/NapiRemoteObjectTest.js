/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
import featureAbility from '@ohos.ability.featureAbility';
import process from '@ohos.process';
import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index';

describe("NapiRemoteObjectTest", function () {
    beforeAll(function() {
        // input testsuit setup step，setup invoked before all testcases
         console.info('beforeAll called')
    })
    
    afterAll(function() {
         // input testsuit teardown step，teardown invoked after all testcases
         console.info('afterAll called')
    })
    
    beforeEach(function() {
        // input testcase setup step，setup invoked before each testcases
         console.info('beforeEach called')
    })
    
    afterEach(function() {
        // input testcase teardown step，teardown invoked after each testcases
         console.info('afterEach called')
    })
    class Proxy extends rpc.RemoteProxy {

    }
    let proxy = null
    let temp1 = 0
    let temp2 = 0
    function myTestSendRequest(){
        let option = new rpc.MessageOption()
        let data = rpc.MessageParcel.create()
        let reply = rpc.MessageParcel.create()
        temp1 = 0
        temp2 = 0
        data.writeByte(-128)
        proxy.sendRequest(1, data, reply, option)
            .then(function(result) {
                console.info("start to send request")
                if (result.errCode != 0) {
                    console.error("send request failed, errCode: " + result.errCode)
                    return
                }
                temp1 = result.reply.readByte()
                temp2 = result.reply.readByte()
                console.info("test reply1: " + temp1)
                console.info("test reply2: " + temp2)
            })
            .catch(function(e) {
                console.error("send request got exception: " + e)
            })
            .finally(() => {
                data.reclaim()
                reply.reclaim()
            })
    }

    /*
     * @tc.name:napiRemoteObjectTest001
     * @tc.desc:The case where only onRemoteRequest is called when the callback function is synchronous.
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it("napiRemoteObjectTest001", 0, async function (){
        let connectId = null
        let want = {
            "bundleName": "com.example.syncre",
            "abilityName": "com.example.entry.ServiceAbility_sync_re",
        }
        if (!proxy) {
            proxy = await new Promise((resolve) => {
                let connect = {
                    onConnect: function (elementName, remote) {
                        console.info("connect success")
                    resolve(remote);
                    },
                    onDisconnect: function (elementName) {
                        console.info("disconnect")
                    },
                    onFailed: function () {
                        proxy = null
                        console.info("connect failed")
                    resolve(null)
                    }
                }
                console.info("before connectid")
                connectId = featureAbility.connectAbility(want, connect)
                console.info("after connectid")
            })
            myTestSendRequest()
            expect(temp1).assertEqual(-128)
            expect(temp2).assertEqual(2)
        }
    })

    /*
     * @tc.name:napiRemoteObjectTest002
     * @tc.desc:The case where only onRemoteMessageRequest is called when the callback function is synchronous.
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it("napiRemoteObjectTest002", 0, async function (){
        let connectId = null
        let want = {
            "bundleName": "com.example.sync_ex",
            "abilityName": "com.example.entry.ServiceAbility_sync_ex",
        }
        if (!proxy) {
            proxy = await new Promise((resolve) => {
            let connect = {
                onConnect: function (elementName, remote) {
                    console.info("connect success")
                resolve(remote);
                },
                onDisconnect: function (elementName) {
                    console.info("disconnect")
                },
                onFailed: function () {
                    proxy = null
                    console.info("connect failed")
                resolve(null)
                }
            }
            connectId = featureAbility.connectAbility(want, connect)
            })
            myTestSendRequest()
            expect(temp1).assertEqual(-128)
            expect(temp2).assertEqual(3)
        }
    })

    /*
     * @tc.name:napiRemoteObjectTest003
     * @tc.desc:The case where only onRemoteMessageRequest is called when the callback function is asynchronous.
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it("napiRemoteObjectTest003", 0, async function (){
        let connectId = null
        let want = {
            "bundleName": "com.example.async_ex",
            "abilityName": "com.example.entry.ServiceAbility_async_ex",
        }
        if (!proxy) {
            proxy = await new Promise((resolve) => {
            let connect = {
                onConnect: function (elementName, remote) {
                    console.info("connect success")
                resolve(remote);
                },
                onDisconnect: function (elementName) {
                    console.info("disconnect")
                },
                onFailed: function () {
                    proxy = null
                    console.info("connect failed")
                resolve(null)
                }
            }
            connectId = featureAbility.connectAbility(want, connect)
            })
            myTestSendRequest()
            expect(temp1).assertEqual(-128)
            expect(temp2).assertEqual(3)
        }
    })

    /*
     * @tc.name:napiRemoteObjectTest004
     * @tc.desc:The case where both onRemoteMessageRequest and onRemoteRequest are called 
     *          when the callbacks are synchronized.
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it("napiRemoteObjectTest004", 0, async function (){
        let connectId = null
        let want = {
            "bundleName": "com.example.sync_re_ex",
            "abilityName": "com.example.entry.ServiceAbility_sync_re_ex",
        }
        if (!proxy) {
            proxy = await new Promise((resolve) => {
            let connect = {
                onConnect: function (elementName, remote) {
                    console.info("connect success")
                resolve(remote);
                },
                onDisconnect: function (elementName) {
                    console.info("disconnect")
                },
                onFailed: function () {
                    proxy = null
                    console.info("connect failed")
                resolve(null)
                }
            }
            connectId = featureAbility.connectAbility(want, connect)
            })
            myTestSendRequest()
            expect(temp1).assertEqual(-128)
            expect(temp2).assertEqual(12)
        }
    })

    /*
     * @tc.name:napiRemoteObjectTest005
     * @tc.desc:The case in which onRemoteRequest is called when the callback is synchronous and 
     *          onRemoteMessageRequest is called asynchronously.
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it("napiRemoteObjectTest005", 0, async function (){
        let connectId = null
        let want = {
            "bundleName": "com.example.sync_re_async_ex",
            "abilityName": "com.example.entry.ServiceAbility_sync_re_async_ex",
        }
        if (!proxy) {
            proxy = await new Promise((resolve) => {
            let connect = {
                onConnect: function (elementName, remote) {
                    console.info("connect success")
                resolve(remote);
                },
                onDisconnect: function (elementName) {
                    console.info("disconnect")
                },
                onFailed: function () {
                    proxy = null
                    console.info("connect failed")
                resolve(null)
                }
            }
            connectId = featureAbility.connectAbility(want, connect)
            })
            myTestSendRequest()
            expect(temp1).assertEqual(-128)
            expect(temp2).assertEqual(14)
        }
    })
})