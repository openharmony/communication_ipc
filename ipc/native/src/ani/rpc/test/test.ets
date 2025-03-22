/* Copyright (c) 2025 Huawei Device Co., Ltd.
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

import rpc from "@ohos.rpc";

export class MyService extends rpc.RemoteObject {
    
    constructor(descriptor: string) {
        super(descriptor);
    }

    public onRemoteMessageRequest(
        code: number,
        data: rpc.MessageSequence,
        reply: rpc.MessageSequence,
        options: rpc.MessageOption
    ): boolean | Promise<boolean> {
        console.log("[TEST] Enter MyService.onRemoteMessageRequest(" + code + ", readString: " + data.readString() + ")");
        console.log("[TEST] Enter MyService.onRemoteMessageRequest(" + code + ", readInterfaceToken: " + data.readInterfaceToken() + ")");
        if (code === 1) {
            return this.handleCode1(data, reply, options);
        }
        else if (code === 2) {
            return this.handleCode2(data, reply, options);
        } else {
            return false;
        }
    }

    private handleCode1(
        data: rpc.MessageSequence,
        reply: rpc.MessageSequence,
        options: rpc.MessageOption
    ): boolean {
        console.log("[TEST] Handling code 1 request synchronously");
        reply.writeString("Handled code 1");
        console.log("[TEST] Handled code 1 synchronously");
        return true;
    }

    private async handleCode2(
        data: rpc.MessageSequence,
        reply: rpc.MessageSequence,
        options: rpc.MessageOption
    ): Promise<boolean> {
        console.log("[TEST] Handling code 2 request asynchronously");
        let result = await this.someAsyncOperation(data);
        console.log("[TEST] Handled code 2 asynchronously");
        return result > 0;
    }

    executeFunc() : int {
        console.log("[TEST] enter executeFunc");
        return 0;
    }

    private async someAsyncOperation(data: rpc.MessageSequence): Promise<int> {
        console.log("[TEST] enter someAsyncOperation");
        let p = new Promise<int>((resolve: (v: int) => void, reject: (error: Object) => void) => {
            let p1 = taskpool.execute(():int =>{
                return this.executeFunc();
            });
            p1.then((e : NullishType)=>{
                console.log("[TEST] in Promise then. e is ", e)
                let r = e as int;
                resolve(r);
            });
         });
        return p;
    }
}

function main() {
    console.println("[TEST] ----------------------------------------------------");
    let messageOptionObj = new rpc.MessageOption(true);
    console.println("[TEST] ----------------------------------------------------");
    let messageOptionObj1 = new rpc.MessageOption(false);
    console.println("[TEST] ----------------------------------------------------");
    let messageOptionObj2 = new rpc.MessageOption();
    console.println("[TEST] ----------------------------------------------------");
    let messageOptionObj3 = new rpc.MessageOption(10);
    console.println("[TEST] ----------------------------------------------------");
    let messageOptionObj4 = new rpc.MessageOption(2, 1);
    console.println("[TEST] ----------------------------------------------------");
    let myService: rpc.RemoteObject = new MyService("myservice");
    console.println("[TEST] ----------------------------------------------------");
    console.println("[TEST] myService.getDescriptor(): " + '[' + myService.getDescriptor() + ']')
    console.println("[TEST] ----------------------------------------------------");
}