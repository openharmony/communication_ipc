/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

export namespace rpc {
    // loadLibrary("rpc_ani");
    export class MessageSequence {
        constructor() {}
        native function readString(): string;
        native function writeString(val: string): void;
        native function readInterfaceToken(): string;

        private nativePtr: long = 0;
    }

    export class MessageOption {
        static { loadLibrary("rpc_ani") }
        constructor(asyncFlag: boolean) {
            console.log("[ETS] Enter MessageOption.constructor(asyncFlag)");
            if (asyncFlag === true) {
                this.init(1, 0);
            }
            else {
                this.init(0, 0);
            }
        }

        constructor(syncFlags?: number, waitTime?: number) {
            console.log("[ETS] Enter MessageOption.constructor(syncFlags, waitTime)");
            if (syncFlags != undefined && waitTime != undefined) {
                this.init(syncFlags, waitTime);
            }
            else if (syncFlags === undefined && waitTime === undefined) {
                this.init(0, 0);
            }
            else if (syncFlags === undefined && waitTime != undefined) {
                this.init(0, waitTime);
            }
            else if (syncFlags != undefined && waitTime === undefined) {
                this.init(syncFlags, 0);
            }
        }

        native init(syncFlags: number, waitTime: number): void;

        getNativePtr():long {
            return this.nativePtr;
        }

        private nativePtr: long = 0;
    }

    export abstract class IRemoteObject {
        native getDescriptor(): string;

        private descriptor:string;
    }

    export class RemoteObject extends IRemoteObject {
        static { loadLibrary("rpc_ani") }
        native constructor(descriptor: string);

        native getDescriptor(): string;

        getNativePtr(): long {
            return this.nativePtr;
        }

        public onRemoteMessageRequest(
            code: number,
            data: rpc.MessageSequence,
            reply: rpc.MessageSequence,
            options: rpc.MessageOption
        ): boolean | Promise<boolean> {
            console.log("[ETS] Enter RemoteObject.onRemoteMessageRequest(" + code + ", " + data.readString() + ")");
            return true;
        }

        private onRemoteMessageRequestWithCallback(
            code: number,
            data: rpc.MessageSequence,
            reply: rpc.MessageSequence,
            options: rpc.MessageOption,
            callback: (result: boolean) => void
        ): void {
            const result = this.onRemoteMessageRequest(code, data, reply, options);

            if (result instanceof Promise) {
                result.then((resolvedResult: boolean): void => {
                    callback(resolvedResult);
                })
            } else {
                callback(result);
            }
        }

        private onRemoteMessageRequestSync(
            code: number,
            data: rpc.MessageSequence,
            reply: rpc.MessageSequence,
            options: rpc.MessageOption
        ): void {
            return this.onRemoteMessageRequestWithCallback(code, data, reply, options, (result: boolean): void => {
                this.onRemoteMessageRequestCallback(result);
            });
        }

        native onRemoteMessageRequestCallback(result: boolean): void;

        private nativePtr: long = 0;
    }

    export class RemoteProxy extends IRemoteObject {
        native getDescriptor(): string;
    }
}
