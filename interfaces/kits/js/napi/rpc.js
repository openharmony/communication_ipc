/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

const rpcSo = requireInternal("rpc");

let NAPIMessageParcel = rpcSo.MessageParcel;
let NAPIIPCSkeleton = rpcSo.IPCSkeleton;
let NAPIRemoteObject = rpcSo.RemoteObject;
let RemoteProxy = rpcSo.RemoteProxy;
let MessageOption = rpcSo.MessageOption;

class RemoteObject extends NAPIRemoteObject {
    constructor(descriptor) {
        if (typeof descriptor === 'string' && descriptor.length > 0) {
            super(descriptor, descriptor.length);
            this.descriptor = descriptor;
        } else {
            throw new NullPointerException("invalid descriptor");
        }
    }

    addDeathRecipient(recipient, flags) {
        return false;
    }

    removeDeathRecipient(recipient, flags) {
        return false;
    }

    isObjectDead() {
        return false;
    }

    attachLocalInterface(localInterface, descriptor) {
        this.descriptor = descriptor;
        this.interface = localInterface;
    }

    queryLocalInterface(descriptor) {
        if (this.descriptor === descriptor) {
            return this.interface;
        }
        return null;
    }
}

class IPCSkeleton extends NAPIIPCSkeleton {
    static setCallingIdentity(identity) {
        if (typeof identity === 'string') {
            return NAPIIPCSkeleton.setCallingIdentity(identity, identity.length);
        }
        return false;
    }
}

class Exception {
    constructor(msg) {
        this.message = msg;
    }

    getMessage() {
        return this.message;
    }
}

class NullPointerException extends Exception {}
class SecurityException extends Exception {}
class IllegalArgumentException extends Exception {}
class IllegalStateException extends Exception {}
class UnsupportedOperationException extends Exception {}
class IndexOutOfBoundsException extends Exception {}
class NegativeArraySizeException extends Exception {}
class ArrayStoreException extends Exception {}
class ClassCastException extends Exception {}
class RemoteException extends Exception {}
class ParcelException extends Exception {}
class RuntimeException extends Exception {}

class MessageParcel extends NAPIMessageParcel {
    static EXC_INSECURITY = -1;
    static EXC_ILLEGAL_ARGUMENT = -3;
    static EXC_NULL_POINTER = -4;
    static EXC_ILLEGAL_STATE = -5;
    static EXC_UNSUPPORTED_OPERATION = -7;
    static EXC_INDEX_OUTOF_BOUNDS = -10;
    static EXC_NEGATIVE_ARRAY_SIZE = -11;
    static EXC_ARRAY_STORE = -12;
    static EXC_CLASS_CAST = -13;
    static EXC_PARCEL_CAPACITY_ERROR = -14;
    static EXC_REMOTE_TRANSACTION_FAILED = -200;

    createException(code, msg) {
        switch (code) {
            case MessageParcel.EXC_INSECURITY: {
                return new SecurityException(msg);
            }
            case MessageParcel.EXC_ILLEGAL_ARGUMENT: {
                return new IllegalArgumentException(msg);
            }
            case MessageParcel.EXC_NULL_POINTER: {
                return new NullPointerException(msg);
            }
            case MessageParcel.EXC_ILLEGAL_STATE: {
                return new IllegalStateException(msg);
            }
            case MessageParcel.EXC_UNSUPPORTED_OPERATION: {
                return new UnsupportedOperationException(msg);
            }
            case MessageParcel.EXC_INDEX_OUTOF_BOUNDS: {
                return new IndexOutOfBoundsException(msg);
            }
            case MessageParcel.EXC_NEGATIVE_ARRAY_SIZE: {
                return new NegativeArraySizeException(msg);
            }
            case MessageParcel.EXC_ARRAY_STORE: {
                return new ArrayStoreException(msg);
            }
            case MessageParcel.EXC_CLASS_CAST: {
                return new ClassCastException(msg);
            }
            case MessageParcel.EXC_REMOTE_TRANSACTION_FAILED: {
                return new RemoteException(msg);
            }
            case MessageParcel.EXC_PARCEL_CAPACITY_ERROR: {
                return new ParcelException(msg);
            }
            default: {
                return new RuntimeException("Unknown exception code: " + code + " msg " + msg);
            }
        }
    }

    writeException(exception) {
        let code = 0;
        if (exception instanceof SecurityException) {
            code = MessageParcel.EXC_INSECURITY;
        } else if (exception instanceof IllegalArgumentException) {
            code = MessageParcel.EXC_ILLEGAL_ARGUMENT;
        } else if (exception instanceof NullPointerException) {
            code = MessageParcel.EXC_NULL_POINTER;
        } else if (exception instanceof IllegalStateException) {
            code = MessageParcel.EXC_ILLEGAL_STATE;
        } else if (exception instanceof UnsupportedOperationException) {
            code = MessageParcel.EXC_UNSUPPORTED_OPERATION;
        } else if (exception instanceof IndexOutOfBoundsException) {
            code = MessageParcel.EXC_INDEX_OUTOF_BOUNDS;
        } else if (exception instanceof NegativeArraySizeException) {
            code = MessageParcel.EXC_NEGATIVE_ARRAY_SIZE;
        } else if (exception instanceof ArrayStoreException) {
            code = MessageParcel.EXC_ARRAY_STORE;
        } else if (exception instanceof ClassCastException) {
            code = MessageParcel.EXC_CLASS_CAST;
        } else if (exception instanceof RemoteException) {
            code = MessageParcel.EXC_REMOTE_TRANSACTION_FAILED;
        } else if (exception instanceof ParcelException) {
            code = MessageParcel.EXC_PARCEL_CAPACITY_ERROR;
        } else {
            code = 0;
        }
        this.writeInt(code);
        if (code === 0) {
            throw new RuntimeException(exception.getMessage());
        }  
        this.writeString(exception.getMessage());
    }

    writeNoException() {
        this.writeInt(0);
    }

    readException() {
        let code = this.readInt();
        if (code === 0) {
            return;
        }
        let msg = this.readString();
        let exception = this.createException(code, msg);
        throw exception;
    }

    createRemoteObjectArray() {
        let num = this.readInt();
        if (num <= 0) {
            return null;
        }
        let list = new Array(num);
        for (let i = 0; i < num; i++) {
            list[i] = this.readRemoteObject();
        }
        return list;
    }

    writeRemoteObjectArray(objects) {
        if (objects === null || objects.length <= 0) {
            this.writeInt(-1);
            return false;
        }

        let num = objects.length;
        this.writeInt(num);
        for (let i = 0; i < num; i++) {
            this.writeRemoteObject(objects[i]);
        }
        return true;
    }

    readRemoteObjectArray(objects) {
        if (objects === null) {
            return;
        }

        let num = this.readInt();
        if (num !== objects.length) {
            return;
        }
        for (let i = 0; i < num; i++) {
            objects[i] = this.readRemoteObject();
        }
    }
}

export default {
    MessageParcel: MessageParcel,
    IPCSkeleton: IPCSkeleton,
    RemoteObject: RemoteObject,
    RemoteProxy: RemoteProxy,
    MessageOption: MessageOption,
    NullPointerException: NullPointerException,
    SecurityException: SecurityException,
    IllegalArgumentException: IllegalArgumentException,
    IllegalStateException: IllegalStateException,
    UnsupportedOperationException: UnsupportedOperationException,
    IndexOutOfBoundsException: IndexOutOfBoundsException,
    NegativeArraySizeException: NegativeArraySizeException,
    ArrayStoreException: ArrayStoreException,
    ClassCastException: ClassCastException,
    RemoteException: RemoteException,
    ParcelException: ParcelException,
    RuntimeException: RuntimeException
}