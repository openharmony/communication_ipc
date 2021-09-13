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

const EXC_INSECURITY = -1;
const EXC_ILLEGAL_ARGUMENT = -3;
const EXC_NULL_POINTER = -4;
const EXC_ILLEGAL_STATE = -5;
const EXC_UNSUPPORTED_OPERATION = -7;
const EXC_INDEX_OUTOF_BOUNDS = -10;
const EXC_NEGATIVE_ARRAY_SIZE = -11;
const EXC_ARRAY_STORE = -12;
const EXC_CLASS_CAST = -13;
const EXC_PARCEL_CAPACITY_ERROR = -14;
const EXC_REMOTE_TRANSACTION_FAILED = -200;

let MessageParcel = rpcSo.MessageParcel;
let IPCSkeleton = rpcSo.IPCSkeleton;
let RemoteObject = rpcSo.RemoteObject;
let RemoteProxy = rpcSo.RemoteProxy;
let MessageOption = rpcSo.MessageOption;

class Exception {
    message;
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


MessageParcel.prototype.createException = function(code, msg) {
    switch (code) {
        case EXC_INSECURITY: {
            return new SecurityException(msg);
        }
        case EXC_ILLEGAL_ARGUMENT: {
            return new IllegalArgumentException(msg);
        }
        case EXC_NULL_POINTER: {
            return new NullPointerException(msg);
        }
        case EXC_ILLEGAL_STATE: {
            return new IllegalStateException(msg);
        }
        case EXC_UNSUPPORTED_OPERATION: {
            return new UnsupportedOperationException(msg);
        }
        case EXC_INDEX_OUTOF_BOUNDS: {
            return new IndexOutOfBoundsException(msg);
        }
        case EXC_NEGATIVE_ARRAY_SIZE: {
            return new NegativeArraySizeException(msg);
        }
        case EXC_ARRAY_STORE: {
            return new ArrayStoreException(msg);
        }
        case EXC_CLASS_CAST: {
            return new ClassCastException(msg);
        }
        case EXC_REMOTE_TRANSACTION_FAILED: {
            return new RemoteException(msg);
        }
        case EXC_PARCEL_CAPACITY_ERROR: {
            return new ParcelException(msg);
        }
        default: {
            return new RuntimeException("Unknown exception code: " + code + " msg " + msg);
        }
    }
}

MessageParcel.prototype.writeException = function(exception) {
    let code = 0;
    if (exception instanceof SecurityException) {
        code = EXC_INSECURITY;
    } else if (exception instanceof IllegalArgumentException) {
        code = EXC_ILLEGAL_ARGUMENT;
    } else if (exception instanceof NullPointerException) {
        code = EXC_NULL_POINTER;
    } else if (exception instanceof IllegalStateException) {
        code = EXC_ILLEGAL_STATE;
    } else if (exception instanceof UnsupportedOperationException) {
        code = EXC_UNSUPPORTED_OPERATION;
    } else if (exception instanceof IndexOutOfBoundsException) {
        code = EXC_INDEX_OUTOF_BOUNDS;
    } else if (exception instanceof NegativeArraySizeException) {
        code = EXC_NEGATIVE_ARRAY_SIZE;
    } else if (exception instanceof ArrayStoreException) {
        code = EXC_ARRAY_STORE;
    } else if (exception instanceof ClassCastException) {
        code = EXC_CLASS_CAST;
    } else if (exception instanceof RemoteException) {
        code = EXC_REMOTE_TRANSACTION_FAILED;
    } else if (exception instanceof ParcelException) {
        code = EXC_PARCEL_CAPACITY_ERROR;
    } else {
        code = 0;
    }
    this.writeInt(code);
    if (code === 0) {
        if (exception instanceof RuntimeException) {
            throw new RuntimeException(exception.getMessage());
        }
        throw new RuntimeException(exception.getMessage());
    }
    this.writeString(exception.getMessage());
}

MessageParcel.prototype.writeNoException = function() {
    this.writeInt(0);
}

MessageParcel.prototype.readException = function() {
    let code = this.readInt();
        if (code === 0) {
            return;
        }
        let msg = this.readString();
        let exception = this.createException(code, msg);
        return exception;
}

MessageParcel.prototype.createRemoteObjectArray = function() {
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

MessageParcel.prototype.writeRemoteObjectArray = function(objects) {
    if (objects === null || objects.length <= 0 ) {
        this.writeInt(-1);
        return false;
    }

    let num = objects.length;
    this.writeInt(num);
    for (let i = 0; i < num; i ++)   {
        this.writeRemoteObject(objects[i]);
    }
    return true;
}

MessageParcel.prototype.readRemoteObjectArray = function(objects) {
    if (objects === null) {
        return;
    }

    let num = this.readInt();
    if (num !== objects.length) {
        return;
    }
    for (let i = 0; i < num; i ++) {
        objects[i] = this.readRemoteObject();
    }
}

RemoteObject.prototype.addDeathRecipient = function(recipient, flags) {
    return false;
}

RemoteObject.prototype.removeDeathRecipient = function(recipient, flags) {
    return false;
}

RemoteObject.prototype.isObjectDead = function() {
    return false;
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