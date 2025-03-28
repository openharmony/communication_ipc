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

#ifndef OHOS_IPC_TEST_SMALL_CLIENT_BUSINESS_IMPL_H
#define OHOS_IPC_TEST_SMALL_CLIENT_BUSINESS_IMPL_H

#include "serializer.h"

void InitLocalIdentity();
void RegisterToService();

void SendBool();
void SendInt8();
void SendInt16();
void SendInt32();
void SendInt64();
void SendUint8();
void SendUint16();
void SendUint32();
void SendUint64();
void SendFloat();
void SendDouble();

void SendInt8Vector();
void SendInt16Vector();
void SendInt32Vector();
void SendInt64Vector();
void SendUint8Vector();
void SendUint16Vector();
void SendUint32Vector();
void SendUint64Vector();
void SendFloatVector();
void SendDoubleVector();

void SendString();
void SendFileDescriptor();
void SendRawData();
void SendBuffer();

#endif // OHOS_IPC_TEST_SMALL_CLIENT_BUSINESS_IMPL_H