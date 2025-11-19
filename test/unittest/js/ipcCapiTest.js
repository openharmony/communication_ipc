/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

import { describe, it, expect, TestType, Size, Level} from '@ohos/hypium'
import iPCCApi from 'libIPCCApi.so'

export default function iPCCApiTest() {
  describe('IPCCApiTest', () => {

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCSkeleton_JoinWorkThread_0100
     * @tc.name       : testOHIPCSkeletonJoinWorkThread
     * @tc.desc       : test OH_IPCSkeleton_JoinWorkThread
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCSkeleton_JoinWorkThread_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCSkeletonJoinWorkThread();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCSkeleton_StopWorkThread_0100
     * @tc.name       : testOHIPCSkeletonStopWorkThread
     * @tc.desc       : test OH_IPCSkeleton_StopWorkThread
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCSkeleton_StopWorkThread_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCSkeletonStopWorkThread();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCSkeleton_GetCallingTokenId_0100
     * @tc.name       : testOHIPCSkeletonGetCallingTokenId
     * @tc.desc       : test OH_IPCSkeleton_GetCallingTokenId
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCSkeleton_GetCallingTokenId_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCSkeletonGetCallingTokenId();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCSkeleton_GetFirstTokenId_0100
     * @tc.name       : testOHIPCSkeletonGetFirstTokenId
     * @tc.desc       : test OH_IPCSkeleton_GetFirstTokenId
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCSkeleton_GetFirstTokenId_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCSkeletonGetFirstTokenId();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCSkeleton_GetSelfTokenId_0100
     * @tc.name       : testOHIPCSkeletonGetSelfTokenId
     * @tc.desc       : test OH_IPCSkeleton_GetSelfTokenId
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCSkeleton_GetSelfTokenId_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCSkeletonGetSelfTokenId();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCSkeleton_GetCallingPid_0100
     * @tc.name       : testOHIPCSkeletonGetCallingPid
     * @tc.desc       : test OH_IPCSkeleton_GetCallingPid
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCSkeleton_GetCallingPid_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCSkeletonGetCallingPid();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCSkeleton_GetCallingUid_0100
     * @tc.name       : testOHIPCSkeletonGetCallingUid
     * @tc.desc       : test OH_IPCSkeleton_GetCallingUid
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCSkeleton_GetCallingUid_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCSkeletonGetCallingUid();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCSkeleton_IsLocalCalling_0100
     * @tc.name       : testOHIPCSkeletonIsLocalCalling
     * @tc.desc       : test OH_IPCSkeleton_IsLocalCalling
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCSkeleton_IsLocalCalling_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCSkeletonIsLocalCalling();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCSkeleton_SetMaxWorkThreadNum_0100
     * @tc.name       : testOHIPCSkeletonSetMaxWorkThreadNum
     * @tc.desc       : test OH_IPCSkeleton_SetMaxWorkThreadNum
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCSkeleton_SetMaxWorkThreadNum_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCSkeletonSetMaxWorkThreadNum();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCSkeleton_ResetCallingIdentity_0100
     * @tc.name       : testOHIPCSkeletonResetCallingIdentity
     * @tc.desc       : test OH_IPCSkeleton_ResetCallingIdentity
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCSkeleton_ResetCallingIdentity_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCSkeletonResetCallingIdentity();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCSkeleton_SetCallingIdentity_0100
     * @tc.name       : testOHIPCSkeletonSetCallingIdentity
     * @tc.desc       : test OH_IPCSkeleton_SetCallingIdentity
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCSkeleton_SetCallingIdentity_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCSkeletonSetCallingIdentity();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCSkeleton_IsHandlingTransaction_0100
     * @tc.name       : testOHIPCSkeletonIsHandlingTransaction
     * @tc.desc       : test OH_IPCSkeleton_IsHandlingTransaction
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCSkeleton_IsHandlingTransaction_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCSkeletonIsHandlingTransaction();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCRemoteStub_Create_0100
     * @tc.name       : testOHIPCRemoteStubCreate
     * @tc.desc       : test OH_IPCRemoteStub_Create
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCRemoteStub_Create_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCRemoteStubCreate();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCRemoteStub_Destroy_0100
     * @tc.name       : testOHIPCRemoteStubDestroy
     * @tc.desc       : test OH_IPCRemoteStub_Destroy
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCRemoteStub_Destroy_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCRemoteStubDestroy();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCRemoteProxy_Destroy_0100
     * @tc.name       : testOHIPCRemoteProxyDestroy
     * @tc.desc       : test OH_IPCRemoteProxy_Destroy
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCRemoteProxy_Destroy_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCRemoteProxyDestroy();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCRemoteProxy_SendRequest_0100
     * @tc.name       : testOHIPCRemoteProxySendRequest
     * @tc.desc       : test OH_IPCRemoteProxy_SendRequest
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCRemoteProxy_SendRequest_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCRemoteProxySendRequest();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCRemoteProxy_GetInterfaceDescriptor_0100
     * @tc.name       : testOHIPCRemoteProxyGetInterfaceDescriptor
     * @tc.desc       : test OH_IPCRemoteProxy_GetInterfaceDescriptor
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCRemoteProxy_GetInterfaceDescriptor_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCRemoteProxyGetInterfaceDescriptor();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCDeathRecipient_Create_0100
     * @tc.name       : testOHIPCDeathRecipientCreate
     * @tc.desc       : test OH_IPCDeathRecipient_Create
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCDeathRecipient_Create_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCDeathRecipientCreate();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCDeathRecipient_Destroy_0100
     * @tc.name       : testOHIPCDeathRecipientDestroy
     * @tc.desc       : test OH_IPCDeathRecipient_Destroy
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCDeathRecipient_Destroy_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCDeathRecipientDestroy();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCRemoteProxy_AddDeathRecipient_0100
     * @tc.name       : testOHIPCRemoteProxyAddDeathRecipient
     * @tc.desc       : test OH_IPCRemoteProxy_AddDeathRecipient
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCRemoteProxy_AddDeathRecipient_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCRemoteProxyAddDeathRecipient();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCRemoteProxy_RemoveDeathRecipient_0100
     * @tc.name       : testOHIPCRemoteProxyRemoveDeathRecipient
     * @tc.desc       : test OH_IPCRemoteProxy_RemoveDeathRecipient
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCRemoteProxy_RemoveDeathRecipient_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCRemoteProxyRemoveDeathRecipient();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCRemoteProxy_IsRemoteDead_0100
     * @tc.name       : testOHIPCRemoteProxyIsRemoteDead
     * @tc.desc       : test OH_IPCRemoteProxy_IsRemoteDead
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCRemoteProxy_IsRemoteDead_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCRemoteProxyIsRemoteDead();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_Create_0100
     * @tc.name       : testOHIPCParcelCreate
     * @tc.desc       : test OH_IPCParcel_Create
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_Create_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelCreate();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_Destroy_0100
     * @tc.name       : testOHIPCParcelDestroy
     * @tc.desc       : test OH_IPCParcel_Destroy
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_Destroy_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelDestroy();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_GetDataSize_0100
     * @tc.name       : testOHIPCParcelGetDataSize
     * @tc.desc       : test OH_IPCParcel_GetDataSize
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_GetDataSize_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelGetDataSize();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_GetWritableBytes_0100
     * @tc.name       : testOHIPCParcelGetWritableBytes
     * @tc.desc       : test OH_IPCParcel_GetWritableBytes
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_GetWritableBytes_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelGetWritableBytes();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_GetReadableBytes_0100
     * @tc.name       : testOHIPCParcelGetReadableBytes
     * @tc.desc       : test OH_IPCParcel_GetReadableBytes
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_GetReadableBytes_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelGetReadableBytes();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_GetReadPosition_0100
     * @tc.name       : testOHIPCParcelGetReadPosition
     * @tc.desc       : test OH_IPCParcel_GetReadPosition
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_GetReadPosition_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelGetReadPosition();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_GetWritePosition_0100
     * @tc.name       : testOHIPCParcelGetWritePosition
     * @tc.desc       : test OH_IPCParcel_GetWritePosition
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_GetWritePosition_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelGetWritePosition();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_RewindReadPosition_0100
     * @tc.name       : testOHIPCParcelRewindReadPosition
     * @tc.desc       : test OH_IPCParcel_RewindReadPosition
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_RewindReadPosition_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelRewindReadPosition();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_RewindWritePosition_0100
     * @tc.name       : testOHIPCParcelRewindWritePosition
     * @tc.desc       : test OH_IPCParcel_RewindWritePosition
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_RewindWritePosition_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelRewindWritePosition();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_WriteInt8_0100
     * @tc.name       : testOHIPCParcelWriteInt8
     * @tc.desc       : test OH_IPCParcel_WriteInt8
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_WriteInt8_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelWriteInt8();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_ReadInt8_0100
     * @tc.name       : testOHIPCParcelReadInt8
     * @tc.desc       : test OH_IPCParcel_ReadInt8
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_ReadInt8_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelReadInt8();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_WriteInt16_0100
     * @tc.name       : testOHIPCParcelWriteInt16
     * @tc.desc       : test OH_IPCParcel_WriteInt16
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_WriteInt16_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelWriteInt16();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_ReadInt16_0100
     * @tc.name       : testOHIPCParcelReadInt16
     * @tc.desc       : test OH_IPCParcel_ReadInt16
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_ReadInt16_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelReadInt16();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_WriteInt32_0100
     * @tc.name       : testOHIPCParcelWriteInt32
     * @tc.desc       : test OH_IPCParcel_WriteInt32
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_WriteInt32_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelWriteInt32();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_ReadInt32_0100
     * @tc.name       : testOHIPCParcelReadInt32
     * @tc.desc       : test OH_IPCParcel_ReadInt32
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_ReadInt32_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelReadInt32();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_WriteInt64_0100
     * @tc.name       : testOHIPCParcelWriteInt64
     * @tc.desc       : test OH_IPCParcel_WriteInt64
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_WriteInt64_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelWriteInt64();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_ReadInt64_0100
     * @tc.name       : testOHIPCParcelReadInt64
     * @tc.desc       : test OH_IPCParcel_ReadInt64
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_ReadInt64_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelReadInt64();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_WriteFloat_0100
     * @tc.name       : testOHIPCParcelWriteFloat
     * @tc.desc       : test OH_IPCParcel_WriteFloat
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_WriteFloat_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelWriteFloat();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_ReadFloat_0100
     * @tc.name       : testOHIPCParcelReadFloat
     * @tc.desc       : test OH_IPCParcel_ReadFloat
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_ReadFloat_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelReadFloat();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_WriteDouble_0100
     * @tc.name       : testOHIPCParcelWriteDouble
     * @tc.desc       : test OH_IPCParcel_WriteDouble
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_WriteDouble_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelWriteDouble();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_ReadDouble_0100
     * @tc.name       : testOHIPCParcelReadDouble
     * @tc.desc       : test OH_IPCParcel_ReadDouble
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_ReadDouble_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelReadDouble();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_WriteString_0100
     * @tc.name       : testOHIPCParcelWriteString
     * @tc.desc       : test OH_IPCParcel_WriteString
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_WriteString_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelWriteString();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_ReadString_0100
     * @tc.name       : testOHIPCParcelReadString
     * @tc.desc       : test OH_IPCParcel_ReadString
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_ReadString_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelReadString();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_WriteBuffer_0100
     * @tc.name       : testOHIPCParcelWriteBuffer
     * @tc.desc       : test OH_IPCParcel_WriteBuffer
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_WriteBuffer_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelWriteBuffer();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_ReadBuffer_0100
     * @tc.name       : testOHIPCParcelReadBuffer
     * @tc.desc       : test OH_IPCParcel_ReadBuffer
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_ReadBuffer_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelReadBuffer();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_WriteRemoteStub_0100
     * @tc.name       : testOHIPCParcelWriteRemoteStub
     * @tc.desc       : test OH_IPCParcel_WriteRemoteStub
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_WriteRemoteStub_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelWriteRemoteStub();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_ReadRemoteStub_0100
     * @tc.name       : testOHIPCParcelReadRemoteStub
     * @tc.desc       : test OH_IPCParcel_ReadRemoteStub
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_ReadRemoteStub_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelReadRemoteStub();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_WriteRemoteProxy_0100
     * @tc.name       : testOHIPCParcelWriteRemoteProxy
     * @tc.desc       : test OH_IPCParcel_WriteRemoteProxy
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_WriteRemoteProxy_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelWriteRemoteProxy();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_ReadRemoteProxy_0100
     * @tc.name       : testOHIPCParcelReadRemoteProxy
     * @tc.desc       : test OH_IPCParcel_ReadRemoteProxy
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_ReadRemoteProxy_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelReadRemoteProxy();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_WriteFileDescriptor_0100
     * @tc.name       : testOHIPCParcelWriteFileDescriptor
     * @tc.desc       : test OH_IPCParcel_WriteFileDescriptor
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_WriteFileDescriptor_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelWriteFileDescriptor();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_ReadFileDescriptor_0100
     * @tc.name       : testOHIPCParcelReadFileDescriptor
     * @tc.desc       : test OH_IPCParcel_ReadFileDescriptor
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_ReadFileDescriptor_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelReadFileDescriptor();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_Append_0100
     * @tc.name       : testOHIPCParcelAppend
     * @tc.desc       : test OH_IPCParcel_Append
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_Append_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelAppend();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_WriteInterfaceToken_0100
     * @tc.name       : testOHIPCParcelWriteInterfaceToken
     * @tc.desc       : test OH_IPCParcel_WriteInterfaceToken
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_WriteInterfaceToken_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelWriteInterfaceToken();
      expect(result).assertEqual(0);
      done();
    });

    /**
     * @tc.number     : SUB_DSoftbus_IPC_N_IPCParcel_ReadInterfaceToken_0100
     * @tc.name       : testOHIPCParcelReadInterfaceToken
     * @tc.desc       : test OH_IPCParcel_ReadInterfaceToken
     * @tc.size       : MediumTest
     * @tc.type       : Function
     * @tc.level      : Level 3
     */
    it('SUB_DSoftbus_IPC_N_IPCParcel_ReadInterfaceToken_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL3, async (done: Function) => {
      let result: number = iPCCApi.oHIPCParcelReadInterfaceToken();
      expect(result).assertEqual(0);
      done();
    });

  })

}