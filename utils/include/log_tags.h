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

#ifndef OHOS_COMMUNICATION_LOG_TAGS_H
#define OHOS_COMMUNICATION_LOG_TAGS_H

namespace OHOS {
const unsigned int LOG_ID_COMMUNICATION = 0xD001500;

const unsigned int LOG_ID_IPC = LOG_ID_COMMUNICATION | 0x10;

const unsigned int LOG_ID_RPC = LOG_ID_COMMUNICATION | 0x18;

const unsigned int LOG_ID_DISC = LOG_ID_COMMUNICATION | 0x20;

const unsigned int LOG_ID_DNET = LOG_ID_COMMUNICATION | 0x30;

const unsigned int LOG_ID_SMARTNET = LOG_ID_COMMUNICATION | 0x40;

const unsigned int LOG_ID_BLUETOOTH = LOG_ID_COMMUNICATION | 0x50;

const unsigned int LOG_ID_WIFI = LOG_ID_COMMUNICATION | 0x60;
const unsigned int LOG_ID_WIFI_HOTSPOT = LOG_ID_WIFI | 0x01;
const unsigned int LOG_ID_WIFI_ENHANCER = LOG_ID_WIFI | 0x02;

const unsigned int LOG_ID_NFC = LOG_ID_COMMUNICATION | 0x70;

const unsigned int LOG_ID_NSTACK = LOG_ID_COMMUNICATION | 0x80;

const unsigned int LOG_ID_RADIO = LOG_ID_COMMUNICATION | 0x90;

const unsigned int LOG_ID_REMOTE_P2P = LOG_ID_COMMUNICATION | 0xA0;

const unsigned int LOG_ID_NET_MANAGER = LOG_ID_COMMUNICATION | 0xB0;
} // namespace OHOS
#endif // OHOS_COMMUNICATION_LOG_TAGS_H
