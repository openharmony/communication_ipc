/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_IPC_ACTV_BINDER_H
#define OHOS_IPC_ACTV_BINDER_H

#include <sys/types.h>

#ifdef CONFIG_ACTV_BINDER

#define BINDER_SET_ACTVMGR                          _IOWR('b', 64, uint64_t)

#define ACTV_BINDER_HANDLE_BIT                      1

#define ACTV_BINDER_WRITE_READ                      _IOWR('b', 97, struct binder_write_read)

#define ACTV_BINDER_FEATURE_MASK                    (1 << 1)

// Allocate the extra memory for the actv binder transaction
#define ACTV_BINDER_VM_SIZE                         (2 * 1024 * 1024)

// Decrease this after introducing the elastic machinism
#define ACTV_BINDER_DEFAULT_NR_THREADS              32

#define ACTV_BINDER_SERVICES_CONFIG                 "/system/etc/libbinder_actv.json"

// The interval for checking the ABA dead lock (unit: us)
#define ACTV_BINDER_ABA_LOCK_CHK_INTVL              (10 * 1000 * 1000)
#define ACTV_BINDER_ABA_LOCK_CHK_LIMIT              5

#endif // CONFIG_ACTV_BINDER

#endif // OHOS_IPC_ACTV_BINDER_H
