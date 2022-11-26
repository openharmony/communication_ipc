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

#include "access_token_adapter.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "bits/ioctl.h"

#define ACCESS_TOKEN_ID_IOCTL_BASE 'A'

enum {
    GET_TOKEN_ID = 1,
    SET_TOKEN_ID,
    GET_FTOKEN_ID,
    SET_FTOKEN_ID,
    ACCESS_TOKENID_MAX_NR,
};

#define ACCESS_TOKENID_GET_TOKENID \
    _IOR(ACCESS_TOKEN_ID_IOCTL_BASE, GET_TOKEN_ID, unsigned long long)
#define ACCESS_TOKENID_GET_FTOKENID \
    _IOR(ACCESS_TOKEN_ID_IOCTL_BASE, GET_FTOKEN_ID, unsigned long long)

#define ACCESS_TOKEN_OK 0
#define ACCESS_TOKEN_ERROR (-1)

#define INVAL_TOKEN_ID 0x0
#define TOKEN_ID_LOWMASK 0xffffffff

#define TOKENID_DEVNODE "/dev/access_token_id"

uint64_t RpcGetSelfTokenID(void)
{
    uint64_t token = INVAL_TOKEN_ID;
    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return INVAL_TOKEN_ID;
    }
    int ret = ioctl(fd, ACCESS_TOKENID_GET_TOKENID, &token);
    if (ret) {
        close(fd);
        return INVAL_TOKEN_ID;
    }

    close(fd);
    return token;
}

uint64_t RpcGetFirstCallerTokenID(void)
{
    uint64_t token = INVAL_TOKEN_ID;
    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return INVAL_TOKEN_ID;
    }
    int ret = ioctl(fd, ACCESS_TOKENID_GET_FTOKENID, &token);
    if (ret) {
        close(fd);
        return INVAL_TOKEN_ID;
    }

    close(fd);
    return token;
}