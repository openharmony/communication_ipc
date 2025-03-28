/*
 * Copyright (C) 2021-2025 Huawei Device Co., Ltd.
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

#include "binder_connector.h"

#include <cinttypes>
#include <cstdint>
#include <thread>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <cstdio>

#include "__mutex_base"
#include "cerrno"
#include "hilog/log_c.h"
#include "hilog/log_cpp.h"
#include "iosfwd"
#include "ipc_debug.h"
#include "ipc_types.h"
#include "log_tags.h"
#include "new"
#include "string"
#include "sys_binder.h"
#include "fd_san.h"

namespace OHOS {
static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC_BINDER_CONNECT, "BinderConnector" };
std::mutex BinderConnector::skeletonMutex;
constexpr int SZ_1_M = 1048576;
constexpr int DOUBLE = 2;
static const int IPC_MMAP_SIZE = (SZ_1_M - sysconf(_SC_PAGE_SIZE) * DOUBLE);
static constexpr const char *DRIVER_NAME = "/dev/binder";
static constexpr const char *TOKENID_DEVNODE = "/dev/access_token_id";
BinderConnector *BinderConnector::instance_ = nullptr;

BinderConnector::BinderConnector(const std::string &deviceName)
    : driverFD_(-1), vmAddr_(MAP_FAILED), deviceName_(deviceName), version_(0), featureSet_(0), selfTokenID_(0)
{}

BinderConnector::~BinderConnector()
{
    if (vmAddr_ != MAP_FAILED) {
        munmap(vmAddr_, IPC_MMAP_SIZE);
        vmAddr_ = MAP_FAILED;
    }

    CloseDriverFd();
};

bool BinderConnector::IsDriverAlive()
{
    return driverFD_.load() >= 0;
}

bool BinderConnector::OpenDriver()
{
    int fd = open(deviceName_.c_str(), O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        ZLOGE(LABEL, "fail to open errno:%{public}d", errno);
        return false;
    }
    fdsan_exchange_owner_tag(fd, 0, IPC_FD_TAG);

    int32_t version = 0;
    int ret = ioctl(fd, BINDER_VERSION, &version);
    if (ret != 0 || version != BINDER_CURRENT_PROTOCOL_VERSION) {
        ZLOGE(LABEL, "Get Binder version failed, error:%{public}d "
            "or version not match, driver version:%{public}d, ipc version:%{public}d",
            errno, version, BINDER_CURRENT_PROTOCOL_VERSION);
        fdsan_close_with_tag(fd, IPC_FD_TAG);
        return false;
    }
    uint64_t featureSet = 0;
    ret = ioctl(fd, BINDER_FEATURE_SET, &featureSet);
    if (ret != 0) {
        ZLOGE(LABEL, "Get Binder featureSet failed:%{public}d, disable all enhance feature.", errno);
        featureSet = 0;
    }
    ZLOGD(LABEL, "success to open fd:%{public}d", fd);
    driverFD_.store(fd);

    if (!MapMemory(featureSet)) {
        fdsan_close_with_tag(driverFD_.load(), IPC_FD_TAG);
        driverFD_.store(-1);
        return false;
    }
    version_ = version;
    featureSet_ = featureSet;
    return true;
}

bool BinderConnector::MapMemory(uint64_t featureSet)
{
    vmAddr_ = mmap(0, IPC_MMAP_SIZE, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, driverFD_.load(), 0);
    if (vmAddr_ == MAP_FAILED) {
        ZLOGE(LABEL, "fail to mmap");
        return false;
    }
    return true;
}

bool BinderConnector::IsAccessTokenSupported()
{
    if (IsDriverAlive() != true) {
        return false;
    }
    return (featureSet_ & ACCESS_TOKEN_FAETURE_MASK) != 0;
}

bool BinderConnector::IsRealPidSupported()
{
    return (featureSet_ & SENDER_INFO_FAETURE_MASK) != 0;
}

int BinderConnector::WriteBinder(unsigned long request, void *value)
{
    int err = -EINTR;

    while (err == -EINTR) {
        if (driverFD_.load() < 0) {
            return -EBADF;
        }
        if (ioctl(driverFD_.load(), request, value) >= 0) {
            err = ERR_NONE;
        } else {
            err = -errno;
        }

        if (err == -EINTR) {
            uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
            ZLOGD(LABEL, "ioctl_binder returned EINTR time:%{public}" PRIu64, curTime);
        }
    }

    return err;
}

void BinderConnector::ExitCurrentThread(unsigned long request)
{
    if (driverFD_.load() > 0) {
        ioctl(driverFD_.load(), request, 0);
    }
}

uint64_t BinderConnector::GetSelfTokenID()
{
    if (IsAccessTokenSupported() != true) {
        return 0;
    }
    FILE *fp = fopen(TOKENID_DEVNODE, "r+");
    if (fp == nullptr) {
        ZLOGE(LABEL, "fail to open tokenId node, errno:%{public}d", errno);
        return 0;
    }
    int fd = fileno(fp);
    if (fd < 0) {
        ZLOGE(LABEL, "fail to open tokenId node, errno:%{public}d", errno);
        (void)fclose(fp);
        return 0;
    }
    int ret = ioctl(fd, ACCESS_TOKENID_GET_TOKENID, &selfTokenID_);
    if (ret != 0) {
        selfTokenID_ = 0;
    }
    (void)fclose(fp);
    return selfTokenID_;
}


uint64_t BinderConnector::GetSelfFirstCallerTokenID()
{
    if (IsAccessTokenSupported() != true) {
        return 0;
    }
    FILE *fp = fopen(TOKENID_DEVNODE, "r+");
    if (fp == nullptr) {
        ZLOGE(LABEL, "fail to open tokenId node, errno:%{public}d", errno);
        return 0;
    }
    int fd = fileno(fp);
    if (fd < 0) {
        ZLOGE(LABEL, "fail to open tokenId node, errno:%{public}d", errno);
        (void)fclose(fp);
        return 0;
    }
    uint64_t token = 0;
    int ret = ioctl(fd, ACCESS_TOKENID_GET_FTOKENID, &token);
    if (ret != 0) {
        token = 0;
    }
    (void)fclose(fp);
    return token;
}

void BinderConnector::CloseDriverFd()
{
    if (driverFD_.load() >= 0) {
        int tmpFd = driverFD_.exchange(-1);
        // avoid call 'close' and 'ioctl' concurrently
        std::this_thread::sleep_for(std::chrono::milliseconds(CLOSE_WAIT_TIME_MS));
        fdsan_close_with_tag(tmpFd, IPC_FD_TAG);
    }
}

BinderConnector *BinderConnector::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lockGuard(skeletonMutex);
        if (instance_ == nullptr) {
            auto temp = new (std::nothrow) BinderConnector(std::string(DRIVER_NAME));
            if (temp == nullptr) {
                ZLOGE(LABEL, "create BinderConnector object failed");
                return nullptr;
            }
            if (!temp->OpenDriver()) {
                delete temp;
                temp = nullptr;
            }
            instance_ = temp;
        }
    }

    return instance_;
}
} // namespace OHOS
