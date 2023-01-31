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

#include "binder_connector.h"

#include <cstdint>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

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

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
namespace IPC_SINGLE {
#endif

static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "BinderConnector" };
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

    if (driverFD_ >= 0) {
        close(driverFD_);
        driverFD_ = -1;
    }
};

bool BinderConnector::IsDriverAlive()
{
    return driverFD_ >= 0;
}

bool BinderConnector::OpenDriver()
{
    int fd = open(deviceName_.c_str(), O_RDWR);
    if (fd < 0) {
        ZLOGE(LABEL, "%{public}s:fail to open", __func__);
#ifndef BUILD_PUBLIC_VERSION
        ReportEvent(DbinderErrorCode::KERNEL_DRIVER_ERROR, std::string(DbinderErrorCode::ERROR_CODE),
            DbinderErrorCode::OPEN_IPC_DRIVER_FAILURE);
#endif
        return false;
    }
    int32_t version = 0;
    int ret = ioctl(fd, BINDER_VERSION, &version);
    if (ret != 0 || version != BINDER_CURRENT_PROTOCOL_VERSION) {
        ZLOGE(LABEL, "Get Binder version failed, error: %{public}d, "
            "or version not match, driver version:%{public}d, ipc version:%{public}d",
            errno, version, BINDER_CURRENT_PROTOCOL_VERSION);
        close(fd);
        return false;
    }
    uint64_t featureSet = 0;
    ret = ioctl(fd, BINDER_FEATURE_SET, &featureSet);
    if (ret != 0) {
        ZLOGE(LABEL, "Get Binder featureSet failed: %{public}d, disable all enhance feature.", errno);
        featureSet = 0;
    }
    ZLOGI(LABEL, "%{public}s:succ to open, fd=%{public}d", __func__, fd);
    driverFD_ = fd;
    vmAddr_ = mmap(0, IPC_MMAP_SIZE, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, driverFD_, 0);
    if (vmAddr_ == MAP_FAILED) {
        ZLOGE(LABEL, "%{public}s:fail to mmap\n", __func__);
        close(driverFD_);
        driverFD_ = -1;
#ifndef BUILD_PUBLIC_VERSION
        ReportEvent(DbinderErrorCode::KERNEL_DRIVER_ERROR, std::string(DbinderErrorCode::ERROR_CODE),
            DbinderErrorCode::OPEN_IPC_DRIVER_FAILURE);
#endif
        return false;
    }
    version_ = version;
    featureSet_ = featureSet;
    return true;
}

bool BinderConnector::IsAccessTokenSupported()
{
    if (IsDriverAlive() != true) {
        return false;
    }
    return (featureSet_ & ACCESS_TOKEN_FAETURE_MASK) != 0;
}

int BinderConnector::WriteBinder(unsigned long request, void *value)
{
    int err = -EINTR;

    while (err == -EINTR) {
        if (ioctl(driverFD_, request, value) >= 0) {
            err = ERR_NONE;
        } else {
            err = -errno;
        }

        if (err == -EINTR) {
            ZLOGE(LABEL, "%s:ioctl_binder returned EINTR", __func__);
#ifndef BUILD_PUBLIC_VERSION
            ReportEvent(DbinderErrorCode::KERNEL_DRIVER_ERROR, std::string(DbinderErrorCode::ERROR_CODE),
                DbinderErrorCode::WRITE_IPC_DRIVER_FAILURE);
#endif
        }
    }

    return err;
}

void BinderConnector::ExitCurrentThread(unsigned long request)
{
    if (driverFD_ > 0) {
        ioctl(driverFD_, request, 0);
    }
}

uint64_t BinderConnector::GetSelfTokenID()
{
    if (IsAccessTokenSupported() != true) {
        return 0;
    }
    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        ZLOGE(LABEL, "%{public}s: fail to open tokenId node", __func__);
        return 0;
    }
    int ret = ioctl(fd, ACCESS_TOKENID_GET_TOKENID, &selfTokenID_);
    if (ret != 0) {
        selfTokenID_ = 0;
    }
    close(fd);
    return selfTokenID_;
}

uint64_t BinderConnector::GetSelfFirstCallerTokenID()
{
    if (IsAccessTokenSupported() != true) {
        return 0;
    }
    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        ZLOGE(LABEL, "%{public}s: fail to open tokenId node", __func__);
        return 0;
    }
    uint64_t token = 0;
    int ret = ioctl(fd, ACCESS_TOKENID_GET_FTOKENID, &token);
    if (ret != 0) {
        token = 0;
    }
    close(fd);
    return token;
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
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS
