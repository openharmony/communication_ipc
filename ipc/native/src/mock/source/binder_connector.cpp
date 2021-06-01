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
#include <fcntl.h>
#include <unistd.h>
#include <mutex>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include "hilog/log.h"
#include "ipc_types.h"
#include "ipc_debug.h"
#include "dbinder_error_code.h"
#include "log_tags.h"

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
namespace IPC_SINGLE {
#endif

static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "BinderConnector" };
std::mutex BinderConnector::skeletonMutex;
constexpr int SZ_1_M = 1048576;
constexpr int DOUBLE = 2;
static const int IPC_MMAP_SIZE = (SZ_1_M - sysconf(_SC_PAGE_SIZE) * DOUBLE);
#if (defined CONFIG_DUAL_FRAMEWORK)
static const std::string DRIVER_NAME = std::string("/dev/binder");
#else
static const std::string DRIVER_NAME = std::string("/dev/zbinder");
#endif /* CONFIG_DUAL_FRAMEWORK */
BinderConnector *BinderConnector::instance_ = nullptr;

BinderConnector::BinderConnector(const std::string &deviceName)
    : driverFD_(-1), vmAddr_(MAP_FAILED), deviceName_(deviceName)
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
        ZLOGE(LABEL, "%s:fail to open", __func__);
#ifndef BUILD_PUBLIC_VERSION
        ReportEvent(DbinderErrorCode::KERNEL_DRIVER_ERROR, DbinderErrorCode::ERROR_CODE,
            DbinderErrorCode::OPEN_IPC_DRIVER_FAILURE);
#endif
        return false;
    }

    ZLOGI(LABEL, "%s:succ to open, fd=%d", __func__, fd);
    driverFD_ = fd;
    vmAddr_ = mmap(0, IPC_MMAP_SIZE, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, driverFD_, 0);
    if (vmAddr_ == MAP_FAILED) {
        ZLOGE(LABEL, "%s:fail to mmap\n", __func__);
        close(driverFD_);
        driverFD_ = -1;
#ifndef BUILD_PUBLIC_VERSION
        ReportEvent(DbinderErrorCode::KERNEL_DRIVER_ERROR, DbinderErrorCode::ERROR_CODE,
            DbinderErrorCode::OPEN_IPC_DRIVER_FAILURE);
#endif
        return false;
    }

    return true;
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
            ReportEvent(DbinderErrorCode::KERNEL_DRIVER_ERROR, DbinderErrorCode::ERROR_CODE,
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

BinderConnector *BinderConnector::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lockGuard(skeletonMutex);
        if (instance_ == nullptr) {
            BinderConnector *temp = new BinderConnector(DRIVER_NAME);
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
