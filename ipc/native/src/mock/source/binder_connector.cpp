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
#ifdef CONFIG_ACTV_BINDER
#include <sys/prctl.h>
#endif
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
#ifdef CONFIG_ACTV_BINDER
#include "actv_binder.h"

#include <fstream>
#include <unordered_set>
#include <nlohmann/json.hpp>
#endif

namespace OHOS {
static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC_BINDER_CONNECT, "BinderConnector" };
std::mutex BinderConnector::skeletonMutex;
constexpr int SZ_1_M = 1048576;
constexpr int DOUBLE = 2;
#ifdef CONFIG_ACTV_BINDER
static const int PROC_NAME_LEN = 128;
#endif
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
#ifdef CONFIG_ACTV_BINDER
        munmap(vmAddr_, vmSize_);
#else
        munmap(vmAddr_, IPC_MMAP_SIZE);
#endif
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

#ifdef CONFIG_ACTV_BINDER
const std::unordered_set<uint32_t> *BinderConnector::GetActvBinderBlockedCodes(const std::string &desc)
{
    auto iter = actvBinder_.actvBlockedCodes_.find(desc);
    if (iter != actvBinder_.actvBlockedCodes_.end()) {
        return &iter->second;
    }
    return nullptr;
}

ActvHandlerInfo *BinderConnector::GetActvHandlerInfo(uint32_t id)
{
    const std::vector<ActvHandlerInfo *> &infos = actvBinder_.actvHandlerInfos_;
    return ((id < infos.size()) ? infos[id] : nullptr);
}

ActvHandlerInfo::ActvHandlerInfo() : desc_(std::string())
{
}

void ActvHandlerInfo::AddActvHandlerInfo(const std::string &desc, uint32_t code)
{
    std::lock_guard<std::mutex> lockGuard(lock_);

    if (count_ != -1) {
        ZLOGW(LABEL, "ActvBinder: thread %{public}d is in an old transaction %{public}s %{public}u, "
                     "coming tr %{public}s %{public}u", tid_, desc_.c_str(), code_, desc.c_str(), code);
    } else {
        desc_  = desc;
        code_  = code;
        count_ = 0;
        tid_   = ((tid_ == -1) ? gettid() : tid_);
    }
}

void ActvHandlerInfo::ClrActvHandlerInfo()
{
    std::lock_guard<std::mutex> lockGuard(lock_);

    desc_  = std::string();
    code_  = 0;
    count_ = -1;
}

void ActvHandlerInfo::ChkActvHandlerInfo(int32_t limit)
{
    std::lock_guard<std::mutex> lockGuard(lock_);

    if (count_ == -1) {
        return;
    } else {
        count_++;
    }

    if (count_ >= limit) {
        ZLOGW(LABEL, "ActvBinder: thread %{public}d maybe in ABA dead lock, service=%{public}s "
                     "code=%{public}u count=%{public}d", tid_, desc_.c_str(), code_, count_);
    }
}

std::mutex ActvBinderConnector::skeletonMutex_;
ActvBinderJoinThreadFunc ActvBinderConnector::joinActvThreadFunc_ = nullptr;
ActvBinderSetHandlerInfoFunc ActvBinderConnector::setActvHandlerInfoFunc_ = nullptr;

ActvBinderConnector::ActvBinderConnector()
    : isActvMgr_(false)
{
}

void ActvBinderConnector::JoinActvThread(bool initiative)
{
    if (ActvBinderConnector::joinActvThreadFunc_ != nullptr) {
        ActvBinderConnector::joinActvThreadFunc_(initiative);
    } else {
        ZLOGW(LABEL, "ActvBinder: no available func to add thread for the actv binder service");
    }
}

void ActvBinderConnector::SetJoinActvThreadFunc(ActvBinderJoinThreadFunc func)
{
    if (ActvBinderConnector::joinActvThreadFunc_ == nullptr) {
        std::lock_guard<std::mutex> lockGuard(skeletonMutex_);

        if (ActvBinderConnector::joinActvThreadFunc_ == nullptr) {
            ActvBinderConnector::joinActvThreadFunc_ = func;
        }
    }
}

void ActvBinderConnector::SetActvHandlerInfo(uint32_t id)
{
    if (ActvBinderConnector::setActvHandlerInfoFunc_ != nullptr) {
        ActvBinderConnector::setActvHandlerInfoFunc_(id);
    } else {
        ZLOGW(LABEL, "ActvBinder: no available func to set the actv handler info");
    }
}

void ActvBinderConnector::AddSetActvHandlerInfoFunc(ActvBinderSetHandlerInfoFunc func)
{
    if (ActvBinderConnector::setActvHandlerInfoFunc_ == nullptr) {
        std::lock_guard<std::mutex> lockGuard(skeletonMutex_);

        if (ActvBinderConnector::setActvHandlerInfoFunc_ == nullptr) {
            ActvBinderConnector::setActvHandlerInfoFunc_ = func;
        }
    }
}

void *ActvBinderConnector::ActvThreadEntry(void *arg)
{
    int ret;
    std::string name = "ACTVIPC_" + std::to_string(reinterpret_cast<uintptr_t>(arg)) + "_" + std::to_string(getpid());

    ret = prctl(PR_SET_NAME, name.c_str());
    if (ret != 0) {
        ZLOGE(LABEL, "ActvBinder: set thread name: %{public}s failed, errno: %{public}d", name.c_str(), errno);
    } else {
        ActvBinderConnector::SetActvHandlerInfo(reinterpret_cast<uintptr_t>(arg));
        ActvBinderConnector::JoinActvThread(false);
        ZLOGW(LABEL, "ActvBinder: thread %{public}s exited", name.c_str());
    }

    return nullptr;
}

void *ActvBinderConnector::ABALockCheckThreadEntry(void *arg)
{
    int ret;
    ActvBinderConnector *actvBinder = reinterpret_cast<ActvBinderConnector *>(arg);
    const std::vector<ActvHandlerInfo *> &infos = actvBinder->actvHandlerInfos_;

    ret = prctl(PR_SET_NAME, "ABALockChecker");
    if (ret != 0) {
        ZLOGE(LABEL, "ActvBinder: set thread name ABALockChecker failed, errno: %{public}d", errno);
        return nullptr;
    }

    while (true) {
        usleep(ACTV_BINDER_ABA_LOCK_CHK_INTVL);

        for (uint32_t i = 0; i < infos.size(); i++) {
            infos[i]->ChkActvHandlerInfo(ACTV_BINDER_ABA_LOCK_CHK_LIMIT);
        }
    }

    return nullptr;
}

char *ActvBinderConnector::GetProcName(char *buf, size_t len)
{
    int fd;
    char *name = nullptr;

    fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd != -1) {
        ssize_t cnt;

        cnt = read(fd, buf, len - 1);
        if (cnt > 0) {
            buf[cnt] = '\0';
            name = buf;
        }

        close(fd);
    }

    return name;
}

int ActvBinderConnector::InitActvBinder(int fd)
{
    if (!isActvMgr_) {
        return 0;
    }

    int ret;
    pthread_t thread;
    uint64_t poolCref;

    ret = ioctl(fd, BINDER_SET_ACTVMGR, &poolCref);
    if (ret != 0) {
        ZLOGE(LABEL, "ActvBinder: set actv binder service failed, errno: %{public}d", errno);
        return ret;
    }

    for (int i = 0; i < ACTV_BINDER_DEFAULT_NR_THREADS; i++) {
        ActvHandlerInfo *info = new ActvHandlerInfo();
        if (info == nullptr) {
            ZLOGE(LABEL, "ActvBinder: prepare actv handler info for thread#%{public}d failed", i);
            return -ENOMEM;
        }
        actvHandlerInfos_.push_back(info);
    }

    for (int i = 0; i < ACTV_BINDER_DEFAULT_NR_THREADS; i++) {
        ret = pthread_create(&thread, nullptr, &ActvBinderConnector::ActvThreadEntry, reinterpret_cast<void *>(i));
        if (ret != 0) {
            ZLOGE(LABEL, "ActvBinder: create thread#%{public}d failed, errno: %{public}d", i, errno);
            return ret;
        }

        ret = pthread_detach(thread);
        if (ret != 0) {
            ZLOGE(LABEL, "ActvBinder: detach thread#%{public}d failed, errno: %{public}d", i, errno);
            return ret;
        }
    }

    ret = pthread_create(&thread, nullptr, &ActvBinderConnector::ABALockCheckThreadEntry,
                         reinterpret_cast<void *>(this));
    if (ret != 0) {
        ZLOGE(LABEL, "ActvBinder: create checker thread failed, errno: %{public}d", errno);
        return ret;
    }

    ret = pthread_detach(thread);
    if (ret != 0) {
        ZLOGE(LABEL, "ActvBinder: detach checker thread failed, errno: %{public}d", errno);
        return ret;
    }

    return 0;
}

/*
 * The JSON format of the /system/etc/libbinder_actv.json should be:
 *
 * {
 *      "pname0": {
 *          "serviceDesc0": [code0, code1, ...],
 *          "serviceDesc1": [code0, code1, ...],
 *          ...
 *          "serviceDescN": [code0, code1, ...]
 *      },
 *      "pname1": {
 *          "serviceDesc0": [code0, code1, ...],
 *          "serviceDesc1": [code0, code1, ...],
 *          ...
 *          "serviceDescN": [code0, code1, ...]
 *      },
 *      ...
 *      "pnameN": {
 *          "serviceDesc0": [code0, code1, ...],
 *          "serviceDesc1": [code0, code1, ...],
 *          ...
 *          "serviceDescN": [code0, code1, ...]
 *      }
 * }
 *
 * 1. Configure pname0 ~ pnameN as the actv binder service.
 *
 * 2. The interface specified by the serviceDesc0 ~ serviceDescN and the
 *    code0 ~ codeN cannot be accessed through the Actv Binder IPC.
 *
 * 3. If no code0 ~ codeN specified for the serviceDescX, then all interfaces
 *    of the serviceDescX cannot be accessed through the Actv Binder IPC.
 *
 * 4. If no serviceDescs are specified, then all interfaces in process of pnameX
 *    are accessed through the Actv Binder IPC.
 */
void ActvBinderConnector::InitActvBinderConfig(uint64_t featureSet)
{
    if ((featureSet & ACTV_BINDER_FEATURE_MASK) == 0) {
        return;
    }

    std::ifstream configFile(ACTV_BINDER_SERVICES_CONFIG);
    if (!configFile.is_open()) {
        ZLOGI(LABEL, "ActvBinder: no available config file %{public}s", ACTV_BINDER_SERVICES_CONFIG);
        return;
    }

    char buffer[PROC_NAME_LEN];
    char *procName = ActvBinderConnector::GetProcName(buffer, PROC_NAME_LEN);

    if (procName == nullptr) {
        ZLOGE(LABEL, "ActvBinder: get the process name of pid=%{public}d failed", getpid());
        return;
    }

    nlohmann::json configData = nlohmann::json::parse(configFile, nullptr, false);
    if (configData.is_discarded()) {
        ZLOGE(LABEL, "ActvBinder: parse config file %{public}s failed", ACTV_BINDER_SERVICES_CONFIG);
        return;
    }

    for (auto &procItem : configData.items()) {
        if (isActvMgr_ == false) {
            isActvMgr_ = (strcmp(procItem.key().c_str(), procName) == 0);
            if (isActvMgr_) {
                ZLOGI(LABEL, "ActvBinder: set %{public}s as the actv binder service", procName);
            }
        }

        nlohmann::json &services = procItem.value();
        for (auto &srvItem : services.items()) {
            std::unordered_set<uint32_t> codeSet;
            const std::string &desc = srvItem.key();
            nlohmann::json &codes = srvItem.value();

            codes.get_to(codeSet);

            auto iter = actvBlockedCodes_.find(desc);
            if (codeSet.empty() || (iter == actvBlockedCodes_.end())) {
                actvBlockedCodes_[desc] = codeSet;
            } else if (iter->second.empty()) {
                /* block all codes */
            } else {
                iter->second.insert(codeSet.begin(), codeSet.end());
            }
        }
    }
}
#endif // CONFIG_ACTV_BINDER

bool BinderConnector::OpenDriver()
{
    int fd = open(deviceName_.c_str(), O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        ZLOGE(LABEL, "fail to open errno:%{public}d", errno);
        return false;
    }
    int32_t version = 0;
    int ret = ioctl(fd, BINDER_VERSION, &version);
    if (ret != 0 || version != BINDER_CURRENT_PROTOCOL_VERSION) {
        ZLOGE(LABEL, "Get Binder version failed, error:%{public}d "
            "or version not match, driver version:%{public}d, ipc version:%{public}d",
            errno, version, BINDER_CURRENT_PROTOCOL_VERSION);
        close(fd);
        return false;
    }
    uint64_t featureSet = 0;
    ret = ioctl(fd, BINDER_FEATURE_SET, &featureSet);
    if (ret != 0) {
        ZLOGE(LABEL, "Get Binder featureSet failed:%{public}d, disable all enhance feature.", errno);
        featureSet = 0;
    }
    ZLOGD(LABEL, "success to open fd:%{public}d", fd);
    driverFD_ = fd;
#ifdef CONFIG_ACTV_BINDER
    actvBinder_.InitActvBinderConfig(featureSet);

    vmSize_ = IPC_MMAP_SIZE + (actvBinder_.isActvMgr_ ? ACTV_BINDER_VM_SIZE : 0);
    vmAddr_ = mmap(0, vmSize_, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, driverFD_, 0);
#else
    vmAddr_ = mmap(0, IPC_MMAP_SIZE, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, driverFD_, 0);
#endif
    if (vmAddr_ == MAP_FAILED) {
        ZLOGE(LABEL, "fail to mmap");
        close(driverFD_);
        driverFD_ = -1;
        return false;
    }
#ifdef CONFIG_ACTV_BINDER
    ret = actvBinder_.InitActvBinder(driverFD_);
    if (ret != 0) {
        munmap(vmAddr_, vmSize_);
        vmAddr_ = MAP_FAILED;
        vmSize_ = 0;

        close(driverFD_);
        driverFD_ = -1;
        return false;
    }
#endif
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

bool BinderConnector::IsRealPidSupported()
{
    return (featureSet_ & SENDER_INFO_FAETURE_MASK) != 0;
}
#ifdef CONFIG_ACTV_BINDER
bool BinderConnector::IsActvBinderSupported()
{
    return (IsDriverAlive() && ((featureSet_ & ACTV_BINDER_FEATURE_MASK) != 0));
}
#endif

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
            ZLOGE(LABEL, "ioctl_binder returned EINTR");
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
        ZLOGE(LABEL, "fail to open tokenId node");
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
        ZLOGE(LABEL, "fail to open tokenId node");
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
} // namespace OHOS
