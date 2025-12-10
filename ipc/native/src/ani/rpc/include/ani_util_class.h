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

#ifndef ANI_UTIL_CLASS_H
#define ANI_UTIL_CLASS_H

#include <ani.h>
#include <cstdarg>

#include "ani_util_common.h"

class AniTypeFinder {
public:
    AniTypeFinder(ani_env *env) : env_(env) {}

    expected<ani_namespace, ani_status> FindNamespace(const char *nsName)
    {
        ani_namespace ns;
        ani_status status = env_->FindNamespace(nsName, &ns);
        if (ANI_OK != status) {
            return status;
        }
        return ns;
    }

    template <typename... Names>
    expected<ani_namespace, ani_status> FindNamespace(const char *firstNs, const char *nextNs, Names... restNs)
    {
        const std::string nsName = std::string(firstNs).append(".").append(nextNs);
        return FindNamespace(nsName.c_str(), restNs...);
    }

    expected<ani_class, ani_status> FindClass(const char *clsName)
    {
        ani_class cls;
        ani_status status = env_->FindClass(clsName, &cls);
        if (ANI_OK != status) {
            return status;
        }
        return cls;
    }

    expected<ani_class, ani_status> FindClass(const char *nsName, const char *clsName)
    {
        const std::string fullClsName = std::string(nsName).append(".").append(clsName);
        return FindClass(fullClsName.c_str());
    }

    template <typename... Names>
    expected<ani_class, ani_status> FindClass(const char *firstNs,
                                              const char *secondNs,
                                              Names... restNs,
                                              const char *clsName)
    {
        const std::string nsName = std::string(firstNs).append(".").append(secondNs);
        return FindClass(nsName.c_str(), restNs..., clsName);
    }

    expected<ani_enum, ani_status> FindEnum(const char *nsName, const char *enumName)
    {
        ani_enum aniEnum {};
        const std::string fullEnumName = std::string(nsName).append(".").append(enumName);
        ani_status status = env_->FindEnum(fullEnumName.c_str(), &aniEnum);
        if (ANI_OK != status) {
            return status;
        }
        return aniEnum;
    }

private:
    ani_env *env_ = nullptr;
};

#endif
