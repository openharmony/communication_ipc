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

#ifndef ANI_UTIL_COMMON_H
#define ANI_UTIL_COMMON_H

#include <exception>
#include <memory>
#include <type_traits>
#include <utility>
#include <variant>

template <typename T, typename E>
class expected {
private:
    std::variant<T, E> data_;
    bool has_value_;

public:
    expected(const T &value) : data_(value), has_value_(true) {}

    expected(T &&value) : data_(std::move(value)), has_value_(true) {}

    expected(const E &error) : data_(error), has_value_(false) {}

    expected(E &&error) : data_(std::move(error)), has_value_(false) {}

    bool has_value() const noexcept
    {
        return has_value_;
    }

    explicit operator bool() const noexcept
    {
        return has_value();
    }

    T &value() &
    {
        if (!has_value()) {
            std::terminate();
        }
        return std::get<T>(data_);
    }

    const T &value() const &
    {
        if (!has_value()) {
            std::terminate();
        }
        return std::get<T>(data_);
    }

    T &&value() &&
    {
        if (!has_value()) {
            std::terminate();
        }
        return std::get<T>(std::move(data_));
    }

    E &error() &
    {
        if (has_value()) {
            std::terminate();
        }
        return std::get<E>(data_);
    }

    const E &error() const &
    {
        if (has_value()) {
            std::terminate();
        }
        return std::get<E>(data_);
    }

    E &&error() &&
    {
        if (has_value()) {
            std::terminate();
        }
        return std::get<E>(std::move(data_));
    }

    T &operator*() &
    {
        return value();
    }

    const T &operator*() const &
    {
        return value();
    }

    T &&operator*() &&
    {
        return std::move(*this).value();
    }

    T *operator->()
    {
        return &value();
    }

    const T *operator->() const
    {
        return &value();
    }

    template <typename U>
    T value_or(U &&default_value) const &
    {
        return has_value() ? value() : static_cast<T>(std::forward<U>(default_value));
    }

    template <typename U>
    T value_or(U &&default_value) &&
    {
        return has_value() ? std::move(*this).value() : static_cast<T>(std::forward<U>(default_value));
    }
};

template <typename F>
class FinalAction {
public:
    explicit FinalAction(F func) : func_(std::move(func)) {}

    ~FinalAction() noexcept(noexcept(func_()))
    {
        if (!dismissed_) {
            func_();
        }
    }

    FinalAction(const FinalAction &) = delete;
    FinalAction &operator=(const FinalAction &) = delete;

    FinalAction(FinalAction &&other) noexcept : func_(std::move(other.func_)), dismissed_(other.dismissed_)
    {
        other.dismissed_ = true;
    }

    void dismiss() noexcept
    {
        dismissed_ = true;
    }

private:
    F func_;
    bool dismissed_ = false;
};

template <typename F>
inline FinalAction<F> finally(F &&func)
{
    return FinalAction<F>(std::forward<F>(func));
}

#endif
