// Copyright (C) 2024 Huawei Device Co., Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! ipc async impl

mod ipc_ylong;

use std::future::Future;
use std::pin::Pin;

pub use ipc_ylong::{Runtime, Ylong};
use ylong_runtime::task::JoinHandle;

use crate::errors::IpcResult;

/// A type alias for a pinned, boxed future that lets you write shorter code
/// without littering it with Pin and Send bounds.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A thread pool for running ipc transactions.
pub trait IpcAsyncPool {
    /// This function should conceptually behave like this:
    ///
    /// ```text
    /// let result = spawn(spawn, after_handle).await;
    /// ```
    fn spawn<'a, F1, F2, Fut, A, B>(
        spawn_this: F1,
        after_handle: F2,
    ) -> BoxFuture<'a, IpcResult<B>>
    where
        F1: FnOnce() -> A,
        F2: FnOnce(A) -> Fut,
        Fut: Future<Output = IpcResult<B>>,
        F1: Send + 'static,
        F2: Send + 'a,
        Fut: Send + 'a,
        A: Send + 'static,
        B: Send + 'a;
}

/// A runtime for executing an async ipc server.
pub trait IpcAsyncRuntime {
    /// Using the default task setting, spawns a task onto the global runtime.
    fn spawn<T, R>(task: T) -> JoinHandle<R>
    where
        T: Future<Output = R>,
        T: Send + 'static,
        R: Send + 'static;

    /// Using the default task setting, spawns a blocking task.
    fn spawn_blocking<T, R>(task: T) -> JoinHandle<R>
    where
        T: FnOnce() -> R,
        T: Send + 'static,
        R: Send + 'static;

    /// Block on the provided future, running it to completion and returning its
    /// output.
    fn block_on<F: Future>(future: F) -> F::Output;
}
