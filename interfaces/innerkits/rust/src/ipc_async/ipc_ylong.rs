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

use super::*;

extern crate ylong_runtime;

use std::future::Future;

use crate::errors::IpcStatusCode;

/// Use the Ylong `spawn_blocking` pool
pub enum Ylong {}

impl IpcAsyncPool for Ylong {
    fn spawn<'a, F1, F2, Fut, A, B>(spawn_this: F1, after_handle: F2) -> BoxFuture<'a, IpcResult<B>>
    where
        F1: FnOnce() -> A,
        F2: FnOnce(A) -> Fut,
        Fut: Future<Output = IpcResult<B>>,
        F1: Send + 'static,
        F2: Send + 'a,
        Fut: Send + 'a,
        A: Send + 'static,
        B: Send + 'a,
    {
        if crate::process::is_handling_transaction() {
            // We are currently on the thread pool for a binder server, so we should execute
            // the transaction on the current thread so that the binder kernel
            // driver is able to apply its deadlock prevention strategy to the
            // sub-call.
            //
            // This shouldn't cause issues with blocking the thread as only one task will
            // run in a call to `block_on`, so there aren't other tasks to
            // block.
            let result = spawn_this();
            Box::pin(after_handle(result))
        } else {
            let handle = Runtime::spawn_blocking(spawn_this);
            Box::pin(async move {
                // The `is_panic` branch is not actually reachable in OH as we compile
                // with `panic = abort`.
                match handle.await {
                    Ok(res) => after_handle(res).await,
                    Err(_) => Err(IpcStatusCode::Failed),
                }
            })
        }
    }
}

/// Wrapper around Ylong runtime types for providing a runtime to a binder
/// server.
pub struct Runtime;

impl IpcAsyncRuntime for Runtime {
    fn spawn<T, R>(task: T) -> JoinHandle<R>
    where
        T: Future<Output = R>,
        T: Send + 'static,
        R: Send + 'static,
    {
        ylong_runtime::spawn(task)
    }

    fn spawn_blocking<T, R>(task: T) -> JoinHandle<R>
    where
        T: FnOnce() -> R,
        T: Send + 'static,
        R: Send + 'static,
    {
        ylong_runtime::spawn_blocking(task)
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        ylong_runtime::block_on(future)
    }
}
