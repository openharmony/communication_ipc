/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#[macro_export]
macro_rules! define_remote_object {
    {
        $remote_broker:path[$descriptor:expr] {
            stub: $stub:ident($on_remote_request:path),
            proxy: $proxy:ident,
        }
    } => {
        $crate::define_remote_object! {
            $remote_broker[$descriptor] {
                stub: $stub($on_remote_request),
                proxy: $proxy {},
            }
        }
    };

    {
        $remote_broker:path[$descriptor:expr] {
            stub: $stub:ident($on_remote_request:path),
            proxy: $proxy:ident {
                $($item_name:ident: $item_type:ty = $item_init:expr),*
            },
        }
    } => {
        pub struct $proxy {
            remote: $crate::RemoteObj,
            $($item_name: $item_type,)*
        }

        impl $proxy {
            fn from_remote_object(remote: RemoteObj) -> $crate::Result<Self> {
                Ok(Self {remote, $($item_name: $item_init),* })
            }
            
            #[allow(dead_code)]
            fn get_descriptor() -> &'static str {
                $descriptor
            }
        }

        impl $crate::IRemoteBroker for $proxy {
            fn as_object(&self) -> Option<$crate::RemoteObj> {
                Some(self.remote.clone())
            }
        }

        pub struct $stub(Box<dyn $remote_broker + Sync + Send>);

        impl $stub {
            /// Create a new remote stub service
            #[allow(dead_code)]
            pub fn new_remote_stub<T: $remote_broker + Send + Sync + 'static>(obj: T) -> Option<$crate::RemoteStub<Self>> {
                RemoteStub::new($stub(Box::new(obj)))
            }
        }

        impl $crate::IRemoteStub for $stub {
            fn get_descriptor() -> &'static str {
                $descriptor
            }

            fn on_remote_request(&self, code: u32, data: &$crate::BorrowedMsgParcel,
                reply: &mut $crate::BorrowedMsgParcel) -> i32 {
                // For example, "self.0" is "Box<dyn ITest>", "*self.0" is "dyn ITest"
                $on_remote_request(&*self.0, code, data, reply)
            }
        }

        impl $crate::FromRemoteObj for dyn $remote_broker {
            // For example, convert RemoteObj to RemoteObjRef<dyn ITest>
            fn from(object: $crate::RemoteObj) -> $crate::Result<$crate::RemoteObjRef<dyn $remote_broker>> {
                Ok($crate::RemoteObjRef::new(Box::new($proxy::from_remote_object(object)?)))
            }
        }
    };
}