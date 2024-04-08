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


use super::msg::MsgParcel;
use crate::errors::IpcResult;
/// Data structures that can be serialized and written by MsgPracel
///
/// # Example:
///
/// ```rust
/// use ipc::parcel::{MsgParcel, Serialize};
/// use ipc::IpcResult;
///
/// struct Foo {
///     a: Vec<i32>,
///     b: String,
/// }
///
/// impl Serialize for Foo {
///     fn serialize(&self, parcel: &mut MsgParcel) -> IpcResult<()> {
///         parcel.write(&self.a)?;
///         parcel.write(&self.b)?;
///         Ok(())
///     }
/// }
/// ```
pub trait Serialize {
    /// serialize and write into MsgParcel
    fn serialize(&self, parcel: &mut MsgParcel) -> IpcResult<()>;
}

/// Data structures that can be deserialized and read out by MsgPracel,typically
/// used in conjunction with [`Serialize`].
///
/// # Example:
///
/// ```rust
/// use ipc::parcel::{Deserialize, MsgParcel};
/// use ipc::IpcResult;
///
/// struct Foo {
///     a: Vec<i32>,
///     b: String,
/// }
///
/// impl Deserialize for Foo {
///     fn deserialize(parcel: &mut MsgParcel) -> IpcResult<Self> {
///         let a = parcel.read()?;
///         let b = parcel.read()?;
///         Ok(Self { a, b })
///     }
/// }
/// ```
pub trait Deserialize: Sized {
    /// Deserialize and read out from MsgParcel.
    fn deserialize(parcel: &mut MsgParcel) -> IpcResult<Self>;
}

pub const NULL_FLAG: i32 = 0;
pub const NON_NULL_FLAG: i32 = 1;

impl<T: Serialize> Serialize for Option<T> {
    fn serialize(&self, parcel: &mut MsgParcel) -> IpcResult<()> {
        if let Some(inner) = self {
            parcel.write(&NON_NULL_FLAG)?;
            parcel.write(inner)
        } else {
            parcel.write(&NULL_FLAG)
        }
    }
}

impl<T: Deserialize> Deserialize for Option<T> {
    fn deserialize(parcel: &mut MsgParcel) -> IpcResult<Self> {
        let null: i32 = parcel.read()?;
        if null == NULL_FLAG {
            Ok(None)
        } else {
            parcel.read().map(Some)
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Deserialize, Serialize};
    use crate::parcel::MsgParcel;
    #[derive(PartialEq, Eq, Debug)]
    struct TestStruct {
        a: bool,
        b: i8,
        c: String,
    }

    /// UT test cases for `Serialize`
    ///
    /// # Brief
    /// 1. Impl Serialize for a type.
    /// 2. Write this type to the MsgParcel and then read it out, check the
    ///    correctness.
    #[test]
    fn serialize_test() {
        impl Serialize for TestStruct {
            fn serialize(&self, parcel: &mut crate::parcel::MsgParcel) -> crate::IpcResult<()> {
                parcel.write(&self.a).unwrap();
                parcel.write(&self.c).unwrap();
                Ok(())
            }
        }
        let mut msg = MsgParcel::new();
        let test = TestStruct {
            a: true,
            b: 0,
            c: String::from("hello"),
        };
        msg.write(&test).unwrap();
        assert!(msg.read::<bool>().unwrap());
        assert_eq!(String::from("hello"), msg.read::<String>().unwrap());
    }

    /// UT test cases for `Deserialize`
    ///
    /// # Brief
    /// 1. Impl Deserialize for a type.
    /// 2. Write this type to the MsgParcel and then read it out, check the
    ///    correctness.
    #[test]
    fn deserialize_test() {
        impl Deserialize for TestStruct {
            fn deserialize(parcel: &mut MsgParcel) -> crate::IpcResult<Self> {
                let a = parcel.read().unwrap();
                let b = parcel.read().unwrap();
                let c = parcel.read().unwrap();
                Ok(Self { a, b, c })
            }
        }
        let mut msg = MsgParcel::new();
        let test = TestStruct {
            a: true,
            b: 0,
            c: String::from("hello"),
        };
        msg.write(&test.a).unwrap();
        msg.write(&test.b).unwrap();
        msg.write(&test.c).unwrap();
        assert_eq!(test, msg.read().unwrap());
    }
}
