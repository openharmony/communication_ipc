# IPC/RPC组件<a name="ZH-CN_TOPIC_0000001103602398"></a>

-   [简介](#section11660541593)
-   [系统架构](#section1950291414611)
-   [目录](#section161941989596)
-   [约束](#section119744591305)
-   [编译构建](#section137768191623)
-   [说明](#section1312121216216)
    -   [接口说明](#section1551164914237)
    -   [使用说明](#section129654513264)

-   [相关仓](#section1371113476307)

## 简介<a name="section11660541593"></a>

IPC（Inter-Process Communication）与RPC（Remote Procedure Call）机制用于实现跨进程通信，不同的是前者使用Binder驱动，用于设备内的跨进程通信，而后者使用软总线驱动，用于跨设备跨进程通信。IPC和RPC通常采用客户端-服务器（Client-Server）模型，服务请求方（Client）可获取提供服务提供方（Server）的代理 （Proxy），并通过此代理读写数据来实现进程间的数据通信。通常，系统能力（System Ability）Server侧会先注册到系统能力管理者（System Ability Manager，缩写SAMgr）中，SAMgr负责管理这些SA并向Client提供相关的接口。Client要和某个具体的SA通信，必须先从SAMgr中获取该SA的代理，然后使用代理和SA通信。三方应用可以使用FA提供的接口绑定服务提供方的Ability，获取代理，进行通信。下文使用Proxy表示服务请求方，Stub表示服务提供方。

## 系统架构<a name="section1950291414611"></a>

**图 1**  IPC通信机制架构图<a name="fig312319321710"></a>
![](figures/ipc-architecture.png "IPC通信机制架构图")

## 目录<a name="section161941989596"></a>

```
/foundation/communication/ipc
├── interfaces        # 对外接口存放目录
│   └── innerkits     # 对内部子系统暴露的头文件存放目录
│       ├── ipc_core     # ipc 接口存放目录
│       └── libdbinder   # dbinder 接口存放目录
├── ipc            # ipc 框架代码
│   ├── native     # ipc native 实现存放目录
│       ├── src    # ipc native 源代码存放目录
│       └── test   # ipc native 单元测试用例存放目录
│   └── test       # ipc native 模块测试用例存放目录
├── service        # dbinder 实现存放目录
│   └── dbinder    # dbinder 源代码存放目录
```

## 约束<a name="section119744591305"></a>

1. 单个设备上跨进程通信时，传输的数据量最大约为1MB，过大的数据量请使用匿名共享内存。
2. 不支持把跨设备的Proxy对象传递回该Proxy对象所指向的Stub对象所在的设备。

## 编译构建<a name="section137768191623"></a>

**JS侧依赖**

```
import rpc from "@ohos.rpc"
```

**Native侧编译依赖**

sdk依赖：

```
external_deps = [
  "ipc:ipc_core",
]
```

此外， IPC/RPC依赖的refbase实现在公共基础库下，请增加对utils的依赖：

```
external_deps = [
  "c_utils:utils",
]
```

**Rust侧编译依赖**

```
external_deps = [ "ipc:ipc_rust" ]
```

## 说明<a name="section1312121216216"></a>

**JS侧实现跨进程通信基本步骤：**

1. 获取代理

   使用ohos.app.ability.UIAbility提供的globalThis.context.connectServiceExtensionAbility方法绑定Ability，在参数里指定要绑定的Ability所在应用的包名、组件名，如果是跨设备的情况，还需要指定所在设备的NetworkId。用户需要在服务端的onConnect方法里返回一个继承自ohos.rpc.RemoteObject的对象，此对象会在其onRemoteMessageRequest方法里接收到请求。

2. 发送请求

   客户端在globalThis.context.connectServiceExtensionAbility参数指定的回调函数接收到代理对象后，使用ohos.rpc模块提供的方法完成RPC通信，其中MessageParcel提供了读写各种类型数据的方法，IRemoteObject提供了发送请求的方法，RemoteObject提供了处理请求的方法onRemoteRequest，用户需要重写。

**Native侧实现跨进程通信的基本步骤：**

1. 定义接口类

   接口类继承IRemoteBroker，定义描述符、业务函数和消息码。

2. 实现服务提供端\(Stub\)

   Stub继承IRemoteStub\(Native\)，除了接口类中未实现方法外，还需要实现AsObject方法及OnRemoteRequest方法。

3. 实现服务请求端\(Proxy\)

   Proxy继承IRemoteProxy\(Native\)，封装业务函数，调用SendRequest将请求发送到Stub。

4. 注册SA

   服务提供方所在进程启动后，申请SA的唯一标识，将Stub注册到SAMgr。

5. 获取SA

6. 通过SA的标识和设备NetworkId，从SAMgr获取Proxy，通过Proxy实现与Stub的跨进程通信。

**Rust侧实现跨进程通信的基本步骤：**

1. 定义接口

   继承IPC框架的IRemoteBroker特征，定义一个业务自己的trait，在此trait中定义proxy和stub之间的IPC方法。

2. 定义服务

   和c++ 定义的服务类似，Rust服务相关的类型有两个；

   1）由业务提供名字，通过宏define_remote_object定义。

   2）由业务定义，框架不关心其内容，只要求其必须实现步骤1中定义的接口trait。

3. 定义代理

   代理的定义由业务提供名字，通过宏define_remote_object定义代理的类型。

4. 创建并注册服务

   服务定义完成后，只有注册到samgr后，其他进程才能获取该服务的代理，完成和该服务的通信。

5. 获取代理

   通过向samgr发起请求，可以获取到指定服务的代理对象，之后便可以调用该代理对象的IPC方法实现和服务的通信。

6. 测试服务能力

### 接口说明<a name="section1551164914237"></a>

**表 1**  JS侧IPC关键API

| 模块                       | 方法                                                         | 功能说明                                    |
| -------------------------- | ------------------------------------------------------------ | ------------------------------------------- |
| ohos.app.ability.UIAbility | globalThis.context.connectServiceExtensionAbility(want: Want, options:ConnectOptions ): number | 绑定指定的Ability，在回调函数里接收代理对象 |
| ohos.rpc.RemoteObject      | onRemoteMessageRequest(code: number, data: MessageParcel, reply: MessageParcel, options: MessageOption): boolean \| Promise<boolean> | 服务端处理请求，返回结果                    |
| ohos.rpc.IRemoteObject     | sendRequest(code: number, data: MessageParcel, reply: MessageParcel, options: MessageOption): Promise<SendRequestResult> | 发送请求，在期约里接收结果                  |
| ohos.rpc.IRemoteObject     | sendRequest(code: number, data: MessageParcel, reply: MessageParcel, options: MessageOption, callback: AsyncCallback<SendRequestResult>): void | 发送请求，在回调函数里接收结果              |
| ohos.rpc.MessageParcel     | writeRemoteObject(object: IRemoteObject): boolean            | 序列化IRemoteObject对象                     |
| ohos.rpc.MessageParcel     | readRemoteObject(): IRemoteObject                            | 反序列化IRemoteObject对象                   |



**表 2**  Native侧IPC接口

<a name="table178849240013"></a>

<table><thead align="left"><tr id="row6884924608"><th class="cellrowborder" valign="top" width="14.12141214121412%" id="mcps1.2.4.1.1"><p id="p98846241706"><a name="p98846241706"></a><a name="p98846241706"></a>类/接口</p>
</th>
<th class="cellrowborder" valign="top" width="52.54525452545254%" id="mcps1.2.4.1.2"><p id="p1488482414020"><a name="p1488482414020"></a><a name="p1488482414020"></a>方法</p>
</th>
<th class="cellrowborder" valign="top" width="33.33333333333333%" id="mcps1.2.4.1.3"><p id="p388516244016"><a name="p388516244016"></a><a name="p388516244016"></a>功能说明</p>
</th>
</tr>
</thead>
<tbody><tr id="row15885824402"><td class="cellrowborder" valign="top" width="14.12141214121412%" headers="mcps1.2.4.1.1 "><p id="p08859241008"><a name="p08859241008"></a><a name="p08859241008"></a>IRemoteBroker</p>
</td>
<td class="cellrowborder" valign="top" width="52.54525452545254%" headers="mcps1.2.4.1.2 "><p id="p388572412010"><a name="p388572412010"></a><a name="p388572412010"></a>sptr&lt;IRemoteObject&gt; AsObject()</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.2.4.1.3 "><p id="p13885724405"><a name="p13885724405"></a><a name="p13885724405"></a>返回通信对象。派生类需要实现，Stub端返回RemoteObject对象本身，Proxy端返回代理对象。</p>
</td>
</tr>
<tr id="row138859241808"><td class="cellrowborder" valign="top" width="14.12141214121412%" headers="mcps1.2.4.1.1 "><p id="p1888515245012"><a name="p1888515245012"></a><a name="p1888515245012"></a>IRemoteStub</p>
</td>
<td class="cellrowborder" valign="top" width="52.54525452545254%" headers="mcps1.2.4.1.2 "><p id="p1388516240011"><a name="p1388516240011"></a><a name="p1388516240011"></a>virtual int OnRemoteRequest(uint32_t code, MessageParcel &amp;data, MessageParcel &amp;reply, MessageOption &amp;option)</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.2.4.1.3 "><p id="p1188582414016"><a name="p1188582414016"></a><a name="p1188582414016"></a>请求处理方法，派生类需要重写，处理Proxy的请求并返回结果。</p>
</td>
</tr>
<tr id="row108856241904"><td class="cellrowborder" valign="top" width="14.12141214121412%" headers="mcps1.2.4.1.1 "><p id="p6885924609"><a name="p6885924609"></a><a name="p6885924609"></a>IRemoteProxy</p>
</td>
<td class="cellrowborder" valign="top" width="52.54525452545254%" headers="mcps1.2.4.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.2.4.1.3 "><p id="p688592413018"><a name="p688592413018"></a><a name="p688592413018"></a>业务Proxy类派生自IRemoteProxy类。</p>
</td>
</tr>
</tbody>
</table>

### 使用说明<a name="section129654513264"></a>

**JS侧使用说明**

1. 客户端构造变量want，指定要绑定的Ability所在应用的包名、组件名，如果是跨设备的场景，还需要目标设备NetworkId。构造变量connect，指定绑定成功、绑定失败、断开连接时的回调函数。使用UIAbility提供的接口绑定Ability。

   ```
   import rpc from "@ohos.rpc"

   let proxy = null
   let connectId = null

   // 单个设备
   let want = {
       // 包名和组件名写实际的值
       "bundleName": "ohos.rpc.test.server",
       "abilityName": "ohos.rpc.test.server.ServiceAbility",
   }
   let connect = {
       onConnect:function(elementName, remote) {
           proxy = remote
       },
       onDisconnect:function(elementName) {
       },
       onFailed:function() {
           proxy = null
       }
   }
   connectId = globalThis.context.connectServiceExtensionAbility(want, connect)

   // 如果是跨设备绑定，可以使用deviceManager获取目标设备NetworkId
   import deviceManager from '@ohos.distributedHardware.deviceManager'
   function deviceManagerCallback(deviceManager) {
       let deviceList = deviceManager.getTrustedDeviceListSync()
       let deviceId = deviceList[0].deviceId
       let want = {
           "bundleName": "ohos.rpc.test.server",
           "abilityName": "ohos.rpc.test.service.ServiceAbility",
           "deviceId": deviceId,
           "flags": 256
       }
       connectId = globalThis.context.connectServiceExtensionAbility(want, connect)
   }
   // 第一个参数是本应用的包名，第二个参数是接收deviceManager的回调函数
   deviceManager.createDeviceManager("ohos.rpc.test", deviceManagerCallback)
   ```



2. 服务端被绑定的Ability在onConnect方法里返回继承自rpc.RemoteObject的对象，该对象需要实现onRemoteMessageRequest方法，处理客户端的请求。

   ```
   import rpc from "@ohos.rpc"
   onConnect(want: Want) {
       var robj:rpc.RemoteObject = new Stub("rpcTestAbility")
       return robj
   }
   class Stub extends rpc.RemoteObject {
       constructor(descriptor) {
           super(descriptor)
       }
       onRemoteMessageRequest(code, data, reply, option) {
           // 根据code处理客户端的请求
           return true
       }
   }
   ```



3. 客户端在onConnect回调里接收到代理对象，调用sendRequest方法发起请求，在期约或者回调函数里接收结果。

   ```
   import rpc from "@ohos.rpc"
   // 使用期约
   let option = new rpc.MessageOption()
   let data = rpc.MessageParcel.create()
   let reply = rpc.MessageParcel.create()
   // 往data里写入参数
   proxy.sendRequest(1, data, reply, option)
       .then(function(result) {
           if (result.errCode != 0) {
               console.error("send request failed, errCode: " + result.errCode)
               return
           }
           // 从result.reply里读取结果
       })
       .catch(function(e) {
           console.error("send request got exception: " + e)
       }
       .finally(() => {
           data.reclaim()
           reply.reclaim()
       })

   // 使用回调函数
   function sendRequestCallback(result) {
       try {
           if (result.errCode != 0) {
               console.error("send request failed, errCode: " + result.errCode)
               return
           }
           // 从result.reply里读取结果
       } finally {
           result.data.reclaim()
           result.reply.reclaim()
       }
   }
   let option = new rpc.MessageOption()
   let data = rpc.MessageParcel.create()
   let reply = rpc.MessageParcel.create()
   // 往data里写入参数
   proxy.sendRequest(1, data, reply, option, sendRequestCallback)
   ```



4. IPC通信结束后，使用UIAbility的接口断开连接。

   ```
   import rpc from "@ohos.rpc"
   globalThis.context.disconnectServiceExtensionAbility(connectionId).then((data) => {
       console.info('disconnectServiceExtensionAbility success');
   }).catch((error) => {
       console.error('disconnectServiceExtensionAbility failed');
   })
   ```



**Native侧使用说明**

1. 定义IPC接口ITestAbility

   IPC接口继承IPC基类接口IRemoteBroker，接口里定义描述符、业务函数和消息码，其中业务函数在Proxy端和Stub端都需要实现。

   ```
   class ITestAbility : public IRemoteBroker {
   public:
   // DECLARE_INTERFACE_DESCRIPTOR是必须的， 入参需使用std::u16string；
   DECLARE_INTERFACE_DESCRIPTOR(u"test.ITestAbility"); // DESCRIPTOR接口描述符建议使用"组件名.类名"的格式
   int TRANS_ID_PING_ABILITY = 1; // 定义消息码
   virtual int TestPingAbility(const std::u16string &dummy) = 0; // 定义业务函数
   };
   ```



2. 定义和实现服务端TestAbilityStub

   该类是和IPC框架相关的实现，需要继承自IRemoteStub<ITestAbility\>。Stub端作为接收请求的一端，需重写OnRemoteRequest方法用于接收客户端调用。

   ```
   class TestAbilityStub : public IRemoteStub<ITestAbility> {
   public:
       virtual int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
       int TestPingAbility(const std::u16string &dummy) override;
   };

   int TestAbilityStub::OnRemoteRequest(uint32_t code,
       MessageParcel &data, MessageParcel &reply, MessageOption &option)
   {
       if (data.ReadInterfaceToken() != GetDescriptor()) { // 校验是否为本服务的接口描述符，避免中继攻击
           return -1;
       }
       switch (code) {
           case TRANS_ID_PING_ABILITY: {
               std::u16string dummy = data.ReadString16();
               int result = TestPingAbility(dummy);
               reply.WriteInt32(result);
               return 0;
           }
           default:
               return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
       }
   }
   ```



3. 定义服务端业务函数具体实现类TestAbility

   ```
   class TestAbility : public TestAbilityStub {
   public:
       int TestPingAbility(const std::u16string &dummy);
   }

   int TestAbility::TestPingAbility(const std::u16string &dummy) {
       return 0;
   }
   ```



4. 定义和实现客户端TestAbilityProxy

   该类是Proxy端实现，继承自IRemoteProxy<ITestAbility\>，调用SendRequest接口向Stub端发送请求，对外暴露服务端提供的能力。

   ```
   class TestAbilityProxy : public IRemoteProxy<ITestAbility> {
   public:
       explicit TestAbilityProxy(const sptr<IRemoteObject> &impl);
       int TestPingService(const std::u16string &dummy) override;
   private:
       static inline BrokerDelegator<TestAbilityProxy> delegator_; // 方便使用iface_cast宏
   }

   TestAbilityProxy::TestAbilityProxy(const sptr<IRemoteObject> &impl)
       : IRemoteProxy<ITestAbility>(impl)
   {
   }

   int TestAbilityProxy::TestPingService(const std::u16string &dummy) {
       MessageOption option;
       MessageParcel dataParcel, replyParcel;
       if(!dataParcel.WriteInterfaceToken(GetDescriptor())) { // 所有对外接口的proxy实现都要写入接口描述符，用于stub端检验
           return -1;
       }
       if(!dataParcel.WriteString16(dummy)) {
           return -1;
       }
       int error = Remote()->SendRequest(TRANS_ID_PING_ABILITY, dataParcel, replyParcel, option);
       int result = (error == ERR_NONE) ? replyParcel.ReadInt32() : -1;
       return result;
   }
   ```



5. 同步调用与异步调用

   MessageOption作为发送接口（原型如下）的入参，可设定同步（TF\_SYNC）、异步（TF\_ASYNC），默认情况下设定为同步，其余可通过MessageOption构造方法或void SetFlags\(int flags\)设定。

   ```
   int SendRequest(uint32_t code, MessageParcel &data,
       MessageParcel &reply, MessageOption &option) override;
   MessageOption option;
   option.setFlags(option.TF_ASYNC);
   ```



6. SA注册与启动

   SA需要将自己的TestAbilityStub实例通过AddSystemAbility接口注册到SystemAbilityManager，设备内与分布式的注册参数不同。

   ```
   // 注册到本设备内
   auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
   samgr->AddSystemAbility(said, new TestAbility());

   // 在组网场景下，会被同步到其他设备上
   auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
   ISystemAbilityManager::SAExtraProp saExtra;
   saExtra.isDistributed = true; // 设置为分布式SA
   int result = samgr->AddSystemAbility(said, new TestAbility(), saExtra);
   ```



7. SA获取与调用

   通过SystemAbilityManager的GetSystemAbility方法可获取到对应SA的代理IRemoteObject，然后构造TestAbilityProxy即可。

   ```
   // 获取本设备内注册的SA的proxy
   sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
   sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(said);
   sptr<ITestAbility> testAbility = iface_cast<ITestAbility>(remoteObject); // 使用iface_cast宏转换成具体类型

   // 获取其他设备注册的SA的Proxy
   sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
   sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(sdid, deviceId); // deviceId是指定设备的标识符
   sptr<TestAbilityProxy> proxy(new TestAbilityProxy(remoteObject)); // 直接构造具体Proxy
   ```

**Rust侧使用说明**

以下为CALCULATOR服务的完整开发步骤。

1. 定义接口

   继承IPC框架IRemoteBroker特征，定义一个业务自己的trait，该trait中定义proxy和stub之间的IPC方法。示例如下定义了ICalc trait:

   ```
   /// Function between proxy and stub of ICalcService
   pub trait ICalc: IRemoteBroker {
       /// Calc add num1 + num2
       fn add(&self, num1: i32, num2: i32) -> IpcResult<i32>;
       /// Calc sub num1 + num2
       fn sub(&self, num1: i32, num2: i32) -> IpcResult<i32>;
       /// Calc mul num1 + num2
       fn mul(&self, num1: i32, num2: i32) -> IpcResult<i32>;
       /// Calc div num1 + num2
       fn div(&self, num1: i32, num2: i32) -> IpcResult<i32>;
   }
   ```

   1.1 定义枚举ICalcCode

   ICalcCode枚举中的变体表示calculator服务的不同功能。当然这一步不是必须的，但是为了提高代码的可读性，建议按照如下方法为每一个IPC方法定义code,示例如下：

   ```
   /// Function code of ICalcService
   pub enum ICalcCode {
       /// add
       CodeAdd = FIRST_CALL_TRANSACTION, // 由IPC框架定义，值为1，建议业务使用该值作为第一个IPC方法的code
       /// sub
       CodeSub,
       /// mul
       CodeMul,
       /// div
       CodeDiv,
   }
   ```

   1.2 ICalCode转换

   ICalCode实现TryFrom trait，可以实现u32类型到CalCode枚举类型的转换。

   ```
   impl TryFrom<u32> for ICalcCode {
       type Error = IpcStatusCode;
       fn try_from(code: u32) -> IpcResult<Self> {
           match code {
               _ if code == ICalcCode::CodeAdd as u32 => Ok(ICalcCode::CodeAdd),
               _ if code == ICalcCode::CodeSub as u32 => Ok(ICalcCode::CodeSub),
               _ if code == ICalcCode::CodeMul as u32 => Ok(ICalcCode::CodeMul),
               _ if code == ICalcCode::CodeDiv as u32 => Ok(ICalcCode::CodeDiv),
               _ => Err(IpcStatusCode::Failed),
           }
       }
   }
   ```

2. 定义服务

   和c++ 定义的服务类似，Rust服务相关的类型有两个：

   1）由业务提供名字，通过宏define_remote_object!定义，如本例中的CalcStub。

   2）由业务定义，框架不关心其内容，只要求其必须实现步骤1中定义的接口trait，如本例中的CalcService。

   2.1 定义CalcService服务

   CalcService的定义如下所示，实现了ICalc和IRemoteBroker特征，服务中没有任何成员，如有需要可以根据业务需要进行定义。

   ```
   /// example.calc.ipc.ICalcService type
   pub struct CalcService;
   // 实现ICalc特征
   impl ICalc for CalcService {
       fn add(&self, num1: i32, num2: i32) -> IpcResult<i32> {
           Ok(add(&num1, &num2))
       }
       fn sub(&self, num1: i32, num2: i32) -> IpcResult<i32> {
           Ok(sub(&num1, &num2))
       }
       fn mul(&self, num1: i32, num2: i32) -> IpcResult<i32> {
           Ok(mul(&num1, &num2))
       }
       fn div(&self, num1: i32, num2: i32) -> IpcResult<i32> {
           Ok(div(&num1, &num2))
       }
   }
   // 实现IRemoteBroker特征
   impl IRemoteBroker for CalcService {}
   /// add num1 + num2
   pub fn add(num1: &i32, num2: &i32) -> i32 {
       num1 + num2
   }
   /// sub num1 + num2
   pub fn sub(num1: &i32, num2: &i32) -> i32 {
       num1 - num2
   }
   /// mul num1 + num2
   pub fn mul(num1: &i32, num2: &i32) -> i32 {
       num1 * num2
   }
   /// div num1 + num2
   pub fn div(num1: &i32, num2: &i32) -> i32 {
       match num2 {
           0 => {
               println!("Zero cannot be divided");
               -1
           },
           _ => num1 / num2,
       }
   }
   ```

   2.2 实现on_icalc_remote_request()方法

   当服务收到IPC请求，IPC框架会回调该方法，业务在该方法中完成如下处理：

   1）完成参数的解析。

   2）调用具体的服务IPC方法。

   3）将处理结果写会reply。

   示例代码如下：

   ```
   fn on_icalc_remote_request(stub: &dyn ICalc, code: u32, data: &BorrowedMsgParcel,
       reply: &mut BorrowedMsgParcel) -> IpcResult<()> {
       match code.try_into()? {
           ICalcCode::CodeAdd => {
               let num1: i32 = data.read().expect("Failed to read num1 in addition operation");
               let num2: i32 = data.read().expect("Failed to read num2 in addition operation");
               let ret = stub.add(num1, num2)?;
               reply.write(&ret)?;
               Ok(())
           }
           ICalcCode::CodeSub => {
               let num1: i32 = data.read().expect("Failed to read num1 in subtraction operation");
               let num2: i32 = data.read().expect("Failed to read num1 in subtraction operation");
               let ret = stub.sub(num1, num2)?;
               reply.write(&ret)?;
               Ok(())
           }
           ICalcCode::CodeMul => {
               let num1: i32 = data.read().expect("Failed to read num1 in multiplication operation");
               let num2: i32 = data.read().expect("Failed to read num1 in multiplication operation");
               let ret = stub.mul(num1, num2)?;
               reply.write(&ret)?;
               Ok(())
           }
           ICalcCode::CodeDiv => {
               let num1: i32 = data.read().expect("Failed to read num1 in division  operation");
               let num2: i32 = data.read().expect("Failed to read num1 in division  operation");
               let ret = stub.div(num1, num2)?;
               reply.write(&ret)?;
               Ok(())
           }
       }
   }
   ```

3. 定义代理

   代理的定义由业务提供名字，通过宏define_remote_object定义代理的类型，业务需要为代理实现ICalc。示例如下：

   ```
   impl ICalc for CalcProxy {
       fn add(&self, num1: i32, num2: i32) -> IpcResult<i32> {
           let mut data = MsgParcel::new().expect("MsgParcel should success");
           data.write(&num1)?;
           data.write(&num2)?;
           let reply = self.remote.send_request(ICalcCode::CodeAdd as u32,
               &data, false)?;
           let ret: i32 = reply.read().expect("need reply i32");
           Ok(ret)
       }
       fn sub(&self, num1: i32, num2: i32) -> IpcResult<i32> {
           let mut data = MsgParcel::new().expect("MsgParcel should success");
           data.write(&num1)?;
           data.write(&num2)?;
           let reply = self.remote.send_request(ICalcCode::CodeSub as u32,
               &data, false)?;
           let ret: i32 = reply.read().expect("need reply i32");
           Ok(ret)
       }
       fn mul(&self, num1: i32, num2: i32) -> IpcResult<i32> {
           let mut data = MsgParcel::new().expect("MsgParcel should success");
           data.write(&num1)?;
           data.write(&num2)?;
           let reply = self.remote.send_request(ICalcCode::CodeMul as u32,
               &data, false)?;
           let ret: i32 = reply.read().expect("need reply i32");
           Ok(ret)
       }
       fn div(&self, num1: i32, num2: i32) -> IpcResult<i32> {
           let mut data = MsgParcel::new().expect("MsgParcel should success");
           data.write(&num1)?;
           data.write(&num2)?;
           let reply = self.remote.send_request(ICalcCode::CodeDiv as u32,
               &data, false)?;
           let ret: i32 = reply.read().expect("need reply i32");
           Ok(ret)
       }
   }
   ```

   上述对象最终通过宏define_remote_object调用，将业务定义的类型和IPC框架进行结合，宏define_remote_object提供了如下几个关键信息：

   1）服务的接口特征ICalc。

   2）服务的描述符为“example.calc.ipc.ICalcService”。

   3）Rust服务类型名为CalcStub。

   4）服务处理IPC请求的入口方法为on_icalc_remote_request。

   5）代理类型为CalcProxy。

   示例代码如下：

   ```
   define_remote_object!(
       ICalc["example.calc.ipc.ICalcService"] {
           stub: CalcStub(on_icalc_remote_request),
           proxy: CalcProxy,
       }
   );
   ```

4.  创建并注册服务

   服务定义完成后，只有注册到samgr后，其他进程才能获取该服务的代理，然后完成和该服务的通信。示例代码如下：

   ```
   fn main() {
       init_access_token();
       // 创建服务对象，最终的服务对象为CalcStub
       let service = CalcStub::new_remote_stub(CalcService).expect("create CalcService success");
       // 向samgr注册服务
       add_service(&service.as_object().expect("get ICalc service failed"),
           EXAMPLE_IPC_CALC_SERVICE_ID).expect("add server to samgr failed");
       println!("join to ipc work thread");
       // 将主线程转换为IPC线程，至此服务所在进程陷入循环
       join_work_thread();
   }
   ```

   注意：add_service为IPC 框架提供的临时调试接口，该接口应该由samgr模块提供。

5. 获取代理

   通过向samgr发起请求，可以获取到指定服务的代理对象，之后便可以调用该代理对象的IPC方法实现和服务的通信。示例代码如下：

   ```
   fn get_calc_service() -> RemoteObjRef<dyn ICalc>
   {
       let object = get_service(EXAMPLE_IPC_CALC_SERVICE_ID).expect("get icalc service failed");
       let remote = <dyn ICalc as FromRemoteObj>::try_from(object);
       let remote = match remote {
           Ok(x) => x,
           Err(error) => {
               println!("convert RemoteObj to CalcProxy failed: {}", error);
               panic!();
           }
       };
       remote
   }
   ```

   注意：示例中的get_service()为IPC框架提供的临时接口，该接口由samgr模块提供。

6. 测试Calculartor服务能力

   当测试用例Calculator_Ability pass表示CalcService 服务能力ok。

   ```
   #[test]
   fn calculator_ability() {
       let remote = get_calc_service();
       // add
       let ret = remote.add(5, 5).expect("add failed");
       assert_eq!(ret, 10);
       // sub
       let ret = remote.sub(5, 5).expect("sub failed");
       assert_eq!(ret, 0);
       // mul
       let ret = remote.mul(5, 5).expect("mul failed");
       assert_eq!(ret, 25);
       // div
       let ret = remote.div(5, 5).expect("div failed");
       assert_eq!(ret, 1);
   }
   ```

## 相关仓<a name="section1371113476307"></a>

分布式软总线子系统

**communication\_ipc**

[commonlibrary\_c\_utils](https://gitee.com/openharmony/commonlibrary_c_utils)

[distributedschedule\_samgr](https://gitee.com/openharmony/distributedschedule_samgr)

