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

IPC（Inter-Process Communication）与RPC（Remote Procedure Call）机制用于实现跨进程通信，不同的是前者使用Binder驱动，用于设备内的跨进程通信，而后者使用软总线驱动，用于跨设备跨进程通信。IPC和RPC通常采用客户端-服务器（Client-Server）模型，服务请求方（Client）可获取提供服务提供方（Server）的代理 （Proxy），并通过此代理读写数据来实现进程间的数据通信。通常，Server会先注册系统能力（System Ability）到系统能力管理者（System Ability Manager，缩写SAMgr）中，SAMgr负责管理这些SA并向Client提供相关的接口。Client要和某个具体的SA通信，必须先从SAMgr中获取该SA的代理，然后使用代理和SA通信。下文使用Proxy表示服务请求方，Stub表示服务提供方。

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

目前暂不支持的场景：

跨设备RPC调用

## 编译构建<a name="section137768191623"></a>

**Native侧编译依赖**

sdk依赖：

```
external_deps = [
  "ipc:ipc_core",
]
```

此外， IPC/RPC依赖的refbase实现在公共基础库实现//utils下，请增加对utils的源码依赖：

```
deps = [
  "//utils/native/base:utils",
]
```

## 说明<a name="section1312121216216"></a>

Native侧和Java侧实现跨进程通信的步骤基本相同。

1.  定义接口类

    接口类继承IRemoteBroker，定义描述符、业务函数和消息码。

2.  实现服务提供端\(Stub\)

    Stub继承IRemoteStub\(Native\)或者RemoteObject\(Java\)，除了接口类中未实现方法外，还需要实现AsObject方法及OnRemoteRequest方法。

3.  实现服务请求端\(Proxy\)

    Proxy继承IRemoteProxy\(Native\)或者RemoteProxy\(Java\)，封装业务函数，调用SendRequest将请求发送到Stub。

4.  注册SA

    服务提供方所在进程启动后，申请SA的唯一标识，将Stub注册到SAMgr。

5.  获取SA
6.  通过SA的标识和设备标识，从SAMgr获取Proxy，通过Proxy实现与Stub的跨进程通信。

### 接口说明<a name="section1551164914237"></a>

**表 1**  Native侧IPC接口

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

**Native侧使用说明**

定义IPC接口ITestAbility

IPC接口继承IPC基类接口IRemoteBroker，接口里定义描述符、业务函数和消息码，其中业务函数在Proxy端和Stub端都需要实现。

```
class ITestAbility : public IRemoteBroker {
public:
// DECLARE_INTERFACE_DESCRIPTOR是必须的， 入参需使用std::u16string；
DECLARE_INTERFACE_DESCRIPTOR(u"test.ITestAbility");
int TRANS_ID_PING_ABILITY = 1; // 定义消息码
virtual int TestPingAbility(const std::u16string &dummy) = 0; // 定义业务函数
};
```

定义和实现服务端TestAbilityStub

该类是和IPC框架相关的实现，需要继承 IRemoteStub<ITestAbility\>。Stub端作为接收请求的一端，需重写OnRemoteRequest方法用于接收客户端调用。

```
class TestAbilityStub : public IRemoteStub<ITestAbility> {
public:
    virtual int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    int TestPingAbility(const std::u16string &dummy) override;
};
 
int TestServiceStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
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

定义服务端业务函数具体实现类TestAbility

```
class TestAbility : public TestAbilityStub {
public:
    int TestPingAbility(const std::u16string &dummy);
}

int TestAbility::TestPingAbility(const std::u16string &dummy) {
    return 0;
}
```

定义和实现客户端TestAbilityProxy

该类是Proxy端实现，继承IRemoteProxy<ITestAbility\>，调用SendRequest接口向Stub端发送请求，对外暴露服务端提供的能力。

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
    dataParcel.WriteString16(dummy);
    int error = Remote()->SendRequest(TRANS_ID_PING_ABILITY, dataParcel, replyParcel, option);
    int result = (error == ERR_NONE) ? replyParcel.ReadInt32() : -1;
    return result;
}
```

同步调用与异步调用

MessageOption作为发送接口（原型如下）的入参，可设定同步（TF\_SYNC）、异步（TF\_ASYNC）、接收FD（TF\_ACCEPT\_FDS），默认情况下设定为同步，其余可通过MessageOption构造方法或void SetFlags\(int flags\)设定。

```
int SendRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option) override;
MessageOption option = { MessageOption::TF_ASYNC };
```

SA注册与启动

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

SA获取与调用

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

## 相关仓<a name="section1371113476307"></a>

分布式软总线子系统

**communication\_ipc**

utils

utils\_native

distributedschedule\_samgr

