# snmp-agent-go

一个兼容 SNMPv2c（RFC 1901/1905）的网络管理代理服务。代理在本地回环
UDP 端口上收发报文，维护本地管理信息库（MIB），向管理端提供查询、
遍历、批量与设置能力，并支持 Trap / InformRequest 上报。

## 构建与运行

```sh
go build -o snmp-agent .
./snmp-agent -config agent-config.json
```

配置文件缺失时使用内置默认值；`-config` 指定 JSON 配置文件路径。
收到 SIGINT/SIGTERM 时持久化状态后退出。

## 数据模型

代理启动时构建如下对象（按字典序排序存储，支撑整库遍历）：

| OID | 名称 | 类型 | 访问 | 说明 |
| --- | --- | --- | --- | --- |
| 1.3.6.1.2.1.1.1.0 | sysDescr | OCTET STRING | 只读 | 代理描述 |
| 1.3.6.1.2.1.1.2.0 | sysObjectID | OBJECT IDENTIFIER | 只读 | 企业 OID |
| 1.3.6.1.2.1.1.3.0 | sysUpTime | TimeTicks | 只读 | 运行时间（每秒 +100） |
| 1.3.6.1.2.1.1.4.0 | sysContact | OCTET STRING | 读写 | 联系人（≤255 字节），持久化 |
| 1.3.6.1.2.1.1.5.0 | sysName | OCTET STRING | 读写 | 主机名（≤255 字节），持久化 |
| 1.3.6.1.2.1.1.6.0 | sysLocation | OCTET STRING | 读写 | 位置（≤255 字节），持久化 |
| 1.3.6.1.2.1.1.7.0 | sysServices | INTEGER | 只读 | 服务层 |
| 1.3.6.1.4.1.53864.1.1.0 | demoCounter | Counter32 | 只读 | 每秒 +1，到达 2^32-1 后回绕为 0 |
| 1.3.6.1.4.1.53864.1.2.0 | demoGauge | Gauge32 | 读写 | 到达 2^32-1 后保持最大值，持久化 |
| 1.3.6.1.4.1.53864.1.3.0 | demoMessage | OCTET STRING | 读写 | 演示字符串（≤64 字节），持久化 |

语义要点：

- **Counter32**：无符号 32 位，递增溢出后回绕为 0。
- **Gauge32**：无符号 32 位，递增溢出后钳制在 2^32-1。
- 两类对象在存储层分别处理，设置时类型标签必须精确匹配，不会混淆。
- GetRequest 命中不存在的对象时，对应 varbind 返回 `noSuchObject`
  异常（RFC 1905 §4.2.1）。
- GetNextRequest / GetBulkRequest 越过最后一个对象时返回
  `endOfMibView`（§4.2.2/4.2.3）；空 MIB 行为确定：每个请求的
  varbind 都返回 `endOfMibView`。
- SetRequest 先做全量校验（存在性、可写性、类型、长度），任一
  varbind 失败则整体不生效，并以 `error-status`/`error-index` 指出
  失败位置（`notWritable`/`wrongType`/`wrongLength` 等）；全部合法时
  在单个写锁内一次性提交，并发读取只能观察到完整的修改前或修改后
  状态。

## 访问控制

基于 community 的两档访问控制：

- `roCommunity`：允许 GetRequest / GetNextRequest / GetBulkRequest。
- `rwCommunity`：以上之外还允许 SetRequest。
- 其他 community，或用只读 community 发起 SetRequest：**不返回任何
  响应**，报文被静默丢弃。
- 可写对象范围受限于上表中标为"读写"的对象，其余对象一律
  `notWritable`。

无法解析或字段非法的报文同样被静默丢弃，不会影响后续请求。

## GetBulkRequest 语义

- `error-status` 字段承载 non-repeaters，`error-index` 字段承载
  max-repetitions（负值按 0 处理）。
- 前 non-repeaters 个 varbind 各前进一步；其余 varbind 各自按字典序
  重复遍历至多 max-repetitions 次，遇到 MIB 末尾以 `endOfMibView`
  结束该列。
- 响应编码后若超过 `responseSizeLimit`，从尾部截断 varbind 直至
  装下；一个也装不下时返回 `tooBig` 错误与空 varbind 列表。

## Trap 与 InformRequest

- 启动后向 `trapTargets` 发送 coldStart Trap（不等待确认）。
- `sendInform` 发送 InformRequest 并等待确认：超时
  `informTimeoutMs` 未收到匹配 request-id 的 Response 即重传，最多
  重试 `informRetries` 次。
- 重传始终发往**最新已知的管理端地址**（最近一次收到合法请求的源
  地址；未知时回退到 `trapTargets` 第一项）。
- 重复确认是空操作：不会触发重复上报，也不会 panic。

## 持久化与重启恢复

- 每次成功的 SetRequest 之后，以及正常退出时，全部可写对象以 JSON
  原子写入 `statePath`（临时文件 + rename）。
- 启动时在绑定监听端口**之前**恢复状态，恢复期间不响应任何请求、
  不暴露中间状态；状态文件损坏时拒绝启动。
- 访问控制配置（community 等）本身即配置文件，重启后自然恢复。

## 配置项

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `listenAddr` | `127.0.0.1:1161` | UDP 监听地址 |
| `roCommunity` | `public` | 只读 community |
| `rwCommunity` | `private` | 读写 community |
| `statePath` | `agent-state.json` | 可写对象持久化文件 |
| `trapTargets` | `[]` | Trap/Inform 目的地址列表 |
| `trapCommunity` | `public` | 上报报文使用的 community |
| `informRetries` | `3` | Inform 超时重传次数 |
| `informTimeoutMs` | `1000` | Inform 确认超时（毫秒） |
| `responseSizeLimit` | `1400` | 响应报文字节上限 |

## 测试

```sh
go test -race ./...
```

覆盖：BER 编解码往返、遍历边界、GetBulk 语义与响应上限、空 MIB、
原子设置（含并发读写一致性）、Counter32 回绕与 Gauge32 钳制、
权限拒绝（错误 community / 只读越权均无响应）、畸形报文静默丢弃、
Inform 重传与重复确认去重、重传指向最新管理端地址、重启恢复。
