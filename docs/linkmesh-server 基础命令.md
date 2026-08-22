# linkmesh-server 基础命令

linkmesh-server 是中心化信令 + 中继服务。维护路由表（公钥 → 虚拟 IP → Endpoint），负责客户端之间的坐标交换与数据面中继转发；只转发密文，不解密任何业务数据，也从不接触客户端的私钥。

> 安全模型（身份认证 / 密钥轮换 / 吊销）的设计见《身份认证与密钥管理体系设计》，相应 CLI 命令随实施阶段落地。

所有配置集中保存在 `./server.json`（JSON 格式），命令行操作会直接改写该文件。

## --start "PORT"
### 说明
    启动信令服务并监听指定端口，后台运行。
    客户端上线注册、坐标查询、中继转发均通过该端口进行（中继默认与信令同端口）。
### 示例
    linkmesh-server --start 8080

## --stop
### 说明
    停止信令服务。停止后客户端无法再上线注册或查询坐标，但已建立的直连不受影响。
### 示例
    linkmesh-server --stop

## --genkey
### 说明
    生成服务端的私钥和公钥对，写入 server.json，用于信令通道加密。
    每台机器只允许一套密钥：如果本机已存在密钥对，则报错。
    公钥通过 --showpubkey 分发给客户端；私钥只保存在本机。
### 示例
    linkmesh-server --genkey

## --showpubkey
### 说明
    显示服务器的公钥，供客户端获取并配置。
### 示例
    linkmesh-server --showpubkey

## --list
### 说明
    查看当前路由表：每个在线客户端的公钥、虚拟 IP 与 Endpoint。
### 示例
    linkmesh-server --list

## --delpeer "public key"
### 说明
    从路由表中移除指定公钥对应的客户端（强制下线）。
    移除后，其他客户端将无法再查询到该客户端的坐标。
### 示例
    linkmesh-server --delpeer "Pub_B"

## --status
### 说明
    查看信令服务实时运行状态（在线客户端数量、中继开关、收发包与中继字节数）。
### 示例
    linkmesh-server --status

## --log [行数]
### 说明
    查看服务端运行日志。默认显示最近 50 行，可指定行数。
    支持 --follow 参数实时追踪日志输出。
### 示例
    一：linkmesh-server --log 100
    二：linkmesh-server --log --follow

## --version
### 说明
    显示当前服务端版本号。
### 示例
    linkmesh-server --version

## --help [命令名]
### 说明
    显示帮助信息。如果指定了具体命令名，则只显示该命令的详细用法；否则显示所有可用命令摘要。
### 示例
    一：linkmesh-server --help
    二：linkmesh-server --help start

> 所有命令均支持 `--quiet` 参数以抑制非错误输出（对 --status/--list 等同样生效，错误仍输出到 stderr），
> `--config <路径>` 可指定配置文件位置（默认 ./server.json）。

## 认证体系命令（P0-2 / P1）

> 网格认证（mesh，**强制**）：服务端必须以 `--mesh-init` 初始化网格后才能运行，
> 进入证书认证模式（root 签名 ServerInfo / JOIN / AUTH / CRL）。未初始化网格时服务端拒绝启动。
> 设备接入一律通过一次性加入码 `--join`（客户端侧）离线/在线签发证书；不再有授权表机制。
> 认证体系设计见《身份认证与密钥管理体系设计》。

> 说明：历史版本的 `--authorize` / `--deauthorize` / `--auth-list`（授权表）已移除。
> 设备准入统一走 mesh 证书（`--join` + 加入码 / `--issue` 离线签发）。

## --add-room "房间名" "令牌"
### 说明
    新增/更新房间令牌（分房间隔离）。令牌只以 SHA-256 哈希存储，不落明文。
    rooms 非空时启用令牌验证：客户端 JOIN/AUTH/REGISTER 必须携带有效令牌，
    令牌决定设备所属房间；不同房间的设备互相隔离（查询/中继/NOTIFY 均限同房间）。
    rooms 为空 = 单房间开放模式（无令牌验证），服务启动与日志中会给出警告。
### 示例
    linkmesh-server --add-room office "my-office-token"

## --remove-room "房间名"
### 说明
    删除房间令牌（该房间设备此后无法通过令牌验证接入）。
### 示例
    linkmesh-server --remove-room office

## --rooms
### 说明
    查看房间令牌列表（名称 + 令牌哈希前缀）。
### 示例
    linkmesh-server --rooms

## --alias "别名" "虚拟IP"
### 说明
    绑定别名（如 computer -> 10.13.13.5）。绑定后同房间任意客户端即可用
    `computer:8080` 这类地址访问该设备（内嵌 DNS 应答器 / --resolve 按名解析）。
    别名规则：小写字母、数字、`-`、`_`，最长 32 字符（大写自动转小写）。
    管理员别名优先于设备自报别名（防自报抢占命名）。
### 示例
    linkmesh-server --alias computer 10.13.13.5

## --alias-del "别名"
### 说明
    删除别名绑定。
### 示例
    linkmesh-server --alias-del computer

## --alias-list
### 说明
    查看管理员别名表。
### 示例
    linkmesh-server --alias-list

## --mesh-init
### 说明
    初始化网格根（生成 mesh.json，显示网格根指纹）。只能初始化一次（需先 --genkey）。
### 示例
    linkmesh-server --mesh-init

## --invite [--ip x.x.x.x]
### 说明
    生成一次性加入码（10 分钟有效，单次使用）；--ip 可预绑定虚拟 IP。
    注意：运行中的守护进程内存中持有 mesh.json，新加入码需重启服务端后对运行实例生效。
### 示例
    linkmesh-server --invite --ip 10.13.13.2

## --issue "ik_x公钥" "ik_s公钥" [--ip x.x.x.x]
### 说明
    离线签发设备证书（类似 authorized_keys 工作流，无需加入码）。
### 示例
    linkmesh-server --issue "ik_x..." "ik_s..." --ip 10.13.13.2

## --revoke <device_id|ik_x> [--reason compromised|leaked|rotated|admin|discontinued]
### 说明
    吊销设备并更新 CRL（版本单调递增）；运行中的守护进程按 CRL 拒绝其接入，
    已建立的会话由控制通道 revoke 立即踢下线。
### 示例
    linkmesh-server --revoke "device_id" --reason leaked

## --crl
### 说明
    查看当前吊销列表（CRL 版本与条目）。
### 示例
    linkmesh-server --crl

## --show-fingerprint
### 说明
    显示网格根指纹（加入时带外比对）。
### 示例
    linkmesh-server --show-fingerprint

## 配置文件 server.json

本机所有配置集中于此文件，可直接手工编辑（JSON 格式），也可用上面的命令修改。常用字段：

| 字段 | 说明 |
| :--- | :--- |
| `listen` | 信令监听地址，如 `0.0.0.0:8080` |
| `keypair.public / keypair.private` | 服务端密钥对（base64）。私钥只保存在本机 |
| `signing` | 服务端签名密钥对（Ed25519，mesh 模式 ServerInfo 签名用） |
| `relay` | 中继配置：`enabled` 是否启用中继；`port` 非 0 时中继使用独立 UDP 端口，否则与信令同端口；`batch` 批量转发（`window_ms`/`max_bytes`） |
| `route_ttl_sec` | 路由表与认证会话过期时间（秒）：客户端停止心跳后自动下线，认证会话同步回收 |
| `authorized[]` | 历史遗留字段（不再使用；旧 server.json 可保留，解析时忽略） |
| `rooms[]` | 房间令牌：`name` / `token_hash`（SHA-256，不落明文）。空 = 单房间开放（启动警告） |
| `aliases[]` | 管理员别名表：`name` → `ip`（客户端可按名访问） |
| `mesh_path` | mesh.json 路径（`--mesh-init` 生成，含 root 私钥，chmod 600） |
| `server_name` | 服务器显示名称（ServerInfo 用） |
| `control_port` | 本机控制通道端口（供 --list、--status、运行中 revoke/加房间 等使用） |
| `control_token` | 控制通道鉴权令牌（--genkey 自动生成，防本地任意进程控制） |
| `log_file` / `pid_file` | 日志与 PID 文件位置 |
