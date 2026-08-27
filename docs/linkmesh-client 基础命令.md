# linkmesh-client 基础命令

linkmesh-client 是 NAT 穿透客户端。每台设备在本地生成自己的密钥对，私钥绝不上传服务器；连接时先尝试 UDP 打洞建立直连，打洞失败（超时 / 返回错误次数超限）后自动降级为中继。

> 安全模型（身份认证 / 密钥轮换 / 吊销）的设计见《身份认证与密钥管理体系设计》，相应 CLI 命令随实施阶段落地。

所有配置集中保存在 `./client.json`（JSON 格式），命令行操作会直接改写该文件，本机所有参数都可在其中调整。

## --genkey
### 说明
    生成本机密钥对（X25519），写入 client.json。
    每台设备只允许一套密钥：如果本机已存在密钥对，则报错。
    私钥只保存在本机，绝不发送给服务器。
### 示例
    linkmesh-client --genkey

## --showpubkey
### 说明
    显示本机公钥，供对方/服务器识别。
### 示例
    linkmesh-client --showpubkey

## --newvmnic "vmnic's name" [--ip x.x.x.x]
### 说明
    新建虚拟网卡（Linux 内核 TUN / Windows 内置 Wintun）。
    mesh 模式下虚拟 IP 一律以服务端证书绑定为准（JOIN/AUTH 下发），本机 --ip 仅作占位，
    认证握手后自动覆盖为证书绑定 IP。不指定 --ip 时占位留空。网卡已存在则报错。
    （历史 `--mode static|dhcp` 选项已移除，统一按证书绑定 IP 处理。）
### 示例
    一：linkmesh-client --newvmnic "linkmesh0"
    二：linkmesh-client --newvmnic "linkmesh0" --ip 10.13.13.1

## --delvmnic "vmnic's name"
### 说明
    删除指定的虚拟网卡。删除前会自动断开该网卡上的所有连接。
### 示例
    linkmesh-client --delvmnic "linkmesh0"

## --newserver IP(:Port) "server's name"
### 说明
    新增或修改服务器配置，写入 client.json。
    如果 server's name 为空，则表示删除该地址对应的服务器。
### 示例
    一：linkmesh-client --newserver 1.2.3.4 "my-server"
    二：linkmesh-client --newserver 1.2.3.4:1234 "my-server"
    三：linkmesh-client --newserver 1.2.3.4 ""

## --connect "server's name" "vmnic" [--token 房间令牌] [-d]
### 说明
    连接服务器并建立隧道。
    默认占用终端并实时输出日志到控制台（方便调试）；加 `-d` 则后台运行，不占用终端，日志仅写入文件。
    先尝试 UDP 打洞与对端直连；打洞失败（超时/错误次数超限）自动降级为中继；
    `hole_punch.enabled=false` 时直接全程走中继（不再尝试直连）。
    中继默认使用服务器本身，可在 client.json 的 relay 段修改。
    首次连接（该服务器公钥尚未保存）时向服务器索取 root 签名的 ServerInfo，校验本机已
    `--join` 加入该网格并持有设备证书；服务器公钥写入 client.json，之后每次连接都会校验
    服务器出示的公钥与已保存的公钥一致，不一致则拒绝连接（防中间人 / 服务器更换密钥）。
    -y：默认信任网格根指纹（适合 CI/CD 脚本）；-n：默认拒绝；不加则交互式确认，无输入时默认拒绝。
    是否「已连接」以守护进程运行状态判定（而非配置残留的 connections[]），
    --stop 后可直接重新 --connect。
    --token <令牌>：服务器启用了房间令牌验证时必填（写入 servers[].token 持久化）；
    未配置令牌且服务器要求令牌时，连接会在启动前被明确拒绝（不会空转重连）。
    连接断开后的自动重连由 client.json 的 `reconnect_secs` 控制（0 = 不自动重连，
    默认 5 秒重试一次；与 Android 版「断线自动重连」对齐）。
### 示例
    一：linkmesh-client --connect "my-server" "linkmesh0"
    二：linkmesh-client --connect "my-server" "linkmesh0" -y   # CI 中自动信任首次公钥
    三：linkmesh-client --connect "my-server" "linkmesh0" --token my-room-token
    四：linkmesh-client --connect "my-server" "linkmesh0" -n   # CI 中拒绝信任并退出
    五：linkmesh-client --connect "my-server" "linkmesh0" -d   # 后台运行，不占用终端

## --join "server's name" "vmnic" --code LMJ-... [--token 房间令牌] [-y|-n]
### 说明
    加入服务器网格（TOFU 网格根指纹 → 换取设备证书 → 分配虚拟 IP）。
    服务器启用了房间令牌验证时，--token 必须与服务器 rooms 中的某个令牌一致，否则拒绝加入。
    若本机 client.json 的 aliases 中存在「名称 → 本机虚拟 IP」的条目，
    该名称会作为设备别名随 JOIN 自报给服务器，同房间设备即可按名访问本机。
### 示例
    linkmesh-client --join "my-server" "linkmesh0" --code LMJ-XXXX-XXXX --token my-room-token

## --alias "名称" "虚拟IP"
### 说明
    新增/更新本地别名（如 computer -> 10.13.13.5），写入 client.json 的 aliases。
    本地别名有两个作用：
    1）本机覆盖：解析该名称时优先返回此 IP（无需查询服务器）；
    2）自报身份：若 IP 与本机虚拟 IP 一致，该名称会在注册/心跳时自报给服务器，
       同房间设备即可用 `computer:8080` 这类地址直接访问本机。
    别名规则：小写字母、数字、`-`、`_`，最长 32 字符（大写自动转小写）。
    运行中的守护进程会在下一个心跳周期（heartbeat_sec）自动重载别名，无需断开重连。
### 示例
    linkmesh-client --alias computer 10.13.13.5

## --alias-del "名称"
### 说明
    删除本地别名。
### 示例
    linkmesh-client --alias-del computer

## --alias-list
### 说明
    查看本地别名表。完整解析结果（含服务端别名表与设备自报别名）用 --resolve 查看。
### 示例
    linkmesh-client --alias-list

## --resolve "名称"
### 说明
    经后台守护进程解析别名到虚拟 IP（按名向服务器查询，仅限同房间）。
    内嵌 DNS 应答器（默认 udp 127.0.0.1:5353）也基于同一解析逻辑，
    把系统 DNS 指向它即可让任意应用直接使用 `computer:8080`。
### 示例
    一：linkmesh-client --resolve computer
    二：echo "nameserver 127.0.0.1" 后 curl http://computer:8080/   # 需配置系统 DNS 指向本机 5353 端口

## --disconnect "server's name"
### 说明
    断开与指定服务器的连接，并从配置中移除该连接。
### 示例
    linkmesh-client --disconnect "my-server"

## --stop
### 说明
    停止客户端后台守护进程，并清理配置中的 connections[]（停止即断开全部连接）。
    守护进程未运行时也会清理残留的 connections[]（修复旧版残留条目阻塞 --connect 的问题）。
### 示例
    linkmesh-client --stop

## --list
### 说明
    列出当前配置的服务器、虚拟网卡与连接。
### 示例
    linkmesh-client --list

## --status ["server's name"]
### 说明
    查看运行中连接的状态（对端、Endpoint、传输方式：直连/中继、收发字节）。
    指定服务器名称则只看该连接，否则显示全部。
### 示例
    一：linkmesh-client --status
    二：linkmesh-client --status "my-server"

## --log [行数]
### 说明
    查看客户端运行日志。默认显示最近 50 行，可指定行数。
    支持 --follow 参数实时追踪日志输出。
### 示例
    一：linkmesh-client --log 100
    二：linkmesh-client --log --follow

## --version
### 说明
    显示当前客户端版本号。
### 示例
    linkmesh-client --version

## --help [命令名]
### 说明
    显示帮助信息。如果指定了具体命令名，则只显示该命令的详细用法；否则显示所有可用命令摘要。
### 示例
    一：linkmesh-client --help
    二：linkmesh-client --help connect

> 所有命令均支持 `--quiet` 参数以抑制非错误输出，`--config <路径>` 可指定配置文件位置（默认 ./client.json）。

## 配置文件 client.json

本机所有配置集中于此文件，可直接手工编辑（JSON 格式），也可用上面的命令修改。常用字段：

| 字段 | 说明 |
| :--- | :--- |
| `identity` | 设备身份（`--genkey` 生成）：X25519 `ik_x` + Ed25519 `ik_s`（私钥绝不发送给服务器）。历史 `keypair` 字段已移除 |
| `vm_nics[]` | 虚拟网卡列表：`name` / `ip`（证书绑定 IP 的占位，认证后自动覆盖）/ `netmask` / `mtu` |
| `servers[]` | 服务器列表：`name` / `endpoint` / `public_key`（首次连接经 `--connect` 确认信任后保存，之后每次连接校验一致）/ `relay` / `token`（房间令牌，服务器启用令牌验证时必填）；mesh 认证后含 `mesh_root_pub` / `device_cert` / `crl_version` |
| `servers[].relay` | 中继配置：`enabled` 是否启用中继，`endpoint` 为空表示用服务器自身 |
| `connections[]` | 当前连接：`server` + `vm_nic`（`--stop` 时清空） |
| `hole_punch` | UDP 打洞参数：`enabled`（false 则直接走中继）、`timeout_ms`、`max_retries`、`interval_ms`、`max_errors` |
| `heartbeat_sec` | 注册心跳间隔（秒） |
| `rekey_every_pkts` / `rekey_every_secs` | 数据面路由密钥按包数 / 按秒自动轮换（PFS，0 表示禁用对应维度） |
| `reconnect_secs` | 自动重连间隔（秒）：连接异常退出后按该间隔自动重连；`0` = 不自动重连（默认 5） |
| `aliases` | 本地别名表（对象：`{"computer": "10.13.13.5"}`）；IP 与本机虚拟 IP 一致时自动自报给服务器 |
| `dns` | 内嵌 DNS 应答器：`enabled`（默认 true）、`bind`（默认 127.0.0.1）、`port`（默认 5353）；只解析网格内已知别名，不向上游转发 |
| `control_port` | 本机控制通道端口（供 --status 等命令使用） |
| `control_token` | 控制通道鉴权令牌（`--genkey` 自动生成，防本地任意进程控制） |
| `log_file` / `pid_file` | 日志与 PID 文件位置 |

数据面：Linux 使用内核 TUN；Windows 使用内置的 Wintun 驱动（wintun.dll 已内嵌在可执行文件中，运行时自动释放到可执行文件同目录）。
