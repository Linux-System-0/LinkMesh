# LinkMesh 服务端 · Docker 一键部署

把中心化信令 + 中继服务 `linkmesh-server` 打包成容器，一条命令拉起。
镜像用 **musl 静态编译**（static-pie），不依赖宿主 glibc 版本，可在任意 x86_64 Linux 上运行。

## 目录

```
deploy/docker/
├── Dockerfile            # 多阶段构建（musl 静态编译，两阶段）
├── entrypoint.sh         # 容器入口（首次自动 genkey、日志走 stdout、前台运行）
├── docker-compose.yml    # 一键部署编排
└── README.md
```

## 一键启动

```bash
cd deploy/docker
docker compose up -d --build
```

首次启动会自动完成：

1. 生成默认 `server.json`；
2. `linkmesh-server --genkey` 生成服务端密钥对 + 控制通道令牌；
3. 以 `--run` 前台模式启动，监听 UDP 端口 `8080`。

查看启动日志与**服务端公钥**（分发给客户端用）：

```bash
docker compose logs linkmesh-server
# 或
docker compose exec linkmesh-server linkmesh-server --showpubkey
```

## 常用运维命令

容器内以 `linkmesh-server` 作为入口（工作目录 `/data`，配置即 `server.json`），
所有 CLI 命令都可用：

```bash
# 运行状态
docker compose exec linkmesh-server linkmesh-server --status

# 在线路由表
docker compose exec linkmesh-server linkmesh-server --list

# 授权设备接入并绑定虚拟 IP（auth_required 默认开启，授权后才能接入）
docker compose exec linkmesh-server \
  linkmesh-server --authorize "<设备公钥>" 10.13.13.2 "client-a"

# 房间令牌（分房间隔离）
docker compose exec linkmesh-server linkmesh-server --add-room office "my-office-token"

# 网格（证书模式）
docker compose exec linkmesh-server linkmesh-server --mesh-init
docker compose exec linkmesh-server linkmesh-server --invite --ip 10.13.13.2
```

更多命令见仓库 `docs/linkmesh-server 基础命令.md`。

## 配置与持久化

- 所有运行时状态（`server.json`、日志、`mesh.json` 等）都保存在 **named volume `linkmesh-data`**（挂载到容器 `/data`），重启/升级不丢失。
- 直接编辑配置：可改为 bind mount 后修改宿主机上的 `server.json`，再 `docker compose restart`。
- **`server.json` 含私钥**，务必保管好卷与备份。

### 端口

| 端口 | 协议 | 说明 |
| :--- | :--- | :--- |
| `8080` | UDP | 信令 + 中继（默认共用） |

- 改用别的端口：改 compose 里的 `PORT` 环境变量，同时改 `ports` 映射。
- 独立中继端口：在 `server.json` 里设置 `relay.port` 后，在 compose `ports` 中补一行 `"<port>:<port>/udp"`。

## 镜像自定义

| 构建参数 | 默认 | 说明 |
| :--- | :--- | :--- |
| `RUST_IMAGE` | `rust:1-slim-bookworm` | Rust 编译镜像 |
| `RUSTUP_DIST_SERVER` | `https://rsproxy.cn` | rustup 组件下载镜像（国外网络可改官方源） |
| `RUNTIME_IMAGE` | `alpine:3.20` | 运行时基础镜像 |

## 健康检查

镜像内置 `HEALTHCHECK`：定期执行 `linkmesh-server --status` 探测控制通道。
`docker compose ps` 的 `STATUS` 列会显示 `healthy` / `unhealthy`。

## 常见问题

- **`docker compose logs` 看不到日志？** 入口脚本会把 `log_file` 改写为 `/dev/stdout`，
  服务日志直接进 docker logs；`--status` 等命令的 `info` 输出也走 stdout。
- **提示权限/卷问题？** 若改用 bind mount，需保证宿主机目录对容器可写（可 `chmod 777` 或指定 `--user`）。
- **为何用 `--run` 而不是 `--start`？** `--start` 会 `setsid` 后台化并让父进程退出，
  会让容器 PID 1 立即结束；容器内使用 `--run` 前台运行。
- **客户端也要容器化？** 客户端需要 root + `/dev/net/tun`（`--device /dev/net/tun` + `--cap-add NET_ADMIN`），
  一般直接部署到终端主机更合适；本镜像只打包服务端。

## 安全提示

- 默认 `auth_required=true`（拒绝未授权设备），接入前务必先 `--authorize`。
- 私钥只在 `linkmesh-data` 卷内，勿提交、勿外传。
- 公钥通过 `--showpubkey` 带外分发给客户端。
