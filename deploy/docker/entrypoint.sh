#!/bin/sh
# LinkMesh 服务端容器入口
#
# 设计要点：
#   1. 容器里用 `--run` 前台模式（PID 1）运行，而不是 `--start`（后者会 setsid 后台化，
#      会导致容器 PID 1 立即退出）。配置由 /data 卷持久化。
#   2. 首次启动自动 `--genkey` 生成密钥对，公钥会打印到 docker logs，方便带外分发。
#   3. 把日志写到 /dev/stdout，让 docker logs / 日志采集直接可见。

set -eu

CONFIG="${CONFIG:-/data/server.json}"
PORT="${PORT:-8080}"

# 保证数据目录存在（卷首次挂载时）
mkdir -p "$(dirname "$CONFIG")"
cd "$(dirname "$CONFIG")"

# ---- 首次启动：生成默认配置 + 服务端密钥对 ----
if [ ! -f "$CONFIG" ]; then
    echo "[entrypoint] 未找到 $CONFIG，首次初始化并生成密钥对..."
    linkmesh-server --config "$CONFIG" --genkey
    # 上面已生成默认 server.json，公钥打印在上一行输出
fi

# ---- 让日志走 stdout，便于 docker logs ----
# 仅当 log_file 仍是默认值 server.log 时改写，尊重用户自定义配置
if grep -q '"log_file": "server.log"' "$CONFIG"; then
    sed -i 's|"log_file": "server.log"|"log_file": "/dev/stdout"|' "$CONFIG"
fi

# ---- 用环境变量覆盖监听端口（仅当用户未显式配置 listen 时）----
if grep -q '"listen": "0.0.0.0:8080"' "$CONFIG"; then
    sed -i "s/\"listen\": \"0.0.0.0:8080\"/\"listen\": \"0.0.0.0:${PORT}\"/" "$CONFIG"
fi

echo "[entrypoint] 启动 linkmesh-server，监听 UDP 端口 ${PORT}"
echo "[entrypoint] 公钥：$(linkmesh-server --config "$CONFIG" --showpubkey 2>/dev/null || echo '(见首次启动日志)')"

# exec 以 PID 1 前台运行，接收 docker stop 的信号
exec linkmesh-server --config "$CONFIG" --run
