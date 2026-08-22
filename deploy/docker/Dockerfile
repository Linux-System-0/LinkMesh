# syntax=docker/dockerfile:1
#
# LinkMesh 服务端镜像 —— 多阶段构建
#
# 采用 musl 静态编译（static-pie），产物不依赖目标机 glibc 版本，
# 可在任意 x86_64 Linux（glibc / musl）上直接运行。
# 详见 AGENTS.md「构建要求」。

# ---------- 可覆盖参数 ----------
# Rust 官方镜像标签（默认稳定版 slim-bookworm）
ARG RUST_IMAGE=rust:1-slim-bookworm
# rustup 组件下载镜像（国内网络可保持默认 rsproxy.cn）
ARG RUSTUP_DIST_SERVER=https://rsproxy.cn
# 运行时基础镜像
ARG RUNTIME_IMAGE=alpine:3.20

# ---------- Stage 1: 编译 ----------
FROM ${RUST_IMAGE} AS builder

ARG RUSTUP_DIST_SERVER
ENV RUSTUP_DIST_SERVER=${RUSTUP_DIST_SERVER} \
    RUSTUP_UPDATE_ROOT=${RUSTUP_DIST_SERVER} \
    RUSTUP_DOWNLOADS_TIMEOUT=300

# musl-tools 提供 musl-gcc；随后安装 x86_64-musl 目标 triple
RUN apt-get update \
    && apt-get install -y --no-install-recommends musl-tools \
    && rustup target add x86_64-unknown-linux-musl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# 先把清单与源码拷入，构建依赖缓存命中更快
COPY . .

# 静态编译 linkmesh-server。
# 注意：target 用了 cache mount（加速增量编译），产物不会落到 stage 文件系统，
# 因此必须在同一个 RUN 里把二进制拷到普通路径 /out，供 COPY --from 使用。
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --target x86_64-unknown-linux-musl -p linkmesh-server \
 && mkdir -p /out \
 && cp /build/target/x86_64-unknown-linux-musl/release/linkmesh-server /out/linkmesh-server

# ---------- Stage 2: 运行时 ----------
FROM ${RUNTIME_IMAGE}

# 基础工具与可信证书
RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder \
    /out/linkmesh-server \
    /usr/local/bin/linkmesh-server
# 构建上下文是仓库根目录，路径相对于 context 根
COPY deploy/docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# 数据目录：server.json / 日志 / 网格文件都放这里，用卷持久化
WORKDIR /data

ENV PORT=8080

# 信令 + 中继共用 UDP 端口（若配置了独立中继端口 relay.port，请额外映射）
EXPOSE 8080/udp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD linkmesh-server --config /data/server.json --status

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
