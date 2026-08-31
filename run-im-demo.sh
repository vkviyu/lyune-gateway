#!/usr/bin/env bash

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REACTOR_ROOT="$(cd "${SCRIPT_DIR}/../lyune-reactor" 2>/dev/null && pwd || true)"
readonly REACTOR_APP="${REACTOR_ROOT}/reactor"
readonly AGENT_APP="${SCRIPT_DIR}/validation/client-agent"
readonly WEB_APP="${SCRIPT_DIR}/validation/web-client"
readonly RUN_DIR="/private/tmp/lyune-im-demo"
readonly DATABASE_PATH="/private/tmp/lyune-im-demo.sqlite"
readonly WEB_URL="http://127.0.0.1:5173"
readonly GENERATED_GATEWAY_CONFIG="${RUN_DIR}/gateway-config.json"

RESET_DATABASE=false
OPEN_BROWSER=true
CLEANING_UP=false
WORKER_COUNT=1

REACTOR_PID=""
GATEWAY_PID=""
AGENT_PID=""
WEB_PID=""

usage() {
    cat <<'EOF'
用法：./run-im-demo.sh [选项]

一键构建并启动 Lyune 真实 IM 本地体验环境：
  Browser WSS :8444 / Raw QUIC via agent :8787 -> Gateway -> Reactor :9443 -> SQLite

选项：
  --reset      启动前清空 /private/tmp/lyune-im-demo.sqlite 及其 WAL 文件
  --no-open    启动后不自动打开浏览器
  --workers N  使用 N 个 Gateway Worker；默认 1，Mac 多 Worker 验证使用 2
  -h, --help   显示帮助

所有服务日志写入 /private/tmp/lyune-im-demo/。按 Ctrl+C 有序停止全部服务。
EOF
}

log() {
    printf '[lyune-im] %s\n' "$*"
}

fail() {
    printf '[lyune-im] 错误：%s\n' "$*" >&2
    exit 1
}

while (($# > 0)); do
    case "$1" in
        --reset)
            RESET_DATABASE=true
            ;;
        --no-open)
            OPEN_BROWSER=false
            ;;
        --workers)
            (($# >= 2)) || fail "--workers 缺少数量"
            WORKER_COUNT="$2"
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            fail "未知参数：$1"
            ;;
    esac
    shift
done

[[ "${WORKER_COUNT}" =~ ^[1-9][0-9]*$ ]] || fail "Worker 数量必须是 1–256 的整数"
((WORKER_COUNT <= 256)) || fail "Worker 数量必须是 1–256 的整数"

[[ -n "${REACTOR_ROOT}" && -d "${REACTOR_APP}" ]] ||
    fail "未找到相邻项目 ../lyune-reactor/reactor"
[[ -f "${SCRIPT_DIR}/config/validation-im-macos.json" ]] ||
    fail "缺少 config/validation-im-macos.json"
[[ -f "${SCRIPT_DIR}/server.crt" && -f "${SCRIPT_DIR}/server.key" ]] ||
    fail "缺少本地开发证书 server.crt/server.key"

# 非交互 shell 未必加载 GVM。若本机安装了预期版本，在隔离的子 shell 中读取
# GOROOT，避免 GVM 覆盖 cd 等内建命令并污染这个严格模式的启动脚本。
# 如果目标版本不存在，则继续使用 PATH 中的 Go，由 go build 给出准确错误。
if [[ -f "${HOME}/.gvm/scripts/gvm" ]]; then
    gvm_go_root="$(
        (
            set +e
            set +u
            # shellcheck disable=SC1091
            source "${HOME}/.gvm/scripts/gvm" >/dev/null 2>&1
            gvm use go1.27.0 >/dev/null 2>&1 || exit 0
            go env GOROOT
        ) 2>/dev/null
    )"
    if [[ -n "${gvm_go_root}" && -x "${gvm_go_root}/bin/go" ]]; then
        export GOROOT="${gvm_go_root}"
        export PATH="${gvm_go_root}/bin:${PATH}"
    fi
fi

for required_command in zig go node npm curl lsof; do
    command -v "${required_command}" >/dev/null 2>&1 ||
        fail "找不到命令 ${required_command}，请先安装后重试"
done

assert_port_free() {
    local protocol="$1"
    local port="$2"
    local -a lsof_args=("-i${protocol}:${port}")
    if [[ "${protocol}" == TCP ]]; then
        # 浏览器会短暂保留 CLOSED 连接的 fd；它不占监听端口，不能阻止重启演示环境。
        lsof_args+=("-sTCP:LISTEN")
    fi

    if lsof -nP "${lsof_args[@]}" 2>/dev/null | grep -q .; then
        lsof -nP "${lsof_args[@]}" >&2 || true
        fail "${protocol} 端口 ${port} 已被占用；请先停止上面的进程"
    fi
}

assert_port_free UDP 9443
assert_port_free UDP 8443
assert_port_free TCP 8444
assert_port_free TCP 8787
assert_port_free TCP 5173

mkdir -p "${RUN_DIR}"
: >"${RUN_DIR}/reactor.log"
: >"${RUN_DIR}/gateway.log"
: >"${RUN_DIR}/agent.log"
: >"${RUN_DIR}/web.log"

# 保留版本库中的单 Worker 验证配置不变；多 Worker 只生成运行期副本，避免为了一个
# 数字维护整份重复 JSON。替换后立即核验，配置格式变化时脚本会明确失败。
sed "s/\"threads\": 1/\"threads\": ${WORKER_COUNT}/" \
    "${SCRIPT_DIR}/config/validation-im-macos.json" >"${GENERATED_GATEWAY_CONFIG}"
grep -Fq "\"threads\": ${WORKER_COUNT}" "${GENERATED_GATEWAY_CONFIG}" ||
    fail "无法在验证配置中设置 Worker 数量"

if [[ "${RESET_DATABASE}" == true ]]; then
    log "清空演示数据库 ${DATABASE_PATH}"
    rm -f \
        "${DATABASE_PATH}" \
        "${DATABASE_PATH}-shm" \
        "${DATABASE_PATH}-wal"
fi

stop_process() {
    local name="$1"
    local pid="$2"
    local max_wait_steps="$3"

    [[ -n "${pid}" ]] || return 0
    kill -0 "${pid}" 2>/dev/null || {
        wait "${pid}" 2>/dev/null || true
        return 0
    }

    log "停止 ${name}（PID ${pid}）"
    kill -INT "${pid}" 2>/dev/null || true
    for ((step = 0; step < max_wait_steps; step++)); do
        if ! kill -0 "${pid}" 2>/dev/null; then
            wait "${pid}" 2>/dev/null || true
            return 0
        fi
        sleep 0.2
    done

    kill -TERM "${pid}" 2>/dev/null || true
    sleep 0.5
    if kill -0 "${pid}" 2>/dev/null; then
        log "${name} 未及时退出，强制终止 PID ${pid}"
        kill -KILL "${pid}" 2>/dev/null || true
    fi
    wait "${pid}" 2>/dev/null || true
}

cleanup() {
    local exit_status=$?
    [[ "${CLEANING_UP}" == false ]] || return
    CLEANING_UP=true
    trap - EXIT INT TERM

    printf '\n'
    log "正在关闭本地 IM 环境……"
    stop_process "Web" "${WEB_PID}" 25
    stop_process "client-agent" "${AGENT_PID}" 25
    # Gateway 最多可能执行 60 秒 drain；先停止客户端后通常会立即结束。
    stop_process "Gateway" "${GATEWAY_PID}" 325
    stop_process "Reactor" "${REACTOR_PID}" 25
    log "全部服务已停止；数据库保留在 ${DATABASE_PATH}"

    exit "${exit_status}"
}
trap cleanup EXIT INT TERM

wait_for_log() {
    local name="$1"
    local pid="$2"
    local log_file="$3"
    local marker="$4"
    local max_wait_steps="${5:-150}"

    for ((step = 0; step < max_wait_steps; step++)); do
        if grep -Fq "${marker}" "${log_file}"; then
            return 0
        fi
        if ! kill -0 "${pid}" 2>/dev/null; then
            printf '\n---- %s ----\n' "${log_file}" >&2
            tail -n 60 "${log_file}" >&2 || true
            fail "${name} 在就绪前退出"
        fi
        sleep 0.2
    done

    printf '\n---- %s ----\n' "${log_file}" >&2
    tail -n 60 "${log_file}" >&2 || true
    fail "等待 ${name} 就绪超时"
}

wait_for_http() {
    local name="$1"
    local pid="$2"
    local url="$3"
    local log_file="$4"

    for ((step = 0; step < 150; step++)); do
        if curl --fail --silent --show-error --max-time 1 "${url}" >/dev/null 2>&1; then
            return 0
        fi
        if ! kill -0 "${pid}" 2>/dev/null; then
            printf '\n---- %s ----\n' "${log_file}" >&2
            tail -n 60 "${log_file}" >&2 || true
            fail "${name} 在就绪前退出"
        fi
        sleep 0.2
    done

    printf '\n---- %s ----\n' "${log_file}" >&2
    tail -n 60 "${log_file}" >&2 || true
    fail "等待 ${name} HTTP 就绪超时"
}

log "构建 Gateway（ReleaseSafe）"
(cd "${SCRIPT_DIR}" && zig build -Doptimize=ReleaseSafe)

log "构建 Reactor"
(cd "${REACTOR_APP}" && go build -o "${RUN_DIR}/lyune-reactor" .)

log "构建 client-agent"
(cd "${AGENT_APP}" && go build -o "${RUN_DIR}/lyune-client-agent" .)

if [[ ! -x "${WEB_APP}/node_modules/.bin/vite" ]]; then
    log "首次运行：安装 Web 依赖"
    npm --prefix "${WEB_APP}" install
fi

log "启动 Reactor :9443"
(
    cd "${REACTOR_APP}"
    exec "${RUN_DIR}/lyune-reactor" \
        --listen 127.0.0.1:9443 \
        --cert "${SCRIPT_DIR}/server.crt" \
        --key "${SCRIPT_DIR}/server.key" \
        --db "${DATABASE_PATH}"
) >"${RUN_DIR}/reactor.log" 2>&1 &
REACTOR_PID=$!
wait_for_log "Reactor" "${REACTOR_PID}" "${RUN_DIR}/reactor.log" "QUIC server listening"

log "启动 Gateway Raw QUIC :8443 + WSS :8444（${WORKER_COUNT} Worker）"
(
    cd "${SCRIPT_DIR}"
    exec "${SCRIPT_DIR}/zig-out/bin/lyune_gateway" server \
        --config "${GENERATED_GATEWAY_CONFIG}"
) >"${RUN_DIR}/gateway.log" 2>&1 &
GATEWAY_PID=$!
wait_for_log "Gateway" "${GATEWAY_PID}" "${RUN_DIR}/gateway.log" "[BACKEND] transport ready"
wait_for_log "Gateway WSS" "${GATEWAY_PID}" "${RUN_DIR}/gateway.log" "[WSS] listener started"

log "启动 client-agent :8787"
(
    cd "${AGENT_APP}"
    exec "${RUN_DIR}/lyune-client-agent" --listen 127.0.0.1:8787
) >"${RUN_DIR}/agent.log" 2>&1 &
AGENT_PID=$!
wait_for_http "client-agent" "${AGENT_PID}" "http://127.0.0.1:8787/api/health" "${RUN_DIR}/agent.log"

log "启动 React Web :5173"
(
    cd "${WEB_APP}"
    exec "${WEB_APP}/node_modules/.bin/vite" --host 127.0.0.1
) >"${RUN_DIR}/web.log" 2>&1 &
WEB_PID=$!
wait_for_http "React Web" "${WEB_PID}" "${WEB_URL}" "${RUN_DIR}/web.log"

printf '\n'
log "Lyune 真实 IM 已就绪：${WEB_URL}"
log "打开两个标签页，默认由浏览器直接连接 WSS；也可切换 Raw QUIC 对照。"
log "首次使用 WSS 前，请让 macOS/浏览器信任本地 server.crt 开发证书。"
log "日志目录：${RUN_DIR}"
log "数据库：${DATABASE_PATH}"
log "按 Ctrl+C 有序停止全部服务。"

if [[ "${OPEN_BROWSER}" == true ]]; then
    if command -v open >/dev/null 2>&1; then
        open "${WEB_URL}" >/dev/null 2>&1 || true
    else
        log "系统没有 open 命令，请手动打开 ${WEB_URL}"
    fi
fi

while true; do
    for process_spec in \
        "Reactor:${REACTOR_PID}:${RUN_DIR}/reactor.log" \
        "Gateway:${GATEWAY_PID}:${RUN_DIR}/gateway.log" \
        "client-agent:${AGENT_PID}:${RUN_DIR}/agent.log" \
        "Web:${WEB_PID}:${RUN_DIR}/web.log"; do
        IFS=: read -r process_name process_pid process_log <<<"${process_spec}"
        if ! kill -0 "${process_pid}" 2>/dev/null; then
            printf '\n---- %s ----\n' "${process_log}" >&2
            tail -n 60 "${process_log}" >&2 || true
            fail "${process_name} 意外退出"
        fi
    done
    sleep 1
done
