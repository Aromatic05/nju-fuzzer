# NJU-Fuzzer

NJU-Fuzzer 是一个以 **coverage-guided mutation-based fuzzing** 为核心的 Java 模糊测试工具，用于课程/研究场景的“可运行闭环”实现：选种 → 调度 → 变异 → 执行 → 覆盖反馈 → 晋升入队 → 统计落盘。

**文档入口（必读）**
- 架构总览：[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- 项目总文档（运行方法/参数/模块实现细节）：[docs/PROJECT.md](docs/PROJECT.md)
- 开发日志（里程碑与问题复盘）：[docs/Devlog.md](docs/Devlog.md)

**Docker 镜像与日志（外部链接）**
- https://1drv.ms/f/c/0463a6f942bf48e1/IgDUEFJfUitwRaJ6-g-RWlGDAT9i10H71X17c_tYepxBiUo?e=rAWwjB

---

## 快速开始：docker-compose 一键跑

仓库已提供 [docker-compose.yml](docker-compose.yml) 与 [Dockerfile](Dockerfile)。整体思路是：

1) 通过 `build-image` 构建基础镜像 `nju-fuzzer:latest`（镜像内会包含 `env/out` 与 `env/seeds` 等运行所需产物）。
2) 通过 `fuzzer-<target>` 服务在容器内执行 `one_click.sh <target>`。
3) 将宿主机的 `./workdir/<target>/` 挂载到容器内，持久化每次运行产物。

### 前置依赖

- Docker Engine
- Docker Compose（插件版 `docker compose`）

### 运行示例（以 lua 为例）

前台运行（结束后容器退出，workdir 保留在宿主机）：

```bash
docker compose run --rm fuzzer-lua
```

后台运行（可用 `docker compose logs -f fuzzer-lua` 追日志）：

```bash
docker compose up fuzzer-lua
```

如果你希望只先构建镜像：

```bash
docker compose up --build build-image
```

### 当前内置目标（docker-compose 已配置）

- `fuzzer-cppfilt`（`c++filt`）
- `fuzzer-readelf`
- `fuzzer-nm`
- `fuzzer-objdump`
- `fuzzer-djpeg`
- `fuzzer-readpng`
- `fuzzer-xmllint`
- `fuzzer-lua`
- `fuzzer-mjs`
- `fuzzer-tcpdump`

这些服务统一调用 [one_click.sh](one_click.sh)，脚本内部会按目标程序选择：
- seeds 目录（`env/seeds/<ID>`）
- `SeedType`（如 `LUA/XML/PNG/...`）
- 目标命令模板（STDIN 或 FILE：是否包含 `@@`）
- 覆盖模式默认 `shmex`

---

## workdir/：数据目录里具体是什么

`workdir/` 是 **fuzz 运行产物的落盘目录**，用于复现、triage、统计分析与可视化。docker-compose 会将其挂载到宿主机，确保容器退出后数据仍保留。

### 顶层结构

- `workdir/<target>/`：按目标程序分组
- `workdir/<target>/<run-id>/`：每次运行一个独立目录（`run-id` 通常形如 `YYYYMMDD-HHMMSS-<pid>`）

例如：`workdir/c++filt/20260102-163549-1/`。

### 单次 run 目录结构与含义

- `queue/`
  - **晋升为 interesting 的输入样本**（语料库）。
  - 常见文件名形如：`id_000123_cov_<k>_<hash>`，同时会生成同名的 `*.meta` 元数据文件。
  - `*.meta` 为属性文件格式，记录该 seed 的关键调度/覆盖信息，例如：`seed_type`、`favored`、`depth`、`exec_time`、`rarity_score`、`stability`、`birth_type` 等。

- `crashes/`
  - **崩溃样本**（如果本次 run 捕获到 crash，会落盘到这里）。

- `hangs/`
  - **超时样本**（单次执行超过 `--timeout` 的输入）。

- `stats/`
  - `stats.csv`：高频统计（多行，包含 exec_count、covered_edges、queue_size、crash/hang 计数等）。
  - `curve.csv`：按时间分桶（默认 1 秒）生成的增长曲线（如 new_edges/new_paths/new_execs 等），便于画图对比不同策略。

- `tmp/`
  - 运行期临时产物与可复现信息（会做降噪/限量，避免长跑 I/O 爆炸）。
  - `tmp/exec-logs/`：stdout/stderr 捕获结果。
    - 默认策略是“interesting 才抓”：只有当输入晋升入队时，才 best-effort 二次执行抓 stdout/stderr，并且通常只保存非空输出。

> 说明：FILE 模式下引擎会把当前输入写到固定路径 `.cur_input` 再替换 `@@`；默认会优先使用 `/dev/shm`（tmpfs），因此你可能不会在 `workdir/tmp/` 里看到 `.cur_input`。

---

## 进一步阅读

- 如果你想了解完整参数、STDIN/FILE 输入模式、覆盖模式 `none|shm|shmex`、以及 workdir 更详细的复现指南：
  - [docs/PROJECT.md](docs/PROJECT.md)
- 如果你想从整体模块划分与闭环流程理解代码结构：
  - [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- 如果你想追溯关键问题与里程碑（例如 SHM attach、IO 爆炸优化、Mutator 迭代）：
  - [docs/Devlog.md](docs/Devlog.md)
