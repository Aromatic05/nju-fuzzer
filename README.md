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

下面的命令都在仓库根目录执行（与 [docker-compose.yml](docker-compose.yml) 同级）。

1) 仅构建镜像（不启动 fuzzer）：

```bash
docker compose build build-image
```

2) 单个目标，前台跑（退出即停止，容器自动删除；产物保留在宿主机 workdir）：

```bash
docker compose run --rm fuzzer-lua
```

如果你修改了代码/依赖，想确保先重新 build：

```bash
docker compose run --rm --build fuzzer-lua
```

3) 单个目标，后台跑：

```bash
docker compose up -d fuzzer-lua
docker compose logs -f fuzzer-lua
```

停止并删除该服务容器（不删除 workdir 数据）：

```bash
docker compose stop fuzzer-lua
docker compose rm -f fuzzer-lua
```

4) 多个目标并行跑（会比较吃 CPU/内存）：

```bash
docker compose up -d fuzzer-lua fuzzer-mjs fuzzer-xmllint
docker compose logs -f --tail=200 fuzzer-lua
```

5) 启动全部服务（包含 10 个 fuzzer + 1 个 build-image；build-image 会很快退出）：

```bash
docker compose up -d
docker compose ps
```

停止全部服务（同样不删除 workdir 数据）：

```bash
docker compose down
```

6) 产物位置（以 lua 为例）：

- 宿主机目录：`./workdir/lua/`
- 每次 run 会创建独立子目录：`./workdir/lua/<run-id>/`
- 典型内容：`queue/`、`crashes/`、`hangs/`、`stats/`、`tmp/`

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

## 实验结果与可视化

本仓库包含两类“结果相关内容”：

1) **实验结果产物（图片/报告）**：在 `result/` 下，可直接阅读。
2) **可视化脚本（Python）**：在 `visualization/` 下，用于从 `stats.csv` 生成图表。

### result/ 目录说明

- `result/figures/`：按实验配置分类的最终图表输出（例如 `G-100ms/`、`nonG-2000ms/`、`vertical/` 等）。
- `result/report/report2.md`：实验分析报告（引用并嵌入 `result/report/Images/` 里的图）。
- `result/report/Images/`：报告用的图表集合（通常是把生成的图片整理到这里，便于在报告中引用）。

其中配置目录名含义：

- `G-100ms/`、`G-2000ms/`：开启语法相关处理（G = Grammar），单次执行超时（timeout）分别为 100ms / 2000ms
- `nonG-100ms/`、`nonG-2000ms/`：不启用语法相关处理（nonG = non-Grammar），timeout 分别为 100ms / 2000ms
- `vertical/`：纵向对比（固定同一目标，在一张图里对比不同配置的曲线）

补充说明可见：`docs/Visual/visualization.md`。

### 可视化脚本位置与依赖

脚本位于：`src/main/java/edu/nju/fuzzing/visualization/`

- `visualize.py`：单个目标的单次 run 作图（覆盖曲线、20 分钟均值 exec/s、最终覆盖柱状图）。
- `visualize_totally.py`：同一配置下 10 个目标横向对比（覆盖曲线叠加 + 最终覆盖对比）。
- `vertical.py`：同一目标在不同配置之间纵向对比（覆盖曲线叠加 + 最终覆盖对比）。

依赖（本机 Python 环境安装一次即可）：

```bash
python3 -m pip install -U pandas matplotlib
```

### 1) 单次 run 单目标：visualize.py

输入：一个 `stats.csv`（列至少包含 `timestamp/target_name/covered_edges/execs_per_sec`）。

推荐用法：进入某次 run 的 stats 目录直接运行（例如 lua）：

```bash
cd workdir/lua/<run-id>/stats
python3 ../../../../src/main/java/edu/nju/fuzzing/visualization/visualize.py
```

输出：会在当前目录生成：
- `coverage_<target>.png`
- `execs_per_sec_20min_avg.png`
- `final_coverage.png`

### 2) 同一配置 10 目标横向对比：visualize_totally.py

该脚本默认读取如下目录结构（在你执行脚本的当前目录下）：

```text
./c++filt/stats.csv
./djpeg/stats.csv
./lua/stats.csv
...（共 10 个目标）
```

也就是说，你需要先把每个目标的一次 run 的 `workdir/<target>/<run-id>/stats/stats.csv` 拷贝/汇总为 `./<target>/stats.csv`。

在“汇总目录”中运行：

```bash
python3 /abs/path/to/nju-fuzzer/src/main/java/edu/nju/fuzzing/visualization/visualize_totally.py
```

输出：
- `coverage_all_targets.png`
- `final_coverage_comparison.png`

### 3) 同一目标跨配置纵向对比：vertical.py

该脚本默认读取如下目录结构（在你执行脚本的当前目录下）：

```text
./G-100ms/<target>/stats.csv
./G-2000ms/<target>/stats.csv
./nonG-100ms/<target>/stats.csv
./nonG-2000ms/<target>/stats.csv
```

然后编辑脚本里的 `TARGET_NAME`（默认为 `xmllint`）并运行：

```bash
python3 /abs/path/to/nju-fuzzer/visualization/vertical.py
```

输出：
- `coverage_vertical_<target>.png`
- `final_coverage_vertical_<target>.png`

---

## 进一步阅读

- 如果你想了解完整参数、STDIN/FILE 输入模式、覆盖模式 `none|shm|shmex`、以及 workdir 更详细的复现指南：
  - [docs/PROJECT.md](docs/PROJECT.md)
- 如果你想从整体模块划分与闭环流程理解代码结构：
  - [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- 如果你想追溯关键问题与里程碑（例如 SHM attach、IO 爆炸优化、Mutator 迭代）：
  - [docs/Devlog.md](docs/Devlog.md)
