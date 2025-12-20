## 框架状态说明

### 已实现（可运行）

* **CLI**：支持 `--workdir --duration --timeout --tid --cmd`，并将 `--cmd` 解析为 argv 模板（支持引号），构造 `TargetSpec`。
* **目标适配层**：`TargetSpec / TargetCommand / CommandResolver`

    * 自动推断输入模式：有 `@@` → FILE；无 `@@` → STDIN
    * 支持多处 `@@` 替换。
* **执行组件（Executor）**：`ProcessExecutor`

    * 子进程执行、环境变量注入、超时终止、stdout/stderr 重定向落盘，返回 `RunResult`。
* **引擎骨架（Engine）**：`FuzzingEngine`

    * 生成 testcase 文件（workdir/tmp/inputs）
    * 每个 testcase 单独输出日志目录（workdir/tmp/exec-logs/tc_xxx/）
    * 统计写入 `workdir/stats/stats.csv`。
* **测试**：已包含单元测试与 CLI smoke test（覆盖 FILE/STDIN/timeout/基本落盘）。

### 当前限制（刻意留空）

* 未接入 **afl-cc 插装构建**（建议用脚本完成）
* 未实现 **覆盖率监控（SHM bitmap）**
* 未实现 **变异算子、种子队列、种子排序、能量调度**
* 评估仅有 stats.csv，尚未生成覆盖率曲线图

---

## 下一步要做什么（按优先级）

### 1) 插装构建链路（非 Java，脚本优先）

* 在仓库添加 `scripts/build_Txx.sh`（至少先跑通 1 个 target）
* 用 `afl-cc` 编译出插装后的可执行文件，并记录输出路径
* 用现有 CLI 的 `--cmd "<binary> @@ ..."` 真跑目标（不要求覆盖率）

**交付物**：可复现的 build 脚本 + 1 个 target 冒烟成功。

### 2) 种子队列（Queue）+ 从 seedDir 读取

* CLI 增加：`--seedDir`
* Engine 改为：从 seedDir 加载初始 seeds → queue 管理 → 选择 seed

**交付物**：不依赖覆盖率也能轮转种子、保存执行产物。

### 3) 最小变异组件（Mutator）

* 先实现简化版 havoc（随机翻转/插入/删除少量字节）
* 结合 energy（先常数）生成多个 testcase

**交付物**：输入不再固定，能大量产生不同 testcase。

### 4) 覆盖率监控（Monitor，核心难点）

* 接入 AFL++ SHM bitmap：beforeRun 清零、afterRun 读取、判定 new coverage
* new coverage → 保存到 queue 并入队

**交付物**：queue 随覆盖率增长，开始成为真正的 coverage-guided fuzzer。

### 5) 种子排序 + 能量调度（启发式）

* 实现至少一种非随机排序策略
* 实现启发式能量分配（参考 AFL++ calculate_score）

**交付物**：提升覆盖率增长速度与执行效率。

---