import pandas as pd
import matplotlib.pyplot as plt


def main():
    # ==============================
    # 1. 读取 CSV（单种子版本）
    # ==============================
    csv_path = "./stats.csv"
    df = pd.read_csv(csv_path)

    # 基本检查
    required_columns = [
        "timestamp",
        "target_name",
        "covered_edges",
        "execs_per_sec"
    ]
    for col in required_columns:
        if col not in df.columns:
            raise ValueError(f"Missing required column: {col}")

    # ==============================
    # 颜色设置（可自行修改）
    # ==============================
    LINE_COLOR = "tab:blue"
    """
    可选颜色（matplotlib 默认 tab10 调色板）：
    tab:blue
    tab:orange
    tab:green
    tab:red
    tab:purple
    tab:brown
    tab:pink
    tab:gray
    tab:olive
    tab:cyan
    """

    # ==============================
    # 2. 覆盖率随时间变化曲线（单种子）
    # ==============================
    # 由于已保证每次只读一个种子，直接取即可
    target = df["target_name"].iloc[0]
    group = df.sort_values("timestamp")

    plt.figure(figsize=(12, 6))  # 保留你的宽高比例 8:6

    plt.plot(
        group["timestamp"] / 3600,  # X轴单位小时
        group["covered_edges"],
        label=target,
        color=LINE_COLOR
    )

    plt.xlabel("Time (hours)")
    plt.ylabel("Covered Edges")
    plt.title(f"Coverage Growth: {target}")
    plt.xticks(range(0, 25, 6))

    # 网格
    plt.grid(True, which='both', linestyle='--', alpha=0.5)

    # 顶部留白 10%
    plt.margins(y=0.1)

    # 图例
    plt.legend()

    # 自动调整边距
    plt.tight_layout()

    # 保存文件
    filename = f"coverage_{target}.png"
    plt.savefig(filename, dpi=300)
    plt.close()

    # ==============================
    # 3. 执行速度随时间变化（20 分钟平均，单种子）
    # ==============================
    df["timestamp"] = pd.to_numeric(df["timestamp"])
    df["time"] = pd.to_timedelta(df["timestamp"], unit="s")
    df = df.set_index("time")

    # 每 20 分钟取平均
    resampled = df["execs_per_sec"].resample("20min").mean()

    plt.figure(figsize=(10, 6))

    plt.plot(
        resampled.index.total_seconds() / 60,
        resampled.values,
        label=target,
        color=LINE_COLOR
    )

    plt.xlabel("Time (minutes)")
    plt.ylabel("Executions per Second")
    plt.title("Execution Speed (20-Minute Average)")
    plt.legend()
    plt.grid(True)
    plt.margins(y=0.1)
    plt.tight_layout()
    plt.savefig("execs_per_sec_20min_avg.png", dpi=300)
    plt.close()

    # ==============================
    # 4. 最终覆盖率展示（单种子）
    # ==============================
    final_coverage = df["covered_edges"].iloc[-1]

    plt.figure(figsize=(6, 5))
    plt.bar([target], [final_coverage], color=LINE_COLOR)

    plt.xlabel("Fuzz Target")
    plt.ylabel("Final Covered Edges")
    plt.title("Final Coverage Result")

    plt.grid(axis="y", linestyle="--", alpha=0.6)
    plt.text(0, final_coverage, str(final_coverage), ha="center", va="bottom", fontsize=9)

    plt.margins(y=0.1)
    plt.tight_layout()
    plt.savefig("final_coverage.png", dpi=300)
    plt.close()


if __name__ == "__main__":
    main()
