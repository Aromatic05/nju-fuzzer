import os

# ==============================
# 0. 重定向 matplotlib 缓存目录（避免污染 C 盘）
# ==============================
os.environ["MPLCONFIGDIR"] = "./.matplotlib_cache"

import pandas as pd
import matplotlib.pyplot as plt


def main():
    # ==============================
    # 0. 基本配置（保持不变）
    # ==============================
    ROOT_DIR = "."  # 当前目录
    TARGETS = [
        "c++filt", "djpeg", "lua", "mjs", "nm",
        "objdump", "readelf", "readpng", "tcpdump", "xmllint"
    ]

    # matplotlib 默认 tab10 颜色循环（正好 10 个）
    colors = plt.rcParams["axes.prop_cycle"].by_key()["color"]

    all_data = []

    # ==============================
    # 1. 读取所有 stats.csv（优化：usecols + dtype）
    # ==============================
    for target in TARGETS:
        csv_path = os.path.join(ROOT_DIR, target, "stats.csv")
        if not os.path.isfile(csv_path):
            raise FileNotFoundError(f"Missing stats.csv in {target}")

        df = pd.read_csv(
            csv_path,
            usecols=["timestamp", "covered_edges"],   # 只读必要列
            dtype={
                "timestamp": "int64",
                "covered_edges": "int32"
            }
        )

        # 用文件夹名作为 target
        df["target_name"] = target
        all_data.append(df)

    # 合并为一个 DataFrame
    df_all = pd.concat(all_data, ignore_index=True)

    # ==============================
    # 2. 覆盖率随时间变化（10 条曲线）
    # ==============================
    plt.figure(figsize=(12, 6))  # X:Y = 12:6（保持不变）

    for i, target in enumerate(TARGETS):
        group = df_all[df_all["target_name"] == target]

        plt.plot(
            group["timestamp"] / 3600,   # 小时
            group["covered_edges"],
            label=target,
            color=colors[i]
        )

    plt.xlabel("Time (hours)")
    plt.ylabel("Covered Edges")
    plt.title("Coverage Growth Over Time (All Targets)")
    plt.xticks(range(0, 25, 6))
    plt.xlim(left=0)
    plt.ylim(bottom=0)
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.margins(y=0.1)
    plt.legend(ncol=2)
    plt.tight_layout()
    plt.savefig("coverage_all_targets.png", dpi=300)
    plt.close()   # 显式释放资源，避免缓存累积

    # ==============================
    # 3. 最终覆盖率柱状图
    # ==============================
    final_coverage = (
        df_all.groupby("target_name")["covered_edges"]
        .last()
        .loc[TARGETS]  # 保持顺序一致
    )

    plt.figure(figsize=(12, 6))

    plt.bar(
        final_coverage.index,
        final_coverage.values,
        color=colors
    )

    plt.xlabel("Fuzz Target")
    plt.ylabel("Final Covered Edges")
    plt.title("Final Coverage Comparison")
    plt.grid(axis="y", linestyle="--", alpha=0.6)

    for i, value in enumerate(final_coverage.values):
        plt.text(i, value, str(value), ha="center", va="bottom", fontsize=9)

    plt.margins(y=0.1)
    plt.tight_layout()
    plt.savefig("final_coverage_comparison.png", dpi=300)
    plt.close()   # 显式释放资源


if __name__ == "__main__":
    main()
