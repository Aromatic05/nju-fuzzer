import os
import pandas as pd
import matplotlib.pyplot as plt


def main():
    # ==============================
    # 0. 用户配置区（你只改这里）
    # ==============================
    ROOT_DIR = "."
    TARGET_NAME = "xmllint"   # ← 指定这次纵向比较的样例

    CONFIGS = [
        "G-100ms",
        "G-2000ms",
        "nonG-100ms",
        "nonG-2000ms"
    ]

    colors = plt.rcParams["axes.prop_cycle"].by_key()["color"]

    data = {}

    # ==============================
    # 1. 读取四种参数组合的数据
    # ==============================
    for cfg in CONFIGS:
        csv_path = os.path.join(ROOT_DIR, cfg, TARGET_NAME, "stats.csv")
        if not os.path.isfile(csv_path):
            raise FileNotFoundError(f"Missing: {csv_path}")

        df = pd.read_csv(
            csv_path,
            usecols=["timestamp", "covered_edges"],
            dtype={"timestamp": "int64", "covered_edges": "int32"}
        )

        df = df.sort_values("timestamp")
        data[cfg] = df

    # ==============================
    # 2. 覆盖率随时间变化（纵向对比）
    # ==============================
    plt.figure(figsize=(12, 6))

    for i, cfg in enumerate(CONFIGS):
        df = data[cfg]
        plt.plot(
            df["timestamp"] / 3600,
            df["covered_edges"],
            label=cfg,
            color=colors[i]
        )

    plt.xlabel("Time (hours)")
    plt.ylabel("Covered Edges")
    plt.title(f"Coverage Growth Comparison ({TARGET_NAME})")
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.margins(y=0.1)
    plt.legend()
    plt.tight_layout()

    plt.savefig(
        f"coverage_vertical_{TARGET_NAME}.png",
        dpi=300
    )
    plt.close()

    # ==============================
    # 3. 最终覆盖率柱状图（纵向对比）
    # ==============================
    final_coverage = [
        data[cfg]["covered_edges"].iloc[-1]
        for cfg in CONFIGS
    ]

    plt.figure(figsize=(8, 6))
    plt.bar(CONFIGS, final_coverage, color=colors[:len(CONFIGS)])

    plt.xlabel("Configuration")
    plt.ylabel("Final Covered Edges")
    plt.title(f"Final Coverage Comparison ({TARGET_NAME})")
    plt.grid(axis="y", linestyle="--", alpha=0.6)

    for i, value in enumerate(final_coverage):
        plt.text(i, value, str(value), ha="center", va="bottom", fontsize=9)

    plt.margins(y=0.1)
    plt.tight_layout()

    plt.savefig(
        f"final_coverage_vertical_{TARGET_NAME}.png",
        dpi=300
    )
    plt.close()


if __name__ == "__main__":
    main()
