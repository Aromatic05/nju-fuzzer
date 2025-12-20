package edu.nju.fuzzing.model;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * TargetSpec 描述一个 fuzz target 的运行方式（与 AFL-CMD 对齐）。
 * - argvTemplate: 命令行参数模板，可能包含 "@@" 占位符（可出现多次）
 * - binary: 目标可执行文件路径（也可以等价地放在 argvTemplate[0]）
 * - env: 运行时环境变量（后续放 SHM、AFL_MAP_SIZE 等）
 * - timeout: 单次执行超时时间
 */
public record TargetSpec(
        String tid,
        Path binary,
        List<String> argvTemplate,
        Map<String, String> env,
        Duration timeout
) {
    public TargetSpec {
        if (tid == null || tid.isBlank()) throw new IllegalArgumentException("tid is blank");
        if (binary == null) throw new IllegalArgumentException("binary is null");
        if (argvTemplate == null || argvTemplate.isEmpty())
            throw new IllegalArgumentException("argvTemplate is empty");
        if (env == null) env = Map.of();
        if (timeout == null) timeout = Duration.ofSeconds(1);
    }
}
