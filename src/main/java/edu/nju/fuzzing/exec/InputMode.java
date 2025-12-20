package edu.nju.fuzzing.exec;

public enum InputMode {
    FILE,   // 通过 "@@" 把输入文件路径传给目标
    STDIN   // 无 "@@" 时，将输入写入子进程 stdin
}

