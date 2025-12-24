package edu.nju.fuzzing.exec;

import edu.nju.fuzzing.model.RunResult;

import java.util.Objects;
import java.util.Set;

/**
 * Crash classification policy.
 *
 * <p>By default, this project historically treated any non-zero exit code as a crash.
 * Some real-world targets (e.g., parsers like xmllint) use non-zero exit codes to
 * signal "input rejected" rather than a memory-safety crash. This oracle allows
 * configuring a whitelist of exit codes that should NOT be treated as crashes.
 */
public final class CrashOracle {

    /**
     * Conventional shell exit codes for interrupt/termination:
     * - 130: SIGINT
     * - 143: SIGTERM
     *
     * We ignore them by default to avoid polluting crash stats when a run is interrupted.
     */
    public static final Set<Integer> DEFAULT_NON_CRASH_EXIT_CODES = Set.of(130, 143);

    private final Set<Integer> nonCrashExitCodes;

    private CrashOracle(Set<Integer> nonCrashExitCodes) {
        this.nonCrashExitCodes = Set.copyOf(Objects.requireNonNull(nonCrashExitCodes, "nonCrashExitCodes"));
    }

    /**
     * Default oracle: preserves historical behavior except it ignores conventional
     * interrupt exit codes (130/143).
     */
    public static CrashOracle defaultOracle() {
        return new CrashOracle(DEFAULT_NON_CRASH_EXIT_CODES);
    }

    /**
     * Builds an oracle that ignores both the project defaults (130/143) and the provided codes.
     */
    public static CrashOracle withNonCrashExitCodes(Set<Integer> additionalNonCrashExitCodes) {
        if (additionalNonCrashExitCodes == null || additionalNonCrashExitCodes.isEmpty()) {
            return defaultOracle();
        }
        java.util.HashSet<Integer> merged = new java.util.HashSet<>(DEFAULT_NON_CRASH_EXIT_CODES);
        merged.addAll(additionalNonCrashExitCodes);
        return new CrashOracle(Set.copyOf(merged));
    }

    public Set<Integer> nonCrashExitCodes() {
        return nonCrashExitCodes;
    }

    /**
     * Returns true if the given run result should be treated as a crash.
     */
    public boolean isCrash(RunResult run) {
        if (run == null) return false;

        // Timeouts are handled as hangs.
        if (run.timedOut() || run.termination() == RunResult.Termination.TIMEOUT) {
            return false;
        }

        if (run.termination() != RunResult.Termination.ERROR) {
            return false;
        }

        int exitCode = run.exitCode();
        return !nonCrashExitCodes.contains(exitCode);
    }
}
