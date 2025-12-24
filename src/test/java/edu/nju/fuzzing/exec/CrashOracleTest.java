package edu.nju.fuzzing.exec;

import edu.nju.fuzzing.model.RunResult;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class CrashOracleTest {

    @Test
    void defaultOracle_shouldTreatInterruptExitCodesAsNonCrash() {
        CrashOracle oracle = CrashOracle.defaultOracle();

        RunResult sigint = new RunResult(
                1,
                null,
                1,
                1_000_000L,
                130,
                false,
                RunResult.Termination.ERROR,
                Path.of("/tmp/stdout"),
                Path.of("/tmp/stderr")
        );

        assertFalse(oracle.isCrash(sigint));
    }

    @Test
    void withNonCrashExitCodes_shouldHonorWhitelist() {
        CrashOracle oracle = CrashOracle.withNonCrashExitCodes(Set.of(1, 2, 4));

        RunResult rejected = new RunResult(
                1,
                null,
                1,
                1_000_000L,
                2,
                false,
                RunResult.Termination.ERROR,
                Path.of("/tmp/stdout"),
                Path.of("/tmp/stderr")
        );

        RunResult realCrash = new RunResult(
                2,
                null,
                1,
                1_000_000L,
                139,
                false,
                RunResult.Termination.ERROR,
                Path.of("/tmp/stdout"),
                Path.of("/tmp/stderr")
        );

        assertFalse(oracle.isCrash(rejected));
        assertTrue(oracle.isCrash(realCrash));
    }

    @Test
    void isCrash_shouldNeverTreatTimeoutAsCrash() {
        CrashOracle oracle = CrashOracle.defaultOracle();

        RunResult timeout = new RunResult(
                1,
                null,
                1000,
                1_000_000_000L,
                0,
                true,
                RunResult.Termination.TIMEOUT,
                Path.of("/tmp/stdout"),
                Path.of("/tmp/stderr")
        );

        assertFalse(oracle.isCrash(timeout));
    }
}
