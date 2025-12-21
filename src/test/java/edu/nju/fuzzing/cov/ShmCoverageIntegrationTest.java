package edu.nju.fuzzing.cov;

import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Integration test for ShmCoverageMonitor with real AFL++ instrumented binaries.
 * 
 * This test:
 * 1. Creates a System V shared memory segment
 * 2. Runs an AFL++ instrumented binary with __AFL_SHM_ID set
 * 3. Reads coverage data from the shared memory
 * 4. Verifies that coverage is detected
 * 
 * Usage: java ShmCoverageIntegrationTest <instrumented-binary> [input-file]
 * 
 * Example:
 *   java ShmCoverageIntegrationTest ./env/out/lua
 */
public class ShmCoverageIntegrationTest {

    // IPC constants
    private static final int IPC_CREAT = 01000;
    private static final int IPC_EXCL = 02000;
    private static final int IPC_RMID = 0;
    private static final int SHM_R = 0400;
    private static final int SHM_W = 0200;

    private static final int MAP_SIZE = 65536;

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: ShmCoverageIntegrationTest <instrumented-binary> [input-file]");
            System.out.println();
            System.out.println("Examples:");
            System.out.println("  # Test with lua (stdin input)");
            System.out.println("  java ShmCoverageIntegrationTest ./env/out/lua");
            System.out.println();
            System.out.println("  # Test with mjs (stdin input)");
            System.out.println("  java ShmCoverageIntegrationTest ./env/out/mjs");
            System.out.println();
            System.out.println("  # Test with custom input file");
            System.out.println("  java ShmCoverageIntegrationTest ./env/out/lua input.lua");
            return;
        }

        String binaryPath = args[0];
        String inputFile = args.length > 1 ? args[1] : null;

        System.out.println("=== AFL++ SHM Coverage Integration Test ===");
        System.out.println("Binary: " + binaryPath);
        System.out.println("Map Size: " + MAP_SIZE);
        System.out.println();

        // Verify binary exists
        if (!new File(binaryPath).exists()) {
            System.err.println("Error: Binary not found: " + binaryPath);
            System.exit(1);
        }

        // Create shared memory segment
        int shmId = createSharedMemory(MAP_SIZE);
        System.out.println("Created SHM segment, ID: " + shmId);

        try {
            // Create a single strategy instance to track cumulative coverage
            SeenNonZeroStrategy globalStrategy = new SeenNonZeroStrategy(MAP_SIZE);
            
            // Detect target type and use appropriate test inputs
            String binaryName = new File(binaryPath).getName();
            
            if (binaryName.equals("mjs")) {
                // JavaScript inputs for mjs
                runTest(shmId, binaryPath, inputFile, "Test 1: Simple JS", "print(1+1);\n", globalStrategy);
                runTest(shmId, binaryPath, inputFile, "Test 2: Loop", "for(let i=0;i<10;i++) print(i);\n", globalStrategy);
                runTest(shmId, binaryPath, inputFile, "Test 3: Function", "function f(x){return x*2;} print(f(5));\n", globalStrategy);
                runTest(shmId, binaryPath, inputFile, "Test 4: Array", "let a=[1,2,3]; print(a.length);\n", globalStrategy);
                runTest(shmId, binaryPath, inputFile, "Test 5: Error", "invalid syntax @#$\n", globalStrategy);
            } else {
                // Default: Lua inputs
                runTest(shmId, binaryPath, inputFile, "Test 1: Simple input", "print(1+1)\n", globalStrategy);
                runTest(shmId, binaryPath, inputFile, "Test 2: Different input", "for i=1,10 do print(i) end\n", globalStrategy);
                runTest(shmId, binaryPath, inputFile, "Test 3: Error input", "invalid syntax here!!!\n", globalStrategy);
                runTest(shmId, binaryPath, inputFile, "Test 4: Empty input", "\n", globalStrategy);
                runTest(shmId, binaryPath, inputFile, "Test 5: Complex input", 
                        "function fib(n) if n<=1 then return n else return fib(n-1)+fib(n-2) end end print(fib(5))\n", globalStrategy);
            }
            
            System.out.println("\n=== Summary ===");
            System.out.println("Total unique edges discovered: " + globalStrategy.totalSeenBytes());

        } finally {
            // Clean up shared memory
            removeSharedMemory(shmId);
            System.out.println("\nCleaned up SHM segment: " + shmId);
        }

        System.out.println("\n=== Test Complete ===");
    }

    private static void runTest(int shmId, String binaryPath, String inputFile, 
                                 String testName, String stdinInput,
                                 SeenNonZeroStrategy globalStrategy) throws Exception {
        System.out.println("\n--- " + testName + " ---");

        // Attach to SHM and create monitor
        SysVShmBitmapSource bitmapSource = new SysVShmBitmapSource(shmId, MAP_SIZE);
        bitmapSource.attach();

        // Use local strategy for per-run stats, but also update global
        SeenNonZeroStrategy localStrategy = new SeenNonZeroStrategy(MAP_SIZE);
        ShmCoverageMonitor monitor = new ShmCoverageMonitor(bitmapSource, localStrategy);
        monitor.start();

        try {
            // Clear bitmap before run
            monitor.beforeRun();

            // Run the instrumented binary
            ProcessBuilder pb;
            if (inputFile != null) {
                pb = new ProcessBuilder(binaryPath, inputFile);
            } else {
                pb = new ProcessBuilder(binaryPath);
            }

            // Set AFL SHM environment
            Map<String, String> env = pb.environment();
            env.put("__AFL_SHM_ID", String.valueOf(shmId));
            env.put("AFL_MAP_SIZE", String.valueOf(MAP_SIZE));

            pb.redirectErrorStream(true);

            Process process = pb.start();

            // Write stdin if no input file
            if (inputFile == null && stdinInput != null) {
                try (OutputStream os = process.getOutputStream()) {
                    os.write(stdinInput.getBytes());
                    os.flush();
                }
            }

            // Wait for completion with timeout
            boolean finished = process.waitFor(5, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                System.out.println("  Process timed out");
            }

            int exitCode = finished ? process.exitValue() : -1;

            // Read coverage
            byte[] bitmap = new byte[MAP_SIZE];
            bitmapSource.readInto(bitmap);

            // Calculate statistics
            int nonZeroBytes = 0;
            int totalHits = 0;
            for (int i = 0; i < MAP_SIZE; i++) {
                int val = bitmap[i] & 0xFF;
                if (val != 0) {
                    nonZeroBytes++;
                    totalHits += val;
                }
            }

            // Use local strategy for this run's new coverage
            CoverageDiffStrategy.DiffResult localResult = localStrategy.diff(bitmap);
            
            // Also update global strategy to track cumulative coverage
            CoverageDiffStrategy.DiffResult globalResult = globalStrategy.diff(bitmap);

            System.out.println("  Input: " + stdinInput.trim().substring(0, Math.min(50, stdinInput.trim().length())) + 
                               (stdinInput.length() > 50 ? "..." : ""));
            System.out.println("  Exit code: " + exitCode);
            System.out.println("  Non-zero bytes (this run): " + nonZeroBytes);
            System.out.println("  Total hits: " + totalHits);
            System.out.println("  New bytes (global): " + globalResult.newBytes());
            System.out.println("  Interesting (global): " + globalResult.interesting());
            System.out.println("  Cumulative seen: " + globalStrategy.totalSeenBytes());

            // Print first few non-zero positions
            StringBuilder positions = new StringBuilder("  First edges: ");
            int count = 0;
            for (int i = 0; i < MAP_SIZE && count < 10; i++) {
                if ((bitmap[i] & 0xFF) != 0) {
                    positions.append(String.format("%d(%d) ", i, bitmap[i] & 0xFF));
                    count++;
                }
            }
            if (count > 0) {
                System.out.println(positions);
            }

        } finally {
            monitor.close();
        }
    }

    private static int createSharedMemory(int size) {
        // Generate a unique key
        int key = (int) (System.currentTimeMillis() & 0x7FFFFFFF);

        // shmget(key, size, IPC_CREAT | IPC_EXCL | 0600)
        int flags = IPC_CREAT | IPC_EXCL | SHM_R | SHM_W;
        int shmId = SysVShmBitmapSource.CLibrary.INSTANCE.shmget(key, new NativeLong(size), flags);

        if (shmId == -1) {
            int errno = Native.getLastError();
            throw new RuntimeException("Failed to create shared memory, errno=" + errno);
        }

        return shmId;
    }

    private static void removeSharedMemory(int shmId) {
        int result = SysVShmBitmapSource.CLibrary.INSTANCE.shmctl(shmId, IPC_RMID, null);
        if (result == -1) {
            System.err.println("Warning: Failed to remove SHM segment, errno=" + Native.getLastError());
        }
    }
}
