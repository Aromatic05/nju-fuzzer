package edu.nju.fuzzing.cov;

import com.sun.jna.Native;
import com.sun.jna.NativeLong;

import java.io.*;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Integration test comparing different coverage diff strategies.
 * 
 * This test runs the same inputs through multiple strategies and compares
 * their behavior to validate Iteration 2 improvements.
 * 
 * Usage: java StrategyComparisonTest <instrumented-binary>
 */
public class StrategyComparisonTest {

    private static final int IPC_CREAT = 01000;
    private static final int IPC_EXCL = 02000;
    private static final int IPC_RMID = 0;
    private static final int SHM_R = 0400;
    private static final int SHM_W = 0200;
    private static final int MAP_SIZE = 65536;

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: StrategyComparisonTest <instrumented-binary>");
            System.out.println("Example: java StrategyComparisonTest ./env/out/lua");
            return;
        }

        String binaryPath = args[0];

        System.out.println("=== Strategy Comparison Test ===");
        System.out.println("Binary: " + binaryPath);
        System.out.println();

        if (!new File(binaryPath).exists()) {
            System.err.println("Error: Binary not found: " + binaryPath);
            System.exit(1);
        }

        int shmId = createSharedMemory(MAP_SIZE);
        System.out.println("Created SHM segment, ID: " + shmId);

        try {
            // Create different strategies for comparison
            SeenNonZeroStrategy seenStrategy = new SeenNonZeroStrategy(MAP_SIZE);
            PrevBitmapStrategy prevStrategy = new PrevBitmapStrategy(MAP_SIZE);
            CoverageDiffStrategy hashFilteredStrategy = CoverageDiffStrategy.createDefault(MAP_SIZE);
            
            // Test inputs that exercise different paths
            String[] inputs = {
                "print(1+1)\n",
                "print(2+2)\n",                          // Similar to first
                "for i=1,10 do print(i) end\n",          // Loop
                "for i=1,10 do print(i) end\n",          // Repeat loop
                "function f() return 42 end print(f())\n", // Function
                "x = {1,2,3} print(#x)\n",               // Table
                "invalid!!!\n",                          // Error path
                "invalid!!!\n",                          // Repeat error
                "print(1+1)\n",                          // Back to first
            };

            System.out.println("Running " + inputs.length + " test cases...\n");
            System.out.println(String.format("%-30s | %-12s | %-12s | %-12s",
                    "Input", "Seen(global)", "Prev", "HashFiltered"));
            System.out.println("-".repeat(75));

            int seenInteresting = 0;
            int prevInteresting = 0;
            int hashInteresting = 0;

            for (int i = 0; i < inputs.length; i++) {
                String input = inputs[i];
                String shortInput = input.trim();
                if (shortInput.length() > 25) {
                    shortInput = shortInput.substring(0, 22) + "...";
                }

                // Run the binary and collect bitmap
                byte[] bitmap = runAndGetBitmap(shmId, binaryPath, input);

                // Compare all strategies
                CoverageDiffStrategy.DiffResult seenResult = seenStrategy.diff(bitmap);
                CoverageDiffStrategy.DiffResult prevResult = prevStrategy.diff(bitmap);
                CoverageDiffStrategy.DiffResult hashResult = hashFilteredStrategy.diff(bitmap);

                if (seenResult.interesting()) seenInteresting++;
                if (prevResult.interesting()) prevInteresting++;
                if (hashResult.interesting()) hashInteresting++;

                System.out.println(String.format("%-30s | %3d %-8s | %3d %-8s | %3d %-8s",
                        shortInput,
                        seenResult.newBytes(), seenResult.interesting() ? "✓" : "",
                        prevResult.newBytes(), prevResult.interesting() ? "✓" : "",
                        hashResult.newBytes(), hashResult.interesting() ? "✓" : ""));
            }

            System.out.println("-".repeat(75));
            System.out.println(String.format("%-30s | %3d %-8s | %3d %-8s | %3d %-8s",
                    "TOTAL INTERESTING",
                    seenInteresting, "/" + inputs.length,
                    prevInteresting, "/" + inputs.length,
                    hashInteresting, "/" + inputs.length));

            System.out.println("\n=== Analysis ===");
            System.out.println("SeenNonZero (global seen):  " + seenInteresting + " interesting");
            System.out.println("  - Only reports truly new coverage");
            System.out.println("  - Total unique bytes seen: " + seenStrategy.totalSeenBytes());

            System.out.println("\nPrevBitmap (compare to prev): " + prevInteresting + " interesting");
            System.out.println("  - Reports any change from previous execution");
            System.out.println("  - May have more false positives for fuzzing queue");

            System.out.println("\nHashFiltered (optimized):    " + hashInteresting + " interesting");
            System.out.println("  - Same as SeenNonZero but skips identical bitmaps");
            System.out.println("  - Recommended for production use");

            // Verify hash filtering works correctly
            System.out.println("\n=== Hash Filter Verification ===");
            CoverageDiffStrategy freshHash = CoverageDiffStrategy.createDefault(MAP_SIZE);
            
            byte[] bitmap1 = runAndGetBitmap(shmId, binaryPath, "print(1)\n");
            byte[] bitmap2 = runAndGetBitmap(shmId, binaryPath, "print(1)\n");  // Same input

            CoverageDiffStrategy.DiffResult r1 = freshHash.diff(bitmap1);
            CoverageDiffStrategy.DiffResult r2 = freshHash.diff(bitmap2);

            System.out.println("First run:  " + r1.newBytes() + " new bytes, interesting=" + r1.interesting());
            System.out.println("Second run: " + r2.newBytes() + " new bytes, interesting=" + r2.interesting());
            System.out.println("Hash filter correctly skipped identical bitmap: " + !r2.interesting());

        } finally {
            removeSharedMemory(shmId);
            System.out.println("\nCleaned up SHM segment: " + shmId);
        }

        System.out.println("\n=== Test Complete ===");
    }

    private static byte[] runAndGetBitmap(int shmId, String binaryPath, String input) throws Exception {
        SysVShmBitmapSource bitmapSource = new SysVShmBitmapSource(shmId, MAP_SIZE);
        bitmapSource.attach();

        try {
            // Clear bitmap
            bitmapSource.clear();

            // Run binary
            ProcessBuilder pb = new ProcessBuilder(binaryPath);
            Map<String, String> env = pb.environment();
            env.put("__AFL_SHM_ID", String.valueOf(shmId));
            env.put("AFL_MAP_SIZE", String.valueOf(MAP_SIZE));
            pb.redirectErrorStream(true);

            Process process = pb.start();
            try (OutputStream os = process.getOutputStream()) {
                os.write(input.getBytes());
                os.flush();
            }
            process.waitFor(5, TimeUnit.SECONDS);

            // Read bitmap
            byte[] bitmap = new byte[MAP_SIZE];
            bitmapSource.readInto(bitmap);
            return bitmap;

        } finally {
            bitmapSource.close();
        }
    }

    private static int createSharedMemory(int size) {
        int key = (int) (System.currentTimeMillis() & 0x7FFFFFFF);
        int flags = IPC_CREAT | IPC_EXCL | SHM_R | SHM_W;
        int shmId = SysVShmBitmapSource.CLibrary.INSTANCE.shmget(key, new NativeLong(size), flags);
        if (shmId == -1) {
            throw new RuntimeException("Failed to create SHM, errno=" + Native.getLastError());
        }
        return shmId;
    }

    private static void removeSharedMemory(int shmId) {
        SysVShmBitmapSource.CLibrary.INSTANCE.shmctl(shmId, IPC_RMID, null);
    }
}
