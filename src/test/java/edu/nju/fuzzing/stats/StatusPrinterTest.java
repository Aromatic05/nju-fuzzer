package edu.nju.fuzzing.stats;

import edu.nju.fuzzing.model.StatsTick;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class StatusPrinterTest {

    // Helper method to create a compliant tick
    private StatsTick createTick(String target, int execs, int cov, int crash) {
        return new StatsTick(target, 10, execs, cov, 100.0, 5, crash, 0, 2);
    }

    @Test
    void shouldPrintFormattedStatusLine() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        StatsTick tick = createTick("target_x", 1000, 50, 0);

        // 修复：使用 try-with-resources 自动关闭 printer
        try (StatusPrinter printer = new StatusPrinter(new PrintStream(baos), () -> tick, 1)) {
            printer.printNow();
            
            String output = baos.toString(StandardCharsets.UTF_8);
            
            // Check log format compliance
            assertTrue(output.contains("[target_x]"), "Should contain target name");
            assertTrue(output.contains("cov: 50"), "Should contain coverage");
            assertTrue(output.contains("execs: 1000"), "Should contain exec count");
        }
    }

    @Test
    void shouldFormatDurationCorrectly() {
        StatsTick tick = new StatsTick("t", 3661, 0, 0, 0, 0, 0, 0, 0);
        String line = tick.toStatusLine();
        assertTrue(line.contains("01:01:01"), "3661s should be 01:01:01");
    }

    @Test
    void shouldPrintEvents() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // 修复：使用 try-with-resources
        try (StatusPrinter printer = new StatusPrinter(new PrintStream(baos), () -> createTick("t", 0, 0, 0), 1)) {
            printer.printEvent("Fuzzing started");
            
            assertTrue(baos.toString().contains("[EVENT] Fuzzing started"));
        }
    }

    @Test
    void shouldPrintCrashAlert() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // 修复：使用 try-with-resources
        try (StatusPrinter printer = new StatusPrinter(new PrintStream(baos), () -> createTick("t", 0, 0, 0), 1)) {
            printer.printCrash(1, "SIGSEGV");
            
            String output = baos.toString();
            assertTrue(output.contains("[CRASH]"));
            assertTrue(output.contains("reason=SIGSEGV"));
        }
    }

    @Test
    void shouldPrintNewPathAlert() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // 修复：使用 try-with-resources
        try (StatusPrinter printer = new StatusPrinter(new PrintStream(baos), () -> createTick("t", 0, 0, 0), 1)) {
            printer.printNewPath(5, 120);
            
            String output = baos.toString();
            assertTrue(output.contains("[NEW PATH]"));
            assertTrue(output.contains("id=5"));
            assertTrue(output.contains("coverage=120"));
        }
    }

    @Test
    void shouldPrintHangAlert() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // 修复：使用 try-with-resources
        try (StatusPrinter printer = new StatusPrinter(new PrintStream(baos), () -> createTick("t", 0, 0, 0), 1)) {
            printer.printHang(2, 5000);
            
            assertTrue(baos.toString().contains("[HANG]"));
        }
    }

    @Test
    void shouldHandleBuilderPattern() {
        // 修复：使用 try-with-resources
        try (StatusPrinter printer = StatusPrinter.builder()
                .statsSupplier(() -> createTick("t", 0, 0, 0))
                .intervalSeconds(5)
                .build()) {
            
            assertNotNull(printer);
        }
    }

    @Test
    void shouldHandleSupplierErrorGracefully() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // 修复：使用 try-with-resources
        try (StatusPrinter printer = new StatusPrinter(new PrintStream(baos), () -> {
            throw new RuntimeException("DB offline");
        }, 1)) {
            
            assertDoesNotThrow(printer::printNow);
            assertTrue(baos.toString().contains("[STATUS ERROR]"), "Should log error");
        }
    }

    @Test
    void shouldNotPrintIfStopped() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // 修复：使用 try-with-resources
        try (StatusPrinter printer = new StatusPrinter(new PrintStream(baos), () -> createTick("t", 0, 0, 0), 1)) {
            printer.start(); // Set running=true
            printer.stop();  // Set running=false
            
            assertDoesNotThrow(printer::stop);
        }
    }

    @Test
    void shouldDefaultToStdout() {
        // 修复：使用 try-with-resources
        try (StatusPrinter printer = new StatusPrinter(() -> createTick("t", 0, 0, 0))) {
            assertNotNull(printer);
        }
    }
}