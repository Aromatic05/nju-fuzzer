package edu.nju.fuzzing.stats;

import edu.nju.fuzzing.model.StatsTick;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class StatusPrinterTest {

    @Test
    void shouldPrintStatusOnDemand() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(baos);
        
        StatsTick tick = new StatsTick(60, 1000, 16.7, 50, 2, 1, 100, 30);
        
        StatusPrinter printer = new StatusPrinter(ps, () -> tick, 1);
        printer.printNow();
        
        String output = baos.toString(StandardCharsets.UTF_8);
        assertTrue(output.contains("execs: 1000"));
        assertTrue(output.contains("paths: 100"));
        assertTrue(output.contains("crashes: 2"));
    }

    @Test
    void shouldPrintEvent() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(baos);
        
        StatsTick tick = new StatsTick(0, 0, 0, 0, 0, 0, 0, 0);
        StatusPrinter printer = new StatusPrinter(ps, () -> tick, 1);
        
        printer.printEvent("New crash found!");
        
        String output = baos.toString(StandardCharsets.UTF_8);
        assertTrue(output.contains("[EVENT]"));
        assertTrue(output.contains("New crash found!"));
    }

    @Test
    void shouldPrintNewPath() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(baos);
        
        StatsTick tick = new StatsTick(0, 0, 0, 0, 0, 0, 0, 0);
        StatusPrinter printer = new StatusPrinter(ps, () -> tick, 1);
        
        printer.printNewPath(42, 1500);
        
        String output = baos.toString(StandardCharsets.UTF_8);
        assertTrue(output.contains("[NEW PATH]"));
        assertTrue(output.contains("id=42"));
        assertTrue(output.contains("coverage=1500"));
    }

    @Test
    void shouldPrintCrash() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(baos);
        
        StatsTick tick = new StatsTick(0, 0, 0, 0, 0, 0, 0, 0);
        StatusPrinter printer = new StatusPrinter(ps, () -> tick, 1);
        
        printer.printCrash(5, "SIGSEGV");
        
        String output = baos.toString(StandardCharsets.UTF_8);
        assertTrue(output.contains("[CRASH]"));
        assertTrue(output.contains("id=5"));
        assertTrue(output.contains("reason=SIGSEGV"));
    }

    @Test
    void shouldPrintHang() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(baos);
        
        StatsTick tick = new StatsTick(0, 0, 0, 0, 0, 0, 0, 0);
        StatusPrinter printer = new StatusPrinter(ps, () -> tick, 1);
        
        printer.printHang(3, 5000);
        
        String output = baos.toString(StandardCharsets.UTF_8);
        assertTrue(output.contains("[HANG]"));
        assertTrue(output.contains("id=3"));
        assertTrue(output.contains("timeout=5000ms"));
    }

    @Test
    void shouldBuildWithBuilder() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(baos);
        StatsTick tick = new StatsTick(0, 0, 0, 0, 0, 0, 0, 0);
        
        StatusPrinter printer = StatusPrinter.builder()
                .output(ps)
                .statsSupplier(() -> tick)
                .intervalSeconds(5)
                .build();
        
        assertNotNull(printer);
    }

    @Test
    void shouldRequireStatsSupplierInBuilder() {
        assertThrows(IllegalStateException.class, () -> 
            StatusPrinter.builder().build()
        );
    }

    @Test
    void shouldHandleSupplierException() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(baos);
        
        StatusPrinter printer = new StatusPrinter(ps, () -> {
            throw new RuntimeException("Test error");
        }, 1);
        
        // Should not throw
        assertDoesNotThrow(printer::printNow);
    }

    @Test
    void shouldUseStdoutByDefault() {
        StatsTick tick = new StatsTick(0, 0, 0, 0, 0, 0, 0, 0);
        StatusPrinter printer = new StatusPrinter(() -> tick);
        
        assertNotNull(printer);
    }

    @Test
    void statsTickShouldFormatStatusLine() {
        StatsTick tick = new StatsTick(3661, 100000, 27.3, 50, 3, 2, 150, 120);
        
        String line = tick.toStatusLine();
        
        assertTrue(line.contains("01:01:01")); // formatted duration
        assertTrue(line.contains("execs: 100000"));
        assertTrue(line.contains("exec/s: 27.3"));
        assertTrue(line.contains("paths: 150"));
        assertTrue(line.contains("crashes: 3"));
        assertTrue(line.contains("hangs: 2"));
        assertTrue(line.contains("last_path: 120s ago"));
    }

    @Test
    void statsTickShouldHaveBackwardCompatibleConstructor() {
        // Old constructor with 6 params
        StatsTick tick = new StatsTick(100, 1000, 10.0, 20, 1, 0);
        
        assertEquals(100, tick.elapsedSec());
        assertEquals(1000, tick.execsTotal());
        assertEquals(10.0, tick.execsPerSec());
        assertEquals(20, tick.queueSize());
        assertEquals(1, tick.crashes());
        assertEquals(0, tick.hangs());
        // Default values for new fields
        assertEquals(20, tick.totalPaths()); // defaults to queueSize
        assertEquals(0, tick.lastNewPathSecAgo());
    }
}
