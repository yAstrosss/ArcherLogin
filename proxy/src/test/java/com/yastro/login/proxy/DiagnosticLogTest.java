package com.yastro.login.proxy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class DiagnosticLogTest {

    /** Acha o único arquivo de log do boot (logs/diagnostic-*.log). */
    private static Path theLog(Path dir) throws IOException {
        try (Stream<Path> s = Files.list(dir)) {
            return s.filter(p -> p.getFileName().toString().startsWith("diagnostic-"))
                    .findFirst().orElseThrow();
        }
    }

    private static long countLogs(Path dir) throws IOException {
        try (Stream<Path> s = Files.list(dir)) {
            return s.filter(p -> p.getFileName().toString().startsWith("diagnostic-")).count();
        }
    }

    @Test
    void writesSignalLine(@TempDir Path dir) throws Exception {
        new DiagnosticLog(dir, true, 30).signal("LOGIN_FAIL", "bob from 1.2.3.4");
        String content = Files.readString(theLog(dir));
        assertTrue(content.contains("[LOGIN_FAIL]"));
        assertTrue(content.contains("bob from 1.2.3.4"));
    }

    @Test
    void disabledWritesNothing(@TempDir Path dir) throws Exception {
        new DiagnosticLog(dir, false, 30).signal("X", "y");
        assertEquals(0, countLogs(dir));
    }

    @Test
    void sanitizesNewlinesAgainstLogInjection(@TempDir Path dir) throws Exception {
        // nick cracked pode conter \r\n e forjar uma linha própria no log forense.
        new DiagnosticLog(dir, true, 30).signal("FLOOD", "bob\n[FAKE] linha forjada");
        String content = Files.readString(theLog(dir));
        assertEquals(1, content.lines().count()); // 1 entrada, não 2
        assertTrue(content.contains("bob [FAKE] linha forjada")); // \n virou espaço
    }

    @Test
    void retentionKeepsOnlyNewest(@TempDir Path dir) throws Exception {
        // 35 logs antigos com timestamps distintos (ordem lexical = cronológica)
        for (int i = 1; i <= 35; i++) {
            Files.writeString(dir.resolve(String.format("diagnostic-2026-01-01_00-00-%02d.log", i)), "x");
        }
        // novo boot com retain=30: poda pra 29 antigos + cria o deste boot = 30
        new DiagnosticLog(dir, true, 30).signal("BOOT", "novo");
        assertEquals(30, countLogs(dir));
    }

    @Test
    void floodCounterTripsAboveThreshold() {
        FloodCounter fc = new FloodCounter(3);
        long t = 1_000_000L;
        assertFalse(fc.record(t));
        assertFalse(fc.record(t));
        assertFalse(fc.record(t));
        assertTrue(fc.record(t)); // 4ª na janela > limiar 3
    }

    @Test
    void floodCounterForgetsOldHits() {
        FloodCounter fc = new FloodCounter(2);
        fc.record(0L);
        fc.record(0L);
        assertFalse(fc.record(61_000L)); // os 2 antigos saíram da janela de 60s
    }
}
