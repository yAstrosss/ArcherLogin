package com.yastro.login.proxy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class DiagnosticLogTest {

    @Test
    void writesSignalLine(@TempDir Path dir) throws Exception {
        new DiagnosticLog(dir, true, 1_000_000).signal("LOGIN_FAIL", "bob from 1.2.3.4");
        String content = Files.readString(dir.resolve("diagnostic.log"));
        assertTrue(content.contains("[LOGIN_FAIL]"));
        assertTrue(content.contains("bob from 1.2.3.4"));
    }

    @Test
    void disabledWritesNothing(@TempDir Path dir) {
        new DiagnosticLog(dir, false, 1000).signal("X", "y");
        assertFalse(Files.exists(dir.resolve("diagnostic.log")));
    }

    @Test
    void sanitizesNewlinesAgainstLogInjection(@TempDir Path dir) throws Exception {
        // nick cracked pode conter \r\n e forjar uma linha própria no log forense.
        new DiagnosticLog(dir, true, 1_000_000).signal("FLOOD", "bob\n[FAKE] linha forjada");
        String content = Files.readString(dir.resolve("diagnostic.log"));
        assertEquals(1, content.lines().count()); // 1 entrada, não 2
        assertTrue(content.contains("bob [FAKE] linha forjada")); // \n virou espaço
    }

    @Test
    void rotatesWhenOverSize(@TempDir Path dir) {
        DiagnosticLog log = new DiagnosticLog(dir, true, 50);
        for (int i = 0; i < 30; i++) log.signal("T", "linha-de-teste-" + i);
        assertTrue(Files.exists(dir.resolve("diagnostic.log.1")));
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
