package com.yastro.login.proxy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

/**
 * Log forense. Gera um arquivo NOVO por boot do proxy em
 * {@code logs/diagnostic-<data>_<hora>.log}; no boot poda os antigos e mantém só os
 * {@code retain} mais recentes. Thread-safe (escrita serializada).
 */
public final class DiagnosticLog {

    // sem ':' no padrão: ':' é ilegal em nome de arquivo no Windows
    private static final DateTimeFormatter STAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss");
    private static final String PREFIX = "diagnostic-";
    private static final String SUFFIX = ".log";

    private final Path file;
    private final boolean enabled;
    private final Object lock = new Object();

    public DiagnosticLog(Path logsDirectory, boolean enabled, int retain) {
        this.enabled = enabled;
        if (!enabled) {
            this.file = null;
            return;
        }
        prune(logsDirectory, retain);
        this.file = logsDirectory.resolve(uniqueName(logsDirectory));
    }

    /** Nome do arquivo deste boot; desambigua com sufixo {@code _N} se dois boots
     * caírem no mesmo segundo (mesmo timestamp). */
    private static String uniqueName(Path dir) {
        String base = PREFIX + LocalDateTime.now().format(STAMP);
        if (!Files.exists(dir.resolve(base + SUFFIX))) {
            return base + SUFFIX;
        }
        for (int i = 2; ; i++) {
            String name = base + "_" + i + SUFFIX;
            if (!Files.exists(dir.resolve(name))) {
                return name;
            }
        }
    }

    public void signal(String tag, String detail) {
        if (!enabled || file == null) {
            return;
        }
        String line = "[" + LocalDateTime.now() + "] [" + sanitize(tag) + "] " + sanitize(detail)
                + System.lineSeparator();
        byte[] bytes = line.getBytes(StandardCharsets.UTF_8);
        synchronized (lock) {
            try {
                Files.write(file, bytes, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            } catch (IOException ignored) {
                // forense é best-effort: nunca quebra o fluxo de auth
            }
        }
    }

    /** Mantém só os {@code retain} logs mais recentes (vai criar mais um logo em seguida,
     * então poda até sobrarem {@code retain-1}). */
    private static void prune(Path dir, int retain) {
        if (retain < 1) {
            return;
        }
        List<Path> logs = new ArrayList<>();
        try (Stream<Path> s = Files.list(dir)) {
            s.filter(p -> {
                String n = p.getFileName().toString();
                return n.startsWith(PREFIX) && n.endsWith(SUFFIX);
            }).forEach(logs::add);
        } catch (IOException ignored) {
            return;
        }
        // nome = timestamp largura-fixa -> ordem lexical == ordem cronológica
        logs.sort(Comparator.comparing(p -> p.getFileName().toString()));
        int remove = logs.size() - (retain - 1);
        for (int i = 0; i < remove; i++) {
            try {
                Files.deleteIfExists(logs.get(i));
            } catch (IOException ignored) {
                // best-effort
            }
        }
    }

    /** Remove caracteres de controle do conteudo: um nick cracked (ate 16 chars arbitrarios)
     * poderia conter \r\n e forjar uma linha propria no log forense (log injection), ou ESC
     * (0x1b) e injetar sequencias ANSI que falsificam cores/linhas quando visto num terminal. */
    private static String sanitize(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            sb.append((c < 0x20 || c == 0x7f) ? ' ' : c);
        }
        return sb.toString();
    }
}
