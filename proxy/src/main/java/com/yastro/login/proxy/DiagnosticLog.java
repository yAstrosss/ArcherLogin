package com.yastro.login.proxy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;

/** Log forense rotativo (1 arquivo + .1 ao passar de maxBytes). Thread-safe. */
public final class DiagnosticLog {
    private final Path file;
    private final Path rolled;
    private final long maxBytes;
    private final boolean enabled;
    private final Object lock = new Object();
    private long written = -1L; // tamanho atual do arquivo em memória (-1 = ainda não medido)

    public DiagnosticLog(Path dataDirectory, boolean enabled, long maxBytes) {
        this.file = dataDirectory.resolve("diagnostic.log");
        this.rolled = dataDirectory.resolve("diagnostic.log.1");
        this.maxBytes = maxBytes;
        this.enabled = enabled;
    }

    public void signal(String tag, String detail) {
        if (!enabled) {
            return;
        }
        String line = "[" + LocalDateTime.now() + "] [" + sanitize(tag) + "] " + sanitize(detail)
                + System.lineSeparator();
        byte[] bytes = line.getBytes(StandardCharsets.UTF_8);
        synchronized (lock) {
            try {
                if (written < 0) { // mede o arquivo UMA vez; depois mantém o tamanho em memória
                    written = Files.exists(file) ? Files.size(file) : 0L;
                }
                if (written > 0 && written + bytes.length > maxBytes) {
                    Files.deleteIfExists(rolled);
                    Files.move(file, rolled);
                    written = 0L;
                }
                Files.write(file, bytes, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                written += bytes.length;
            } catch (IOException ignored) {
                // forense é best-effort: nunca quebra o fluxo de auth
                written = -1L; // erro: re-mede o tamanho na próxima escrita
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
