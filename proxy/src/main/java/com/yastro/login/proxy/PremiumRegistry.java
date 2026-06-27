package com.yastro.login.proxy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import com.yastro.login.common.AccountKey;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Registro PERSISTENTE de nicks já confirmados como originais (HTTP 200 da
 * Mojang). Impede o ataque de "downgrade": se a Mojang ficar indisponível
 * (429/erro) e o proxy não souber se o nick é original, um nick que JÁ foi visto
 * como original nunca pode ser rebaixado a registrável, é negado até a Mojang
 * voltar, em vez de virar uma conta pirata sequestrável.
 *
 * <p>Arquivo: {@code plugins/archerlogin/premium-names.txt} (um nick minúsculo por linha).
 *
 * <p>Persistência em LOTE: cada nick novo entra num buffer em memória e um flusher
 * de fundo grava todos de uma vez a cada {@link #FLUSH_INTERVAL_SECONDS}s (uma única
 * syscall por janela, em vez de uma por nick novo no caminho de PreLogin). A marcação
 * em memória é imediata; só a escrita em disco é adiada. {@link #close()} faz o flush
 * final e encerra o flusher (chamar no shutdown do proxy).
 */
public final class PremiumRegistry {

    private static final long FLUSH_INTERVAL_SECONDS = 5;

    private final Path file;
    private final Set<String> names = ConcurrentHashMap.newKeySet();
    private final ConcurrentLinkedQueue<String> dirty = new ConcurrentLinkedQueue<>();
    private final ScheduledExecutorService flusher;

    private PremiumRegistry(Path file) {
        this.file = file;
        this.flusher = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "ArcherLogin-PremiumRegistry");
            t.setDaemon(true);
            return t;
        });
        this.flusher.scheduleWithFixedDelay(this::flush,
                FLUSH_INTERVAL_SECONDS, FLUSH_INTERVAL_SECONDS, TimeUnit.SECONDS);
    }

    public static PremiumRegistry load(Path dataDirectory) {
        Path file = dataDirectory.resolve("premium-names.txt");
        PremiumRegistry reg = new PremiumRegistry(file);
        try {
            if (Files.exists(file)) {
                List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
                for (String line : lines) {
                    String n = AccountKey.normalize(line.trim());
                    if (!n.isEmpty()) {
                        reg.names.add(n);
                    }
                }
            }
        } catch (IOException ignored) {
            // Sem o arquivo, começa vazio (apenas perde a proteção histórica).
        }
        return reg;
    }

    public boolean contains(String nameLower) {
        return names.contains(nameLower);
    }

    /** Marca um nick como original. Persiste (em lote) só na primeira vez que vê. */
    public void add(String nameLower) {
        if (names.add(nameLower)) {
            dirty.offer(nameLower);
        }
    }

    /** Drena o buffer e grava todos os nicks pendentes numa única escrita (append). */
    private void flush() {
        if (dirty.isEmpty()) {
            return;
        }
        List<String> batch = new ArrayList<>();
        for (String n; (n = dirty.poll()) != null; ) {
            batch.add(n);
        }
        if (batch.isEmpty()) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        for (String n : batch) {
            sb.append(n).append(System.lineSeparator());
        }
        try {
            Files.writeString(file, sb.toString(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ignored) {
            // Em memória já está marcado; persistência é best-effort. Re-enfileira pra
            // tentar de novo no próximo flush (não perde a gravação por um erro pontual).
            dirty.addAll(batch);
        }
    }

    /** Flush final + encerra o flusher. Chamar no shutdown do proxy. */
    public void close() {
        flusher.shutdown();
        compact(); // LOW: reescreve o arquivo a partir do Set (dedup), em vez de só dar append
    }

    /** Reescreve o arquivo inteiro a partir do Set em memória, remove linhas duplicadas acumuladas. */
    private void compact() {
        StringBuilder sb = new StringBuilder();
        for (String n : names) {
            sb.append(n).append(System.lineSeparator());
        }
        try {
            Files.writeString(file, sb.toString(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            dirty.clear();
        } catch (IOException ignored) {
            // best-effort; o Set em memória já é a fonte de verdade
        }
    }
}
