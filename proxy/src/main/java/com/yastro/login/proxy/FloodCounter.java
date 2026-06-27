package com.yastro.login.proxy;

import java.util.ArrayDeque;

/** Janela deslizante de 60s; record() devolve true quando passa de perMin. Thread-safe. */
public final class FloodCounter {
    // Teto rigido de elementos rastreados: sob flood massivo a janela de 60s ainda pode
    // acumular muita conexao; limita o uso de memoria (anti-OOM) sem perder o sinal.
    private static final int MAX_TRACKED = 100_000;

    private final int perMin;
    private final ArrayDeque<Long> hits = new ArrayDeque<>();

    public FloodCounter(int perMin) {
        this.perMin = perMin;
    }

    public synchronized boolean record(long nowMillis) {
        hits.addLast(nowMillis);
        while (!hits.isEmpty() && nowMillis - hits.peekFirst() > 60_000L) {
            hits.pollFirst();
        }
        // Sob flood, descarta os mais antigos alem do teto (ja sabemos que e flood).
        while (hits.size() > MAX_TRACKED) {
            hits.pollFirst();
        }
        return hits.size() > perMin;
    }
}
