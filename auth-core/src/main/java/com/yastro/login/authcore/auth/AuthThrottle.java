package com.yastro.login.authcore.auth;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Rate-limit + lockout por chave. Usado SÓ por IP (lockout por nome permitiria
 * griefing da conta de terceiro: mesmo nome -> mesmo alvo). O IP do atacante se
 * auto-limita.
 *
 * <ul>
 * <li>DoS de login: barra ANTES de enfileirar o hash (caro).</li>
 * <li>Brute-force: após {@code maxAttempts} numa janela, o IP entra em lockout.</li>
 * </ul>
 *
 * Buckets ociosos são removidos por TTL para não crescer sem limite sob flood de
 * IPs falsos.
 */
public final class AuthThrottle {

    private static final class Bucket {
        int count;
        long windowStart;
        long lockedUntil;
        long lastTouch;
    }

    private final int maxAttempts;
    private final long windowMillis;
    private final long lockoutMillis;
    private final long evictMillis;

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();
    private final AtomicInteger ops = new AtomicInteger();

    public AuthThrottle(int maxAttempts, int windowSeconds, int lockoutSeconds) {
        this.maxAttempts = maxAttempts;
        this.windowMillis = windowSeconds * 1000L;
        this.lockoutMillis = lockoutSeconds * 1000L;
        this.evictMillis = Math.max(windowMillis, lockoutMillis) * 2L;
    }

    public boolean tryAcquire(String key) {
        long now = System.currentTimeMillis();
        maybeEvict(now);
        Bucket b = buckets.computeIfAbsent(key, k -> {
            // Inicializa os timestamps na criação: senão o bucket nasce com lastTouch=0 e
            // um maybeEvict concorrente (entre este create e o synchronized abaixo) o
            // despejaria antes do primeiro toque, perdendo a 1ª tentativa do rate-limit.
            Bucket nb = new Bucket();
            nb.windowStart = now;
            nb.lastTouch = now;
            return nb;
        });
        synchronized (b) {
            b.lastTouch = now;
            if (now < b.lockedUntil) {
                return false;
            }
            if (now - b.windowStart > windowMillis) {
                b.windowStart = now;
                b.count = 0;
            }
            b.count++;
            if (b.count > maxAttempts) {
                b.lockedUntil = now + lockoutMillis;
                return false;
            }
            return true;
        }
    }

    public long lockoutRemainingSeconds(String key) {
        Bucket b = buckets.get(key);
        if (b == null) {
            return 0;
        }
        synchronized (b) {
            long remaining = b.lockedUntil - System.currentTimeMillis();
            return remaining > 0 ? (remaining / 1000L) + 1 : 0;
        }
    }

    public void clear(String key) {
        buckets.remove(key);
    }

    /** Limpeza preguiçosa: a cada 1000 chamadas remove buckets ociosos e destravados. */
    private void maybeEvict(long now) {
        if (ops.incrementAndGet() % 1000 != 0) {
            return;
        }
        buckets.entrySet().removeIf(e -> {
            Bucket b = e.getValue();
            synchronized (b) {
                return now > b.lockedUntil && (now - b.lastTouch) > evictMillis;
            }
        });
    }
}
