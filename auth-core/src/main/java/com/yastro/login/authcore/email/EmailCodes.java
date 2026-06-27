package com.yastro.login.authcore.email;

import com.yastro.login.common.AccountKey;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Códigos de verificação por e-mail (vínculo/recuperação), em memória, com validade
 * e USO ÚNICO. Limita tentativas erradas (o código é só 6 dígitos = 1M; sem limite,
 * seria brute-forçável dentro da janela).
 */
public final class EmailCodes {

    public enum Kind {
        LINK, RECOVER
    }

    public static final class Pending {
        final String email;
        final String code;
        final long expiresAt;
        final long issuedAt;
        final Kind kind;
        final AtomicInteger attempts = new AtomicInteger();
        volatile long frozenUntil; // 0 = nao congelado; > now = palpites errados bloqueados

        Pending(String email, String code, long expiresAt, long issuedAt, Kind kind) {
            this.email = email;
            this.code = code;
            this.expiresAt = expiresAt;
            this.issuedAt = issuedAt;
            this.kind = kind;
        }

        public String email() {
            return email;
        }
    }

    private static final int MAX_ATTEMPTS = 5;
    // Ao estourar MAX_ATTEMPTS de palpites ERRADOS, congela novos palpites por esta janela em
    // vez de APAGAR o codigo: apagar deixaria um terceiro que so conhece o nick inutilizar a
    // recuperacao da vitima. O codigo correto do dono continua passando (checado antes).
    private static final long ATTEMPT_FREEZE_MILLIS = 30_000L;

    private final SecureRandom random = new SecureRandom();
    private final long ttlMillis;
    private final long cooldownMillis;
    private final Map<String, Pending> pending = new ConcurrentHashMap<>();

    public EmailCodes(long ttlMillis, long cooldownMillis) {
        this.ttlMillis = ttlMillis;
        this.cooldownMillis = cooldownMillis;
    }

    /**
     * Gera (e substitui) um código para o jogador; retorna o código a enviar, ou
     * {@code null} se um código foi pedido há menos que o cooldown (anti-spam/bomb).
     */
    public String issue(String name, String email, Kind kind) {
        String k = key(name);
        long now = System.currentTimeMillis();
        Pending existing = pending.get(k);
        if (existing != null && now - existing.issuedAt < cooldownMillis) {
            return null;
        }
        String code = String.format(Locale.ROOT, "%06d", random.nextInt(1_000_000));
        pending.put(k, new Pending(email, code, now + ttlMillis, now, kind));
        return code;
    }

    /**
     * Confere e CONSOME o código (uso único) do tipo esperado. Retorna o {@link Pending}
     * (com o e-mail) se válido; null caso contrário. Erra demais -> congela novos palpites
     * por uma janela (NAO apaga o código, p/ um terceiro não inutilizar a recuperação do dono).
     */
    public Pending consume(String name, String code, Kind kind) {
        String k = key(name);
        Pending p = pending.get(k);
        long now = System.currentTimeMillis();
        if (p == null || p.kind != kind || now >= p.expiresAt) {
            return null;
        }
        // O código CORRETO consome sempre (uso único), mesmo após palpites errados de
        // terceiros: senão um atacante que só conhece o nick negaria a recuperação do dono.
        if (codeMatches(p.code, code)) {
            pending.remove(k);
            return p;
        }
        // Palpite errado. Dentro da janela de congelamento, rejeita sem contar (anti-brute).
        if (now < p.frozenUntil) {
            return null;
        }
        // Conta o erro. Ao atingir o teto, CONGELA novos palpites por uma janela curta (NAO
        // apaga o código) e zera o contador. Limita o brute a ~MAX por janela; o dono, com o
        // código certo, ainda passa acima. (Defesa completa = throttle por IP no comando.)
        if (p.attempts.incrementAndGet() >= MAX_ATTEMPTS) {
            p.attempts.set(0);
            p.frozenUntil = now + ATTEMPT_FREEZE_MILLIS;
        }
        return null;
    }

    private static boolean codeMatches(String a, String b) {
        if (b == null) {
            return false;
        }
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private static String key(String name) {
        return AccountKey.normalize(name);
    }
}
