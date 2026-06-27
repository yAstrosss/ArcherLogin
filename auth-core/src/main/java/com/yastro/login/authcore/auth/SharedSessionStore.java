package com.yastro.login.authcore.auth;

import com.yastro.login.authcore.storage.SessionStorage;
import com.yastro.login.common.AccountKey;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.LongSupplier;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Sessão de login PERSISTIDA no banco compartilhado (MySQL), o login vale em
 * TODOS os backends da rede atrás do proxy e sobrevive ao restart de um backend.
 *
 * <p>Segurança: guarda só o <b>SHA-256 do token</b> (32 bytes de entropia, não
 * precisa de sal); um vazamento do banco não entrega sessões utilizáveis. A
 * comparação é em tempo constante ({@link MessageDigest#isEqual}). Chave =
 * {@code name.toLowerCase} (mesmo identificador das contas, estável entre
 * backends; o UUID aqui seria função do nome, modo offline, sem ganho).
 *
 * <p>Threading: {@link #open} e {@link #invalidate} retornam na hora e jogam a
 * escrita no {@code writeExecutor} (não bloqueiam o chamador). {@link #matches}
 * faz a LEITURA síncrona no banco, o chamador deve invocá-la fora da main thread.
 *
 * <p>Falha-fechado: erro de banco em {@code matches} retorna {@code false} (cai no
 * fluxo de senha); em {@code open}/{@code invalidate} é logado e a sessão
 * simplesmente não retoma (degradação graciosa, igual a cliente sem cookie).
 */
public final class SharedSessionStore implements SessionStore {

    private static final int TOKEN_LEN = 32;
    private static final int PURGE_EVERY = 500;

    private final SecureRandom random = new SecureRandom();
    private final SessionStorage storage;
    private final Executor writeExecutor;
    private final LongSupplier clock;
    private final Logger logger;
    private final AtomicInteger ops = new AtomicInteger();

    private volatile boolean enabled;
    private volatile long durationMillis;

    public SharedSessionStore(SessionStorage storage, Executor writeExecutor,
                              boolean enabled, int durationMinutes,
                              LongSupplier clock, Logger logger) {
        this.storage = storage;
        this.writeExecutor = writeExecutor;
        this.clock = clock;
        this.logger = logger;
        reconfigure(enabled, durationMinutes);
    }

    @Override
    public byte[] open(String name) {
        if (!enabled) {
            return null;
        }
        byte[] token = new byte[TOKEN_LEN];
        random.nextBytes(token);
        byte[] hash = sha256(token);
        String key = key(name);
        long expiresAt = clock.getAsLong() + durationMillis;
        writeExecutor.execute(() -> {
            try {
                storage.upsertSession(key, hash, expiresAt);
            } catch (Exception e) {
                logger.log(Level.WARNING, "Falha ao gravar sessão compartilhada de " + key, e);
            }
        });
        return token;
    }

    @Override
    public boolean matches(String name, byte[] presentedToken) {
        if (!enabled || presentedToken == null) {
            return false;
        }
        maybePurge();
        try {
            byte[] stored = storage.findSessionHash(key(name), clock.getAsLong());
            if (stored == null) {
                return false;
            }
            return MessageDigest.isEqual(stored, sha256(presentedToken));
        } catch (Exception e) {
            // Fail-closed: sem certeza, não retoma a sessão (pede senha).
            logger.log(Level.WARNING, "Falha ao ler sessão compartilhada de " + name, e);
            return false;
        }
    }

    @Override
    public void invalidate(String name) {
        String key = key(name);
        writeExecutor.execute(() -> {
            try {
                storage.removeSession(key);
            } catch (Exception e) {
                logger.log(Level.WARNING, "Falha ao invalidar sessão compartilhada de " + key, e);
            }
        });
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public void reconfigure(boolean enabled, int durationMinutes) {
        // duration <= 0 desliga sessões (evita sessão permanente acidental).
        this.enabled = enabled && durationMinutes > 0;
        this.durationMillis = durationMinutes * 60_000L;
    }

    private void maybePurge() {
        if (ops.incrementAndGet() % PURGE_EVERY != 0) {
            return;
        }
        long now = clock.getAsLong();
        writeExecutor.execute(() -> {
            try {
                storage.purgeSessions(now);
            } catch (Exception e) {
                logger.log(Level.WARNING, "Falha na purga de sessões expiradas", e);
            }
        });
    }

    private static String key(String name) {
        return AccountKey.normalize(name);
    }

    private static byte[] sha256(byte[] in) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(in);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 indisponível nesta JVM", e);
        }
    }
}
