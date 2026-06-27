package com.yastro.login.authcore.auth;

import com.yastro.login.authcore.storage.SessionStorage;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.function.LongSupplier;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link SharedSessionStore}: mesma semântica de token do {@link SessionManager},
 * mas persistindo no banco compartilhado. Guarda HASH, não o token cru. Executor
 * síncrono e clock injetável tornam o teste determinístico (sem sleep).
 */
class SharedSessionStoreTest {

    /** Store de sessão em memória (fake de teste, só Map, sem comportamento a testar). */
    private static final class FakeSessionStorage implements SessionStorage {
        final Map<String, byte[]> hash = new HashMap<>();
        final Map<String, Long> exp = new HashMap<>();

        @Override public void upsertSession(String key, byte[] tokenHash, long expiresAt) {
            hash.put(key, tokenHash);
            exp.put(key, expiresAt);
        }
        @Override public byte[] findSessionHash(String key, long now) {
            Long e = exp.get(key);
            return (e != null && now < e) ? hash.get(key) : null;
        }
        @Override public void removeSession(String key) {
            hash.remove(key);
            exp.remove(key);
        }
        @Override public void purgeSessions(long now) {
            exp.entrySet().removeIf(en -> now >= en.getValue());
        }
    }

    private static final Executor SYNC = Runnable::run;
    private static final Logger LOG = Logger.getLogger("test");

    private static byte[] sha256(byte[] b) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(b);
    }

    private static SharedSessionStore store(SessionStorage st, LongSupplier clock) {
        return new SharedSessionStore(st, SYNC, true, 5, clock, LOG);
    }

    @Test
    void validOnlyWithSameTokenCaseInsensitive() {
        SharedSessionStore s = store(new FakeSessionStorage(), () -> 1000L);
        assertFalse(s.matches("Bob", new byte[32]));
        byte[] token = s.open("Bob");
        assertNotNull(token);
        assertTrue(s.matches("Bob", token));
        assertTrue(s.matches("bob", token)); // chave case-insensitive
    }

    @Test
    void invalidWithWrongToken() {
        SharedSessionStore s = store(new FakeSessionStorage(), () -> 1000L);
        byte[] token = s.open("Bob");
        byte[] wrong = token.clone();
        wrong[0] ^= 0xFF;
        assertFalse(s.matches("Bob", wrong));
    }

    @Test
    void invalidateClears() {
        SharedSessionStore s = store(new FakeSessionStorage(), () -> 1000L);
        byte[] token = s.open("Bob");
        s.invalidate("Bob");
        assertFalse(s.matches("Bob", token));
    }

    @Test
    void nullTokenNeverValid() {
        SharedSessionStore s = store(new FakeSessionStorage(), () -> 1000L);
        s.open("Bob");
        assertFalse(s.matches("Bob", null));
    }

    @Test
    void disabledNeverOpensNorValidates() {
        SharedSessionStore off = new SharedSessionStore(
                new FakeSessionStorage(), SYNC, false, 5, () -> 1000L, LOG);
        assertNull(off.open("Bob"));
        assertFalse(off.matches("Bob", new byte[32]));
        assertFalse(off.isEnabled());

        SharedSessionStore zero = new SharedSessionStore(
                new FakeSessionStorage(), SYNC, true, 0, () -> 1000L, LOG);
        assertFalse(zero.isEnabled());
        assertNull(zero.open("Bob"));
    }

    @Test
    void storesHashNotRawToken() throws Exception {
        FakeSessionStorage st = new FakeSessionStorage();
        SharedSessionStore s = store(st, () -> 1000L);
        byte[] token = s.open("Bob");
        byte[] stored = st.hash.get("bob");
        assertNotNull(stored);
        assertFalse(MessageDigest.isEqual(token, stored)); // NÃO é o token cru
        assertArrayEquals(sha256(token), stored); // é SHA-256(token)
    }

    @Test
    void expiresAfterDuration() {
        long[] now = {1000L};
        SharedSessionStore s = store(new FakeSessionStorage(), () -> now[0]);
        byte[] token = s.open("Bob");
        assertTrue(s.matches("Bob", token));
        now[0] = 1000L + 5L * 60_000L + 1; // passou da janela de 5 min
        assertFalse(s.matches("Bob", token));
    }
}
