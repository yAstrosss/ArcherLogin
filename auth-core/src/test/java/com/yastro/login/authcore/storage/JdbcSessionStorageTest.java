package com.yastro.login.authcore.storage;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * SQL real de sessão (via SQLite num arquivo temporário). Cobre upsert,
 * leitura-só-se-ativa, expiração por {@code now}, remoção e purga.
 */
class JdbcSessionStorageTest {

    private static byte[] hash(int seed) {
        byte[] h = new byte[32];
        h[0] = (byte) seed;
        h[31] = (byte) (seed * 7);
        return h;
    }

    @Test
    void upsertFindRemovePurge() throws Exception {
        Path db = Files.createTempFile("archer-sess", ".db");
        try (SqliteStorage s = SqliteStorage.open(db)) {
            byte[] h1 = hash(7);
            s.upsertSession("bob", h1, 10_000L);

            assertArrayEquals(h1, s.findSessionHash("bob", 5_000L)); // ativa
            assertNull(s.findSessionHash("bob", 10_000L)); // now >= exp -> expirada
            assertNull(s.findSessionHash("alice", 5_000L)); // inexistente

            byte[] h2 = hash(9);
            s.upsertSession("bob", h2, 20_000L); // upsert sobrescreve
            assertArrayEquals(h2, s.findSessionHash("bob", 5_000L));

            s.removeSession("bob");
            assertNull(s.findSessionHash("bob", 5_000L));

            s.upsertSession("x", h1, 100L);
            s.purgeSessions(200L); // 100 <= 200 -> apaga
            assertNull(s.findSessionHash("x", 50L));
        } finally {
            Files.deleteIfExists(db);
        }
    }
}
