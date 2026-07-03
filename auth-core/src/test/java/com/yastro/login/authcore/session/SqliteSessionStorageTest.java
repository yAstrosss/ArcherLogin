package com.yastro.login.authcore.session;

import com.yastro.login.authcore.storage.SqliteStorage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class SqliteSessionStorageTest {

    @Test
    void upsertFindDeleteRoundTrip(@TempDir Path dir) throws Exception {
        try (SqliteStorage s = SqliteStorage.open(dir.resolve("t.db"))) {
            s.upsertSession("joao", "1.2.3.4", 5000L);
            Optional<Session> got = s.findSession("joao");
            assertTrue(got.isPresent());
            assertEquals("joao", got.get().nameLower());
            assertEquals("1.2.3.4", got.get().ip());
            assertEquals(5000L, got.get().expiresAtMillis());

            // upsert replaces (latest IP + expiry win)
            s.upsertSession("joao", "9.9.9.9", 8000L);
            assertEquals("9.9.9.9", s.findSession("joao").orElseThrow().ip());
            assertEquals(8000L, s.findSession("joao").orElseThrow().expiresAtMillis());

            s.deleteSession("joao");
            assertTrue(s.findSession("joao").isEmpty());
        }
    }

    @Test
    void deleteExpiredRemovesOnlyPast(@TempDir Path dir) throws Exception {
        try (SqliteStorage s = SqliteStorage.open(dir.resolve("t.db"))) {
            s.upsertSession("old", "1.1.1.1", 100L);
            s.upsertSession("new", "2.2.2.2", 10_000L);
            s.deleteExpiredSessions(5000L);
            assertTrue(s.findSession("old").isEmpty());
            assertTrue(s.findSession("new").isPresent());
        }
    }
}
