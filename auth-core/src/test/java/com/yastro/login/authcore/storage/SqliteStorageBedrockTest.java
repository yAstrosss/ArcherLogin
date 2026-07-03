package com.yastro.login.authcore.storage;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class SqliteStorageBedrockTest {

    @Test
    void registerAndFindRoundTripsBedrockFlag(@TempDir Path dir) throws Exception {
        try (SqliteStorage s = SqliteStorage.open(dir.resolve("t.db"))) {
            s.register(new Account(".GamerTag", "uuid-1", "", null, "1.2.3.4", "1.2.3.4",
                    false, 100L, 0L, true)); // bedrock = true
            Optional<Account> a = s.find(".GamerTag");
            assertTrue(a.isPresent());
            assertTrue(a.get().bedrock());
        }
    }

    @Test
    void javaAccountBedrockFalse(@TempDir Path dir) throws Exception {
        try (SqliteStorage s = SqliteStorage.open(dir.resolve("t.db"))) {
            s.register(new Account("Joao", "uuid-2", "$argon2id$...", null, "1.2.3.4", "1.2.3.4",
                    false, 100L, 0L, false));
            assertFalse(s.find("Joao").orElseThrow().bedrock());
        }
    }
}
