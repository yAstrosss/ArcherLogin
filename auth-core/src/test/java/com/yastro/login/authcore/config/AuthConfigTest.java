package com.yastro.login.authcore.config;

import org.junit.jupiter.api.Test;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class AuthConfigTest {

    @Test
    void defaultDbTypeIsSqlite() {
        AuthConfig c = AuthConfig.fromMap(Map.of());
        assertEquals("sqlite", c.dbType);
    }

    @Test
    void defaultArgonMemoryKibIs19456() {
        AuthConfig c = AuthConfig.fromMap(Map.of());
        assertEquals(19456, c.argonMemoryKib);
    }

    @Test
    void clampsArgonMemoryToCeiling() {
        AuthConfig c = AuthConfig.fromMap(Map.of("hash.argon2.memory-kib", 9_999_999));
        assertEquals(65536, c.argonMemoryKib);
    }

    @Test
    void lowercasesDbTypeWithRootLocale() {
        AuthConfig c = AuthConfig.fromMap(Map.of("database.type", "MYSQL"));
        assertEquals("mysql", c.dbType);
    }

    @Test
    void clampsArgonMemoryToFloor() {
        // piso elevado ao baseline OWASP (19456 KiB); a config nunca enfraquece o hash.
        AuthConfig c = AuthConfig.fromMap(Map.of("hash.argon2.memory-kib", 1));
        assertEquals(19456, c.argonMemoryKib);
    }

    @Test
    void clampsMinPasswordBothEnds() {
        AuthConfig c1 = AuthConfig.fromMap(Map.of("password.min-length", 1));
        assertEquals(6, c1.minPassword);

        AuthConfig c2 = AuthConfig.fromMap(Map.of("password.min-length", 999));
        assertEquals(64, c2.minPassword);
    }

    @Test
    void clampsSessionDurationCeiling() {
        AuthConfig c = AuthConfig.fromMap(Map.of("session.duration-minutes", 99999));
        assertEquals(1440, c.sessionDurationMinutes);
    }

    @Test
    void appliesEmailDefaults() {
        AuthConfig c = AuthConfig.fromMap(Map.of());
        assertFalse(c.emailEnabled);
        assertEquals("smtp.gmail.com", c.emailHost);
        assertEquals(587, c.emailPort);
        assertEquals("", c.emailUser);
        assertEquals("", c.emailPassword);
        assertEquals("", c.emailFrom);
        assertEquals("tls", c.emailEncryption);
        assertEquals(10, c.emailCodeTtlMinutes);
    }

    @Test
    void clampsEmailCodeTtl() {
        assertEquals(60, AuthConfig.fromMap(Map.of("email.code-ttl-minutes", 9999)).emailCodeTtlMinutes); // teto
        assertEquals(1, AuthConfig.fromMap(Map.of("email.code-ttl-minutes", 0)).emailCodeTtlMinutes); // piso
    }

    @Test
    void lowercasesEmailEncryptionWithRootLocale() {
        assertEquals("ssl", AuthConfig.fromMap(Map.of("email.smtp.encryption", "SSL")).emailEncryption);
    }
}
