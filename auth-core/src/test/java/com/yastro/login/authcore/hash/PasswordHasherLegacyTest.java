package com.yastro.login.authcore.hash;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class PasswordHasherLegacyTest {

    private final PasswordHasher hasher = new PasswordHasher(19456, 2, 1);
    private static final String AUTHME_SHA256 =
        "$SHA$11aa0706173d7272$dbba96681c2ae4e0bfdf226d70fbbc5e4ee3d8071faa613bc533fe8a64817d10";

    @Test
    void verifiesLegacyAuthMeSha256() {
        assertTrue(hasher.verify("password".toCharArray(), AUTHME_SHA256));
        assertFalse(hasher.verify("nope".toCharArray(), AUTHME_SHA256));
    }

    @Test
    void legacyHashNeedsRehash() {
        assertTrue(hasher.needsRehash(AUTHME_SHA256));
    }

    @Test
    void unknownFormatFailsClosed() {
        assertFalse(hasher.verify("password".toCharArray(), "not-a-hash"));
        assertFalse(hasher.verify("password".toCharArray(), "zzzz$zzzz"));
    }

    // ---- isFastLegacy: guia o padding de timing no login (fecha oráculo da janela de migração) ---

    @Test
    void isFastLegacyTrueForAuthMeSha256() {
        assertTrue(hasher.isFastLegacy(AUTHME_SHA256));
    }

    @Test
    void isFastLegacyTrueForPbkdf2() {
        assertTrue(hasher.isFastLegacy("pbkdf2_sha256$10000$aabbccdd$" + "00".repeat(32)));
    }

    @Test
    void isFastLegacyTrueForBareMd5() {
        assertTrue(hasher.isFastLegacy("d".repeat(32))); // 32 hex = MD5 cru
    }

    @Test
    void isFastLegacyTrueForBareSha512() {
        assertTrue(hasher.isFastLegacy("e".repeat(128))); // 128 hex = SHA512 cru
    }

    @Test
    void isFastLegacyFalseForArgon2id() {
        String argon2 = hasher.hash("password".toCharArray());
        assertFalse(hasher.isFastLegacy(argon2));
    }

    @Test
    void isFastLegacyFalseForBcrypt() {
        assertFalse(hasher.isFastLegacy("$2a$10$" + "a".repeat(53)));
    }

    @Test
    void isFastLegacyFalseForUnknownFormat() {
        assertFalse(hasher.isFastLegacy("not-a-hash"));
        assertFalse(hasher.isFastLegacy(null));
    }
}
