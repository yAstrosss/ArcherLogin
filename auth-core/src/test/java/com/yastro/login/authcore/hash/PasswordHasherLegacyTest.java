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
}
