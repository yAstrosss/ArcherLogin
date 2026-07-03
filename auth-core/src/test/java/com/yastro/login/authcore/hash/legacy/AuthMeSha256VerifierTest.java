package com.yastro.login.authcore.hash.legacy;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class AuthMeSha256VerifierTest {

    private final AuthMeSha256Verifier v = new AuthMeSha256Verifier();

    // Golden vector from AuthMe's Sha256Test.
    private static final String GOLDEN =
        "$SHA$11aa0706173d7272$dbba96681c2ae4e0bfdf226d70fbbc5e4ee3d8071faa613bc533fe8a64817d10";

    @Test
    void matchesOnlyShaPrefix() {
        assertTrue(v.matches(GOLDEN));
        assertFalse(v.matches("$argon2id$v=19$m=1,t=1,p=1$aa$bb"));
        assertFalse(v.matches("$2a$10$abcdefghijklmnopqrstuv"));
        assertFalse(v.matches("deadbeef"));
    }

    @Test
    void verifyCorrectPassword() {
        assertTrue(v.verify("password".toCharArray(), GOLDEN));
    }

    @Test
    void rejectWrongPassword() {
        assertFalse(v.verify("wrong".toCharArray(), GOLDEN));
    }

    @Test
    void malformedReturnsFalseNeverThrows() {
        assertFalse(v.verify("password".toCharArray(), "$SHA$onlyonepart"));
        assertFalse(v.verify("password".toCharArray(), "$SHA$$"));
    }
}
