package com.yastro.login.authcore.auth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionManagerTest {

    // Núcleo puro (token + expiração + reconfigure). O I/O de cookie vive no chamador.

    @Test
    void validOnlyWithSameTokenCaseInsensitive() {
        SessionManager sm = new SessionManager(true, 5);
        assertFalse(sm.matches("Bob", new byte[32]));
        byte[] token = sm.open("Bob");
        assertTrue(sm.matches("Bob", token));
        assertTrue(sm.matches("bob", token)); // chave case-insensitive
    }

    @Test
    void invalidWithWrongToken() {
        SessionManager sm = new SessionManager(true, 5);
        byte[] token = sm.open("Bob");
        byte[] wrong = token.clone();
        wrong[0] ^= 0xFF;
        assertFalse(sm.matches("Bob", wrong));
    }

    @Test
    void invalidateClears() {
        SessionManager sm = new SessionManager(true, 5);
        byte[] token = sm.open("Bob");
        sm.invalidate("Bob");
        assertFalse(sm.matches("Bob", token));
    }

    @Test
    void disabledNeverOpensNorValidates() {
        SessionManager off = new SessionManager(false, 5);
        assertNull(off.open("Bob"));
        assertFalse(off.matches("Bob", new byte[32]));
        assertFalse(off.isEnabled());

        SessionManager zero = new SessionManager(true, 0);
        assertFalse(zero.isEnabled());
        assertNull(zero.open("Bob"));
    }

    @Test
    void nullTokenNeverValid() {
        SessionManager sm = new SessionManager(true, 5);
        sm.open("Bob");
        assertFalse(sm.matches("Bob", null));
    }
}
