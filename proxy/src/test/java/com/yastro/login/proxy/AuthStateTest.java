package com.yastro.login.proxy;

import org.junit.jupiter.api.Test;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class AuthStateTest {

    @Test
    void unknownPlayerIsNotAuthenticated() {
        AuthState s = new AuthState();
        assertFalse(s.isAuthenticated(UUID.randomUUID()));
    }

    @Test
    void markThenIsAuthenticated() {
        AuthState s = new AuthState();
        UUID id = UUID.randomUUID();
        s.markAuthenticated(id);
        assertTrue(s.isAuthenticated(id));
    }

    @Test
    void clearRemovesAuthentication() {
        AuthState s = new AuthState();
        UUID id = UUID.randomUUID();
        s.markAuthenticated(id);
        s.clear(id);
        assertFalse(s.isAuthenticated(id));
    }
}
