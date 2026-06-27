package com.yastro.login.authcore.auth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthThrottleTest {

    @Test
    void locksOutAfterMaxAttempts() {
        AuthThrottle t = new AuthThrottle(3, 60, 300);
        String key = "ip:1.2.3.4";
        assertTrue(t.tryAcquire(key));
        assertTrue(t.tryAcquire(key));
        assertTrue(t.tryAcquire(key));
        assertFalse(t.tryAcquire(key), "4ª tentativa deve travar");
        assertFalse(t.tryAcquire(key));
        assertTrue(t.lockoutRemainingSeconds(key) > 0);
    }

    @Test
    void clearResetsBucket() {
        AuthThrottle t = new AuthThrottle(2, 60, 300);
        String key = "ip:9.9.9.9";
        t.tryAcquire(key);
        t.tryAcquire(key);
        assertFalse(t.tryAcquire(key));
        t.clear(key);
        assertTrue(t.tryAcquire(key));
    }

    @Test
    void independentKeysDoNotInterfere() {
        AuthThrottle t = new AuthThrottle(1, 60, 300);
        assertTrue(t.tryAcquire("ip:a"));
        assertFalse(t.tryAcquire("ip:a"));
        assertTrue(t.tryAcquire("ip:b"), "outro IP não deve ser afetado");
    }
}
