package com.yastro.login.authcore.session;

import org.junit.jupiter.api.Test;

import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

class SessionServiceTest {

    /** Fake in-memory SessionStorage. */
    static final class FakeStorage implements SessionStorage {
        final Map<String, Session> map = new HashMap<>();
        public void upsertSession(String n, String ip, long exp) { map.put(n, new Session(n, ip, exp)); }
        public Optional<Session> findSession(String n) { return Optional.ofNullable(map.get(n)); }
        public void deleteSession(String n) { map.remove(n); }
        public void deleteExpiredSessions(long now) { map.values().removeIf(s -> s.expiresAtMillis() <= now); }
    }

    private final AtomicLong clock = new AtomicLong(1000L);
    private SessionService svc(FakeStorage s, boolean enabled) {
        return new SessionService(s, clock::get, enabled, 30L); // ttl 30 min
    }

    @Test
    void createThenValidateSameIp() {
        FakeStorage s = new FakeStorage();
        SessionService svc = svc(s, true);
        svc.create("joao", "1.2.3.4");
        assertTrue(svc.validate("joao", "1.2.3.4"));
    }

    @Test
    void validateWrongIpFails() {
        FakeStorage s = new FakeStorage();
        SessionService svc = svc(s, true);
        svc.create("joao", "1.2.3.4");
        assertFalse(svc.validate("joao", "9.9.9.9"));
    }

    @Test
    void validateNoSessionFails() {
        assertFalse(svc(new FakeStorage(), true).validate("ghost", "1.2.3.4"));
    }

    @Test
    void validateExpiredFails() {
        FakeStorage s = new FakeStorage();
        SessionService svc = svc(s, true);
        svc.create("joao", "1.2.3.4");           // expires at 1000 + 30*60000
        clock.set(1000L + 30L * 60_000L + 1L);   // just past expiry
        assertFalse(svc.validate("joao", "1.2.3.4"));
    }

    @Test
    void revokeRemoves() {
        FakeStorage s = new FakeStorage();
        SessionService svc = svc(s, true);
        svc.create("joao", "1.2.3.4");
        svc.revoke("joao");
        assertFalse(svc.validate("joao", "1.2.3.4"));
    }

    @Test
    void createReplacesPriorIp() {
        FakeStorage s = new FakeStorage();
        SessionService svc = svc(s, true);
        svc.create("joao", "1.1.1.1");
        svc.create("joao", "2.2.2.2");
        assertFalse(svc.validate("joao", "1.1.1.1"));
        assertTrue(svc.validate("joao", "2.2.2.2"));
    }

    @Test
    void disabledIsNoop() {
        FakeStorage s = new FakeStorage();
        SessionService svc = svc(s, false);
        svc.create("joao", "1.2.3.4");
        assertTrue(s.map.isEmpty());
        assertFalse(svc.validate("joao", "1.2.3.4"));
    }

    @Test
    void nullStorageIsNoop() {
        SessionService svc = new SessionService(null, clock::get, true, 30L);
        svc.create("joao", "1.2.3.4"); // no throw
        assertFalse(svc.validate("joao", "1.2.3.4"));
        svc.revoke("joao"); // no throw
    }
}
