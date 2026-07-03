package com.yastro.login.proxy;

import com.yastro.login.authcore.auth.AuthThrottle;
import com.yastro.login.authcore.config.AuthConfig;
import com.yastro.login.authcore.hash.PasswordHasher;
import com.yastro.login.authcore.storage.Account;
import com.yastro.login.authcore.storage.AccountStorage;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthServiceTest {

    /** Storage fake em memória. */
    static final class FakeStorage implements AccountStorage {
        final Map<String, Account> byName = new HashMap<>();
        @Override public boolean isRegistered(String name) { return byName.containsKey(name.toLowerCase()); }
        @Override public Optional<Account> find(String name) { return Optional.ofNullable(byName.get(name.toLowerCase())); }
        @Override public void register(Account a) { byName.put(a.name().toLowerCase(), a); }
        @Override public void updatePassword(String name, String h) {
            Account a = byName.get(name.toLowerCase());
            byName.put(name.toLowerCase(), new Account(a.name(), a.uuid(), h, a.email(), a.regIp(), a.lastIp(), a.premium(), a.registeredAt(), a.lastLogin(), a.bedrock()));
        }
        @Override public void touchLogin(String name, String ip, long when) { }
        @Override public void setEmail(String name, String email) { }
        @Override public int countByRegIp(String ip) {
            int n = 0;
            for (Account a : byName.values()) {
                if (ip != null && ip.equals(a.regIp())) n++;
            }
            return n;
        }
        @Override public void close() { }
    }

    private AuthService service(AccountStorage storage) {
        return service(storage, IpLimitPolicy.disabled());
    }

    private AuthService service(AccountStorage storage, IpLimitPolicy ipLimit) {
        AuthConfig cfg = AuthConfig.fromMap(Map.of(
                "hash.argon2.memory-kib", "8192",
                "hash.argon2.iterations", "1",
                "password.min-length", "8"));
        PasswordHasher hasher = new PasswordHasher(cfg.argonMemoryKib, cfg.argonIterations, cfg.argonParallelism);
        AuthThrottle throttle = new AuthThrottle(cfg.maxAttempts, cfg.attemptWindowSeconds, cfg.lockoutSeconds);
        AuthThrottle accountThrottle = new AuthThrottle(cfg.accountMaxAttempts, cfg.attemptWindowSeconds, cfg.accountLockoutSeconds);
        return new AuthService(storage, hasher, throttle, accountThrottle, cfg, ipLimit, Runnable::run);
    }

    @Test
    void registerThenLoginSucceeds() {
        FakeStorage st = new FakeStorage();
        AuthService svc = service(st);
        String uuid = "00000000-0000-0000-0000-000000000001";

        AuthOutcome reg = svc.register("Bob", uuid, "supersecret".toCharArray(), "supersecret".toCharArray(), "1.2.3.4");
        assertTrue(reg.success());
        assertEquals("register.success", reg.messageKey());
        assertTrue(st.isRegistered("bob"));

        AuthOutcome log = svc.login("Bob", uuid, "supersecret".toCharArray(), "1.2.3.4");
        assertTrue(log.success());
        assertEquals("login.success", log.messageKey());
    }

    @Test
    void loginUnregisteredFails() {
        AuthOutcome log = service(new FakeStorage()).login("Nobody", "u", "whatever1".toCharArray(), "1.2.3.4");
        assertFalse(log.success());
        assertEquals("login.not-registered", log.messageKey());
    }

    @Test
    void loginWrongPasswordFails() {
        FakeStorage st = new FakeStorage();
        AuthService svc = service(st);
        svc.register("Bob", "u", "rightpass1".toCharArray(), "rightpass1".toCharArray(), "1.2.3.4");
        AuthOutcome log = svc.login("Bob", "u", "wrongpass1".toCharArray(), "1.2.3.4");
        assertFalse(log.success());
        assertEquals("login.wrong", log.messageKey());
    }

    @Test
    void registerMismatchFails() {
        AuthOutcome reg = service(new FakeStorage()).register("Bob", "u", "aaaaaaaa".toCharArray(), "bbbbbbbb".toCharArray(), "1.2.3.4");
        assertFalse(reg.success());
        assertEquals("register.mismatch", reg.messageKey());
    }

    @Test
    void registerTooShortFails() {
        AuthOutcome reg = service(new FakeStorage()).register("Bob", "u", "abc".toCharArray(), "abc".toCharArray(), "1.2.3.4");
        assertFalse(reg.success());
        assertEquals("register.too-short", reg.messageKey());
    }

    @Test
    void registerAlreadyFails() {
        FakeStorage st = new FakeStorage();
        AuthService svc = service(st);
        svc.register("Bob", "u", "supersecret".toCharArray(), "supersecret".toCharArray(), "1.2.3.4");
        AuthOutcome reg = svc.register("Bob", "u", "supersecret".toCharArray(), "supersecret".toCharArray(), "1.2.3.4");
        assertFalse(reg.success());
        assertEquals("register.already", reg.messageKey());
    }

    @Test
    void usernameAsPasswordRejected() {
        AuthOutcome reg = service(new FakeStorage()).register("Roberto", "u", "roberto".toCharArray(), "roberto".toCharArray(), "1.2.3.4");
        assertFalse(reg.success());
        // too-short tem prioridade? "roberto" tem 7 < 8 -> too-short. Use nick longo:
        AuthOutcome reg2 = service(new FakeStorage()).register("RobertoLongo", "u", "robertolongo".toCharArray(), "robertolongo".toCharArray(), "1.2.3.4");
        assertFalse(reg2.success());
        assertEquals("register.username-as-password", reg2.messageKey());
    }

    @Test
    void throttleLocksAfterMaxAttempts() {
        FakeStorage st = new FakeStorage();
        AuthService svc = service(st);
        svc.register("Bob", "u", "rightpass1".toCharArray(), "rightpass1".toCharArray(), "9.9.9.9");
        // maxAttempts default = 5; estoura no 6º
        AuthOutcome last = null;
        for (int i = 0; i < 7; i++) {
            last = svc.login("Bob", "u", "wrongpass1".toCharArray(), "9.9.9.9");
        }
        assertFalse(last.success());
        assertEquals("login.too-many", last.messageKey());
    }

    @Test
    void storageUnavailableFailsClosed() {
        AuthService svc = service(null);
        assertFalse(svc.storageAvailable());
        AuthOutcome log = svc.login("Bob", "u", "whatever1".toCharArray(), "1.2.3.4");
        assertFalse(log.success());
        assertEquals("error.internal", log.messageKey());
    }

    @Test
    void changePasswordSucceedsWithRightCurrent() {
        FakeStorage st = new FakeStorage();
        AuthService svc = service(st);
        svc.register("Bob", "u", "oldpassword".toCharArray(), "oldpassword".toCharArray(), "1.2.3.4");
        AuthOutcome cp = svc.changePassword("Bob", "oldpassword".toCharArray(), "newpassword".toCharArray(), "1.2.3.4");
        assertTrue(cp.success());
        assertEquals("changepass.success", cp.messageKey());
        // a nova senha agora loga
        assertTrue(svc.login("Bob", "u", "newpassword".toCharArray(), "1.2.3.4").success());
    }

    @Test
    void changePasswordWrongCurrentFails() {
        FakeStorage st = new FakeStorage();
        AuthService svc = service(st);
        svc.register("Bob", "u", "oldpassword".toCharArray(), "oldpassword".toCharArray(), "1.2.3.4");
        AuthOutcome cp = svc.changePassword("Bob", "WRONGcurrent".toCharArray(), "newpassword".toCharArray(), "1.2.3.4");
        assertFalse(cp.success());
        assertEquals("changepass.wrong", cp.messageKey());
    }

    @Test
    void changePasswordUnregisteredFails() {
        AuthOutcome cp = service(new FakeStorage()).changePassword("Ghost", "whatever1".toCharArray(), "newpassword".toCharArray(), "1.2.3.4");
        assertFalse(cp.success());
        assertEquals("changepass.not-registered", cp.messageKey());
    }

    @Test
    void loginUuidMismatchFails() {
        FakeStorage st = new FakeStorage();
        AuthService svc = service(st);
        svc.register("Bob", "uuid-AAA", "rightpass1".toCharArray(), "rightpass1".toCharArray(), "1.2.3.4");
        AuthOutcome log = svc.login("Bob", "uuid-BBB", "rightpass1".toCharArray(), "1.2.3.4");
        assertFalse(log.success());
        assertEquals("login.uuid-mismatch", log.messageKey());
    }

    @Test
    void registerTooLongFails() {
        // 73 ASCII chars = 73 UTF-8 bytes > 72 cap; nick differs so username-as-password is not hit first
        char[] pass = "a".repeat(73).toCharArray();
        AuthOutcome reg = service(new FakeStorage()).register("Bob", "u", pass, "a".repeat(73).toCharArray(), "1.2.3.4");
        assertFalse(reg.success());
        assertEquals("register.too-long", reg.messageKey());
    }

    @Test
    void registerIsThrottledPerIpToProtectHashPool() {
        FakeStorage st = new FakeStorage();
        AuthService svc = service(st);
        // maxAttempts default = 5; 6th distinct register from the same IP must lock.
        AuthOutcome last = null;
        for (int i = 0; i < 6; i++) {
            last = svc.register("User" + i, "u" + i,
                    "supersecret".toCharArray(), "supersecret".toCharArray(), "5.5.5.5");
        }
        assertFalse(last.success());
        assertEquals("login.too-many", last.messageKey());
    }

    @Test
    void trySubmitRejectsWhenExecutorSaturated() throws Exception {
        // 1 worker, fila cap 1 -> a 3ª task não cabe (worker ocupado + fila cheia) e é rejeitada (C1).
        java.util.concurrent.ExecutorService ex = AuthService.newExecutor(1, 1);
        AuthConfig cfg = AuthConfig.fromMap(Map.of());
        AuthService svc = new AuthService(new FakeStorage(),
                new PasswordHasher(cfg.argonMemoryKib, cfg.argonIterations, cfg.argonParallelism),
                new AuthThrottle(cfg.maxAttempts, cfg.attemptWindowSeconds, cfg.lockoutSeconds),
                new AuthThrottle(cfg.accountMaxAttempts, cfg.attemptWindowSeconds, cfg.accountLockoutSeconds),
                cfg, IpLimitPolicy.disabled(), ex);
        java.util.concurrent.CountDownLatch started = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch hold = new java.util.concurrent.CountDownLatch(1);
        try {
            assertTrue(svc.trySubmit(() -> {
                started.countDown();
                try { hold.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            }));
            assertTrue(started.await(2, java.util.concurrent.TimeUnit.SECONDS));
            assertTrue(svc.trySubmit(() -> { })); // enche a fila (cap 1)
            assertFalse(svc.trySubmit(() -> { })); // worker ocupado + fila cheia -> rejeitada
        } finally {
            hold.countDown();
            ex.shutdownNow();
        }
    }

    @Test
    void lockoutRemainingSecondsReflectsLockWithoutConsuming() {
        AuthService svc = service(new FakeStorage());
        assertEquals(0L, svc.lockoutRemainingSeconds("7.7.7.7")); // livre antes de qualquer tentativa
        for (int i = 0; i < 7; i++) {
            svc.login("Ghost", "u", "wrongpass1".toCharArray(), "7.7.7.7"); // estoura o lockout por IP
        }
        long a = svc.lockoutRemainingSeconds("7.7.7.7");
        long b = svc.lockoutRemainingSeconds("7.7.7.7");
        assertTrue(a > 0, "IP deve estar em lockout após estourar as tentativas");
        assertTrue(b > 0 && b <= a, "leitura read-only não estende/consome o lockout");
    }

    // ---- lockout por conta (brute-force distribuído) -------------------

    @Test
    void accountLockoutAfterDistributedAttemptsFromManyIps() {
        FakeStorage st = new FakeStorage();
        AuthService svc = service(st);
        svc.register("Bob", "u", "rightpass1".toCharArray(), "rightpass1".toCharArray(), "1.1.1.1"); // lastIp=1.1.1.1
        // accountMaxAttempts default = 10; cada IP DISTINTO (≠ lastIp) tenta 1x: o throttle por IP
        // nunca dispara (1 < 5), mas a CONTA acumula e trava, exatamente o ataque distribuído.
        AuthOutcome last = null;
        for (int i = 0; i < 12; i++) {
            last = svc.login("Bob", "u", "wrongpass1".toCharArray(), "10.0.0." + i);
        }
        assertFalse(last.success());
        assertEquals("login.too-many", last.messageKey());
    }

    @Test
    void accountLockoutExemptsOwnersLastGoodIp() {
        FakeStorage st = new FakeStorage();
        AuthService svc = service(st);
        svc.register("Bob", "u", "rightpass1".toCharArray(), "rightpass1".toCharArray(), "1.1.1.1"); // lastIp=1.1.1.1
        for (int i = 0; i < 12; i++) { // atacantes de vários IPs travam a CONTA
            svc.login("Bob", "u", "wrongpass1".toCharArray(), "10.0.0." + i);
        }
        // o dono, do seu último IP-bom (1.1.1.1), ainda loga com a senha certa apesar da conta travada
        AuthOutcome owner = svc.login("Bob", "u", "rightpass1".toCharArray(), "1.1.1.1");
        assertTrue(owner.success(), "dono no último IP-bom não pode ser trancado fora (anti-grief)");
        assertEquals("login.success", owner.messageKey());
    }

    @Test
    void accountLockoutBlocksEvenCorrectPasswordFromUnknownIp() {
        FakeStorage st = new FakeStorage();
        AuthService svc = service(st);
        svc.register("Bob", "u", "rightpass1".toCharArray(), "rightpass1".toCharArray(), "1.1.1.1");
        for (int i = 0; i < 12; i++) {
            svc.login("Bob", "u", "wrongpass1".toCharArray(), "10.0.0." + i);
        }
        // IP desconhecido + senha CERTA, mas conta travada -> barrado (não é o IP-bom da vítima)
        AuthOutcome attacker = svc.login("Bob", "u", "rightpass1".toCharArray(), "9.9.9.9");
        assertFalse(attacker.success());
        assertEquals("login.too-many", attacker.messageKey());
    }

    @Test
    void registerBlockedWhenIpAtLimit() {
        FakeStorage st = new FakeStorage();
        AuthService svc = service(st, new IpLimitPolicy(true, 2, java.util.Set.of()));
        assertTrue(svc.register("A", "u", "supersecret".toCharArray(), "supersecret".toCharArray(), "3.3.3.3").success());
        assertTrue(svc.register("B", "u", "supersecret".toCharArray(), "supersecret".toCharArray(), "3.3.3.3").success());
        AuthOutcome third = svc.register("C", "u", "supersecret".toCharArray(), "supersecret".toCharArray(), "3.3.3.3");
        assertFalse(third.success());
        assertEquals("register.ip-limit", third.messageKey());
    }

    @Test
    void registerBypassIpExemptFromLimit() {
        FakeStorage st = new FakeStorage();
        AuthService svc = service(st, new IpLimitPolicy(true, 1, java.util.Set.of("127.0.0.1")));
        assertTrue(svc.register("A", "u", "supersecret".toCharArray(), "supersecret".toCharArray(), "127.0.0.1").success());
        assertTrue(svc.register("B", "u", "supersecret".toCharArray(), "supersecret".toCharArray(), "127.0.0.1").success());
    }
}
