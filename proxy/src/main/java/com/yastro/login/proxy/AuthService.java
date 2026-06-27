package com.yastro.login.proxy;

import com.yastro.login.authcore.auth.AuthThrottle;
import com.yastro.login.authcore.config.AuthConfig;
import com.yastro.login.authcore.hash.PasswordHasher;
import com.yastro.login.authcore.storage.Account;
import com.yastro.login.authcore.storage.AccountStorage;
import com.yastro.login.common.AccountKey;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Orquestra a auth: throttle por IP -> storage -> hash, tudo SÍNCRONO (deve ser
 * chamado dentro do executor via {@link #submit}). Retorna {@link AuthOutcome}
 * puro (chave i18n), sem tocar em tipos Velocity, daí ser unit-testável.
 *
 * <p>Fail-closed: {@code storage == null} (banco fora) responde {@code error.internal}
 * e nunca autentica.
 */
public final class AuthService {

    private final AccountStorage storage; // pode ser null (banco fora)
    private final PasswordHasher hasher;
    private final AuthThrottle throttle; // por IP (DoS de login + brute-force de 1 IP)
    private final AuthThrottle accountThrottle; // por CONTA (brute-force distribuído de vários IPs)
    private final AuthConfig cfg;
    private final IpLimitPolicy ipLimit;
    private final Executor executor;

    public AuthService(AccountStorage storage, PasswordHasher hasher, AuthThrottle throttle,
                       AuthThrottle accountThrottle, AuthConfig cfg, IpLimitPolicy ipLimit, Executor executor) {
        this.storage = storage;
        this.hasher = hasher;
        this.throttle = throttle;
        this.accountThrottle = accountThrottle;
        this.cfg = cfg;
        this.ipLimit = ipLimit;
        this.executor = executor;
    }

    public boolean storageAvailable() {
        return storage != null;
    }

    /**
     * Enfileira a task no pool bounded. Retorna {@code false} se a fila estiver
     * cheia, proteção do nunca enfileira sem limite. O caller DEVE responder
     * "ocupado" e não deixar senha/tentativa pendente.
     */
    public boolean trySubmit(Runnable task) {
        try {
            executor.execute(task);
            return true;
        } catch (RejectedExecutionException e) {
            return false;
        }
    }

    /** Segundos restantes de lockout do IP (0 = livre). Read-only: NÃO consome tentativa. */
    public long lockoutRemainingSeconds(String ip) {
        return throttle.lockoutRemainingSeconds(ip);
    }

    public AuthOutcome login(String name, String uuid, char[] pass, String ip) {
        try {
            if (storage == null) {
                return AuthOutcome.fail("error.internal");
            }
            if (!throttle.tryAcquire(ip)) {
                return AuthOutcome.fail("login.too-many",
                        "seconds", Long.toString(throttle.lockoutRemainingSeconds(ip)));
            }
            Optional<Account> acc;
            try {
                acc = storage.find(name);
            } catch (Exception e) {
                return AuthOutcome.fail("error.internal");
            }
            if (acc.isEmpty()) {
                hasher.hashDummy(); // anti-enumeração de timing
                return AuthOutcome.fail("login.not-registered");
            }
            Account a = acc.get();
            // lockout por CONTA contra brute-force distribuído (vários IPs, 1 alvo).
            // Isenta o último IP-bom da conta, o dono real nunca é trancado fora por um atacante
            // (atacante de outro IP não consegue, ele próprio, logar do IP-bom da vítima).
            String accountKey = AccountKey.normalize(a.name());
            boolean fromKnownGoodIp = ip != null && ip.equals(a.lastIp());
            if (!fromKnownGoodIp && !accountThrottle.tryAcquire(accountKey)) {
                return AuthOutcome.fail("login.too-many",
                        "seconds", Long.toString(accountThrottle.lockoutRemainingSeconds(accountKey)));
            }
            if (a.uuid() != null && uuid != null && !a.uuid().equalsIgnoreCase(uuid)) {
                hasher.hashDummy(); // iguala o tempo de resposta ao caminho de senha errada (sem oráculo de timing)
                return AuthOutcome.fail("login.uuid-mismatch");
            }
            if (!hasher.verify(pass, a.passwordHash())) {
                return AuthOutcome.fail("login.wrong");
            }
            // sucesso
            try {
                if (hasher.needsRehash(a.passwordHash())) {
                    storage.updatePassword(a.name(), hasher.hash(pass));
                }
                storage.touchLogin(a.name(), ip, System.currentTimeMillis());
            } catch (Exception ignored) {
                // login válido mesmo se o touch/rehash falhar; não bloquear o jogador
            }
            // NÃO limpar o balde por IP no sucesso, em NAT/CGNAT compartilhado isso zeraria
            // o contador de brute-force de TODOS no mesmo IP (um login bom da vítima destravaria o
            // atacante). A janela por IP é curta e expira sozinha. O balde por CONTA pode limpar
            // (é por conta, sem efeito colateral em terceiros).
            accountThrottle.clear(accountKey);
            return AuthOutcome.ok("login.success");
        } finally {
            Arrays.fill(pass, '\0');
        }
    }

    public AuthOutcome register(String name, String uuid, char[] pass, char[] confirm, String ip) {
        try {
            if (storage == null) {
                return AuthOutcome.fail("error.internal");
            }
            if (!Arrays.equals(pass, confirm)) {
                return AuthOutcome.fail("register.mismatch");
            }
            AuthOutcome bad = checkNewPassword(pass, name, cfg.minPassword); // regra única
            if (bad != null) {
                return bad;
            }
            if (ipLimit.enabled() && ip != null && !ipLimit.bypass().contains(ip)) {
                try {
                    if (storage.countByRegIp(ip) >= ipLimit.max()) {
                        return AuthOutcome.fail("register.ip-limit", "max", Integer.toString(ipLimit.max()));
                    }
                } catch (Exception e) {
                    return AuthOutcome.fail("error.internal");
                }
            }
            // LOW: as validações baratas acima (mismatch/tamanho/nick==senha) vêm antes do throttle DE
            // PROPÓSITO, não custam hash e não devem gastar tentativa de quem só errou de digitação.
            // O throttle abaixo gateia o caminho CARO (isRegistered + hash Argon2id).
            if (!throttle.tryAcquire(ip)) {
                return AuthOutcome.fail("login.too-many",
                        "seconds", Long.toString(throttle.lockoutRemainingSeconds(ip)));
            }
            try {
                if (storage.isRegistered(name)) {
                    return AuthOutcome.fail("register.already");
                }
                long now = System.currentTimeMillis();
                Account a = new Account(name, uuid, hasher.hash(pass), null, ip, ip, false, now, now);
                storage.register(a);
            } catch (Exception e) {
                if (isDuplicateKey(e)) {
                    // corrida de double-register, a 2ª inserção viola a PK name_lower.
                    // A PK protege os dados (sem dup/sobrescrita); mapeia p/ a mensagem correta.
                    return AuthOutcome.fail("register.already");
                }
                return AuthOutcome.fail("error.internal");
            }
            return AuthOutcome.ok("register.success");
        } finally {
            Arrays.fill(pass, '\0');
            Arrays.fill(confirm, '\0');
        }
    }

    /**
     * Admin: força a senha de uma conta (usado pelo {@code /passadmin} do console).
     * SÍNCRONO, chame dentro do executor. Sem throttle (é operador, não jogador).
     * Zera a senha do array ao fim.
     */
    public AuthOutcome adminSetPassword(String name, char[] newPass) {
        try {
            if (storage == null) {
                return AuthOutcome.fail("error.internal");
            }
            AuthOutcome bad = checkNewPassword(newPass, name, cfg.minPassword); // regra única
            if (bad != null) {
                return bad;
            }
            if (!storage.isRegistered(name)) {
                return AuthOutcome.fail("admin.not-found", "name", name);
            }
            storage.updatePassword(name, hasher.hash(newPass));
            return AuthOutcome.ok("admin.passadmin.success", "name", name);
        } catch (Exception e) {
            return AuthOutcome.fail("error.internal");
        } finally {
            Arrays.fill(newPass, '\0');
        }
    }

    public AuthOutcome changePassword(String name, char[] current, char[] next, String ip) {
        try {
            if (storage == null) {
                return AuthOutcome.fail("error.internal");
            }
            if (!throttle.tryAcquire(ip)) {
                return AuthOutcome.fail("login.too-many",
                        "seconds", Long.toString(throttle.lockoutRemainingSeconds(ip)));
            }
            Optional<Account> acc;
            try {
                acc = storage.find(name);
            } catch (Exception e) {
                return AuthOutcome.fail("error.internal");
            }
            if (acc.isEmpty()) {
                return AuthOutcome.fail("changepass.not-registered");
            }
            Account a = acc.get();
            if (!hasher.verify(current, a.passwordHash())) {
                return AuthOutcome.fail("changepass.wrong");
            }
            AuthOutcome bad = checkNewPassword(next, name, cfg.minPassword); // regra única
            if (bad != null) {
                return bad;
            }
            try {
                storage.updatePassword(a.name(), hasher.hash(next));
            } catch (Exception e) {
                return AuthOutcome.fail("error.internal");
            }
            throttle.clear(ip);
            return AuthOutcome.ok("changepass.success");
        } finally {
            Arrays.fill(current, '\0');
            Arrays.fill(next, '\0');
        }
    }

    /**
     * Pool bounded p/ hash+queries: não engasga a thread do proxy no pico de logins.
     * A fila é LIMITADA ({@code queueCapacity}) com {@link ThreadPoolExecutor.AbortPolicy}:
     * sob flood, {@link #trySubmit} devolve {@code false} em vez de a fila crescer sem
     * limite (proteção do C1 contra DoS de heap/CPU por spam de /login).
     */
    public static ExecutorService newExecutor(int poolSize, int queueCapacity) {
        AtomicInteger n = new AtomicInteger();
        ThreadPoolExecutor ex = new ThreadPoolExecutor(
                poolSize, poolSize, 30L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(queueCapacity),
                r -> {
                    Thread t = new Thread(r, "archer-auth-" + n.incrementAndGet());
                    t.setDaemon(true);
                    return t;
                },
                new ThreadPoolExecutor.AbortPolicy());
        ex.allowCoreThreadTimeOut(true);
        return ex;
    }

    /**
     * validação ÚNICA de "nova senha", usada por register/changePassword/adminSetPassword
     * e por {@code EmailFlow.recoverApply}. Garante a MESMA regra em todo caminho que define senha:
     * tamanho mínimo, teto de 72 bytes (uniformiza com bcrypt importado) e senha ≠ nick.
     * @return {@code null} se a senha é válida, ou o {@link AuthOutcome} de falha.
     */
    public static AuthOutcome checkNewPassword(char[] pass, String name, int minPassword) {
        if (pass.length < minPassword) {
            return AuthOutcome.fail("register.too-short", "min", Integer.toString(minPassword));
        }
        if (utf8Length(pass) > 72) {
            return AuthOutcome.fail("register.too-long");
        }
        if (name != null && equalsIgnoreCaseToName(pass, name)) {
            return AuthOutcome.fail("register.username-as-password");
        }
        return null;
    }

    /** True se a exceção (ou sua causa) é violação de UNIQUE/PK: SQLState classe 23 (MySQL/MariaDB)
     * ou mensagem de "constraint" (SQLite). Usado p/ mapear corrida de double-register. */
    private static boolean isDuplicateKey(Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof java.sql.SQLIntegrityConstraintViolationException) {
                return true;
            }
            if (t instanceof java.sql.SQLException sql) {
                String state = sql.getSQLState();
                if (state != null && state.startsWith("23")) {
                    return true;
                }
                String msg = sql.getMessage();
                if (msg != null && msg.toLowerCase(Locale.ROOT).contains("constraint")) {
                    return true;
                }
            }
        }
        return false;
    }

    private static int utf8Length(char[] pass) {
        java.nio.ByteBuffer bb = StandardCharsets.UTF_8.encode(java.nio.CharBuffer.wrap(pass));
        int len = bb.remaining();
        if (bb.hasArray()) {
            Arrays.fill(bb.array(), (byte) 0); // LOW: não deixa cópia da senha no heap
        }
        return len;
    }

    /** Compara a senha (char[]) com o nick, case-insensitive, SEM materializar a senha como String (LOW). */
    private static boolean equalsIgnoreCaseToName(char[] pass, String name) {
        if (pass.length != name.length()) {
            return false;
        }
        for (int i = 0; i < pass.length; i++) {
            if (Character.toLowerCase(pass[i]) != Character.toLowerCase(name.charAt(i))) {
                return false;
            }
        }
        return true;
    }
}
