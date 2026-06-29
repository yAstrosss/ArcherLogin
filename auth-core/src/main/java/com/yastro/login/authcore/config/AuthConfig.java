package com.yastro.login.authcore.config;

import java.util.Locale;
import java.util.Map;

public final class AuthConfig {
    public String dbType;
    public String mysqlHost; public int mysqlPort; public String mysqlDatabase;
    public String mysqlUser; public String mysqlPassword; public int mysqlPoolSize;
    public int argonMemoryKib, argonIterations, argonParallelism;
    public int minPassword;
    public int maxAttempts, attemptWindowSeconds, lockoutSeconds;
    public int accountMaxAttempts, accountLockoutSeconds;
    public boolean emailEnabled;
    public String emailHost;
    public int emailPort;
    public String emailUser;
    public String emailPassword;
    public String emailFrom;
    public String emailEncryption;
    public int emailCodeTtlMinutes;

    public static AuthConfig fromMap(Map<String, Object> r) {
        AuthConfig c = new AuthConfig();
        c.dbType = str(r, "database.type", "sqlite").trim().toLowerCase(Locale.ROOT);
        c.mysqlHost = str(r, "database.mysql.host", "localhost");
        c.mysqlPort = intval(r, "database.mysql.port", 3306);
        c.mysqlDatabase = str(r, "database.mysql.database", "archerlogin");
        c.mysqlUser = str(r, "database.mysql.user", "root");
        c.mysqlPassword = str(r, "database.mysql.password", "");
        c.mysqlPoolSize = clamp(intval(r, "database.mysql.pool-size", 10), 2, 50);
        // piso = baseline OWASP (19456 KiB). A config só permite SUBIR o custo do hash,
        // nunca cair abaixo do recomendado (hash fraco = crack offline barato se o banco vazar).
        c.argonMemoryKib = clamp(intval(r, "hash.argon2.memory-kib", 19456), 19456, 65536);
        c.argonIterations = clamp(intval(r, "hash.argon2.iterations", 2), 1, 10);
        c.argonParallelism = clamp(intval(r, "hash.argon2.parallelism", 1), 1, 8);
        c.minPassword = clamp(intval(r, "password.min-length", 8), 6, 64);
        c.maxAttempts = clamp(intval(r, "bruteforce.max-attempts", 5), 1, 100);
        c.attemptWindowSeconds = clamp(intval(r, "bruteforce.window-seconds", 60), 5, 3600);
        c.lockoutSeconds = clamp(intval(r, "bruteforce.lockout-seconds", 300), 10, 86400);
        c.accountMaxAttempts = clamp(intval(r, "bruteforce.account-max-attempts", 10), 3, 200);
        c.accountLockoutSeconds = clamp(intval(r, "bruteforce.account-lockout-seconds", 600), 10, 86400);
        c.emailEnabled = boolval(r, "email.enabled", false);
        c.emailHost = str(r, "email.smtp.host", "smtp.gmail.com");
        c.emailPort = intval(r, "email.smtp.port", 587);
        c.emailUser = str(r, "email.smtp.user", "");
        c.emailPassword = str(r, "email.smtp.password", "");
        c.emailFrom = str(r, "email.smtp.from", "");
        c.emailEncryption = str(r, "email.smtp.encryption", "tls").trim().toLowerCase(Locale.ROOT);
        c.emailCodeTtlMinutes = clamp(intval(r, "email.code-ttl-minutes", 10), 1, 60);
        return c;
    }

    private static String str(Map<String, Object> r, String k, String def) {
        Object v = r.get(k);
        return v == null ? def : v.toString();
    }

    private static int intval(Map<String, Object> r, String k, int def) {
        Object v = r.get(k);
        if (v instanceof Number n) return n.intValue();
        if (v == null) return def;
        try { return Integer.parseInt(v.toString().trim()); } catch (NumberFormatException e) { return def; }
    }

    private static boolean boolval(Map<String, Object> r, String k, boolean def) {
        Object v = r.get(k);
        return v == null ? def : Boolean.parseBoolean(v.toString());
    }

    private static int clamp(int v, int min, int max) {
        return Math.max(min, Math.min(max, v));
    }
}
