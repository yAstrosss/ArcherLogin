package com.yastro.login.proxy;

import com.yastro.login.authcore.config.AuthConfig;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

/**
 * Config do proxy em {@code plugins/archerlogin/config.properties}. Além das chaves
 * próprias do proxy (lobby, política premium), carrega as chaves de banco que são
 * repassadas ao {@link AuthConfig} do auth-core (única fonte de verdade dos clamps).
 */
public final class ProxyConfig {

    // ---- Proxy ----
    public boolean allowCrackedOnPremiumNicks = false;
    public boolean unknownPolicyDeny = true;
    public String lobbyServer = "lobby";
    public String limboDimension = "THE_END";
    public int limboTimeoutSeconds = 60;
    public boolean limboHidePlayers = true;
    public boolean limboBlindness = false;
    /** Capacidade da fila bounded do pool de auth (C1: rejeita flood em vez de crescer sem limite). */
    public int authQueueCapacity = 128;
    public boolean ipLimitEnabled = true;
    public int ipLimitMax = 3;
    public java.util.Set<String> ipLimitBypass = java.util.Set.of("127.0.0.1");
    public boolean diagnosticEnabled = true;
    public int diagnosticFloodPerMin = 100;
    public boolean uiTitle = true;
    public boolean uiActionBar = true;
    public boolean uiSound = true;

    // ---- Banco (repassado pro AuthConfig) ----
    private final Map<String, Object> authRaw = new HashMap<>();

    private static final String CONFIG_HEADER =
            "ArcherLogin (proxy). unknown-policy=deny (fail-closed) recomendado. "
            + "db-type=sqlite (teste 1 proxy) ou mysql (rede real). "
            + "allow-cracked-on-premium-nicks=true e PERIGOSO: nicks premium viram "
            + "impersonaveis (entram em offline-mode). Deixe false salvo se sabe o que faz. "
            + "hash-argon2-* calibram custo/seguranca do hash (pico = nucleos x memory-kib). "
            + "bruteforce-* = lockout por IP e por CONTA. session-* = nao repedir senha no mesmo IP. "
            + "ip-limit-* = teto de contas por IP. diagnostic-* = log forense. limbo-*/ui-* = limbo. "
            + "ATRAS DE FRONTEND TCP (TCPShield/HAProxy/Cloudflare): ligue proxy-protocol=true no "
            + "velocity.toml E no frontend, senao TODOS os IPs colapsam no IP do frontend e o "
            + "anti-bruteforce/ip-limit punem jogadores legitimos (o plugin avisa no log se detectar isso). "
            + "db-password fica em TEXTO PURO: restrinja a permissao do arquivo e NAO versione.";

    public static ProxyConfig load(Path dataDirectory) {
        ProxyConfig cfg = new ProxyConfig();
        try {
            Files.createDirectories(dataDirectory);
            Path file = dataDirectory.resolve("config.properties");
            Properties props = new Properties();
            boolean needsWrite = !Files.exists(file);
            if (!needsWrite) {
                try (InputStream in = Files.newInputStream(file)) {
                    props.load(in);
                }
            }
            // Merge: garante que TODA chave default exista no arquivo. Assim um config.properties
            // antigo ganha as chaves novas no boot (senão o owner não tem como configurá-las, o seedDefaults sozinho só gravaria num arquivo recém-criado).
            Properties defaults = new Properties();
            seedDefaults(defaults);
            for (String key : defaults.stringPropertyNames()) {
                if (!props.containsKey(key)) {
                    props.setProperty(key, defaults.getProperty(key));
                    needsWrite = true;
                }
            }
            if (needsWrite) {
                try (OutputStream out = Files.newOutputStream(file)) {
                    props.store(out, CONFIG_HEADER);
                }
            }
            // reaperta SEMPRE no boot (idempotente), fecha o caso de um config já completo
            // que ficou com permissão larga (db/smtp password em texto puro).
            restrictPermissions(file);
            cfg.allowCrackedOnPremiumNicks = Boolean.parseBoolean(props.getProperty("allow-cracked-on-premium-nicks", "false"));
            cfg.unknownPolicyDeny = !"offline".equalsIgnoreCase(props.getProperty("unknown-policy", "deny").trim());
            cfg.lobbyServer = props.getProperty("lobby-server", "lobby").trim();
            cfg.limboDimension = props.getProperty("limbo-dimension", "THE_END").trim().toUpperCase(Locale.ROOT);
            cfg.limboTimeoutSeconds = clampInt(props.getProperty("limbo-timeout-seconds", "60"), 0, 600, 60);
            cfg.limboHidePlayers = Boolean.parseBoolean(props.getProperty("limbo-hide-players", "true"));
            cfg.limboBlindness = Boolean.parseBoolean(props.getProperty("limbo-blindness", "false"));
            cfg.authQueueCapacity = clampInt(props.getProperty("auth-queue-capacity", "128"), 16, 4096, 128);
            cfg.ipLimitEnabled = Boolean.parseBoolean(props.getProperty("ip-limit-enabled", "true"));
            cfg.ipLimitMax = clampInt(props.getProperty("ip-limit-max-accounts", "3"), 1, 50, 3);
            cfg.ipLimitBypass = parseSet(props.getProperty("ip-limit-bypass", "127.0.0.1"));
            cfg.diagnosticEnabled = Boolean.parseBoolean(props.getProperty("diagnostic-enabled", "true"));
            cfg.diagnosticFloodPerMin = clampInt(props.getProperty("diagnostic-flood-per-min", "100"), 1, 100000, 100);
            cfg.uiTitle = Boolean.parseBoolean(props.getProperty("ui-title", "true"));
            cfg.uiActionBar = Boolean.parseBoolean(props.getProperty("ui-action-bar", "true"));
            cfg.uiSound = Boolean.parseBoolean(props.getProperty("ui-sound", "true"));

            // idioma das mensagens (clamps/validacao no AuthConfig)
            putIf(cfg.authRaw, "language", props.getProperty("language"));

            // hash Argon2id (custo/seguranca; clamps no AuthConfig)
            putIf(cfg.authRaw, "hash.argon2.memory-kib", props.getProperty("hash-argon2-memory-kib"));
            putIf(cfg.authRaw, "hash.argon2.iterations", props.getProperty("hash-argon2-iterations"));
            putIf(cfg.authRaw, "hash.argon2.parallelism", props.getProperty("hash-argon2-parallelism"));

            // regra de senha
            putIf(cfg.authRaw, "password.min-length", props.getProperty("password-min-length"));

            // sessao (nao repedir senha no mesmo IP dentro da janela)
            putIf(cfg.authRaw, "session.enabled", props.getProperty("session-enabled"));
            putIf(cfg.authRaw, "session.duration-minutes", props.getProperty("session-duration-minutes"));

            // anti-bruteforce (lockout por IP e por CONTA)
            putIf(cfg.authRaw, "bruteforce.max-attempts", props.getProperty("bruteforce-max-attempts"));
            putIf(cfg.authRaw, "bruteforce.window-seconds", props.getProperty("bruteforce-window-seconds"));
            putIf(cfg.authRaw, "bruteforce.lockout-seconds", props.getProperty("bruteforce-lockout-seconds"));
            putIf(cfg.authRaw, "bruteforce.account-max-attempts", props.getProperty("bruteforce-account-max-attempts"));
            putIf(cfg.authRaw, "bruteforce.account-lockout-seconds", props.getProperty("bruteforce-account-lockout-seconds"));

            // chaves de banco -> dot-notation que o AuthConfig.fromMap entende
            putIf(cfg.authRaw, "database.type", props.getProperty("db-type"));
            putIf(cfg.authRaw, "database.mysql.host", props.getProperty("db-host"));
            putIf(cfg.authRaw, "database.mysql.port", props.getProperty("db-port"));
            putIf(cfg.authRaw, "database.mysql.database", props.getProperty("db-name"));
            putIf(cfg.authRaw, "database.mysql.user", props.getProperty("db-user"));
            putIf(cfg.authRaw, "database.mysql.password", props.getProperty("db-password"));
            putIf(cfg.authRaw, "database.mysql.pool-size", props.getProperty("db-pool-size"));

            // e-mail (vínculo + recuperação) -> dot-notation do AuthConfig.fromMap
            putIf(cfg.authRaw, "email.enabled", props.getProperty("email-enabled"));
            putIf(cfg.authRaw, "email.smtp.host", props.getProperty("email-smtp-host"));
            putIf(cfg.authRaw, "email.smtp.port", props.getProperty("email-smtp-port"));
            putIf(cfg.authRaw, "email.smtp.user", props.getProperty("email-smtp-user"));
            putIf(cfg.authRaw, "email.smtp.password", props.getProperty("email-smtp-password"));
            putIf(cfg.authRaw, "email.smtp.from", props.getProperty("email-smtp-from"));
            putIf(cfg.authRaw, "email.smtp.encryption", props.getProperty("email-smtp-encryption"));
            putIf(cfg.authRaw, "email.code-ttl-minutes", props.getProperty("email-code-ttl-minutes"));
        } catch (IOException e) {
            // mantém defaults
        }
        return cfg;
    }

    /** Constrói o AuthConfig (clamps/defaults aplicados pelo auth-core). */
    public AuthConfig authConfig() {
        return AuthConfig.fromMap(authRaw);
    }

    public IpLimitPolicy ipLimitPolicy() {
        return new IpLimitPolicy(ipLimitEnabled, ipLimitMax, ipLimitBypass);
    }

    /** restringe o config a leitura/escrita só do dono (POSIX). No-op em SO sem POSIX (Windows),
     * onde a proteção fica por conta da ACL/permissão do diretório (avisado no header da config). */
    private static void restrictPermissions(Path file) {
        try {
            Files.setPosixFilePermissions(file,
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException | IOException ignored) {
            // SO sem POSIX: confiar na permissão do diretório.
        }
    }

    private static java.util.Set<String> parseSet(String raw) {
        if (raw == null || raw.isBlank()) {
            return java.util.Set.of();
        }
        java.util.Set<String> out = new java.util.HashSet<>();
        for (String s : raw.split(",")) {
            String t = s.trim();
            if (!t.isEmpty()) {
                out.add(t);
            }
        }
        return java.util.Set.copyOf(out);
    }

    private static void seedDefaults(Properties p) {
        p.setProperty("allow-cracked-on-premium-nicks", "false");
        p.setProperty("unknown-policy", "deny");
        p.setProperty("lobby-server", "lobby");
        p.setProperty("limbo-dimension", "THE_END");
        p.setProperty("limbo-timeout-seconds", "60");
        p.setProperty("limbo-hide-players", "true");
        p.setProperty("limbo-blindness", "false");
        p.setProperty("auth-queue-capacity", "128");
        p.setProperty("ip-limit-enabled", "true");
        p.setProperty("ip-limit-max-accounts", "3");
        p.setProperty("ip-limit-bypass", "127.0.0.1");
        p.setProperty("diagnostic-enabled", "true");
        p.setProperty("diagnostic-flood-per-min", "100");
        p.setProperty("ui-title", "true");
        p.setProperty("ui-action-bar", "true");
        p.setProperty("ui-sound", "true");
        p.setProperty("language", "br");
        // Hash Argon2id (baseline OWASP; pico de RAM ~ nucleos x memory-kib, NAO jogadores x memory-kib).
        p.setProperty("hash-argon2-memory-kib", "19456");
        p.setProperty("hash-argon2-iterations", "2");
        p.setProperty("hash-argon2-parallelism", "1");
        // Regra de senha
        p.setProperty("password-min-length", "8");
        // Sessao (0 = desliga; nao repede senha no mesmo IP dentro da janela)
        p.setProperty("session-enabled", "true");
        p.setProperty("session-duration-minutes", "5");
        // Anti-bruteforce: lockout por IP + por CONTA (barra brute-force distribuido)
        p.setProperty("bruteforce-max-attempts", "5");
        p.setProperty("bruteforce-window-seconds", "60");
        p.setProperty("bruteforce-lockout-seconds", "300");
        p.setProperty("bruteforce-account-max-attempts", "10");
        p.setProperty("bruteforce-account-lockout-seconds", "600");
        p.setProperty("db-type", "sqlite");
        p.setProperty("db-host", "localhost");
        p.setProperty("db-port", "3306");
        p.setProperty("db-name", "archerlogin");
        p.setProperty("db-user", "root");
        p.setProperty("db-password", "");
        p.setProperty("db-pool-size", "10");
        // E-mail (vínculo /email + recuperação /recover). Gmail: use uma "senha de app".
        p.setProperty("email-enabled", "false");
        p.setProperty("email-smtp-host", "smtp.gmail.com");
        p.setProperty("email-smtp-port", "587");
        p.setProperty("email-smtp-user", "");
        p.setProperty("email-smtp-password", "");
        p.setProperty("email-smtp-from", "");
        p.setProperty("email-smtp-encryption", "tls");
        p.setProperty("email-code-ttl-minutes", "10");
    }

    private static void putIf(Map<String, Object> m, String key, String val) {
        if (val != null && !val.isBlank()) {
            m.put(key, val.trim());
        }
    }

    private static int clampInt(String raw, int min, int max, int def) {
        int v;
        try {
            v = Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            v = def;
        }
        return Math.max(min, Math.min(max, v));
    }
}
