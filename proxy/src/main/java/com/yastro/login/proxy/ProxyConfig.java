package com.yastro.login.proxy;

import com.yastro.login.authcore.config.AuthConfig;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.MalformedInputException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
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
    public boolean bedrockEnabled = true;
    public boolean bedrockAutoLogin = true;

    // ---- Banco (repassado pro AuthConfig) ----
    private final Map<String, Object> authRaw = new HashMap<>();

    public static ProxyConfig load(Path dataDirectory) {
        ProxyConfig cfg = new ProxyConfig();
        try {
            Files.createDirectories(dataDirectory);
            Path file = dataDirectory.resolve("config.properties");
            Properties props = new Properties();
            if (Files.exists(file)) {
                loadProps(props, file);
            }
            // Merge: garante que TODA chave default exista (config antigo ganha as chaves novas).
            Properties defaults = new Properties();
            seedDefaults(defaults);
            for (String key : defaults.stringPropertyNames()) {
                if (!props.containsKey(key)) {
                    props.setProperty(key, defaults.getProperty(key));
                }
            }
            // Reescreve sempre a partir do template organizado (seções + comentários por chave),
            // preservando os valores do dono. Só toca o disco se o conteúdo mudou (idempotente).
            String rendered = renderTemplate(props);
            String current;
            try {
                current = Files.exists(file) ? Files.readString(file, StandardCharsets.UTF_8) : null;
            } catch (IOException malformed) {
                current = null; // ilegível como UTF-8 (salvo em Latin-1): força a reescrita, conserta
            }
            if (!rendered.equals(current)) {
                Files.writeString(file, rendered, StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            }
            // reaperta SEMPRE no boot (idempotente), fecha o caso de um config já completo
            // que ficou com permissão larga (db/smtp password em texto puro).
            restrictPermissions(file);
            cfg.allowCrackedOnPremiumNicks = Boolean.parseBoolean(props.getProperty("allow-cracked-on-premium-nicks", "false"));
            cfg.unknownPolicyDeny = !"offline".equalsIgnoreCase(props.getProperty("unknown-policy", "deny").trim());
            cfg.lobbyServer = props.getProperty("lobby-server", "lobby").trim();
            cfg.limboDimension = props.getProperty("limbo-dimension", "THE_END").trim().toUpperCase(Locale.ROOT);
            cfg.limboTimeoutSeconds = clampInt(props.getProperty("limbo-timeout-seconds", "60"), 0, 600, 60);
            cfg.authQueueCapacity = clampInt(props.getProperty("auth-queue-capacity", "128"), 16, 4096, 128);
            cfg.ipLimitEnabled = Boolean.parseBoolean(props.getProperty("ip-limit-enabled", "true"));
            cfg.ipLimitMax = clampInt(props.getProperty("ip-limit-max-accounts", "3"), 1, 50, 3);
            cfg.ipLimitBypass = parseSet(props.getProperty("ip-limit-bypass", "127.0.0.1"));
            cfg.diagnosticEnabled = Boolean.parseBoolean(props.getProperty("diagnostic-enabled", "true"));
            cfg.diagnosticFloodPerMin = clampInt(props.getProperty("diagnostic-flood-per-min", "100"), 1, 100000, 100);
            cfg.uiTitle = Boolean.parseBoolean(props.getProperty("ui-title", "true"));
            cfg.uiActionBar = Boolean.parseBoolean(props.getProperty("ui-action-bar", "true"));
            cfg.uiSound = Boolean.parseBoolean(props.getProperty("ui-sound", "true"));
            cfg.bedrockEnabled = Boolean.parseBoolean(props.getProperty("bedrock.enabled", "true"));
            cfg.bedrockAutoLogin = Boolean.parseBoolean(props.getProperty("bedrock.auto-login", "true"));

            // hash Argon2id (custo/seguranca; clamps no AuthConfig)
            putIf(cfg.authRaw, "hash.argon2.memory-kib", props.getProperty("hash-argon2-memory-kib"));
            putIf(cfg.authRaw, "hash.argon2.iterations", props.getProperty("hash-argon2-iterations"));
            putIf(cfg.authRaw, "hash.argon2.parallelism", props.getProperty("hash-argon2-parallelism"));

            // regra de senha
            putIf(cfg.authRaw, "password.min-length", props.getProperty("password-min-length"));

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

            // importação de hash legado (AuthMe/LoginSecurity) -> AuthConfig.fromMap
            putIf(cfg.authRaw, "legacy-import.enabled", props.getProperty("legacy-import.enabled"));

            // sessão (auto-login por IP) -> AuthConfig.fromMap
            putIf(cfg.authRaw, "session.enabled", props.getProperty("session.enabled"));
            putIf(cfg.authRaw, "session.ttl-minutes", props.getProperty("session.ttl-minutes"));

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

    /** Lê o config em UTF-8 (mesmo charset do write do template). Se o dono salvou o arquivo
     * em ISO-8859-1 com acento cru, {@code load(Reader UTF-8)} lança {@link MalformedInputException};
     * nesse caso relê em Latin-1 e o template reescreve em UTF-8 no fim (auto-conserta o charset).
     * Crucial: NÃO usar {@code load(InputStream)}, que decodifica SEMPRE em ISO-8859-1 e não casa
     * com o write UTF-8 (corromperia senha/e-mail não-ASCII a cada boot). */
    private static void loadProps(Properties props, Path file) throws IOException {
        try (BufferedReader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            props.load(r);
        } catch (MalformedInputException latin1) {
            props.clear();
            try (BufferedReader r = Files.newBufferedReader(file, StandardCharsets.ISO_8859_1)) {
                props.load(r);
            }
        }
    }

    /** Renderiza o config.properties organizado: cabeçalho, seções e um comentário por chave,
     * em ordem fixa, com os valores atuais (do dono ou default). Texto válido pra {@link Properties#load}. */
    private static String renderTemplate(Properties v) {
        StringBuilder b = new StringBuilder();
        header(b);

        sec(b, "BANCO DE DADOS",
                "sqlite = um proxy só (arquivo local em database/accounts.db, recomendado pra começar).",
                "mysql/mariadb = vários proxies compartilhando as contas; preencha os db-* abaixo.");
        kv(b, v, "db-type", "sqlite | mysql | mariadb");
        kv(b, v, "db-host", "(mysql) endereço do banco");
        kv(b, v, "db-port", "(mysql) porta do banco");
        kv(b, v, "db-name", "(mysql) nome do schema/database");
        kv(b, v, "db-user", "(mysql) usuário");
        kv(b, v, "db-password", "(mysql) senha — TEXTO PURO, não versione este arquivo");
        kv(b, v, "db-pool-size", "(mysql) conexões no pool");

        sec(b, "SEGURANÇA DE NICK (PREMIUM)",
                "allow-cracked-on-premium-nicks=true é PERIGOSO: deixa um nick de conta paga entrar",
                "em offline-mode, virando impersonável. Mantenha false salvo se sabe o que faz.",
                "unknown-policy=deny (fail-closed): se a Mojang estiver fora e não der pra saber se o",
                "nick é premium, NEGA em vez de liberar como cracked (mais seguro).");
        kv(b, v, "allow-cracked-on-premium-nicks", "true = perigoso (veja acima)");
        kv(b, v, "unknown-policy", "deny | offline");

        sec(b, "LOBBY / LIMBO",
                "Limbo = mundo-vazio onde o jogador fica preso até logar. Itens aqui são de UX.");
        kv(b, v, "lobby-server", "nome (no velocity.toml) do servidor pós-login");
        kv(b, v, "limbo-dimension", "OVERWORLD | THE_NETHER | THE_END");
        kv(b, v, "limbo-timeout-seconds", "expulsa se não logar nesse tempo (0–600)");

        sec(b, "HASH DE SENHA (Argon2id)",
                "Custo do hash. Pico de RAM ≈ parallelism × memory-kib (NÃO multiplica por jogador).",
                "Baseline OWASP. Subir memory-kib/iterations = mais seguro e mais pesado.");
        kv(b, v, "hash-argon2-memory-kib", "RAM por hash em KiB (ex.: 19456 = 19 MiB)");
        kv(b, v, "hash-argon2-iterations", "passagens (custo de tempo)");
        kv(b, v, "hash-argon2-parallelism", "threads por hash");
        kv(b, v, "password-min-length", "tamanho mínimo de senha no registro");

        sec(b, "IMPORTAÇÃO DE HASH LEGADO",
                "Reconhece hash de outro plugin de login no primeiro /login e migra p/ Argon2id.",
                "Desligue depois que a migração dos jogadores tiver assentado.");
        kv(b, v, "legacy-import.enabled", "Reconhece hashes de AuthMe/LoginSecurity no login e migra p/ Argon2id");

        sec(b, "SESSÃO",
                "Sessão: auto-login do cracked por IP (não pede /login de novo enquanto válida).");
        kv(b, v, "session.enabled", "liga o auto-login por sessão");
        kv(b, v, "session.ttl-minutes", "duração da sessão em minutos (1..1440). Fixa desde o login.");

        sec(b, "ANTI-BRUTEFORCE",
                "Lockout por IP e por CONTA (barra brute-force distribuído de vários IPs num só nick).");
        kv(b, v, "bruteforce-max-attempts", "tentativas por IP antes do lockout");
        kv(b, v, "bruteforce-window-seconds", "janela de contagem das tentativas");
        kv(b, v, "bruteforce-lockout-seconds", "tempo de bloqueio do IP (segundos)");
        kv(b, v, "bruteforce-account-max-attempts", "tentativas por CONTA antes do lockout");
        kv(b, v, "bruteforce-account-lockout-seconds", "tempo de bloqueio da conta (segundos)");

        sec(b, "LIMITE POR IP",
                "Teto de contas distintas registráveis a partir do mesmo IP (anti-farm de contas).",
                "ip-limit-bypass: IPs isentos, separados por vírgula (ex.: seu NAT/loopback).");
        kv(b, v, "ip-limit-enabled", "liga o teto por IP");
        kv(b, v, "ip-limit-max-accounts", "máx. de contas por IP (1–50)");
        kv(b, v, "ip-limit-bypass", "IPs isentos, separados por vírgula");

        sec(b, "FILA DE AUTH",
                "Capacidade da fila do pool que faz hash+queries. Cheia = rejeita flood em vez de crescer.");
        kv(b, v, "auth-queue-capacity", "tamanho da fila (16–4096)");

        sec(b, "DIAGNÓSTICO (LOG FORENSE)",
                "Grava eventos de auth em logs/diagnostic-<data>_<hora>.log (um arquivo por boot).");
        kv(b, v, "diagnostic-enabled", "liga o log forense");
        kv(b, v, "diagnostic-flood-per-min", "teto de eventos/min antes de marcar flood");

        sec(b, "INTERFACE",
                "Feedback visual/sonoro no cliente durante o login.");
        kv(b, v, "ui-title", "mostra título na tela");
        kv(b, v, "ui-action-bar", "mostra texto na action bar");
        kv(b, v, "ui-sound", "toca som de feedback");

        sec(b, "BEDROCK (Floodgate)",
                "Auto-login pra jogadores Bedrock via Floodgate (identidade já provada pelo XUID).",
                "Requer o plugin Floodgate instalado no proxy; sem ele este bloco não faz nada.");
        kv(b, v, "bedrock.enabled", "liga o suporte Bedrock (precisa do plugin Floodgate)");
        kv(b, v, "bedrock.auto-login", "true = Bedrock entra direto; false = cai no fluxo cracked/limbo normal");

        sec(b, "E-MAIL (/email e /recuperar)",
                "Vínculo e recuperação de conta por e-mail. Gmail: use uma SENHA DE APP, não a normal.",
                "Senha em TEXTO PURO: não versione este arquivo.");
        kv(b, v, "email-enabled", "liga o sistema de e-mail");
        kv(b, v, "email-smtp-host", "host SMTP (ex.: smtp.gmail.com)");
        kv(b, v, "email-smtp-port", "porta SMTP (ex.: 587)");
        kv(b, v, "email-smtp-user", "usuário/login SMTP");
        kv(b, v, "email-smtp-password", "senha de app SMTP — TEXTO PURO");
        kv(b, v, "email-smtp-from", "remetente exibido");
        kv(b, v, "email-smtp-encryption", "tls | ssl | none");
        kv(b, v, "email-code-ttl-minutes", "validade do código enviado (minutos)");

        extras(b, v);
        return b.toString();
    }

    private static void header(StringBuilder b) {
        b.append("# =====================================================================\n");
        b.append("#  ArcherLogin — configuração do proxy (Velocity)\n");
        b.append("# =====================================================================\n");
        b.append("#  Edite com o servidor DESLIGADO. Linhas com '#' são comentários.\n");
        b.append("#  Este arquivo é reorganizado automaticamente a cada boot (ordem e\n");
        b.append("#  comentários), mantendo os SEUS valores.\n");
        b.append("#  Banco e registro premium ficam em database/. Logs em logs/.\n");
        b.append("#  Atrás de TCPShield/HAProxy/Cloudflare: ligue proxy-protocol no\n");
        b.append("#  velocity.toml E no frontend, senão todos os IPs colapsam num só e o\n");
        b.append("#  anti-bruteforce/ip-limit punem jogadores legítimos.\n");
        b.append("\n");
    }

    private static void sec(StringBuilder b, String title, String... desc) {
        b.append("# ---------------------------------------------------------------------\n");
        b.append("#  ").append(title).append("\n");
        for (String d : desc) {
            b.append("#  ").append(d).append("\n");
        }
        b.append("# ---------------------------------------------------------------------\n");
    }

    private static void kv(StringBuilder b, Properties v, String key, String comment) {
        b.append("# ").append(comment).append("\n");
        b.append(key).append("=").append(escape(v.getProperty(key, ""))).append("\n\n");
    }

    /** Preserva chaves não reconhecidas (config antigo com extras / chaves futuras), não perde. */
    private static void extras(StringBuilder b, Properties v) {
        Properties defaults = new Properties();
        seedDefaults(defaults);
        List<String> unknown = new ArrayList<>();
        for (String k : v.stringPropertyNames()) {
            if (!defaults.containsKey(k)) {
                unknown.add(k);
            }
        }
        if (unknown.isEmpty()) {
            return;
        }
        Collections.sort(unknown);
        sec(b, "OUTRAS CHAVES", "Chaves não reconhecidas (preservadas).");
        for (String k : unknown) {
            b.append(escapeKey(k)).append("=").append(escape(v.getProperty(k, ""))).append("\n");
        }
        b.append("\n");
    }

    /** Escapa a CHAVE pro formato .properties: separadores ({@code = : espaço}) e
     * início-de-comentário ({@code # !}) precisam de barra pra sobreviver ao {@link Properties#load}. */
    private static String escapeKey(String key) {
        StringBuilder sb = new StringBuilder(key.length());
        for (int i = 0; i < key.length(); i++) {
            char c = key.charAt(i);
            switch (c) {
                case '\\', '=', ':', '#', '!', ' ' -> sb.append('\\').append(c);
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    /** Escapa o valor pro formato .properties (o que {@link Properties#load} espera ao reler). */
    private static String escape(String val) {
        StringBuilder sb = new StringBuilder(val.length());
        for (int i = 0; i < val.length(); i++) {
            char c = val.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case ' ' -> sb.append(i == 0 ? "\\ " : " "); // espaço inicial seria descartado pelo load()
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    private static void seedDefaults(Properties p) {
        p.setProperty("allow-cracked-on-premium-nicks", "false");
        p.setProperty("unknown-policy", "deny");
        p.setProperty("lobby-server", "lobby");
        p.setProperty("limbo-dimension", "THE_END");
        p.setProperty("limbo-timeout-seconds", "60");
        p.setProperty("auth-queue-capacity", "128");
        p.setProperty("ip-limit-enabled", "true");
        p.setProperty("ip-limit-max-accounts", "3");
        p.setProperty("ip-limit-bypass", "127.0.0.1");
        p.setProperty("diagnostic-enabled", "true");
        p.setProperty("diagnostic-flood-per-min", "100");
        p.setProperty("ui-title", "true");
        p.setProperty("ui-action-bar", "true");
        p.setProperty("ui-sound", "true");
        // Bedrock (Floodgate): auto-login por XUID já provado; requer o plugin Floodgate.
        p.setProperty("bedrock.enabled", "true");
        p.setProperty("bedrock.auto-login", "true");
        // Hash Argon2id (baseline OWASP; pico de RAM ~ nucleos x memory-kib, NAO jogadores x memory-kib).
        p.setProperty("hash-argon2-memory-kib", "19456");
        p.setProperty("hash-argon2-iterations", "2");
        p.setProperty("hash-argon2-parallelism", "1");
        // Regra de senha
        p.setProperty("password-min-length", "8");
        // Importação de hash legado (AuthMe/LoginSecurity) no primeiro /login
        p.setProperty("legacy-import.enabled", "true");
        // Sessão: auto-login do cracked por IP (não pede /login de novo enquanto válida)
        p.setProperty("session.enabled", "true");
        p.setProperty("session.ttl-minutes", "30");
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
